use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use actix_rt::signal::ctrl_c;
use bitcoin::consensus::serialize;
use bitcoin::constants::genesis_block;
use clap::Parser;
use futures::channel::mpsc::channel;
use hintsfile::Hintsfile;
use log::info;
use log::warn;

use crate::api;
use crate::block_index::BlocksIndex;
use crate::blockfile::BlockFile;
use crate::blockfile::ProofFile;
use crate::chainview;
use crate::cli::CliArgs;
use crate::get_chain_provider;
use crate::init_logger;
use crate::leaf_cache::DiskLeafStorage;
use crate::node;
use crate::node::ProofBackend;
use crate::node::WorkerContext;
use crate::parallel_forest::build_parallel_forest;
use crate::parallel_forest::KernelBlockSource;
use crate::parallel_forest::ParallelForestConfig;
use crate::prover;
use crate::prover::FlatFileProver;
use crate::subdir;

pub fn run_bridge() -> anyhow::Result<()> {
    let cli_options = CliArgs::parse();
    fs::DirBuilder::new()
        .recursive(true)
        .create(subdir(""))
        .unwrap();

    // Initialize the logger
    init_logger(
        Some(&subdir("debug.log")),
        simplelog::LevelFilter::Info,
        true,
    );

    if let Some(hints_path) = cli_options.build_forest.as_deref() {
        let file = File::open(hints_path)?;
        let hints = Hintsfile::from_reader(&mut BufReader::new(file))?;
        let forest_path = cli_options
            .forest_file
            .clone()
            .unwrap_or_else(|| subdir("forest.dat").into());
        let mut config = ParallelForestConfig::new(forest_path);
        config.leaf_map_path = cli_options
            .leaf_map_path
            .clone()
            .unwrap_or_else(|| subdir("leaf-map").into());
        if let Some(workers) = cli_options.forest_leaf_workers {
            config.leaf_workers = workers;
        }
        if let Some(workers) = cli_options.forest_chaser_workers {
            config.chaser_workers = workers;
        }
        if let Some(iterations) = cli_options.forest_spin_iterations {
            config.spin_iterations = iterations;
        }
        config.lock_pages = !cli_options.forest_no_mlock;

        let source = KernelBlockSource::open(cli_options.network)?;
        let summary = build_parallel_forest(&source, &hints, config)?;
        info!(
            "Built flat forest: leaves={} nodes={} leaf_map_entries={} bytes={} roots={} pages_locked={}",
            summary.leaves,
            summary.initialized_nodes,
            summary.leaf_map_entries,
            summary.file_bytes,
            summary.roots.len(),
            summary.pages_locked
        );
        return Ok(());
    }

    if let Some(hints_path) = cli_options.steady_state.as_deref() {
        let file = File::open(hints_path)?;
        let hints = Hintsfile::from_reader(&mut BufReader::new(file))?;
        let forest_path = cli_options
            .forest_file
            .clone()
            .unwrap_or_else(|| subdir("forest.dat").into());
        let leaf_map_path = cli_options
            .leaf_map_path
            .clone()
            .unwrap_or_else(|| subdir("leaf-map").into());
        let proof_index = Arc::new(open_index(subdir("proof-index/")));
        let proof_file = Arc::new(RwLock::new(ProofFile::new(subdir("proofs").into())?));
        let view = open_chain_view(cli_options.network);
        let (block_notifier_tx, block_notifier_rx) = std::sync::mpsc::channel();
        start_p2p(
            cli_options.network,
            view,
            proof_index.clone(),
            ProofBackend::CompactProofs(proof_file.clone()),
            block_notifier_rx,
        );
        let client = get_chain_provider()?;
        let kill_signal = Arc::new(Mutex::new(false));
        let shutdown = kill_signal.clone();
        ctrlc::set_handler(move || {
            *shutdown.lock().unwrap() = true;
        })?;
        let mut prover = FlatFileProver::new(
            client,
            &forest_path,
            &leaf_map_path,
            proof_file,
            proof_index,
            hints.stop_height(),
            !cli_options.forest_no_mlock,
            kill_signal,
            block_notifier_tx,
        )?;
        return prover.keep_up();
    }

    let view = open_chain_view(cli_options.network);

    // This database stores some useful information about the blocks, but not
    // the blocks themselves.
    let index_store = open_index(subdir("index/"));

    // Put it into an Arc so we can share it between threads
    let index_store = Arc::new(index_store);
    // This database stores the blocks themselves, it's a collection of flat files
    // that are indexed by the index above. They are stored in the `blocks/` directory
    // and are serialized as bitcoin blocks, so we don't need to do any parsing
    // before sending to a peer.
    let blocks = Arc::new(RwLock::new(
        BlockFile::new(subdir("blocks").into(), 10_000_000_000).expect("Could not open block file"),
    ));

    // The prover needs some way to pull blocks from a trusted source, we can use anything
    // implementing the [Blockchain] trait, for example a bitcoin core node or an esplora
    // instance.
    let client = get_chain_provider()?;

    // Create a prover, this module will download blocks from the bitcoin core
    // node and save them to disk. It will also create proofs for the blocks
    // and save them to disk.
    let leaf_data = DiskLeafStorage::new(&subdir("leaf_data"));

    // a signal used to stop the prover
    let kill_signal = Arc::new(Mutex::new(false));

    //let leaf_data = HashMap::new(); // In-memory leaf storage,
    // faster than leaf_data but uses more memory

    let (block_notifier_tx, block_notifier_rx) = std::sync::mpsc::channel();
    let mut prover = prover::Prover::new(
        client,
        index_store.clone(),
        blocks.clone(),
        view.clone(),
        leaf_data,
        cli_options.initial_state_path.map(Into::into),
        cli_options.start_height,
        cli_options.acc_snapshot_every_n_blocks,
        kill_signal.clone(),
        cli_options.save_proofs_after.unwrap_or(0),
        block_notifier_tx,
    );

    start_p2p(
        cli_options.network,
        view.clone(),
        index_store.clone(),
        ProofBackend::LegacyBlocks(blocks.clone()),
        block_notifier_rx,
    );

    let (sender, receiver) = channel(1024);
    // This is our implementation of the json-rpc api, it will listen for
    // incoming connections and serve some Utreexo data to clients.
    info!("Starting api");
    let host = env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1:3000".into());
    std::thread::spawn(move || {
        actix_rt::System::new()
            .block_on(api::create_api(sender, view, &host))
            .unwrap()
    });

    // Keep the prover running in the background, it will download blocks and
    // create proofs for them as they are mined.
    info!("Running prover");
    std::thread::spawn(move || {
        actix_rt::System::new().block_on(async {
            let _ = ctrl_c().await;
            warn!("Received a stop signal");
            *kill_signal.lock().unwrap() = true;
        })
    });

    prover.keep_up(receiver)
}

fn open_chain_view(network: bitcoin::Network) -> Arc<chainview::ChainView> {
    let store = kv::Store::new(kv::Config {
        path: subdir("chain_view").into(),
        temporary: false,
        use_compression: false,
        flush_every_ms: None,
        cache_capacity: None,
        segment_size: None,
    })
    .expect("Failed to open chainview database");
    let view = Arc::new(chainview::ChainView::new(store));
    let genesis = genesis_block(network);
    if view.get_height(genesis.block_hash()).is_err() {
        view.save_header(genesis.block_hash(), serialize(&genesis.header))
            .expect("Failed to save genesis header");
        view.save_height(genesis.header.block_hash(), 0)
            .expect("Failed to save genesis height");
    }
    view
}

fn start_p2p(
    network: bitcoin::Network,
    view: Arc<chainview::ChainView>,
    proof_index: Arc<BlocksIndex>,
    proof_backend: ProofBackend,
    block_notifier: std::sync::mpsc::Receiver<bitcoin::BlockHash>,
) {
    info!("Starting BIP 183 proof server");
    let p2p_port = env::var("P2P_PORT").unwrap_or_else(|_| "8333".into());
    let p2p_address = format!(
        "{}:{}",
        env::var("P2P_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
        p2p_port
    );
    let worker_context = WorkerContext {
        chainview: view,
        magic: network.magic(),
        proof_index,
        proof_backend,
    };
    node::Node::run(
        p2p_address.parse().expect("invalid P2P listen address"),
        worker_context,
        block_notifier,
    );
}

fn open_index(path: String) -> BlocksIndex {
    BlocksIndex {
        database: kv::Store::new(kv::Config {
            path: path.into(),
            temporary: false,
            use_compression: false,
            flush_every_ms: Some(1000),
            cache_capacity: Some(1_000_000),
            segment_size: None,
        })
        .expect("Failed to open proof index"),
    }
}
