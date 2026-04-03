use std::env;
use std::fs;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use actix_rt::signal::ctrl_c;
use bitcoin::consensus::serialize;
use bitcoin::constants::genesis_block;
use clap::Parser;
use futures::channel::mpsc::channel;
use log::info;
use log::warn;

use crate::api;
use crate::block_index::BlocksIndex;
use crate::blockfile::BlockFile;
use crate::chainview;
use crate::cli::CliArgs;
use crate::get_chain_provider;
use crate::init_logger;
use crate::leaf_cache::DiskLeafStorage;
use crate::node;
use crate::node::WorkerContext;
use crate::prover;
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

    // to keep track of the current chain state and speed up replying to headers requests
    // from peers.
    let store = kv::Store::new(kv::Config {
        path: subdir("chain_view").into(),
        temporary: false,
        use_compression: false,
        flush_every_ms: None,
        cache_capacity: None,
        segment_size: None,
    })
    .expect("Failed to open chainview database");

    // Chainview is a collection of metadata about the chain, like tip and block
    // indexes. It's stored in a key-value database.
    let view = chainview::ChainView::new(store);
    let view = Arc::new(view);

    let network = cli_options.network;
    let genesis = genesis_block(network);

    if view.get_height(genesis.block_hash()).is_err() {
        view.save_header(genesis.block_hash(), serialize(&genesis.header))
            .expect("Failed to save genesis header");
        view.save_height(genesis.header.block_hash(), 0)
            .expect("Failed to save genesis height");
    }

    // This database stores some useful information about the blocks, but not
    // the blocks themselves
    let index_store = BlocksIndex {
        database: kv::Store::new(kv::Config {
            path: subdir("index/").into(),
            temporary: false,
            use_compression: false,
            flush_every_ms: Some(1000),
            cache_capacity: Some(1_000_000),
            segment_size: None,
        })
        .unwrap(),
    };

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
    let client = get_chain_provider(cli_options.bitcoin_datadir.as_deref())?;

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

    info!("Starting p2p node");

    // This is our implementation of the Bitcoin p2p protocol, it will listen
    // for incoming connections and serve blocks and proofs to peers.
    let p2p_port = env::var("P2P_PORT").unwrap_or_else(|_| "8333".into());
    let p2p_address = format!(
        "{}:{}",
        env::var("P2P_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
        p2p_port
    );

    let worker_context = WorkerContext {
        chainview: view.clone(),
        magic: cli_options.network.magic(),
        proof_index: index_store.clone(),
        proof_backend: blocks.clone(),
    };

    node::Node::run(
        p2p_address.parse().unwrap(),
        worker_context,
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
