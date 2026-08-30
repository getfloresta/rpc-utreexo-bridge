// SPDX-License-Identifier: MIT

//! Build a SwiftSync hintsfile from Bitcoin Core block files through `libbitcoinkernel`.

use std::env;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use ahash::AHashMap;
use ahash::AHashSet;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoin::Txid;
use bitcoinkernel::prelude::ScriptPubkeyExt;
use bitcoinkernel::prelude::TransactionExt;
use bitcoinkernel::prelude::TxInExt;
use bitcoinkernel::prelude::TxOutExt;
use bitcoinkernel::prelude::TxOutPointExt;
use bitcoinkernel::prelude::TxidExt;
use bitcoinkernel::Block as KernelBlock;
use bitcoinkernel::ChainType;
use bitcoinkernel::ChainstateManager;
use bitcoinkernel::Context as KernelContext;
use bitcoinkernel::ContextBuilder;
use clap::Parser;
use hintsfile::EliasFano;
use hintsfile::HintsfileBuilder;

const BIP30_FIRST_TXID_91722: &str =
    "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468";
const BIP30_FIRST_TXID_91812: &str =
    "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599";

#[derive(Debug, Parser)]
#[command(
    name = "bridge-hints",
    about = "Build a hintsfile by reading an unpruned Bitcoin Core datadir with libbitcoinkernel"
)]
struct Cli {
    /// Destination hintsfile. Written atomically after the complete scan.
    #[arg(long, short)]
    output: PathBuf,

    /// Last block height to include. Defaults to Bitcoin Core's active-chain tip.
    #[arg(long)]
    stop_height: Option<u32>,

    /// Bitcoin network represented by the Core datadir.
    #[arg(long, short = 'n', default_value = "bitcoin")]
    network: Network,

    /// Initial capacity for the in-memory UTXO map.
    #[arg(long)]
    utxo_capacity: Option<usize>,

    /// Print progress every N blocks. Zero disables periodic progress.
    #[arg(long, default_value_t = 10_000)]
    progress_every: u32,

    /// Atomically replace an existing destination file.
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeafPosition {
    height: u32,
    index: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct KernelOutPoint {
    txid: [u8; 32],
    vout: u32,
}

struct KernelChain {
    // Fields drop in declaration order; the manager must be destroyed before its context.
    manager: ChainstateManager,
    _context: KernelContext,
    tip_height: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let kernel = KernelChain::open(&cli)?;
    let stop_height = cli.stop_height.unwrap_or(kernel.tip_height);
    if stop_height == 0 {
        bail!("stop height must be greater than zero");
    }
    if stop_height > kernel.tip_height {
        bail!(
            "requested stop height {stop_height} is above Core tip {}",
            kernel.tip_height
        );
    }

    let stop_hash = kernel.block_hash_at_height(stop_height)?;
    eprintln!(
        "Scanning heights 1..={stop_height} through block {stop_hash} via Bitcoin Core's kernel chainstate"
    );

    let mut utxos = match cli.utxo_capacity {
        Some(capacity) => AHashMap::with_capacity(capacity),
        None => AHashMap::new(),
    };
    for height in 1..=stop_height {
        let block = kernel.block_at_height(height)?;
        let eligible_outputs = apply_block(height, &block, &mut utxos)?;

        if cli.progress_every != 0 && (height % cli.progress_every == 0 || height == stop_height) {
            eprintln!(
                "height={height} eligible_outputs={eligible_outputs} live_utxos={}",
                utxos.len()
            );
        }
    }

    let live_utxos = utxos.len();
    let indices = collect_unspent_indices(stop_height, utxos)?;
    write_hints_file(&cli.output, stop_height, &indices, cli.force)?;
    eprintln!(
        "Wrote {} with stop_height={stop_height} live_utxos={live_utxos}",
        cli.output.display()
    );
    Ok(())
}

impl KernelChain {
    fn open(cli: &Cli) -> Result<Self> {
        let home = env::var("HOME").context("HOME is required to locate Bitcoin Core data")?;
        let bitcoin_data_dir = PathBuf::from(home).join(".bitcoin");
        let network_data_dir = network_data_dir(&bitcoin_data_dir, cli.network);
        let blocks_dir = network_data_dir.join("blocks");
        if !blocks_dir.is_dir() {
            bail!(
                "Bitcoin Core blocks directory {} does not exist",
                blocks_dir.display()
            );
        }
        let context = ContextBuilder::new()
            .chain_type(kernel_chain_type(cli.network)?)
            .build()
            .context("failed to create Bitcoin kernel context")?;
        let data_dir = network_data_dir
            .to_str()
            .context("Bitcoin Core network directory is not valid UTF-8")?;
        let blocks_dir = blocks_dir
            .to_str()
            .context("Bitcoin Core blocks directory is not valid UTF-8")?;
        let manager = ChainstateManager::new(&context, data_dir, blocks_dir)
            .context("failed to open Bitcoin Core through the kernel chainstate manager")?;
        let chain = manager.active_chain();
        let tip_height =
            u32::try_from(chain.height()).context("kernel chain tip is outside u32 range")?;
        eprintln!(
            "Opened Bitcoin Core kernel chain height={tip_height} hash={}",
            chain.tip().block_hash()
        );
        Ok(Self {
            manager,
            _context: context,
            tip_height,
        })
    }

    fn block_at_height(&self, height: u32) -> Result<KernelBlock> {
        let chain = self.manager.active_chain();
        let entry = chain
            .at_height(height as usize)
            .ok_or_else(|| anyhow!("kernel active chain has no block at height {height}"))?;
        self.manager
            .read_block_data(&entry)
            .with_context(|| format!("failed to read block data at height {height}"))
    }

    fn block_hash_at_height(&self, height: u32) -> Result<String> {
        self.manager
            .active_chain()
            .at_height(height as usize)
            .map(|entry| entry.block_hash().to_string())
            .ok_or_else(|| anyhow!("kernel active chain has no block at height {height}"))
    }
}

fn kernel_chain_type(network: Network) -> Result<ChainType> {
    match network {
        Network::Bitcoin => Ok(ChainType::Mainnet),
        Network::Testnet => Ok(ChainType::Testnet),
        Network::Testnet4 => Ok(ChainType::Testnet4),
        Network::Signet => Ok(ChainType::Signet),
        Network::Regtest => Ok(ChainType::Regtest),
        _ => bail!("unsupported Bitcoin network {network}"),
    }
}

fn network_data_dir(bitcoin_data_dir: &Path, network: Network) -> PathBuf {
    match network {
        Network::Bitcoin => bitcoin_data_dir.to_owned(),
        Network::Testnet => bitcoin_data_dir.join("testnet3"),
        Network::Testnet4 => bitcoin_data_dir.join("testnet4"),
        Network::Signet => bitcoin_data_dir.join("signet"),
        Network::Regtest => bitcoin_data_dir.join("regtest"),
        _ => bitcoin_data_dir.join(network.to_string()),
    }
}

fn apply_block(
    height: u32,
    block: &KernelBlock,
    utxos: &mut AHashMap<KernelOutPoint, LeafPosition>,
) -> Result<u32> {
    let same_block_spends = same_block_spends(block)?;

    for tx in block.transactions() {
        for input in tx.inputs() {
            let previous_output = input.outpoint();
            if previous_output.is_null() {
                continue;
            }
            let previous_output = KernelOutPoint {
                txid: previous_output.txid().to_bytes(),
                vout: previous_output.index(),
            };
            if same_block_spends.contains(&previous_output) {
                continue;
            }
            utxos.remove(&previous_output).ok_or_else(|| {
                anyhow!(
                    "input {previous_output:?} at height {height} does not reference an indexed UTXO"
                )
            })?;
        }
    }

    let bip30_exclusion = bip30_excluded_outpoint(height);
    let mut eligible_outputs = 0u32;
    for tx in block.transactions() {
        let txid = tx.txid().to_bytes();
        for (vout, output) in tx.outputs().enumerate() {
            let outpoint = KernelOutPoint {
                txid,
                vout: u32::try_from(vout).context("transaction output index exceeds u32::MAX")?,
            };
            let script_pubkey = output.script_pubkey().to_bytes();
            if script_pubkey.len() > 10_000
                || script_pubkey.first() == Some(&0x6a)
                || same_block_spends.contains(&outpoint)
                || bip30_exclusion == Some(outpoint)
            {
                continue;
            }

            let position = LeafPosition {
                height,
                index: eligible_outputs,
            };
            if utxos.insert(outpoint, position).is_some() {
                bail!("duplicate unspent outpoint {outpoint:?} at height {height}");
            }
            eligible_outputs = eligible_outputs
                .checked_add(1)
                .context("one block contains more than u32::MAX eligible outputs")?;
        }
    }
    Ok(eligible_outputs)
}

fn same_block_spends(block: &KernelBlock) -> Result<AHashSet<KernelOutPoint>> {
    let mut created = AHashSet::new();
    let mut spent = AHashSet::new();
    for tx in block.transactions() {
        for input in tx.inputs() {
            let previous_output = input.outpoint();
            let previous_output = KernelOutPoint {
                txid: previous_output.txid().to_bytes(),
                vout: previous_output.index(),
            };
            if created.contains(&previous_output) {
                spent.insert(previous_output);
            }
        }
        let txid = tx.txid().to_bytes();
        for vout in 0..tx.output_count() {
            created.insert(KernelOutPoint {
                txid,
                vout: u32::try_from(vout).context("transaction output index exceeds u32::MAX")?,
            });
        }
    }
    Ok(spent)
}

fn bip30_excluded_outpoint(height: u32) -> Option<KernelOutPoint> {
    let txid = match height {
        91_722 => BIP30_FIRST_TXID_91722,
        91_812 => BIP30_FIRST_TXID_91812,
        _ => return None,
    };
    Some(KernelOutPoint {
        txid: Txid::from_str(txid)
            .expect("hardcoded BIP30 txid must be valid")
            .to_byte_array(),
        vout: 0,
    })
}

fn collect_unspent_indices(
    stop_height: u32,
    utxos: AHashMap<KernelOutPoint, LeafPosition>,
) -> Result<Vec<Vec<u32>>> {
    let mut indices = vec![Vec::new(); stop_height as usize + 1];
    for position in utxos.into_values() {
        let height = usize::try_from(position.height).context("leaf height exceeds usize")?;
        let at_height = indices
            .get_mut(height)
            .ok_or_else(|| anyhow!("leaf height {} exceeds stop height", position.height))?;
        at_height.push(position.index);
    }
    for at_height in &mut indices[1..] {
        at_height.sort_unstable();
        if !at_height.windows(2).all(|pair| pair[0] < pair[1]) {
            bail!("duplicate leaf index while collecting hints");
        }
    }
    Ok(indices)
}

fn encode_hints<W: Write>(writer: W, stop_height: u32, indices: &[Vec<u32>]) -> Result<()> {
    if indices.len() != stop_height as usize + 1 {
        bail!(
            "expected {} per-height hint vectors, got {}",
            stop_height as usize + 1,
            indices.len()
        );
    }
    let mut builder = HintsfileBuilder::new(writer)
        .initialize(stop_height)
        .context("failed to initialize hintsfile")?;
    for height in 1..=stop_height {
        builder
            .append(EliasFano::compress(&indices[height as usize]))
            .with_context(|| format!("failed to encode hints at height {height}"))?;
    }
    builder.finish().context("failed to finish hintsfile")
}

fn write_hints_file(
    output: &Path,
    stop_height: u32,
    indices: &[Vec<u32>],
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "destination {} already exists; pass --force to replace it",
            output.display()
        );
    }
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    let mut temporary_name = output.as_os_str().to_owned();
    temporary_name.push(".tmp");
    let temporary = PathBuf::from(temporary_name);
    if temporary.exists() {
        bail!(
            "temporary output {} already exists; remove it before retrying",
            temporary.display()
        );
    }

    let result = (|| -> Result<()> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        encode_hints(
            BufWriter::with_capacity(1024 * 1024, file),
            stop_height,
            indices,
        )?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&temporary)
            .context("failed to reopen temporary hintsfile")?
            .sync_all()
            .context("failed to sync temporary hintsfile")?;
        std::fs::rename(&temporary, output).with_context(|| {
            format!(
                "failed to move {} to {}",
                temporary.display(),
                output.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bitcoin::absolute;
    use bitcoin::block;
    use bitcoin::block::Header;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction;
    use bitcoin::Amount;
    use bitcoin::Block;
    use bitcoin::BlockHash;
    use bitcoin::CompactTarget;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::Sequence;
    use bitcoin::Transaction;
    use bitcoin::TxIn;
    use bitcoin::TxMerkleNode;
    use bitcoin::TxOut;
    use bitcoin::Witness;
    use hintsfile::Hintsfile;

    use super::*;

    fn transaction(previous_output: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        }
    }

    fn output(value: u64, script_pubkey: ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }
    }

    fn block(nonce: u32, transactions: Vec<Transaction>) -> Block {
        Block {
            header: Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce,
            },
            txdata: transactions,
        }
    }

    fn kernel_block(block: &Block) -> KernelBlock {
        KernelBlock::new(&serialize(block)).unwrap()
    }

    fn kernel_outpoint(outpoint: OutPoint) -> KernelOutPoint {
        KernelOutPoint {
            txid: outpoint.txid.to_byte_array(),
            vout: outpoint.vout,
        }
    }

    #[test]
    fn filters_outputs_before_assigning_per_block_indices() {
        let coinbase = transaction(
            OutPoint::null(),
            vec![
                output(10, ScriptBuf::new()),
                output(20, ScriptBuf::new()),
                output(0, ScriptBuf::from_bytes(vec![0x6a])),
                output(30, ScriptBuf::from_bytes(vec![0; 10_001])),
            ],
        );
        let same_block_outpoint = OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let spend_in_block = transaction(same_block_outpoint, vec![output(40, ScriptBuf::new())]);
        let first_block = block(1, vec![coinbase.clone(), spend_in_block.clone()]);
        let first_kernel_block = kernel_block(&first_block);

        let surviving_first_outpoint = OutPoint {
            txid: coinbase.compute_txid(),
            vout: 1,
        };
        let same_block_created_outpoint = OutPoint {
            txid: spend_in_block.compute_txid(),
            vout: 0,
        };
        let second_coinbase = transaction(OutPoint::null(), vec![output(50, ScriptBuf::new())]);
        let spend_old = transaction(surviving_first_outpoint, vec![output(60, ScriptBuf::new())]);
        let second_block = block(2, vec![second_coinbase.clone(), spend_old.clone()]);
        let second_kernel_block = kernel_block(&second_block);

        let mut utxos = AHashMap::new();
        assert_eq!(apply_block(1, &first_kernel_block, &mut utxos).unwrap(), 2);
        assert_eq!(
            utxos.get(&kernel_outpoint(surviving_first_outpoint)),
            Some(&LeafPosition {
                height: 1,
                index: 0
            })
        );
        assert_eq!(
            utxos.get(&kernel_outpoint(same_block_created_outpoint)),
            Some(&LeafPosition {
                height: 1,
                index: 1
            })
        );
        assert!(!utxos.contains_key(&kernel_outpoint(same_block_outpoint)));

        assert_eq!(apply_block(2, &second_kernel_block, &mut utxos).unwrap(), 2);
        assert!(!utxos.contains_key(&kernel_outpoint(surviving_first_outpoint)));
        let indices = collect_unspent_indices(2, utxos).unwrap();
        assert_eq!(indices[1], vec![1]);
        assert_eq!(indices[2], vec![0, 1]);

        let mut encoded = Vec::new();
        encode_hints(&mut encoded, 2, &indices).unwrap();
        let hints = Hintsfile::from_reader(&mut Cursor::new(encoded)).unwrap();
        assert_eq!(hints.stop_height(), 2);
        assert_eq!(hints.indices_at_height(1), Some(vec![1]));
        assert_eq!(hints.indices_at_height(2), Some(vec![0, 1]));
    }

    #[test]
    fn excludes_only_the_overwritten_bip30_first_occurrences() {
        assert_eq!(
            bip30_excluded_outpoint(91_722),
            Some(KernelOutPoint {
                txid: Txid::from_str(BIP30_FIRST_TXID_91722)
                    .unwrap()
                    .to_byte_array(),
                vout: 0,
            })
        );
        assert_eq!(
            bip30_excluded_outpoint(91_812),
            Some(KernelOutPoint {
                txid: Txid::from_str(BIP30_FIRST_TXID_91812)
                    .unwrap()
                    .to_byte_array(),
                vout: 0,
            })
        );
        assert_eq!(bip30_excluded_outpoint(91_842), None);
        assert_eq!(bip30_excluded_outpoint(91_880), None);
    }
}
