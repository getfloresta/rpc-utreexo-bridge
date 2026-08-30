// SPDX-License-Identifier: MIT

//! Build a SwiftSync hintsfile from an unpruned Bitcoin Core RPC.

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
use bitcoin::Block;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::Txid;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
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
    about = "Build a hintsfile by scanning blocks from an unpruned Bitcoin Core RPC"
)]
struct Cli {
    /// Destination hintsfile. Written atomically after the complete scan.
    #[arg(long, short)]
    output: PathBuf,

    /// Last block height to include. Defaults to the RPC node's current tip.
    #[arg(long)]
    stop_height: Option<u32>,

    /// Bitcoin Core RPC endpoint. Defaults to BITCOIN_CORE_RPC_URL or localhost:8332.
    #[arg(long)]
    rpc_url: Option<String>,

    /// RPC username. Defaults to BITCOIN_CORE_RPC_USER.
    #[arg(long)]
    rpc_user: Option<String>,

    /// RPC password. Defaults to BITCOIN_CORE_RPC_PASSWORD.
    #[arg(long)]
    rpc_password: Option<String>,

    /// Cookie file. Defaults to BITCOIN_CORE_COOKIE_FILE or ~/.bitcoin/.cookie.
    #[arg(long)]
    rpc_cookie_file: Option<PathBuf>,

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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = rpc_client(&cli)?;
    let tip = rpc.get_block_count().context("failed to query RPC tip")?;
    let stop_height = match cli.stop_height {
        Some(height) => {
            if u64::from(height) > tip {
                bail!("requested stop height {height} is above RPC tip {tip}");
            }
            height
        }
        None => u32::try_from(tip).context("RPC tip exceeds u32::MAX")?,
    };
    if stop_height == 0 {
        bail!("stop height must be greater than zero");
    }

    let stop_hash = rpc
        .get_block_hash(u64::from(stop_height))
        .with_context(|| format!("failed to fetch stop block hash at height {stop_height}"))?;
    eprintln!(
        "Scanning heights 1..={stop_height} through block {stop_hash}; this requires an unpruned RPC node"
    );

    let mut utxos = match cli.utxo_capacity {
        Some(capacity) => AHashMap::with_capacity(capacity),
        None => AHashMap::new(),
    };
    for height in 1..=stop_height {
        let block_hash = rpc
            .get_block_hash(u64::from(height))
            .with_context(|| format!("failed to fetch block hash at height {height}"))?;
        let block = rpc
            .get_block(&block_hash)
            .with_context(|| format!("failed to fetch block {block_hash} at height {height}"))?;
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

fn rpc_client(cli: &Cli) -> Result<Client> {
    let url = cli
        .rpc_url
        .clone()
        .or_else(|| env::var("BITCOIN_CORE_RPC_URL").ok())
        .unwrap_or_else(|| "localhost:8332".to_owned());
    let username = cli
        .rpc_user
        .clone()
        .or_else(|| env::var("BITCOIN_CORE_RPC_USER").ok());
    let password = cli
        .rpc_password
        .clone()
        .or_else(|| env::var("BITCOIN_CORE_RPC_PASSWORD").ok());
    let auth = match username {
        Some(username) => Auth::UserPass(
            username,
            password.context("RPC password is required when an RPC username is set")?,
        ),
        None => {
            if password.is_some() {
                bail!("RPC username is required when an RPC password is set");
            }
            let cookie = cli
                .rpc_cookie_file
                .clone()
                .or_else(|| env::var("BITCOIN_CORE_COOKIE_FILE").ok().map(Into::into))
                .or_else(|| {
                    env::var("HOME")
                        .ok()
                        .map(|home| PathBuf::from(home).join(".bitcoin/.cookie"))
                })
                .context("no RPC credentials or Bitcoin Core cookie path available")?;
            Auth::CookieFile(cookie)
        }
    };
    Client::new(&url, auth).context("failed to create Bitcoin Core RPC client")
}

fn apply_block(
    height: u32,
    block: &Block,
    utxos: &mut AHashMap<OutPoint, LeafPosition>,
) -> Result<u32> {
    let same_block_spends = same_block_spends(block)?;

    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        for input in &tx.input {
            if same_block_spends.contains(&input.previous_output) {
                continue;
            }
            utxos.remove(&input.previous_output).ok_or_else(|| {
                anyhow!(
                    "input {} at height {height} does not reference an indexed UTXO",
                    input.previous_output
                )
            })?;
        }
    }

    let bip30_exclusion = bip30_excluded_outpoint(height);
    let mut eligible_outputs = 0u32;
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        for (vout, output) in tx.output.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: u32::try_from(vout).context("transaction output index exceeds u32::MAX")?,
            };
            if is_provably_unspendable(&output.script_pubkey)
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
                bail!("duplicate unspent outpoint {outpoint} at height {height}");
            }
            eligible_outputs = eligible_outputs
                .checked_add(1)
                .context("one block contains more than u32::MAX eligible outputs")?;
        }
    }
    Ok(eligible_outputs)
}

fn same_block_spends(block: &Block) -> Result<AHashSet<OutPoint>> {
    let mut created = AHashSet::new();
    let mut spent = AHashSet::new();
    for tx in &block.txdata {
        if !tx.is_coinbase() {
            for input in &tx.input {
                if created.contains(&input.previous_output) {
                    spent.insert(input.previous_output);
                }
            }
        }
        let txid = tx.compute_txid();
        for vout in 0..tx.output.len() {
            created.insert(OutPoint {
                txid,
                vout: u32::try_from(vout).context("transaction output index exceeds u32::MAX")?,
            });
        }
    }
    Ok(spent)
}

fn is_provably_unspendable(script: &Script) -> bool {
    script.len() > 10_000 || script.as_bytes().first() == Some(&0x6a)
}

fn bip30_excluded_outpoint(height: u32) -> Option<OutPoint> {
    let txid = match height {
        91_722 => BIP30_FIRST_TXID_91722,
        91_812 => BIP30_FIRST_TXID_91812,
        _ => return None,
    };
    Some(OutPoint {
        txid: Txid::from_str(txid).expect("hardcoded BIP30 txid must be valid"),
        vout: 0,
    })
}

fn collect_unspent_indices(
    stop_height: u32,
    utxos: AHashMap<OutPoint, LeafPosition>,
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
    use bitcoin::hashes::Hash;
    use bitcoin::transaction;
    use bitcoin::Amount;
    use bitcoin::BlockHash;
    use bitcoin::CompactTarget;
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

        let mut utxos = AHashMap::new();
        assert_eq!(apply_block(1, &first_block, &mut utxos).unwrap(), 2);
        assert_eq!(
            utxos.get(&surviving_first_outpoint),
            Some(&LeafPosition {
                height: 1,
                index: 0
            })
        );
        assert_eq!(
            utxos.get(&same_block_created_outpoint),
            Some(&LeafPosition {
                height: 1,
                index: 1
            })
        );
        assert!(!utxos.contains_key(&same_block_outpoint));

        assert_eq!(apply_block(2, &second_block, &mut utxos).unwrap(), 2);
        assert!(!utxos.contains_key(&surviving_first_outpoint));
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
            Some(OutPoint {
                txid: Txid::from_str(BIP30_FIRST_TXID_91722).unwrap(),
                vout: 0,
            })
        );
        assert_eq!(
            bip30_excluded_outpoint(91_812),
            Some(OutPoint {
                txid: Txid::from_str(BIP30_FIRST_TXID_91812).unwrap(),
                vout: 0,
            })
        );
        assert_eq!(bip30_excluded_outpoint(91_842), None);
        assert_eq!(bip30_excluded_outpoint(91_880), None);
    }
}
