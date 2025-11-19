//SPDX-License-Identifier: MIT

//! A prover is a thread that keeps up with the blockchain and generates proofs for
//! the utreexo accumulator. Since it holds the entire accumulator, it also provides
//! proofs for other modules. To avoid having multiple channels to and from the prover, it
//! uses a channel to receive requests and sends responses through a oneshot channel, provided
//! by the request sender. Maybe there is a better way to do this, but this is a TODO for later.
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use anyhow::Context;
use bitcoin::consensus::serialize;
use bitcoin::consensus::Encodable;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
#[cfg(feature = "api")]
use bitcoin::Txid;
#[cfg(feature = "api")]
use futures::channel::mpsc::Receiver;
use log::error;
use log::info;
use rustreexo::accumulator::mem_forest::MemForest;
use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use serde::Deserialize;
use serde::Serialize;

use crate::block_index::BlockIndex;
use crate::block_index::BlocksIndex;
use crate::chaininterface::Blockchain;
use crate::chainview;
use crate::udata::LeafContext;
use crate::udata::LeafData;
use crate::udata::UtreexoBlock;

#[cfg(not(feature = "shinigami"))]
pub type AccumulatorHash = rustreexo::accumulator::node_hash::BitcoinNodeHash;

pub trait BlockStorage {
    fn save_block(
        &mut self,
        block: &Block,
        block_height: u32,
        proof: Proof<AccumulatorHash>,
        leaves: Vec<LeafContext>,
        acc: &MemForest<AccumulatorHash>,
    ) -> BlockIndex;
    #[cfg_attr(feature = "shinigami", allow(unused))]
    fn get_block(&self, index: BlockIndex) -> Option<UtreexoBlock>;
}

#[cfg(feature = "shinigami")]
pub type AccumulatorHash = crate::udata::shinigami_udata::PoseidonHash;

pub trait LeafCache: Sync + Send + Sized + 'static {
    fn remove(&mut self, outpoint: &OutPoint) -> Option<LeafContext>;
    fn insert(&mut self, outpoint: OutPoint, leaf_data: LeafContext) -> bool;
    fn flush(&mut self) {}
    #[cfg_attr(feature = "shinigami", allow(unused))]
    fn get(&self, outpoint: &OutPoint) -> Option<LeafContext>;
    fn cache_size(&self) -> usize {
        0
    }
}

impl LeafCache for HashMap<OutPoint, LeafContext> {
    fn remove(&mut self, outpoint: &OutPoint) -> Option<LeafContext> {
        self.remove(outpoint)
    }

    fn insert(&mut self, outpoint: OutPoint, leaf_data: LeafContext) -> bool {
        self.insert(outpoint, leaf_data);
        false
    }

    fn get(&self, outpoint: &OutPoint) -> Option<LeafContext> {
        self.get(outpoint).cloned()
    }
}

/// All the state that the prover needs to keep track of
pub struct Prover<LeafStorage: LeafCache, Storage: BlockStorage> {
    /// A reference to a file manager that holds the blocks on disk, using flat files.
    files: Arc<RwLock<Storage>>,
    /// A reference to the RPC client that is used to query the blockchain.
    rpc: Box<dyn Blockchain>,
    /// The accumulator that holds the state of the utreexo accumulator.
    acc: MemForest<AccumulatorHash>,
    /// An index that keeps track of the blocks that are stored on disk, we need this
    /// to get the blocks from disk.
    storage: Arc<BlocksIndex>,
    /// The height of the blockchain we are on.
    height: u32,
    /// A reference to the chainview, this keeps a map of block hashes to heights and vice versa.
    /// Also keeps block headers for easy access.
    view: Arc<chainview::ChainView>,
    /// A map that keeps track of the leaf data for each outpoint. This is used to generate
    /// proofs for the utreexo accumulator. This is more like a cache, since it won't be
    /// persisted on shutdown.
    leaf_data: LeafStorage,
    /// If set, we'll save a snapshot of the accumulator to disk every n blocks.
    ///
    /// The file will be named <height>.acc and can be used to start this software from
    /// that height.
    snapshot_acc_every: Option<u32>,
    /// A flag that is set when the prover should shut down.
    shutdown_flag: Arc<Mutex<bool>>,
    /// Only save proofs for blocks older than that
    save_proofs_for_blocks_older_than: u32,
    block_notification: Sender<BlockHash>,
    ibd: bool,
}

impl<LeafStorage: LeafCache, Storage: BlockStorage> Prover<LeafStorage, Storage> {
    /// Creates a new prover. It loads the accumulator from disk, if it exists.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rpc: Box<dyn Blockchain>,
        index_database: Arc<BlocksIndex>,
        files: Arc<RwLock<Storage>>,
        view: Arc<chainview::ChainView>,
        leaf_data: LeafStorage,
        start_acc: Option<PathBuf>,
        start_height: Option<u32>,
        snapshot_acc_every: Option<u32>,
        shutdown_flag: Arc<Mutex<bool>>,
        save_proofs_for_blocks_older_than: u32,
        block_notification: Sender<BlockHash>,
    ) -> Prover<LeafStorage, Storage> {
        let height = start_height.unwrap_or_else(|| index_database.load_height() as u32);
        info!("Loaded height {}", height);
        info!("Loading accumulator data...");
        let acc = Self::try_from_disk(start_acc);
        Self {
            snapshot_acc_every,
            rpc,
            acc,
            height,
            storage: index_database,
            files,
            view,
            leaf_data,
            shutdown_flag,
            save_proofs_for_blocks_older_than,
            block_notification,
            ibd: true,
        }
    }

    /// Tries to load the accumulator from disk. If it fails, it creates a new one.
    fn try_from_disk(path: Option<PathBuf>) -> MemForest<AccumulatorHash> {
        if let Some(path) = path {
            let file = File::open(&path).unwrap();
            let reader = BufReader::new(file);
            match MemForest::<AccumulatorHash>::deserialize(reader) {
                Ok(acc) => return acc,
                Err(e) => panic!("Failed to load accumulator at {path:?}, reson: {e:?}"),
            }
        }

        let Ok(file) = std::fs::File::open(crate::subdir("/pollard")) else {
            return MemForest::<AccumulatorHash>::new_with_hash();
        };

        let reader = BufReader::new(file);
        match MemForest::<AccumulatorHash>::deserialize(reader) {
            Ok(acc) => acc,
            Err(_) => MemForest::<AccumulatorHash>::new_with_hash(),
        }
    }

    /// Handles the request from another module. It returns a response through the oneshot channel
    /// provided by the request sender. Errors are returned as strings, maybe this should be changed
    /// to a boxed error or something else.
    #[cfg(feature = "api")]
    fn handle_request(&mut self, req: Requests) -> anyhow::Result<Responses> {
        use bitcoin::ScriptBuf;
        use bitcoin::Sequence;
        use bitcoin::Witness;

        match req {
            Requests::GetProof(node) => {
                let proof = self
                    .acc
                    .prove(&[node])
                    .map_err(|e| anyhow::anyhow!("{}", e))?;

                Ok(Responses::Proof(proof))
            }
            Requests::GetRoots => {
                let roots = self.acc.get_roots().iter().map(|x| x.get_data()).collect();
                Ok(Responses::Roots(roots))
            }
            Requests::GetLeaf(outpoint) => {
                let leaf = self.leaf_data.get(&outpoint).ok_or(anyhow::anyhow!(
                    "Leaf for outpoint {}:{} not found",
                    outpoint.txid,
                    outpoint.vout
                ))?;

                Ok(Responses::LeafData(leaf))
            }
            Requests::GetBlockByHeight(height) => {
                let hash = self
                    .rpc
                    .get_block_hash(height as u64)
                    .map_err(|_| anyhow::anyhow!("Block at height {} not found", height))?;
                let block = self.storage.get_index(hash).ok_or(anyhow::anyhow!(
                    "Block at height {} not found in storage",
                    height
                ))?;

                let block = self
                    .files
                    .read()
                    .unwrap()
                    .get_block(block)
                    .ok_or(anyhow::anyhow!(
                        "Block at height {} not found in files",
                        height
                    ))?;
                Ok(Responses::Block(serialize(&block)))
            }
            Requests::GetTxUnpent(txid) => {
                // returns the unspent outputs of a transaction and a proof for them
                let tx = self
                    .rpc
                    .get_transaction(txid)
                    .map_err(|_| anyhow::anyhow!("Transaction {} not found", txid))?;

                let mut hashes = Vec::new();
                for vout in 0..tx.output.len() {
                    let (hash, _) = self.get_input_leaf_hash(&TxIn {
                        previous_output: OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness: Witness::new(),
                    })?;

                    // if this returns err, this output is spent
                    if self.acc.prove(&[hash]).is_ok() {
                        hashes.push(hash);
                    }
                }

                let proof = self
                    .acc
                    .prove(&hashes)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;

                Ok(Responses::TransactionOut(tx.output, proof))
            }
            Requests::GetTransaction(txid) => {
                // returns the unspent outputs of a transaction and a proof for them
                let tx = self
                    .rpc
                    .get_transaction(txid)
                    .map_err(|_| anyhow::anyhow!("Transaction {} not found", txid))?;

                let mut hashes = Vec::new();
                for vout in 0..tx.output.len() {
                    let (hash, _) = self.get_input_leaf_hash(&TxIn {
                        previous_output: OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness: Witness::new(),
                    })?;

                    hashes.push(hash);
                }

                let proof = self
                    .acc
                    .prove(&hashes)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;

                Ok(Responses::Transaction((tx, proof)))
            }
            Requests::GetCSN => {
                let roots = self.acc.get_roots().iter().map(|x| x.get_data()).collect();
                let leaves = self.acc.leaves;
                Ok(Responses::Csn(Stump { roots, leaves }))
            }
            Requests::GetBlocksByHeight(height, count) => {
                let mut blocks = Vec::new();
                for i in height..height + count {
                    let Some(hash) = self.view.get_block_hash(i)? else {
                        break;
                    };
                    let block = self.storage.get_index(hash).ok_or(anyhow::anyhow!(
                        "Block at height {} not found in storage",
                        i
                    ))?;

                    let block = self
                        .files
                        .read()
                        .unwrap()
                        .get_block(block)
                        .ok_or(anyhow::anyhow!("Block at height {} not found in files", i))?;
                    blocks.push(serialize(&block));
                }
                Ok(Responses::Blocks(blocks))
            }
        }
    }

    /// Gracefully shuts down the prover. It saves the accumulator to disk and flushes the chainview.
    fn shutdown(&mut self) {
        self.save_to_disk(None)
            .expect("could not save the acc to disk");
        self.leaf_data.flush();
        self.view.flush();
    }

    /// Saves the accumulator to disk. This is done by serializing the accumulator to a file,
    /// the serialization is done by the rustreexo library and is a depth first traversal of the
    /// tree.
    fn save_to_disk(&self, height: Option<u32>) -> std::io::Result<()> {
        let file = match height {
            Some(height) => std::fs::File::create(crate::subdir(&format!("{}.acc", height)))?,
            None => std::fs::File::create(crate::subdir("/pollard"))?,
        };

        let mut writer = std::io::BufWriter::new(file);
        self.acc.serialize(&mut writer).unwrap();

        Ok(())
    }

    /// A infinite loop that keeps the prover up to date with the blockchain. It handles requests
    /// from other modules and updates the accumulator when a new block is found. This method is
    /// also how we create proofs for historical blocks.
    pub fn keep_up(
        &mut self,
        #[cfg(feature = "api")] mut receiver: Receiver<(
            Requests,
            futures::channel::oneshot::Sender<Result<Responses, String>>,
        )>,
    ) -> anyhow::Result<()> {
        let mut last_tip_update = std::time::Instant::now();
        loop {
            if *self.shutdown_flag.lock().unwrap() {
                info!("Shutting down prover");
                self.shutdown();
                break;
            }

            #[cfg(feature = "api")]
            while let Ok(Some((req, res))) = receiver.try_next() {
                let ret = self.handle_request(req).map_err(|e| e.to_string());
                res.send(ret)
                    .map_err(|_| anyhow::anyhow!("Error sending response"))?;
            }

            if let Err(e) = self.check_tip(&mut last_tip_update) {
                error!("Error checking tip: {}", e);
                continue;
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        self.save_to_disk(None)
            .expect("could not save the acc to disk");
        self.storage.update_height(self.height as usize);
        Ok(())
    }

    fn check_tip(&mut self, last_tip_update: &mut std::time::Instant) -> anyhow::Result<()> {
        if last_tip_update.elapsed() < std::time::Duration::from_secs(10) {
            return Ok(());
        }

        let height = self.rpc.get_block_count()? as u32;
        if height == self.height {
            self.ibd = false; // we'll flip it once, and keep it false for the rest of the time
            return Ok(());
        }

        if height > self.height {
            self.prove_range(self.height + 1, height)?;

            self.save_to_disk(None)
                .expect("could not save the acc to disk");
            self.storage.update_height(height as usize);
        }
        *last_tip_update = std::time::Instant::now();
        Ok(())
    }

    /// Proves a range of blocks, may be just one block.
    pub fn prove_range(&mut self, start: u32, end: u32) -> anyhow::Result<()> {
        for height in start..=end {
            if *self.shutdown_flag.lock().unwrap() {
                break;
            }

            let block_hash = self.rpc.get_block_hash(height as u64)?;
            // Update the local index
            self.view.save_block_hash(height, block_hash)?;
            self.view.save_height(block_hash, height)?;

            let block = self.rpc.get_block(block_hash)?;

            self.view
                .save_header(block_hash, serialize(&block.header))?;

            info!(
                "processing height={} cache={} txs={}",
                height,
                self.leaf_data.cache_size(),
                block.txdata.len()
            );

            let mtp = self.rpc.get_mtp(block.header.prev_blockhash)?;
            let (proof, leaves) = match self.process_block(&block, height, mtp) {
                Ok((proof, leaves)) => (proof, leaves),
                Err(e) => {
                    error!("Couldn't process block {block_hash} due to {e:?}");
                    return Ok(());
                }
            };

            if height > self.save_proofs_for_blocks_older_than {
                let index = self
                    .files
                    .write()
                    .unwrap()
                    .save_block(&block, height, proof, leaves, &self.acc);
                self.storage.append(index, block.block_hash());
            }

            self.height = height;
            if let Some(n) = self.snapshot_acc_every {
                if height % n == 0 {
                    self.save_to_disk(Some(height))
                        .expect("could not save the acc to disk");
                }
            }

            if !self.ibd {
                // only notify when we're not in IBD
                self.block_notification.send(block.block_hash()).unwrap();
            }
        }

        anyhow::Ok(())
    }

    /// Pulls the [LeafData] from the bitcoin core rpc. We use this as fallback if we can't find
    /// the leaf in leaf_data. This method is slow and should only be used if we can't find the
    /// leaf in the leaf_data.
    fn get_input_leaf_hash_from_rpc(
        rpc: &Box<dyn Blockchain>,
        input: &TxIn,
    ) -> anyhow::Result<LeafContext> {
        let tx_info = rpc.get_raw_transaction_info(&input.previous_output.txid)?;

        let Some(block_hash) = tx_info.blockhash else {
            return Err(anyhow::anyhow!(
                "Transaction wasn't confirmed yet, so there's no leaf hash"
            ));
        };

        let height = tx_info.height;
        let output = &tx_info.tx.output[input.previous_output.vout as usize];
        let prev_block = rpc
            .get_block_header(block_hash)
            .context("Failed to get block header")?
            .prev_blockhash;

        let median_time_past = rpc
            .get_mtp(prev_block)
            .context("Failed to get median time past")?;

        Ok(LeafContext {
            block_hash,
            median_time_past,
            block_height: height,
            is_coinbase: tx_info.is_coinbase,
            pk_script: output.script_pubkey.clone(),
            value: output.value.to_sat(),
            vout: input.previous_output.vout,
            txid: input.previous_output.txid,
        })
    }

    /// Returns the leaf hash and the compact leaf data for a given input. If the leaf is not in
    /// leaf_data we will try to get it from the bitcoin core rpc.
    fn get_input_leaf_hash(
        &mut self,
        input: &TxIn,
    ) -> anyhow::Result<(AccumulatorHash, LeafContext)> {
        let leaf = self.leaf_data.remove(&input.previous_output);

        let leaf = match leaf {
            Some(leaf) => leaf,
            None => Self::get_input_leaf_hash_from_rpc(&self.rpc, input)
                .context("[get_input_leaf_hash] Failure to get leaf hash")?,
        };

        Ok((LeafData::get_leaf_hashes(&leaf), leaf))
    }

    fn is_unspendable(script: &Script) -> bool {
        if script.len() > 10_000 {
            return true;
        }

        if !script.is_empty() && script.as_bytes()[0] == 0x6a {
            return true;
        }

        false
    }

    /// Processes a block and returns the batch proof and the compact leaf data for the block.
    fn process_block(
        &mut self,
        block: &Block,
        height: u32,
        mtp: u32,
    ) -> anyhow::Result<(Proof<AccumulatorHash>, Vec<LeafContext>)> {
        let mut inputs = Vec::new();
        let mut utxos = Vec::new();
        let mut compact_leaves = Vec::new();

        for tx in block.txdata.iter() {
            let txid = tx.compute_txid();
            for input in tx.input.iter() {
                if !tx.is_coinbase() {
                    let (hash, compact_leaf) = self.get_input_leaf_hash(input)?;
                    if let Some(idx) = utxos.iter().position(|h| *h == hash) {
                        utxos.remove(idx);
                    } else {
                        inputs.push(hash);
                        compact_leaves.push(compact_leaf);
                    }
                }
            }

            for (idx, output) in tx.output.iter().enumerate() {
                if !Self::is_unspendable(&output.script_pubkey) {
                    let leaf = LeafContext {
                        block_hash: block.block_hash(),
                        median_time_past: mtp,
                        txid,
                        vout: idx as u32,
                        value: output.value.to_sat(),
                        pk_script: output.script_pubkey.clone(),
                        is_coinbase: tx.is_coinbase(),
                        block_height: height,
                    };

                    utxos.push(LeafData::get_leaf_hashes(&leaf));

                    let flush = self.leaf_data.insert(
                        OutPoint {
                            txid,
                            vout: idx as u32,
                        },
                        leaf,
                    );

                    if flush {
                        self.leaf_data.flush();
                        self.save_to_disk(None)
                            .expect("could not save the acc to disk");
                        self.storage.update_height(self.height as usize);
                    }
                }
            }
        }

        let proof = self.acc.prove(&inputs).unwrap();
        self.acc.modify(&utxos, &inputs).unwrap();

        let mut ser_acc = Vec::new();

        self.acc.leaves.consensus_encode(&mut ser_acc).unwrap();
        self.acc.get_roots().iter().for_each(|x| {
            x.get_data().consensus_encode(&mut ser_acc).unwrap();
        });

        self.view.save_acc(ser_acc, block.block_hash());

        Ok((proof, compact_leaves))
    }
}

#[cfg(feature = "api")]
/// All requests we can send to the prover. The prover will respond with the corresponding
/// response element.
pub enum Requests {
    /// Get the proof for a given leaf hash.
    GetProof(BitcoinNodeHash),
    /// Get the roots of the accumulator.
    GetRoots,
    /// Get a block at a given height. This method returns the block and utreexo data for it.
    GetBlockByHeight(u32),
    /// Returns a transaction and a proof for all inputs
    GetTransaction(Txid),
    /// Returns the CSN of the current acc
    GetCSN,
    /// Returns multiple blocks and utreexo data for them.
    GetBlocksByHeight(u32, u32),
    GetTxUnpent(Txid),
    GetLeaf(OutPoint),
}
/// All responses the prover will send.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Responses {
    /// A utreexo proof
    Proof(Proof),
    /// The roots of the accumulator
    Roots(Vec<BitcoinNodeHash>),
    /// A block and the utreexo data for it, serialized.
    Block(Vec<u8>),
    /// A transaction and a proof for all **outputs**
    Transaction((Transaction, Proof)),
    /// The CSN of the current acc
    #[allow(clippy::upper_case_acronyms)]
    Csn(Stump),
    /// Multiple blocks and utreexo data for them.
    Blocks(Vec<Vec<u8>>),
    TransactionOut(Vec<TxOut>, Proof),
    LeafData(LeafContext),
}
