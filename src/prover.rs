//SPDX-License-Identifier: MIT

//! Pollard-backed steady-state proof generation over the persistent flat forest.

use parking_lot::Mutex;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

use ahash::AHashMap;
use anyhow::Context;
use bitcoin::hashes::Hash;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::Txid;
use bitcoin::VarInt;
use log::debug;
use log::info;
use log::warn;
use rayon::prelude::*;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo::pollard::Pollard;
use rustreexo::pollard::PollardAddition;
#[cfg(test)]
use rustreexo::proof::Proof;
use rustreexo::stump::Stump;

use crate::block_index::BlocksIndex;
use crate::blockfile::ProofFile;
use crate::chaininterface::Blockchain;
use crate::chaininterface::PrevoutInfo;
use crate::chaininterface::TransactionInfo;
use crate::forest_journal::ForestJournal;
use crate::forest_journal::JournalEntry;
use crate::forest_journal::JournalStatus;
use crate::header_index::HeaderIndex;
use crate::parallel_forest::tree_rows;
use crate::parallel_forest::ForestOverlay;
use crate::parallel_forest::ForestView;
use crate::parallel_forest::SteadyStateForest;
use crate::position_timing::PositionTimer;
use crate::position_timing::PositionTiming;
use crate::udata::bitcoin_leaf_data::get_leaf_hash_from_parts;
use crate::udata::BatchProof;
use crate::udata::CompactBlockProof;
use crate::udata::CompactLeafData;
use crate::udata::LeafContext;
use crate::udata::LeafData;

const MIN_PARALLEL_ADDITION_HASHES: usize = 128;

const LEAF_CACHE_BLOCKS: u32 = 144;
pub(crate) fn is_unspendable(script: &Script) -> bool {
    script.len() > 10_000 || script.as_bytes().first() == Some(&0x6a)
}

#[derive(Default)]
struct SteadyBlockTimings {
    rpc_block_hash: Duration,
    rpc_block: Duration,
    scan_prevouts: Duration,
    positions: Duration,
    position_cache: PositionTiming,
    position_leaf_map: PositionTiming,
    position_validation: PositionTiming,
    position_resolution: PositionTiming,
    position_traversal: PositionTiming,
    position_cache_hits: usize,
    position_cache_misses: usize,
    forest_positions_loaded: usize,
    proof_build: Duration,
    prevout_block_hashes: Duration,
    leaf_resolution: Duration,
    proof_verify: Duration,
    additions: Duration,
    stump_update: Duration,
    plan_update: Duration,
    persistence_enqueue: Duration,
    cache_update: Duration,
    total: Duration,
}

const MAX_PENDING_BLOCKS: usize = 8;
const MAX_PENDING_BYTES: usize = 256 * 1024 * 1024;

#[derive(Default)]
struct ApplyTimings {
    blocks: usize,
    journal_flush: Duration,
    apply: Duration,
    state_flush: Duration,
    proof_store: Duration,
    header_store: Duration,
    proof_index_write: Duration,
    height_commit: Duration,
}

struct DurableTip {
    height: u32,
    hash: BlockHash,
    leaves: u64,
    roots: Vec<BitcoinNodeHash>,
}

struct PersistenceBlock {
    entry: Arc<JournalEntry>,
    header: bitcoin::block::Header,
    proof: CompactBlockProof,
    proof_forest_rows: u8,
}

enum PersistenceCommand {
    Block(PersistenceBlock),
    Barrier {
        operation: PersistenceBarrier,
        completion: std::sync::mpsc::SyncSender<anyhow::Result<DurableTip>>,
    },
}

enum PersistenceBarrier {
    Sync { clean_shutdown: bool },
    Resize(u64),
    Rollback { height: u32, hash: BlockHash },
    Repair { outpoint: OutPoint, position: u64 },
}

#[cfg(test)]
type PersistenceHook = Arc<dyn Fn(&str, u32) -> anyhow::Result<()> + Send + Sync>;

/// The only steady-state writer. No foreground lock is held across durability I/O.
struct PersistenceState {
    forest: Arc<RwLock<SteadyStateForest>>,
    journal: ForestJournal,
    proof_file: Arc<ProofFile>,
    proof_index: Arc<BlocksIndex>,
    header_index: Arc<HeaderIndex>,
    block_notification: Sender<BlockHash>,
    height: u32,
    tip_hash: BlockHash,
    bootstrap_height: u32,
    #[cfg(test)]
    hook: Arc<Mutex<Option<PersistenceHook>>>,
}

impl PersistenceState {
    fn persist(&mut self, blocks: &[PersistenceBlock]) -> anyhow::Result<ApplyTimings> {
        let last = blocks.last().context("empty persistence batch")?;
        let mut height = self.height;
        let mut hash = self.tip_hash;
        for block in blocks {
            if block.entry.height != height + 1 || block.entry.previous_block_hash != hash {
                anyhow::bail!("persistence batch does not extend the durable tip");
            }
            height = block.entry.height;
            hash = block.entry.block_hash;
        }
        let mut timings = ApplyTimings {
            blocks: blocks.len(),
            ..Default::default()
        };
        let started = Instant::now();
        for block in blocks {
            self.journal.append(Arc::clone(&block.entry))?;
        }
        self.journal.flush()?;
        timings.journal_flush = started.elapsed();
        #[cfg(test)]
        self.checkpoint("journal", last.entry.height)?;

        let started = Instant::now();
        let mut indexes = Vec::with_capacity(blocks.len());
        for block in blocks {
            let mut index = self.proof_file.append(&block.proof)?;
            if self.proof_file.get(&index).as_ref() != Some(&block.proof) {
                anyhow::bail!(
                    "failed to read back compact proof for {}",
                    block.entry.block_hash
                );
            }
            index.proof_forest_rows = Some(block.proof_forest_rows);
            indexes.push((index, block.entry.block_hash));
        }
        self.proof_file.sync()?;
        timings.proof_store = started.elapsed();
        let started = Instant::now();
        for block in blocks {
            self.header_index.put(block.entry.height, &block.header)?;
        }
        self.header_index.sync()?;
        timings.header_store = started.elapsed();
        let started = Instant::now();
        self.proof_index.append_batch(&indexes)?;
        timings.proof_index_write = started.elapsed();

        let started = Instant::now();
        {
            let mut forest = self
                .forest
                .write()
                .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?;
            for block in blocks {
                forest.apply_forward(&block.entry)?;
                if block.entry.height % 1_000 == 0 {
                    forest.compact_leaf_map()?;
                }
            }
        }
        timings.apply = started.elapsed();
        let started = Instant::now();
        {
            // Shared with foreground readers, excluding mutation/remapping during sync.
            let forest = self
                .forest
                .read()
                .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?;
            #[cfg(test)]
            self.checkpoint("state_flush", last.entry.height)?;
            forest.sync()?;
        }
        timings.state_flush = started.elapsed();
        let started = Instant::now();
        self.proof_index.update_height(last.entry.height as usize)?;
        timings.height_commit = started.elapsed();
        self.height = last.entry.height;
        self.tip_hash = last.entry.block_hash;
        if let Err(error) = self.journal.prune(144) {
            warn!("journal pruning failed; retaining older recovery records: {error:#}");
        }
        for block in blocks {
            let _ = self.block_notification.send(block.entry.block_hash);
        }
        Ok(timings)
    }

    #[cfg(test)]
    fn checkpoint(&self, stage: &str, height: u32) -> anyhow::Result<()> {
        let hook = self.hook.lock().clone();
        if let Some(hook) = hook {
            hook(stage, height)?;
        }
        Ok(())
    }

    fn finish_failed(&self, mut error: anyhow::Error) -> anyhow::Error {
        // Runtime database allocators retain their current page and bucket heads in
        // memory until sync. Seal them before an orderly failed worker exits so the
        // durable journal can be replayed on reopen. This does not commit a height
        // or certify a clean shutdown, and cannot replace hard-crash recovery.
        let forest_result = self
            .forest
            .read()
            .map_err(|_| anyhow::anyhow!("steady forest lock poisoned during error finalization"))
            .and_then(|forest| forest.sync());
        if let Err(cleanup) = forest_result {
            error = error.context(format!(
                "failed to finalize forest after persistence error: {cleanup:#}"
            ));
        }
        if let Err(cleanup) = self.header_index.sync() {
            error = error.context(format!(
                "failed to finalize header index after persistence error: {cleanup:#}"
            ));
        }
        error
    }

    fn barrier(&mut self, operation: PersistenceBarrier) -> anyhow::Result<DurableTip> {
        let clean_shutdown = matches!(
            &operation,
            PersistenceBarrier::Sync {
                clean_shutdown: true
            }
        );
        match operation {
            PersistenceBarrier::Sync { .. } => {
                self.forest
                    .read()
                    .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?
                    .sync()?;
                self.journal.flush()?;
                self.proof_file.sync()?;
                self.header_index.sync()?;
                self.proof_index.update_height(self.height as usize)?;
            }
            PersistenceBarrier::Resize(leaves) => {
                self.forest
                    .write()
                    .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?
                    .ensure_leaf_capacity(leaves)?;
            }
            PersistenceBarrier::Repair { outpoint, position } => {
                self.forest
                    .write()
                    .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?
                    .repair_leaf_position(&outpoint, position)?;
            }
            PersistenceBarrier::Rollback { height, hash } => {
                if (height, hash) != (self.height, self.tip_hash) {
                    anyhow::bail!("rollback does not match the durable tip");
                }
                let (index, record) = self
                    .journal
                    .latest_forward()
                    .context("reorg exceeds retained journal; rebuild from a newer bootstrap")?;
                let entry = record.entry.clone();
                if (entry.height, entry.block_hash) != (height, hash) {
                    anyhow::bail!("rollback journal does not match the durable tip");
                }
                self.journal.mark_rolled_back(index)?;
                {
                    let mut forest = self
                        .forest
                        .write()
                        .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?;
                    forest.apply_backward(&entry)?;
                    forest.sync()?;
                }
                self.header_index.remove(height, hash)?;
                self.header_index.sync()?;
                self.proof_index.remove(hash)?;
                let previous_height = height.saturating_sub(1);
                let previous_index = if previous_height > self.bootstrap_height {
                    Some(
                        self.proof_index
                            .get_index(entry.previous_block_hash)?
                            .context("proof index is missing rollback destination")?,
                    )
                } else {
                    None
                };
                self.proof_file.truncate_after(previous_index.as_ref())?;
                self.proof_index.update_height(previous_height as usize)?;
                self.height = previous_height;
                self.tip_hash = entry.previous_block_hash;
            }
        }
        let forest = self
            .forest
            .read()
            .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?;
        let tip = DurableTip {
            height: self.height,
            hash: self.tip_hash,
            leaves: forest.leaves(),
            roots: forest.roots()?,
        };
        drop(forest);
        if clean_shutdown {
            self.journal.mark_clean_shutdown()?;
        }
        Ok(tip)
    }
}

struct PersistenceWorker {
    sender: Option<std::sync::mpsc::SyncSender<PersistenceCommand>>,
    completions: std::sync::mpsc::Receiver<anyhow::Result<ApplyTimings>>,
    error: Arc<Mutex<Option<String>>>,
    handle: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    hook: Arc<Mutex<Option<PersistenceHook>>>,
}

impl PersistenceWorker {
    fn new(mut state: PersistenceState) -> anyhow::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(MAX_PENDING_BLOCKS);
        let (completed, completions) = std::sync::mpsc::channel();
        let error = Arc::new(Mutex::new(None));
        let worker_error = Arc::clone(&error);
        #[cfg(test)]
        let hook = Arc::clone(&state.hook);
        let handle = std::thread::Builder::new()
            .name("bridge-persistence".to_string())
            .spawn(move || {
                let mut deferred = None;
                loop {
                    let command = match deferred.take().map(Ok).unwrap_or_else(|| receiver.recv()) {
                        Ok(command) => command,
                        Err(_) => break,
                    };
                    let (failure, shutdown) = match command {
                        PersistenceCommand::Block(block) => {
                            let mut batch = Vec::with_capacity(MAX_PENDING_BLOCKS);
                            batch.push(block);
                            while batch.len() < MAX_PENDING_BLOCKS {
                                match receiver.try_recv() {
                                    Ok(PersistenceCommand::Block(block)) => batch.push(block),
                                    Ok(barrier) => {
                                        deferred = Some(barrier);
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                            let result = state.persist(&batch);
                            let result = result.map_err(|error| {
                                *worker_error.lock() = Some(format!("{error:#}"));
                                state.finish_failed(error)
                            });
                            let failure = result.as_ref().err().map(|error| format!("{error:#}"));
                            if let Some(error) = &failure {
                                *worker_error.lock() = Some(error.clone());
                            }
                            let _ = completed.send(result);
                            (failure, false)
                        }
                        PersistenceCommand::Barrier {
                            operation,
                            completion,
                        } => {
                            let shutdown = matches!(
                                operation,
                                PersistenceBarrier::Sync {
                                    clean_shutdown: true
                                }
                            );
                            let result = state.barrier(operation);
                            let result = result.map_err(|error| {
                                *worker_error.lock() = Some(format!("{error:#}"));
                                state.finish_failed(error)
                            });
                            let failure = result.as_ref().err().map(|error| format!("{error:#}"));
                            if let Some(error) = &failure {
                                *worker_error.lock() = Some(error.clone());
                            }
                            let _ = completion.send(result);
                            (failure, shutdown)
                        }
                    };
                    if failure.is_some() || shutdown {
                        break;
                    }
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            completions,
            error,
            handle: Some(handle),
            #[cfg(test)]
            hook,
        })
    }

    fn check(&self) -> anyhow::Result<()> {
        if let Some(error) = self.error.lock().as_ref() {
            anyhow::bail!("background persistence failed: {error}");
        }
        if self
            .handle
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
        {
            anyhow::bail!("background persistence worker stopped");
        }
        Ok(())
    }

    fn send(&self, command: PersistenceCommand) -> anyhow::Result<()> {
        self.check()?;
        self.sender
            .as_ref()
            .context("persistence worker stopped")?
            .send(command)
            .map_err(|_| anyhow::anyhow!("persistence worker stopped"))
    }

    fn barrier(&self, operation: PersistenceBarrier) -> anyhow::Result<DurableTip> {
        let (completion, receiver) = std::sync::mpsc::sync_channel(1);
        self.send(PersistenceCommand::Barrier {
            operation,
            completion,
        })?;
        receiver
            .recv()
            .context("persistence worker stopped during barrier")?
    }
}

impl Drop for PersistenceWorker {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CachedPollardLeaf {
    creation_height: u32,
    position: u64,
    hash: BitcoinNodeHash,
}

#[derive(Clone)]
struct CachedLeaf {
    context: LeafContext,
    position: u64,
}

fn cached_bottom_position(
    pollard_position: Option<u64>,
    cached_leaf: Option<&CachedLeaf>,
) -> Option<u64> {
    pollard_position.or_else(|| cached_leaf.map(|leaf| leaf.position))
}
fn pollard_from_stump_roots(
    mut roots: Vec<BitcoinNodeHash>,
    leaves: u64,
) -> Pollard<BitcoinNodeHash> {
    roots.reverse();
    Pollard::from_roots(roots, leaves)
}

fn pollard_stump_roots(pollard: &Pollard<BitcoinNodeHash>) -> Vec<BitcoinNodeHash> {
    let mut roots = pollard.roots();
    roots.reverse();
    roots
}

fn evict_pollard_cache(
    pollard: &mut Pollard<BitcoinNodeHash>,
    leaves: &mut BinaryHeap<Reverse<CachedPollardLeaf>>,
    memory_limit: usize,
) -> anyhow::Result<(usize, usize, usize)> {
    let initial_usage = pollard.estimated_memory_usage();
    if initial_usage < memory_limit {
        return Ok((0, initial_usage, initial_usage));
    }

    let target = memory_limit / 5;
    let mut evicted = 0usize;
    while pollard.estimated_compact_memory_usage() > target {
        let Some(Reverse(cached)) = leaves.pop() else {
            break;
        };
        if pollard.position_hash(cached.position) != Some(cached.hash) {
            continue;
        }
        pollard
            .prune(&[cached.position])
            .map_err(anyhow::Error::msg)?;
        evicted += 1;
    }
    pollard.shrink_to_fit();
    Ok((evicted, initial_usage, pollard.estimated_memory_usage()))
}

struct PendingApply {
    entry: Arc<JournalEntry>,
    bytes: usize,
}

struct PreparedBlock {
    entry: JournalEntry,
    proof_forest_rows: u8,
}

fn pending_memory(entry: &JournalEntry, proof: &CompactBlockProof) -> usize {
    // Include the shared journal entry, overlay hash tables, and queued proof buffers.
    entry
        .forest
        .capacity()
        .saturating_mul(320)
        .saturating_add(
            entry
                .added
                .capacity()
                .saturating_add(entry.removed.capacity())
                .saturating_mul(256),
        )
        .saturating_add(
            proof
                .proof
                .targets
                .capacity()
                .saturating_mul(std::mem::size_of::<VarInt>()),
        )
        .saturating_add(proof.proof.hashes.capacity().saturating_mul(32))
        .saturating_add(
            proof
                .leaves
                .capacity()
                .saturating_mul(std::mem::size_of::<CompactLeafData>()),
        )
        .saturating_add(
            proof
                .leaves
                .iter()
                .map(|leaf| match &leaf.spk_ty {
                    crate::udata::ScriptPubkeyType::Other(script) => script.len(),
                    _ => 0,
                })
                .sum::<usize>(),
        )
}

/// Sequential steady-state prover backed by the bootstrapped flat forest and persistent leaf map.
pub struct FlatFileProver {
    rpc: Arc<dyn Blockchain>,
    header_index: Arc<HeaderIndex>,
    persistence: PersistenceWorker,
    acc: Arc<RwLock<SteadyStateForest>>,
    overlay: ForestOverlay,
    pollard: Pollard<BitcoinNodeHash>,
    pollard_leaves: BinaryHeap<Reverse<CachedPollardLeaf>>,
    pollard_memory_limit: usize,
    height: u32,
    shutdown_flag: Arc<AtomicBool>,
    leaf_data: HashMap<OutPoint, CachedLeaf>,
    block_hash_cache: HashMap<u32, BlockHash>,
    pending_apply: VecDeque<PendingApply>,
    pending_bytes: usize,
    tip_hash: BlockHash,
}

fn recoverable_journal_height(
    journal: &mut ForestJournal,
    header_index: &HeaderIndex,
    proof_index: &BlocksIndex,
    proof_file: &ProofFile,
    indexed_height: u32,
    bootstrap_height: u32,
) -> anyhow::Result<u32> {
    let candidate_height = match journal.latest_forward() {
        Some((_, record)) => record.entry.height,
        None if !journal.records().is_empty() => {
            journal.records()[0].entry.height.saturating_sub(1)
        }
        None => indexed_height.max(bootstrap_height),
    };
    if candidate_height < bootstrap_height {
        anyhow::bail!(
            "journal height {candidate_height} precedes bootstrap height {bootstrap_height}"
        );
    }
    let retained = journal
        .records()
        .iter()
        .filter(|record| record.status == JournalStatus::Forward)
        .map(|record| (record.entry.height, record.entry.block_hash))
        .collect::<AHashMap<_, _>>();
    let first_proof_height = bootstrap_height
        .checked_add(1)
        .context("bootstrap height overflow")?;
    for height in first_proof_height..=candidate_height {
        let header = header_index.get_by_height(height)?;
        let block_hash = header.as_ref().map(bitcoin::block::Header::block_hash);
        let index = match block_hash {
            Some(block_hash) => proof_index.get_index(block_hash)?,
            None => None,
        };
        let valid = block_hash
            .zip(index.as_ref())
            .is_some_and(|(block_hash, index)| {
                retained
                    .get(&height)
                    .is_none_or(|retained_hash| *retained_hash == block_hash)
                    && proof_file.contains(index)
                    && retained
                        .contains_key(&height)
                        .then(|| proof_file.get(index).is_some())
                        .unwrap_or(true)
            });
        if valid {
            continue;
        }
        let rollback_indices = journal
            .records()
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.status == JournalStatus::Forward && record.entry.height >= height
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if rollback_indices.is_empty()
            || !journal.records().iter().any(|record| {
                record.status == JournalStatus::Forward && record.entry.height == height
            })
        {
            anyhow::bail!(
                "proof gap at height {height} is outside the retained journal; rebuild from a newer bootstrap"
            );
        }
        for index in rollback_indices.into_iter().rev() {
            journal.mark_rolled_back(index)?;
        }
        warn!("rolling back height {height} and later because its proof is missing or corrupt");
        return Ok(height - 1);
    }
    if candidate_height != indexed_height {
        info!(
            "reconciled proof height {indexed_height} to journal-backed height {candidate_height}"
        );
    }
    Ok(candidate_height)
}

impl FlatFileProver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rpc: Arc<dyn Blockchain>,
        header_index: Arc<HeaderIndex>,
        forest_path: &Path,
        journal_path: PathBuf,
        leaf_map_path: &Path,
        proof_file: Arc<ProofFile>,
        proof_index: Arc<BlocksIndex>,
        bootstrap_height: u32,
        lock_pages: bool,
        pollard_memory_limit: usize,
        shutdown_flag: Arc<AtomicBool>,
        block_notification: Sender<BlockHash>,
    ) -> anyhow::Result<Self> {
        if pollard_memory_limit == 0 {
            anyhow::bail!("Pollard memory limit must be greater than zero");
        }
        let (acc, journal, height, tip_hash) = std::thread::scope(|scope| -> anyhow::Result<_> {
            let recovery = std::thread::Builder::new()
                    .name("bridge-recovery".to_string())
                    .spawn_scoped(scope, || -> anyhow::Result<_> {
        let indexed_height =
            u32::try_from(proof_index.load_height()?).context("proof height exceeds u32")?;
        let mut acc = SteadyStateForest::open(forest_path, leaf_map_path, lock_pages)?;
        let mut journal = ForestJournal::open(journal_path)?;
        let recovered_height = recoverable_journal_height(
            &mut journal,
            &header_index,
            &proof_index,
            &proof_file,
            indexed_height,
            bootstrap_height,
        )?;
        if acc.replay_journal(&journal)? {
            if !journal.records().is_empty() {
                info!(
                    "replayed {} journal records after an incomplete shutdown",
                    journal.records().len()
                );
            }
        } else {
            info!("skipped forest journal replay after a clean shutdown");
        }
        for record in journal.records() {
            match record.status {
                JournalStatus::Forward => {
                    let indexed = header_index.get_height(record.entry.block_hash)?
                        == Some(record.entry.height)
                        && header_index
                            .get_by_height(record.entry.height)?
                            .is_some_and(|header| header.block_hash() == record.entry.block_hash);
                    if !indexed {
                        let header = rpc.get_block_header(record.entry.block_hash)?;
                        header_index.put(record.entry.height, &header)?;
                    }
                }
                JournalStatus::RolledBack => {
                    header_index.remove(record.entry.height, record.entry.block_hash)?;
                    proof_index.remove(record.entry.block_hash)?;
                }
            }
        }
        if !journal.records().is_empty() {
            header_index.sync()?;
        }
        let (height, tip_hash, expected_leaves) = match journal.latest_forward() {
            Some((_, record)) => (
                record.entry.height,
                record.entry.block_hash,
                record.entry.num_leaves,
            ),
            None if !journal.records().is_empty() => {
                let first = &journal.records()[0].entry;
                (
                    first.height.saturating_sub(1),
                    first.previous_block_hash,
                    first.previous_num_leaves()?,
                )
            }
            None => (
                recovered_height,
                rpc.get_block_hash(recovered_height as u64)?,
                acc.leaves(),
            ),
        };
        if height != recovered_height {
            anyhow::bail!(
                "forest journal recovered height {height}, proof storage recovered {recovered_height}"
            );
        }
        if acc.leaves() != expected_leaves {
            anyhow::bail!(
                "forest at height {height} has {} leaves, journal expects {expected_leaves}",
                acc.leaves()
            );
        }
        let published_index = if height > bootstrap_height {
            let index = proof_index.get_index(tip_hash)?.ok_or_else(|| {
                anyhow::anyhow!("proof index is missing recovered height {height}")
            })?;
            if proof_file.get(&index).is_none() {
                anyhow::bail!("proof data at recovered height {height} is unreadable");
            }
            Some(index)
        } else {
            None
        };
        proof_file.truncate_after(published_index.as_ref())?;
        proof_index.update_height(height as usize)?;
        info!(
            "Opened steady-state forest at height {height} with {} historical leaves and {} retained journal entries",
            acc.leaves(),
            journal.records().len()
        );
                        Ok((acc, journal, height, tip_hash))
                    })?;
            recovery
                .join()
                .map_err(|_| anyhow::anyhow!("startup recovery worker panicked"))?
        })?;
        let mut block_hash_cache = HashMap::new();
        block_hash_cache.insert(height, tip_hash);
        let forest_roots = acc.roots()?;
        let pollard = pollard_from_stump_roots(forest_roots.clone(), acc.leaves());
        if pollard_stump_roots(&pollard) != forest_roots {
            anyhow::bail!("Pollard roots do not match the recovered flat forest");
        }
        let acc = Arc::new(RwLock::new(acc));
        let persistence = PersistenceWorker::new(PersistenceState {
            forest: Arc::clone(&acc),
            journal,
            proof_file,
            proof_index,
            header_index: Arc::clone(&header_index),
            block_notification,
            height,
            tip_hash,
            bootstrap_height,
            #[cfg(test)]
            hook: Arc::new(Mutex::new(None)),
        })?;
        Ok(Self {
            rpc,
            header_index,
            persistence,
            acc,
            overlay: ForestOverlay::default(),
            pollard,
            pollard_leaves: BinaryHeap::new(),
            pollard_memory_limit,
            height,
            shutdown_flag,
            leaf_data: HashMap::new(),
            block_hash_cache,
            pending_apply: VecDeque::new(),
            pending_bytes: 0,
            tip_hash,
        })
    }

    fn enforce_pollard_memory_limit(&mut self) -> anyhow::Result<()> {
        if self.pollard.estimated_memory_usage() < self.pollard_memory_limit {
            return Ok(());
        }
        // Cache misses remain correct through the pending overlay; eviction is not a
        // durability barrier.
        let (evicted, initial_usage, final_usage) = evict_pollard_cache(
            &mut self.pollard,
            &mut self.pollard_leaves,
            self.pollard_memory_limit,
        )?;
        if evicted == 0 {
            return Ok(());
        }

        let target = self.pollard_memory_limit / 5;
        if final_usage > target {
            warn!(
                "Pollard cache could not reach its memory target: bytes={final_usage} target={target}"
            );
        }
        info!(
            "Pollard cache eviction: leaves={evicted} bytes_before={initial_usage} bytes_after={final_usage}"
        );
        Ok(())
    }

    fn retire_apply(&mut self, timings: ApplyTimings) -> anyhow::Result<()> {
        let first_height = self
            .pending_apply
            .front()
            .context("unexpected persistence completion")?
            .entry
            .height;
        let mut height = first_height;
        for _ in 0..timings.blocks {
            let pending = self
                .pending_apply
                .pop_front()
                .context("persistence batch exceeds pending blocks")?;
            self.overlay.retire(&pending.entry);
            self.pending_bytes -= pending.bytes;
            height = pending.entry.height;
        }
        debug!(
            "background-persistence height={height} first_height={first_height} blocks={} journal_flush={:?} apply={:?} state_flush={:?} proof_store={:?} header_store={:?} proof_index_write={:?} height_commit={:?}",
            timings.blocks, timings.journal_flush, timings.apply, timings.state_flush,
            timings.proof_store, timings.header_store, timings.proof_index_write, timings.height_commit
        );
        Ok(())
    }

    fn collect_completed(&mut self) -> anyhow::Result<()> {
        self.persistence.check()?;
        loop {
            match self.persistence.completions.try_recv() {
                Ok(result) => self.retire_apply(result?)?,
                Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(()),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    anyhow::bail!("persistence completion channel closed");
                }
            }
        }
    }

    fn wait_for_apply(&mut self) -> anyhow::Result<()> {
        let result = self
            .persistence
            .completions
            .recv()
            .context("persistence worker stopped with outstanding blocks")?;
        self.retire_apply(result?)
    }

    fn drain_pending_apply(&mut self) -> anyhow::Result<()> {
        while !self.pending_apply.is_empty() {
            self.wait_for_apply()?;
        }
        self.persistence.check()
    }

    fn reserve_persistence(&mut self, bytes: usize) -> anyhow::Result<()> {
        self.collect_completed()?;
        // A single oversized block is admitted alone; both its working set and the
        // retained journal have protocol/record limits, rather than an unbounded queue.
        while !self.pending_apply.is_empty()
            && (self.pending_apply.len() >= MAX_PENDING_BLOCKS
                || self.pending_bytes.saturating_add(bytes) > MAX_PENDING_BYTES)
        {
            #[cfg(test)]
            {
                let hook = self.persistence.hook.lock().clone();
                if let Some(hook) = hook {
                    hook("backpressure", self.height)?;
                }
            }
            self.wait_for_apply()?;
        }
        Ok(())
    }

    fn verify_durable_tip(&self, tip: &DurableTip) -> anyhow::Result<()> {
        if (tip.height, tip.hash, tip.leaves) != (self.height, self.tip_hash, self.pollard.leaves())
            || tip.roots != pollard_stump_roots(&self.pollard)
        {
            anyhow::bail!("durable forest and producer state diverged");
        }
        Ok(())
    }

    fn ensure_forest_capacity(&mut self, additions: usize) -> anyhow::Result<()> {
        let required_leaves = self
            .pollard
            .leaves()
            .checked_add(additions as u64)
            .context("steady-state leaf count overflow")?;
        let current_capacity = self
            .acc
            .read()
            .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?
            .leaf_capacity()?;
        if required_leaves <= current_capacity {
            return Ok(());
        }

        self.drain_pending_apply()?;
        let tip = self
            .persistence
            .barrier(PersistenceBarrier::Resize(required_leaves))?;
        self.verify_durable_tip(&tip)
    }

    pub fn keep_up(&mut self) -> anyhow::Result<()> {
        loop {
            if self.shutdown_flag.load(Ordering::Acquire) {
                self.sync_for_shutdown()?;
                return Ok(());
            }
            self.sync_to_tip()?;
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }

    fn reconcile_chain(&mut self) -> anyhow::Result<u32> {
        self.collect_completed()?;
        let mut rolled_back = 0u32;
        loop {
            let core_tip = self.rpc.get_block_count()? as u32;
            let active = self.height <= core_tip
                && self
                    .rpc
                    .get_block_hash(self.height as u64)
                    .is_ok_and(|hash| hash == self.tip_hash);
            if active {
                break;
            }
            self.drain_pending_apply()?;
            let orphan_height = self.height;
            let orphan_hash = self.tip_hash;
            let tip = self.persistence.barrier(PersistenceBarrier::Rollback {
                height: self.height,
                hash: self.tip_hash,
            })?;
            self.pollard = pollard_from_stump_roots(tip.roots, tip.leaves);
            self.pollard_leaves.clear();
            self.height = tip.height;
            self.tip_hash = tip.hash;
            self.block_hash_cache
                .retain(|height, _| *height <= tip.height);
            self.leaf_data.clear();
            rolled_back += 1;
            info!(
                "rolled back orphaned block height={orphan_height} hash={orphan_hash} leaves={}",
                tip.leaves
            );
        }
        Ok(rolled_back)
    }

    pub fn sync_to_tip(&mut self) -> anyhow::Result<u32> {
        self.reconcile_chain()?;
        let tip = self.rpc.get_block_count()? as u32;
        let start = self.height.saturating_add(1);
        if start > tip {
            return Ok(0);
        }
        self.prove_range(start, tip)?;
        Ok(tip - start + 1)
    }

    pub fn prove_range(&mut self, start: u32, end: u32) -> anyhow::Result<()> {
        for height in start..=end {
            let total_started = Instant::now();
            let mut timings = SteadyBlockTimings::default();
            let started = Instant::now();
            self.reserve_persistence(0)?;
            timings.persistence_enqueue = started.elapsed();
            if self.shutdown_flag.load(Ordering::Acquire) {
                break;
            }
            let started = Instant::now();
            let block_hash = self.rpc.get_block_hash(height as u64)?;
            timings.rpc_block_hash = started.elapsed();
            let started = Instant::now();
            let block_with_prevouts = self.rpc.get_block_with_prevouts(block_hash)?;
            timings.rpc_block = started.elapsed();
            let block = block_with_prevouts.block;
            let prevouts = block_with_prevouts.prevouts;
            if block.header.prev_blockhash != self.tip_hash {
                self.reconcile_chain()?;
                anyhow::bail!(
                    "block {block_hash} does not build on current tip {}; retrying active chain",
                    self.tip_hash
                );
            }
            let (
                compact_proof,
                leaf_cache_hits,
                leaf_cache_misses,
                prevout_creation_heights,
                process_timings,
                pending,
            ) = self.process_block(&block, &prevouts, height)?;
            timings.scan_prevouts = process_timings.scan_prevouts;
            timings.positions = process_timings.positions;
            timings.position_cache = process_timings.position_cache;
            timings.position_leaf_map = process_timings.position_leaf_map;
            timings.position_validation = process_timings.position_validation;
            timings.position_resolution = process_timings.position_resolution;
            timings.position_traversal = process_timings.position_traversal;
            timings.position_cache_hits = process_timings.position_cache_hits;
            timings.position_cache_misses = process_timings.position_cache_misses;
            timings.forest_positions_loaded = process_timings.forest_positions_loaded;
            timings.proof_build = process_timings.proof_build;
            timings.prevout_block_hashes = process_timings.prevout_block_hashes;
            timings.leaf_resolution = process_timings.leaf_resolution;
            timings.proof_verify = process_timings.proof_verify;
            timings.additions = process_timings.additions;
            timings.stump_update = process_timings.stump_update;
            timings.plan_update = process_timings.plan_update;
            timings.cache_update = process_timings.cache_update;
            let target_count = compact_proof.proof.targets.len();
            let proof_hash_count = compact_proof.proof.hashes.len();
            let leaf_count = compact_proof.leaves.len();
            let started = Instant::now();
            let bytes = pending_memory(&pending.entry, &compact_proof);
            self.reserve_persistence(bytes)?;
            let entry = Arc::new(pending.entry);
            self.persistence
                .send(PersistenceCommand::Block(PersistenceBlock {
                    entry: Arc::clone(&entry),
                    header: block.header,
                    proof: compact_proof,
                    proof_forest_rows: pending.proof_forest_rows,
                }))?;
            self.overlay.push(&entry);
            self.pending_bytes += bytes;
            self.pending_apply.push_back(PendingApply { entry, bytes });
            timings.persistence_enqueue += started.elapsed();
            self.enforce_pollard_memory_limit()?;

            let started = Instant::now();
            self.block_hash_cache.insert(height, block_hash);
            self.height = height;
            self.tip_hash = block_hash;
            timings.cache_update += started.elapsed();

            timings.total = total_started.elapsed();
            let leaves = self.pollard.leaves();
            info!(
                "steady-state height={height} hash={block_hash} targets={} proof_hashes={} leaves={leaves}",
                target_count,
                proof_hash_count,
            );
            debug!(
                "steady-state-cache height={height} leaf_data={} leaf_cache_hits={} leaf_cache_misses={} leaf_cache_entries={} position_cache_hits={} position_cache_misses={} forest_positions_loaded={} prevout_creation_heights={} pollard_cached_nodes={} pollard_ingested_positions={} pollard_bytes={} pollard_quota={}",
                leaf_count,
                leaf_cache_hits,
                leaf_cache_misses,
                self.leaf_data.len(),
                timings.position_cache_hits,
                timings.position_cache_misses,
                timings.forest_positions_loaded,
                prevout_creation_heights,
                self.pollard.cached_nodes(),
                self.pollard.ingested_positions(),
                self.pollard.estimated_memory_usage(),
                self.pollard_memory_limit
            );
            debug!(
                "steady-state-timings height={height} hash={block_hash} total={:?} rpc_block_hash={:?} rpc_block_v3={:?} scan_prevouts={:?} positions={:?} proof_build={:?} prevout_block_hashes={:?} leaf_resolution={:?} proof_verify={:?} additions={:?} stump_update={:?} plan_update={:?} persistence_enqueue={:?} cache_update={:?}",
                timings.total,
                timings.rpc_block_hash,
                timings.rpc_block,
                timings.scan_prevouts,
                timings.positions,
                timings.proof_build,
                timings.prevout_block_hashes,
                timings.leaf_resolution,
                timings.proof_verify,
                timings.additions,
                timings.stump_update,
                timings.plan_update,
                timings.persistence_enqueue,
                timings.cache_update
            );
            debug!(
                "steady-state-position-timings height={height} cache={:?} cache_majflt={:?} leaf_map={:?} leaf_map_majflt={:?} validation={:?} validation_majflt={:?} resolution={:?} resolution_majflt={:?} traversal={:?} traversal_majflt={:?}",
                timings.position_cache.elapsed,
                timings.position_cache.major_faults,
                timings.position_leaf_map.elapsed,
                timings.position_leaf_map.major_faults,
                timings.position_validation.elapsed,
                timings.position_validation.major_faults,
                timings.position_resolution.elapsed,
                timings.position_resolution.major_faults,
                timings.position_traversal.elapsed,
                timings.position_traversal.major_faults,
            );
        }
        Ok(())
    }

    fn creating_block_hash(&mut self, height: u32) -> anyhow::Result<BlockHash> {
        if let Some(block_hash) = self.block_hash_cache.get(&height) {
            return Ok(*block_hash);
        }
        let header = self.header_index.get_by_height(height)?.ok_or_else(|| {
            anyhow::anyhow!("header index has no block header at prevout creation height {height}")
        })?;
        let block_hash = header.block_hash();
        self.block_hash_cache.insert(height, block_hash);
        Ok(block_hash)
    }
    fn recover_leaf_position(
        &self,
        acc: &ForestView<'_>,
        outpoint: OutPoint,
        leaf: &LeafContext,
    ) -> anyhow::Result<u64> {
        let creating_block = self
            .rpc
            .get_block(leaf.block_hash)
            .with_context(|| format!("failed to fetch creating block {}", leaf.block_hash))?;
        let block_leaves = eligible_block_leaves(&creating_block, leaf.block_height)?;
        let leaf_hash = LeafData::get_leaf_hashes(leaf);
        acc.recover_leaf_position_from_block(outpoint, leaf_hash, &block_leaves)
    }

    fn recover_missing_leaf_position(
        &self,
        acc: &ForestView<'_>,
        outpoint: OutPoint,
        prevouts: &HashMap<OutPoint, PrevoutInfo>,
        creating_block_hashes: &HashMap<u32, BlockHash>,
    ) -> anyhow::Result<(u64, LeafContext)> {
        let leaf = if let Some(leaf) = self.leaf_data.get(&outpoint) {
            leaf.context.clone()
        } else if let Some(prevout) = prevouts.get(&outpoint) {
            let block_hash = creating_block_hashes
                .get(&prevout.height)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!("missing creating block hash for height {}", prevout.height)
                })?;
            leaf_context_from_prevout(block_hash, prevout, outpoint)
        } else {
            let transaction = self
                .rpc
                .get_raw_transaction_info(&outpoint.txid)
                .with_context(|| format!("failed to recover transaction for {outpoint}"))?;
            leaf_context_from_transaction(&transaction, outpoint)?
        };
        let position = self.recover_leaf_position(acc, outpoint, &leaf)?;
        Ok((position, leaf))
    }

    fn process_block(
        &mut self,
        block: &Block,
        prevouts: &HashMap<OutPoint, PrevoutInfo>,
        height: u32,
    ) -> anyhow::Result<(
        CompactBlockProof,
        usize,
        usize,
        usize,
        SteadyBlockTimings,
        PreparedBlock,
    )> {
        let mut timings = SteadyBlockTimings::default();
        let started = Instant::now();
        let spent_in_block = same_block_spends(block);
        let external_outpoints: Vec<OutPoint> = block
            .txdata
            .iter()
            .filter(|transaction| !transaction.is_coinbase())
            .flat_map(|transaction| transaction.input.iter())
            .map(|input| input.previous_output)
            .filter(|outpoint| !spent_in_block.contains(outpoint))
            .collect();
        let missing_heights: HashSet<u32> = external_outpoints
            .iter()
            .filter(|outpoint| !self.leaf_data.contains_key(outpoint))
            .filter_map(|outpoint| prevouts.get(outpoint).map(|prevout| prevout.height))
            .collect();
        timings.scan_prevouts = started.elapsed();
        let started = Instant::now();
        let block_hash = block.block_hash();
        let mut addition_contexts = Vec::with_capacity(
            block
                .txdata
                .iter()
                .map(|transaction| transaction.output.len())
                .sum(),
        );
        for transaction in &block.txdata {
            let txid = transaction.compute_txid();
            for (vout, output) in transaction.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).context("transaction output index overflow")?,
                };
                if is_unspendable(&output.script_pubkey) || spent_in_block.contains(&outpoint) {
                    continue;
                }
                addition_contexts.push(LeafContext {
                    block_hash,
                    txid,
                    vout: outpoint.vout,
                    value: output.value.to_sat(),
                    pk_script: output.script_pubkey.clone(),
                    block_height: height,
                    is_coinbase: transaction.is_coinbase(),
                });
            }
        }
        let addition_hashes: Vec<_> = if addition_contexts.len() >= MIN_PARALLEL_ADDITION_HASHES {
            addition_contexts
                .par_iter()
                .map(LeafData::get_leaf_hashes)
                .collect()
        } else {
            addition_contexts
                .iter()
                .map(LeafData::get_leaf_hashes)
                .collect()
        };
        let mut additions = Vec::with_capacity(addition_contexts.len());
        let mut added_leaf_data = Vec::with_capacity(addition_contexts.len());
        for (leaf, hash) in addition_contexts
            .into_iter()
            .zip(addition_hashes.iter().copied())
        {
            let outpoint = OutPoint {
                txid: leaf.txid,
                vout: leaf.vout,
            };
            additions.push((outpoint, hash));
            added_leaf_data.push((outpoint, leaf));
        }
        timings.additions = started.elapsed();
        self.ensure_forest_capacity(addition_hashes.len())?;
        let started = Instant::now();
        let prevout_creation_heights = missing_heights.len();
        let mut creating_block_hashes = HashMap::with_capacity(missing_heights.len());
        for height in missing_heights {
            creating_block_hashes.insert(height, self.creating_block_hash(height)?);
        }
        timings.prevout_block_hashes = started.elapsed();
        let started = Instant::now();
        let timer = PositionTimer::start();

        let cached_leaf_hashes = external_outpoints
            .iter()
            .filter_map(|outpoint| {
                self.leaf_data
                    .get(outpoint)
                    .map(|leaf| (*outpoint, LeafData::get_leaf_hashes(&leaf.context)))
            })
            .collect::<HashMap<_, _>>();
        let cached_bottom_positions = cached_leaf_hashes
            .iter()
            .filter_map(|(outpoint, hash)| {
                cached_bottom_position(
                    self.pollard.leaf_position(hash),
                    self.leaf_data.get(outpoint),
                )
                .map(|position| (*outpoint, position))
            })
            .collect::<HashMap<_, _>>();
        timings.position_cache_hits = cached_bottom_positions.len();
        timings.position_cache_misses = external_outpoints.len() - timings.position_cache_hits;
        let forest_handle = Arc::clone(&self.acc);
        let forest = forest_handle
            .read()
            .map_err(|_| anyhow::anyhow!("steady forest lock poisoned"))?;
        self.persistence.check()?;
        let acc = ForestView::new(&forest, &self.overlay, self.pollard.leaves());
        let uncached_outpoints: Vec<_> = external_outpoints
            .iter()
            .filter(|outpoint| !cached_bottom_positions.contains_key(outpoint))
            .copied()
            .collect();
        timings.position_cache = timer.finish();
        let lookup = acc.leaf_positions(&uncached_outpoints)?;
        timings.position_leaf_map = lookup.fetch;
        timings.position_validation = lookup.validation;
        let timer = PositionTimer::start();
        let mut uncached_positions = lookup.positions.into_iter();
        let mut deletions = Vec::with_capacity(external_outpoints.len());
        let mut proof_targets = Vec::with_capacity(external_outpoints.len());
        let mut recovered_leaf_data = HashMap::new();
        let mut cached_target_hashes = HashMap::with_capacity(cached_leaf_hashes.len());
        for outpoint in external_outpoints {
            let bottom_position = match cached_bottom_positions.get(&outpoint) {
                Some(position) => *position,
                None => match uncached_positions
                    .next()
                    .context("leaf-map batch omitted an uncached outpoint")?
                {
                    Ok(position) => position,
                    Err(map_error) => {
                        let (position, leaf) = self
                            .recover_missing_leaf_position(
                                &acc,
                                outpoint,
                                prevouts,
                                &creating_block_hashes,
                            )
                            .with_context(|| {
                                format!(
                                    "failed explicit position recovery after leaf-map error: {map_error}"
                                )
                            })?;
                        info!(
                            "recovered missing leaf-map position outpoint={outpoint} height={} position={position}",
                            leaf.block_height
                        );
                        recovered_leaf_data.insert(outpoint, leaf);
                        position
                    }
                },
            };
            deletions.push((outpoint, bottom_position));
            proof_targets.push(bottom_position);
        }
        timings.position_resolution = timer.finish();
        let timer = PositionTimer::start();
        acc.translate_proof_positions(&mut proof_targets)?;
        for ((outpoint, _), proof_position) in deletions.iter().zip(&proof_targets) {
            if let Some(hash) = cached_leaf_hashes.get(outpoint) {
                cached_target_hashes.insert(*proof_position, *hash);
            }
        }
        timings.position_traversal = timer.finish();
        timings.positions = started.elapsed();
        let started = Instant::now();

        // Pollard exposes which canonical positions are not cached. Only those hashes are read
        // from the flat forest, then the reconstructed proof is verified while being ingested.
        let missing_positions = self.pollard.missing_positions(&proof_targets);
        let positions_to_load = missing_positions
            .into_iter()
            .filter(|position| !cached_target_hashes.contains_key(position))
            .collect::<Vec<_>>();
        timings.forest_positions_loaded = positions_to_load.len();
        let mut loaded_positions = positions_to_load
            .into_iter()
            .map(|position| acc.position_hash(position).map(|hash| (position, hash)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        loaded_positions.extend(cached_target_hashes);
        let proof = self
            .pollard
            .ingest_positions(&proof_targets, &loaded_positions)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("failed to ingest Pollard targets={proof_targets:?}"))?;
        let original_stump = Stump {
            leaves: self.pollard.leaves(),
            roots: pollard_stump_roots(&self.pollard),
        };
        timings.proof_build = started.elapsed();
        let started = Instant::now();
        let mut deletion_hashes = Vec::with_capacity(deletions.len());
        let mut leaf_data = Vec::with_capacity(deletions.len());
        let mut leaf_cache_hits = 0usize;
        let mut leaf_cache_misses = 0usize;
        let mut fallback_transactions = HashMap::<Txid, TransactionInfo>::new();
        for (outpoint, bottom_position) in &deletions {
            let (leaf, cache_hit) = if let Some(leaf) = recovered_leaf_data.remove(outpoint) {
                (leaf, false)
            } else {
                cached_leaf_context(&self.leaf_data, *outpoint, || {
                    if let Some(prevout) = prevouts.get(outpoint) {
                        let block_hash = creating_block_hashes
                            .get(&prevout.height)
                            .copied()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "missing creating block hash for height {}",
                                    prevout.height
                                )
                            })?;
                        return Ok(leaf_context_from_prevout(block_hash, prevout, *outpoint));
                    }
                    let transaction = match fallback_transactions.entry(outpoint.txid) {
                        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                            self.rpc
                                .get_raw_transaction_info(&outpoint.txid)
                                .with_context(|| {
                                    format!("verbosity-three response omitted prevout {outpoint}")
                                })?,
                        ),
                    };
                    leaf_context_from_transaction(transaction, *outpoint)
                })?
            };
            if cache_hit {
                leaf_cache_hits += 1;
            } else {
                leaf_cache_misses += 1;
            }
            let hash = cached_leaf_hashes
                .get(outpoint)
                .copied()
                .unwrap_or_else(|| LeafData::get_leaf_hashes(&leaf));
            if !cached_bottom_positions.contains_key(outpoint) {
                let stored_hash = acc.leaf_hash(*bottom_position)?;
                if hash != stored_hash {
                    let recovered_position = self
                        .recover_leaf_position(&acc, *outpoint, &leaf)
                        .with_context(|| {
                            format!(
                                "failed to recover {outpoint} after hash mismatch at position {bottom_position}"
                            )
                        })?;
                    drop(forest);
                    self.drain_pending_apply()?;
                    self.persistence.barrier(PersistenceBarrier::Repair {
                        outpoint: *outpoint,
                        position: recovered_position,
                    })?;
                    anyhow::bail!(
                        "repaired leaf-map position for {outpoint}: {bottom_position} -> {recovered_position}; retry the block"
                    );
                }
            }
            deletion_hashes.push(hash);
            leaf_data.push(leaf);
        }
        timings.leaf_resolution = started.elapsed();
        let started = Instant::now();
        let proof_valid = original_stump
            .verify(&proof, &deletion_hashes)
            .map_err(anyhow::Error::msg)?;
        timings.proof_verify = started.elapsed();
        if !proof_valid {
            anyhow::bail!("generated proof does not verify against the flat-forest roots");
        }

        let started = Instant::now();
        let expected_stump = original_stump
            .modify(&addition_hashes, &deletion_hashes, &proof)
            .map_err(anyhow::Error::msg)?;
        timings.stump_update = started.elapsed();
        let started = Instant::now();
        let journal_entry = acc.plan_update(
            height,
            block_hash,
            block.header.prev_blockhash,
            &deletions,
            &additions,
        )?;
        let planned_roots = acc.roots_after(&journal_entry)?;
        if expected_stump.leaves != journal_entry.num_leaves
            || expected_stump.roots != planned_roots
        {
            anyhow::bail!(
                "planned flat-forest update diverged from verified stump update: leaves expected={} planned={}, roots expected={} planned={}",
                expected_stump.leaves,
                journal_entry.num_leaves,
                expected_stump.roots.len(),
                planned_roots.len()
            );
        }
        let pollard_additions = addition_hashes
            .iter()
            .map(|hash| PollardAddition {
                hash: *hash,
                remember: true,
            })
            .collect::<Vec<_>>();
        let cached_pollard_leaves = added_leaf_data
            .iter()
            .zip(addition_hashes.iter())
            .enumerate()
            .map(|(offset, ((_, leaf), hash))| {
                Ok(CachedPollardLeaf {
                    creation_height: leaf.block_height,
                    position: original_stump
                        .leaves
                        .checked_add(offset as u64)
                        .context("Pollard leaf position overflow")?,
                    hash: *hash,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let pollard_update = self
            .pollard
            .modify_stump(&pollard_additions, &deletion_hashes, &proof)
            .map_err(anyhow::Error::msg);
        if let Err(error) = pollard_update {
            self.pollard =
                pollard_from_stump_roots(original_stump.roots.clone(), original_stump.leaves);
            self.pollard_leaves.clear();
            return Err(error.context("failed to modify Pollard"));
        }
        if self.pollard.leaves() != journal_entry.num_leaves
            || pollard_stump_roots(&self.pollard) != expected_stump.roots
        {
            self.pollard =
                pollard_from_stump_roots(original_stump.roots.clone(), original_stump.leaves);
            self.pollard_leaves.clear();
            anyhow::bail!("Pollard mutation diverged from the planned flat-forest update");
        }
        timings.plan_update = started.elapsed();

        let pending = PreparedBlock {
            entry: journal_entry,
            proof_forest_rows: tree_rows(original_stump.leaves),
        };
        let started = Instant::now();
        for (outpoint, _) in &deletions {
            self.leaf_data.remove(outpoint);
        }
        self.leaf_data.extend(
            added_leaf_data
                .into_iter()
                .zip(cached_pollard_leaves.iter())
                .map(|((outpoint, context), cached)| {
                    (
                        outpoint,
                        CachedLeaf {
                            context,
                            position: cached.position,
                        },
                    )
                }),
        );
        let oldest_cached_height = height.saturating_sub(LEAF_CACHE_BLOCKS.saturating_sub(1));
        self.leaf_data
            .retain(|_, leaf| leaf.context.block_height >= oldest_cached_height);
        self.pollard_leaves
            .extend(cached_pollard_leaves.into_iter().map(Reverse));
        timings.cache_update = started.elapsed();

        Ok((
            CompactBlockProof {
                proof: BatchProof {
                    targets: proof.targets.iter().copied().map(VarInt).collect(),
                    hashes: proof
                        .hashes
                        .iter()
                        .map(|hash| BlockHash::from_byte_array(**hash))
                        .collect(),
                },
                leaves: leaf_data.iter().map(CompactLeafData::from).collect(),
            },
            leaf_cache_hits,
            leaf_cache_misses,
            prevout_creation_heights,
            timings,
            pending,
        ))
    }

    #[cfg(test)]
    pub fn sync(&mut self) -> anyhow::Result<()> {
        self.drain_pending_apply()?;
        let tip = self.persistence.barrier(PersistenceBarrier::Sync {
            clean_shutdown: false,
        })?;
        self.verify_durable_tip(&tip)
    }

    fn sync_for_shutdown(&mut self) -> anyhow::Result<()> {
        self.drain_pending_apply()?;
        let tip = self.persistence.barrier(PersistenceBarrier::Sync {
            clean_shutdown: true,
        })?;
        self.verify_durable_tip(&tip)
    }
}

fn same_block_spends(block: &Block) -> HashSet<OutPoint> {
    let mut created = HashSet::new();
    let mut spent = HashSet::new();
    for transaction in &block.txdata {
        for input in &transaction.input {
            if created.contains(&input.previous_output) {
                spent.insert(input.previous_output);
            }
        }
        let txid = transaction.compute_txid();
        for vout in 0..transaction.output.len() {
            created.insert(OutPoint {
                txid,
                vout: vout as u32,
            });
        }
    }
    spent
}
fn eligible_block_leaves(
    block: &Block,
    height: u32,
) -> anyhow::Result<Vec<(OutPoint, BitcoinNodeHash)>> {
    let spent_in_block = same_block_spends(block);
    let block_hash = block.block_hash().to_byte_array();
    let mut leaves = Vec::new();
    for transaction in &block.txdata {
        let txid = transaction.compute_txid();
        let header_code = (height << 1) | u32::from(transaction.is_coinbase());
        for (vout, output) in transaction.output.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: u32::try_from(vout).context("transaction output index overflow")?,
            };
            if is_unspendable(&output.script_pubkey) || spent_in_block.contains(&outpoint) {
                continue;
            }
            let hash = get_leaf_hash_from_parts(
                block_hash,
                txid.to_byte_array(),
                outpoint.vout,
                header_code,
                output.value.to_sat(),
                output.script_pubkey.as_bytes(),
            );
            leaves.push((outpoint, hash));
        }
    }
    Ok(leaves)
}

fn cached_leaf_context(
    cache: &HashMap<OutPoint, CachedLeaf>,
    outpoint: OutPoint,
    fetch: impl FnOnce() -> anyhow::Result<LeafContext>,
) -> anyhow::Result<(LeafContext, bool)> {
    match cache.get(&outpoint) {
        Some(leaf) => Ok((leaf.context.clone(), true)),
        None => fetch().map(|leaf| (leaf, false)),
    }
}

fn leaf_context_from_prevout(
    block_hash: BlockHash,
    prevout: &PrevoutInfo,
    outpoint: OutPoint,
) -> LeafContext {
    LeafContext {
        block_hash,
        block_height: prevout.height,
        is_coinbase: prevout.is_coinbase,
        pk_script: prevout.script_pubkey.clone(),
        value: prevout.value,
        vout: outpoint.vout,
        txid: outpoint.txid,
    }
}

fn leaf_context_from_transaction(
    transaction: &TransactionInfo,
    outpoint: OutPoint,
) -> anyhow::Result<LeafContext> {
    let block_hash = transaction
        .blockhash
        .ok_or_else(|| anyhow::anyhow!("previous transaction {} is unconfirmed", outpoint.txid))?;
    let output = transaction
        .tx
        .output
        .get(outpoint.vout as usize)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "previous transaction {} has no output {}",
                outpoint.txid,
                outpoint.vout
            )
        })?;
    Ok(LeafContext {
        block_hash,
        block_height: transaction.height,
        is_coinbase: transaction.is_coinbase,
        pk_script: output.script_pubkey.clone(),
        value: output.value.to_sat(),
        vout: outpoint.vout,
        txid: outpoint.txid,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::Network;
    use bitcoin::ScriptBuf;

    use super::*;

    struct FixtureChain {
        blocks: Mutex<Vec<Block>>,
    }

    impl Blockchain for FixtureChain {
        fn get_block(&self, hash: BlockHash) -> anyhow::Result<Block> {
            self.blocks
                .lock()
                .iter()
                .find(|block| block.block_hash() == hash)
                .cloned()
                .context("fixture block missing")
        }

        fn get_block_with_prevouts(
            &self,
            hash: BlockHash,
        ) -> anyhow::Result<crate::chaininterface::BlockWithPrevouts> {
            let block = self.get_block(hash)?;
            let mut prevouts = HashMap::new();
            for tx in block.txdata.iter().filter(|tx| !tx.is_coinbase()) {
                for input in &tx.input {
                    let previous = self.get_raw_transaction_info(&input.previous_output.txid)?;
                    let output = &previous.tx.output[input.previous_output.vout as usize];
                    prevouts.insert(
                        input.previous_output,
                        PrevoutInfo {
                            height: previous.height,
                            is_coinbase: previous.is_coinbase,
                            value: output.value.to_sat(),
                            script_pubkey: output.script_pubkey.clone(),
                        },
                    );
                }
            }
            Ok(crate::chaininterface::BlockWithPrevouts { block, prevouts })
        }

        fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
            self.blocks
                .lock()
                .get(height as usize)
                .map(Block::block_hash)
                .context("fixture height missing")
        }

        fn get_block_height(&self, hash: BlockHash) -> anyhow::Result<u32> {
            self.blocks
                .lock()
                .iter()
                .position(|block| block.block_hash() == hash)
                .map(|height| height as u32)
                .context("fixture hash missing")
        }

        fn get_block_header(&self, hash: BlockHash) -> anyhow::Result<bitcoin::block::Header> {
            Ok(self.get_block(hash)?.header)
        }

        fn get_block_count(&self) -> anyhow::Result<u64> {
            Ok(self.blocks.lock().len() as u64 - 1)
        }

        fn get_raw_transaction_info(&self, txid: &Txid) -> anyhow::Result<TransactionInfo> {
            let blocks = self.blocks.lock();
            for (height, block) in blocks.iter().enumerate() {
                if let Some(tx) = block.txdata.iter().find(|tx| tx.compute_txid() == *txid) {
                    return Ok(TransactionInfo {
                        tx: tx.clone(),
                        height: height as u32,
                        blockhash: Some(block.block_hash()),
                        is_coinbase: tx.is_coinbase(),
                    });
                }
            }
            anyhow::bail!("fixture transaction missing")
        }
    }

    struct PersistenceFixture {
        root: PathBuf,
        chain: Arc<FixtureChain>,
    }

    impl PersistenceFixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "bridge-persistence-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            let mut blocks = vec![genesis_block(Network::Signet)];
            let input = |outpoint| bitcoin::TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            };
            for height in 1..=10u32 {
                let mut coinbase = blocks[0].txdata[0].clone();
                coinbase.input[0].script_sig = ScriptBuf::from_bytes(height.to_le_bytes().to_vec());
                coinbase.output = (0..if height == 1 { 4 } else { 1 })
                    .map(|vout| bitcoin::TxOut {
                        value: bitcoin::Amount::from_sat(1000 + u64::from(height) * 10 + vout),
                        script_pubkey: ScriptBuf::new(),
                    })
                    .collect();
                let mut txdata = vec![coinbase];
                if height >= 2 {
                    let previous_tx = blocks.last().unwrap().txdata.last().unwrap();
                    let mut inputs = vec![input(OutPoint {
                        txid: previous_tx.compute_txid(),
                        vout: 0,
                    })];
                    if height == 3 {
                        inputs.push(input(OutPoint {
                            txid: blocks[1].txdata[0].compute_txid(),
                            vout: 1,
                        }));
                    }
                    txdata.push(bitcoin::Transaction {
                        version: bitcoin::transaction::Version::TWO,
                        lock_time: bitcoin::absolute::LockTime::ZERO,
                        input: inputs,
                        output: (0..2u64)
                            .map(|vout| bitcoin::TxOut {
                                value: bitcoin::Amount::from_sat(u64::from(height) * 100 + vout),
                                script_pubkey: ScriptBuf::new(),
                            })
                            .collect(),
                    });
                }
                let mut header = blocks[0].header;
                header.prev_blockhash = blocks.last().unwrap().block_hash();
                header.nonce = height;
                blocks.push(Block { header, txdata });
            }
            let mut config = crate::parallel_forest::ParallelForestConfig::new(root.join("forest"));
            config.leaf_map_path = root.join("leaf-map");
            config.header_file_path = root.join("headers");
            config.header_index_path = root.join("header-index");
            config.minimum_leaf_capacity = Some(64);
            config.leaf_workers = 1;
            config.chaser_workers = 1;
            config.lock_pages = false;
            crate::parallel_forest::tests::bootstrap_fixture(blocks[1].clone(), config).unwrap();
            Self {
                root,
                chain: Arc::new(FixtureChain {
                    blocks: Mutex::new(blocks),
                }),
            }
        }

        fn open(
            &self,
        ) -> (
            FlatFileProver,
            Arc<ProofFile>,
            Arc<BlocksIndex>,
            std::sync::mpsc::Receiver<BlockHash>,
        ) {
            let header_index = Arc::new(
                HeaderIndex::open(&self.root.join("headers"), &self.root.join("header-index"))
                    .unwrap(),
            );
            let proof_file = Arc::new(ProofFile::new(self.root.join("proofs")).unwrap());
            let proof_index = Arc::new(BlocksIndex {
                database: kv::Store::new(kv::Config {
                    path: self.root.join("proof-index"),
                    temporary: false,
                    use_compression: false,
                    flush_every_ms: None,
                    cache_capacity: None,
                    segment_size: None,
                })
                .unwrap(),
            });
            let (sender, receiver) = std::sync::mpsc::channel();
            let prover = FlatFileProver::new(
                self.chain.clone(),
                header_index,
                &self.root.join("forest"),
                self.root.join("journal"),
                &self.root.join("leaf-map"),
                proof_file.clone(),
                proof_index.clone(),
                1,
                false,
                1 << 20,
                Arc::new(AtomicBool::new(false)),
                sender,
            )
            .unwrap();
            (prover, proof_file, proof_index, receiver)
        }
    }

    impl Drop for PersistenceFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct FlushGate {
        released: Mutex<bool>,
        changed: parking_lot::Condvar,
    }

    impl FlushGate {
        fn wait(&self) {
            let mut released = self.released.lock();
            while !*released {
                self.changed.wait(&mut released);
            }
        }

        fn release(&self) {
            *self.released.lock() = true;
            self.changed.notify_all();
        }
    }

    #[test]
    fn asynchronous_persistence_proves_during_flush_and_reopens() {
        let fixture = Arc::new(PersistenceFixture::new());
        let producer_fixture = Arc::clone(&fixture);
        let (storage_tx, storage_rx) = std::sync::mpsc::sync_channel(1);
        let gate = Arc::new(FlushGate::default());
        let (entered, waiting) = std::sync::mpsc::sync_channel(1);
        let worker_gate = gate.clone();
        let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(1);
        let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel(1);
        let batch_gate = Arc::new(FlushGate::default());
        let worker_batch_gate = Arc::clone(&batch_gate);
        let (batch_entered, batch_waiting) = std::sync::mpsc::sync_channel(1);
        let flushes = Arc::new(Mutex::new(Vec::new()));
        let worker_flushes = Arc::clone(&flushes);
        let producer = std::thread::Builder::new()
            .name("fixture-prover".into())
            .spawn(move || {
                let (mut prover, proof_file, proof_index, notifications) = producer_fixture.open();
                *prover.persistence.hook.lock() = Some(Arc::new(move |stage, height| {
                    if stage == "state_flush" {
                        worker_flushes.lock().push(height);
                    }
                    if stage == "state_flush" && height == 4 {
                        batch_entered.send(()).unwrap();
                        worker_batch_gate.wait();
                    }
                    if stage == "state_flush" && height == 2 {
                        entered.send(()).unwrap();
                        worker_gate.wait();
                    }
                    Ok(())
                }));
                storage_tx
                    .send((proof_file, proof_index, notifications))
                    .unwrap();
                println!("steady fixture proving starts tid={}", unsafe {
                    libc::syscall(libc::SYS_gettid)
                });
                prover.prove_range(2, 2).unwrap();
                continue_rx.recv().unwrap();
                let block = prover
                    .rpc
                    .get_block(prover.rpc.get_block_hash(3).unwrap())
                    .unwrap();
                let inputs = &block.txdata[1].input;
                assert!(prover.leaf_data.contains_key(&inputs[0].previous_output));
                assert!(!prover.leaf_data.contains_key(&inputs[1].previous_output));
                prover.pollard_memory_limit = 1;
                prover.enforce_pollard_memory_limit().unwrap();
                prover.prove_range(3, 3).unwrap();
                // Remove the recent-leaf cache too: height four must resolve a not-yet-
                // durable addition through the outpoint overlay, not either cache.
                prover.leaf_data.clear();
                prover.prove_range(4, 4).unwrap();
                progress_tx
                    .send((prover.height, prover.pending_apply.len()))
                    .unwrap();
                let roots = pollard_stump_roots(&prover.pollard);
                prover.sync_for_shutdown().unwrap();
                println!(
                    "steady fixture proving ends height={} leaves={}",
                    prover.height,
                    prover.pollard.leaves()
                );
                roots
            })
            .unwrap();
        let (proof_file, proof_index, notifications) = storage_rx.recv().unwrap();
        let entered_result = waiting.recv_timeout(Duration::from_secs(10));
        let premature_notification = notifications.try_recv().is_ok();
        let height_during_flush = proof_index.load_height();
        let _ = continue_tx.send(());
        let progress = progress_rx.recv_timeout(Duration::from_secs(10));
        gate.release();
        let batch_result = batch_waiting.recv_timeout(Duration::from_secs(10));
        let height_during_batch = proof_index.load_height();
        let first_notification = notifications.recv_timeout(Duration::from_secs(2));
        let premature_batch_notification = notifications.try_recv().is_ok();
        batch_gate.release();
        batch_result.unwrap();
        assert_eq!(height_during_batch.unwrap(), 2);
        assert_eq!(
            first_notification.unwrap(),
            fixture.chain.get_block_hash(2).unwrap()
        );
        assert!(
            !premature_batch_notification,
            "batch must not publish a partial completion"
        );
        entered_result.unwrap();
        assert!(
            !premature_notification,
            "uncommitted block must not be announced"
        );
        assert_eq!(height_during_flush.unwrap(), 1);
        assert_eq!(
            progress.unwrap(),
            (4, 3),
            "producer must advance while height two is flushing"
        );
        let roots = producer.join().unwrap();
        assert_eq!(
            *flushes.lock(),
            [2, 4],
            "queued heights three and four share one state flush"
        );
        println!(
            "group commit: heights 2..=4 persisted in two batches; no partial batch publication"
        );
        assert_eq!(proof_index.load_height().unwrap(), 4);
        let mut proofs = Vec::new();
        for height in 2..=4 {
            let hash = fixture.chain.get_block_hash(height).unwrap();
            if height > 2 {
                assert_eq!(
                    notifications.recv_timeout(Duration::from_secs(2)).unwrap(),
                    hash
                );
            }
            let index = proof_index.get_index(hash).unwrap().unwrap();
            proofs.push(proof_file.get(&index).unwrap());
        }
        assert!(fixture.root.join("journal.clean").exists());
        drop(proof_file);
        drop(proof_index);
        let (mut reopened, proof_file, proof_index, _) = fixture.open();
        assert_eq!(reopened.height, 4);
        assert_eq!(pollard_stump_roots(&reopened.pollard), roots);
        for (height, expected) in (2..=4).zip(proofs) {
            let index = proof_index
                .get_index(fixture.chain.get_block_hash(height).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(proof_file.get(&index).unwrap(), expected);
        }
        reopened.sync_for_shutdown().unwrap();
        println!("steady fixture reopened durable height=4, all three compact proofs identical");
    }

    #[test]
    fn failed_group_commit_recovers_only_a_contiguous_proof_prefix() {
        for failure_stage in ["journal", "state_flush"] {
            let fixture = PersistenceFixture::new();
            let (mut prover, proofs, index, notifications) = fixture.open();
            let gate = Arc::new(FlushGate::default());
            let worker_gate = Arc::clone(&gate);
            let (entered, waiting) = std::sync::mpsc::sync_channel(1);
            *prover.persistence.hook.lock() = Some(Arc::new(move |stage, height| {
                if stage == "state_flush" && height == 2 {
                    entered.send(()).unwrap();
                    worker_gate.wait();
                }
                if stage == failure_stage && height == 4 {
                    anyhow::bail!("injected batch persistence failure");
                }
                Ok(())
            }));
            prover.prove_range(2, 2).unwrap();
            let at_two = pollard_stump_roots(&prover.pollard);
            let entered = waiting.recv_timeout(Duration::from_secs(10));
            if entered.is_err() {
                gate.release();
            }
            entered.unwrap();
            let produced = prover.prove_range(3, 4);
            let at_four = pollard_stump_roots(&prover.pollard);
            gate.release();
            produced.unwrap();
            assert!(format!("{:#}", prover.sync().unwrap_err()).contains("injected batch"));
            assert_eq!(index.load_height().unwrap(), 2);
            assert_eq!(
                notifications.recv_timeout(Duration::from_secs(2)).unwrap(),
                fixture.chain.get_block_hash(2).unwrap()
            );
            assert!(notifications.try_recv().is_err());
            assert!(prover.sync_for_shutdown().is_err());
            drop(prover);
            assert!(!fixture.root.join("journal.clean").exists());
            drop(proofs);
            drop(index);
            let (mut reopened, _, _, _) = fixture.open();
            let (height, roots) = if failure_stage == "journal" {
                (2, at_two)
            } else {
                (4, at_four)
            };
            assert_eq!(reopened.height, height);
            assert_eq!(pollard_stump_roots(&reopened.pollard), roots);
            reopened.sync_for_shutdown().unwrap();
        }
    }

    #[test]
    fn orderly_persistence_failures_stop_publication_and_recover() {
        for stage in ["journal", "state_flush"] {
            let fixture = PersistenceFixture::new();
            let (mut prover, proof_file, proof_index, notifications) = fixture.open();
            let baseline = pollard_stump_roots(&prover.pollard);
            *prover.persistence.hook.lock() = Some(Arc::new(move |at, _| {
                if at == stage {
                    anyhow::bail!("injected {stage} failure");
                }
                Ok(())
            }));
            prover.prove_range(2, 2).unwrap();
            let advanced = pollard_stump_roots(&prover.pollard);
            let failure = prover.sync().unwrap_err();
            assert!(format!("{failure:#}").contains(&format!("injected {stage} failure")));
            assert!(prover.prove_range(3, 3).is_err());
            assert!(prover.sync_for_shutdown().is_err());
            assert!(notifications.try_recv().is_err());
            assert!(!fixture.root.join("journal.clean").exists());
            drop(prover);
            drop(proof_file);
            drop(proof_index);
            let (mut reopened, _, _, _) = fixture.open();
            let (height, roots) = if stage == "journal" {
                (1, baseline)
            } else {
                (2, advanced)
            };
            assert_eq!(reopened.height, height);
            assert_eq!(pollard_stump_roots(&reopened.pollard), roots);
            reopened.sync_for_shutdown().unwrap();
        }
    }

    #[test]
    fn bounded_pipeline_drains_before_reorg() {
        let fixture = Arc::new(PersistenceFixture::new());
        let producer_fixture = Arc::clone(&fixture);
        let gate = Arc::new(FlushGate::default());
        let (entered, waiting) = std::sync::mpsc::sync_channel(1);
        let (limited_tx, limited_rx) = std::sync::mpsc::channel();
        let worker_gate = gate.clone();
        let (full_tx, full_rx) = std::sync::mpsc::sync_channel(1);
        let producer = std::thread::spawn(move || {
            let (mut prover, _, proof_index, _) = producer_fixture.open();
            let baseline = pollard_stump_roots(&prover.pollard);
            *prover.persistence.hook.lock() = Some(Arc::new(move |stage, height| {
                if stage == "state_flush" && height == 2 {
                    entered.send(()).unwrap();
                    worker_gate.wait();
                }
                if stage == "backpressure" {
                    let _ = limited_tx.send(());
                }
                Ok(())
            }));
            prover.prove_range(2, 9).unwrap();
            full_tx.send(prover.pending_apply.len()).unwrap();
            prover.prove_range(10, 10).unwrap();
            producer_fixture.chain.blocks.lock().truncate(2);
            assert_eq!(prover.reconcile_chain().unwrap(), 9);
            assert_eq!(prover.height, 1);
            assert_eq!(pollard_stump_roots(&prover.pollard), baseline);
            assert_eq!(proof_index.load_height().unwrap(), 1);
            assert_eq!(
                std::fs::metadata(producer_fixture.root.join("proofs"))
                    .unwrap()
                    .len(),
                0
            );
            prover.sync_for_shutdown().unwrap();
            baseline
        });
        let entered_result = waiting.recv_timeout(Duration::from_secs(10));
        let full = full_rx.recv_timeout(Duration::from_secs(10));
        let limited = limited_rx.recv_timeout(Duration::from_secs(10));
        gate.release();
        entered_result.unwrap();
        assert_eq!(full.unwrap(), MAX_PENDING_BLOCKS);
        limited.unwrap();
        let baseline = producer.join().unwrap();
        let (mut reopened, _, _, _) = fixture.open();
        assert_eq!(reopened.height, 1);
        assert_eq!(pollard_stump_roots(&reopened.pollard), baseline);
        reopened.sync_for_shutdown().unwrap();
    }

    fn leaf(outpoint: OutPoint) -> LeafContext {
        LeafContext {
            block_hash: BlockHash::all_zeros(),
            txid: outpoint.txid,
            vout: outpoint.vout,
            value: 42,
            pk_script: ScriptBuf::new(),
            block_height: 10,
            is_coinbase: false,
        }
    }

    #[test]
    fn startup_rolls_back_past_a_skipped_proof_height() {
        let root =
            std::env::temp_dir().join(format!("bridge-skipped-proof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut header_11 = genesis_block(Network::Signet).header;
        header_11.nonce = 11;
        let hash_11 = header_11.block_hash();
        let mut header_12 = header_11;
        header_12.prev_blockhash = hash_11;
        header_12.nonce = 12;
        let hash_12 = header_12.block_hash();
        let mut header_13 = header_12;
        header_13.prev_blockhash = hash_12;
        header_13.nonce = 13;
        let hash_13 = header_13.block_hash();
        let header_index =
            HeaderIndex::create(&root.join("headers"), &root.join("header-index"), 13).unwrap();
        for (height, header) in [(11, &header_11), (12, &header_12), (13, &header_13)] {
            header_index.put(height, header).unwrap();
        }
        header_index.sync().unwrap();

        let mut journal = ForestJournal::open(root.join("journal")).unwrap();
        for (height, block_hash, previous_block_hash) in [
            (11, hash_11, BlockHash::from_byte_array([10; 32])),
            (12, hash_12, hash_11),
            (13, hash_13, hash_12),
        ] {
            journal
                .append(JournalEntry {
                    height,
                    block_hash,
                    num_leaves: 100 + u64::from(height),
                    previous_block_hash,
                    forest: Vec::new(),
                    removed: Vec::new(),
                    added: Vec::new(),
                })
                .unwrap();
        }
        journal.flush().unwrap();

        let proof_file = ProofFile::new(root.join("proofs")).unwrap();
        let proof = CompactBlockProof::default();
        let index_11 = proof_file.append(&proof).unwrap();
        let index_13 = proof_file.append(&proof).unwrap();
        proof_file.sync().unwrap();
        let proof_index = BlocksIndex {
            database: kv::Store::new(kv::Config {
                path: root.join("proof-index"),
                temporary: false,
                use_compression: false,
                flush_every_ms: None,
                cache_capacity: None,
                segment_size: None,
            })
            .unwrap(),
        };
        proof_index.append(index_11, hash_11).unwrap();
        proof_index.append(index_13, hash_13).unwrap();
        proof_index.update_height(13).unwrap();

        assert_eq!(
            recoverable_journal_height(
                &mut journal,
                &header_index,
                &proof_index,
                &proof_file,
                13,
                10,
            )
            .unwrap(),
            11
        );
        assert_eq!(journal.records()[0].status, JournalStatus::Forward);
        assert_eq!(journal.records()[1].status, JournalStatus::RolledBack);
        assert_eq!(journal.records()[2].status, JournalStatus::RolledBack);

        header_index.close().unwrap();
        drop(proof_index);
        drop(proof_file);
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn steady_leaf_cache_bypasses_fallback_fetch() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 2,
        };
        let mut cache = HashMap::new();
        cache.insert(
            outpoint,
            CachedLeaf {
                context: leaf(outpoint),
                position: 7,
            },
        );
        let mut fetched = false;

        let (cached, hit) = cached_leaf_context(&cache, outpoint, || {
            fetched = true;
            anyhow::bail!("fallback must not run for a cache hit")
        })
        .unwrap();

        assert!(hit);
        assert!(!fetched);
        assert_eq!(cached.txid, outpoint.txid);
        assert_eq!(cached.vout, outpoint.vout);
    }

    #[test]
    fn steady_leaf_position_cache_survives_pollard_eviction() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([3; 32]),
            vout: 4,
        };
        let cached = CachedLeaf {
            context: leaf(outpoint),
            position: 7,
        };

        assert_eq!(cached_bottom_position(None, Some(&cached)), Some(7));
        assert_eq!(
            cached_bottom_position(Some(9), Some(&cached)),
            Some(9),
            "the Pollard remains the preferred position cache"
        );
    }

    #[test]
    fn steady_leaf_cache_uses_fallback_on_miss() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 3,
        };
        let mut fetched = false;

        let (leaf, hit) = cached_leaf_context(&HashMap::new(), outpoint, || {
            fetched = true;
            Ok(leaf(outpoint))
        })
        .unwrap();

        assert!(!hit);
        assert!(fetched);
        assert_eq!(leaf.value, 42);
    }

    #[test]
    fn pollard_quota_evicts_oldest_leaves_to_low_watermark() {
        let additions = (0u8..64)
            .map(|value| PollardAddition {
                hash: BitcoinNodeHash::from([value; 32]),
                remember: true,
            })
            .collect::<Vec<_>>();
        let mut pollard = Pollard::new();
        pollard.modify(&additions, &[], Proof::default()).unwrap();
        let mut leaves = BinaryHeap::new();
        for (position, addition) in additions.iter().enumerate() {
            leaves.push(Reverse(CachedPollardLeaf {
                creation_height: position as u32,
                position: position as u64,
                hash: addition.hash,
            }));
        }
        let quota = pollard.estimated_memory_usage();
        let (evicted, before, after) =
            evict_pollard_cache(&mut pollard, &mut leaves, quota).unwrap();

        assert!(evicted > 0);
        assert_eq!(before, quota);
        assert!(
            after <= quota / 5,
            "before={before} after={after} target={} evicted={evicted} nodes={}",
            quota / 5,
            pollard.cached_nodes()
        );
        assert_eq!(pollard.position_hash(0), None);
        assert_eq!(pollard.leaf_position(&additions[0].hash), None);
        assert_eq!(pollard.position_hash(63), Some(additions[63].hash));
        assert_eq!(pollard.leaf_position(&additions[63].hash), Some(63));
    }
}
