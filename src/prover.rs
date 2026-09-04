//SPDX-License-Identifier: MIT

//! Pollard-backed steady-state proof generation over the persistent flat forest.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::sync::Arc;
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
use crate::forest_journal::ForestJournalFlusher;
use crate::forest_journal::JournalEntry;
use crate::forest_journal::JournalStatus;
use crate::header_index::HeaderIndex;
use crate::parallel_forest::tree_rows;
use crate::parallel_forest::SteadyStateForest;
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
    rpc_mtp: Duration,
    scan_prevouts: Duration,
    positions: Duration,
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
    journal_append: Duration,
    header_store: Duration,
    cache_update: Duration,
    proof_store: Duration,
    proof_index_write: Duration,
    total: Duration,
}

#[derive(Default)]
pub(crate) struct ApplyTimings {
    pub(crate) journal_flush: Duration,
    pub(crate) apply: Duration,
    pub(crate) state_flush: Duration,
}
type ApplyResult = anyhow::Result<(SteadyStateForest, ApplyTimings)>;

struct ApplyJob {
    entry: JournalEntry,
    published_size: u64,
    forest: SteadyStateForest,
    completion: std::sync::mpsc::SyncSender<ApplyResult>,
}

pub(crate) struct JournalApplyWorker {
    sender: Option<std::sync::mpsc::Sender<ApplyJob>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl JournalApplyWorker {
    pub(crate) fn new(flusher: ForestJournalFlusher) -> anyhow::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::channel::<ApplyJob>();
        let handle = std::thread::Builder::new()
            .name("bridge-journal-apply".to_string())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    let ApplyJob {
                        entry,
                        published_size,
                        mut forest,
                        completion,
                    } = job;
                    let result = (|| -> ApplyResult {
                        let started = Instant::now();
                        flusher.flush_through(published_size)?;
                        let journal_flush = started.elapsed();
                        let started = Instant::now();
                        forest.apply_forward(&entry)?;
                        let apply = started.elapsed();
                        let started = Instant::now();
                        forest.sync()?;
                        let timings = ApplyTimings {
                            journal_flush,
                            apply,
                            state_flush: started.elapsed(),
                        };
                        Ok((forest, timings))
                    })();
                    let failed = result.is_err();
                    let _ = completion.send(result);
                    if failed {
                        break;
                    }
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            handle: Some(handle),
        })
    }

    pub(crate) fn enqueue(
        &self,
        entry: JournalEntry,
        published_size: u64,
        forest: SteadyStateForest,
    ) -> anyhow::Result<std::sync::mpsc::Receiver<ApplyResult>> {
        let (completion, receiver) = std::sync::mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .context("journal apply worker stopped")?
            .send(ApplyJob {
                entry,
                published_size,
                forest,
                completion,
            })
            .map_err(|_| anyhow::anyhow!("journal apply worker stopped"))?;
        Ok(receiver)
    }
}

impl Drop for JournalApplyWorker {
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
    completion: std::sync::mpsc::Receiver<ApplyResult>,
    journal_index: usize,
    height: u32,
    proof_forest_rows: u8,
}

/// Sequential steady-state prover backed by the bootstrapped flat forest and persistent leaf map.
pub struct FlatFileProver {
    rpc: Arc<dyn Blockchain>,
    header_index: Arc<HeaderIndex>,
    apply_worker: JournalApplyWorker,
    acc: Option<SteadyStateForest>,
    pollard: Pollard<BitcoinNodeHash>,
    pollard_leaves: BinaryHeap<Reverse<CachedPollardLeaf>>,
    pollard_memory_limit: usize,
    proof_file: Arc<ProofFile>,
    proof_index: Arc<BlocksIndex>,
    height: u32,
    bootstrap_height: u32,
    shutdown_flag: Arc<AtomicBool>,
    block_notification: Sender<BlockHash>,
    leaf_data: HashMap<OutPoint, LeafContext>,
    block_hash_cache: HashMap<u32, BlockHash>,
    pending_apply: Option<PendingApply>,
    journal: ForestJournal,
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
        acc.replay_journal(&journal)?;
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
        let mut block_hash_cache = HashMap::new();
        block_hash_cache.insert(height, tip_hash);
        let forest_roots = acc.roots()?;
        let pollard = pollard_from_stump_roots(forest_roots.clone(), acc.leaves());
        if pollard_stump_roots(&pollard) != forest_roots {
            anyhow::bail!("Pollard roots do not match the recovered flat forest");
        }
        let flusher = journal.flusher()?;
        let apply_worker = JournalApplyWorker::new(flusher)?;
        let prover = Self {
            rpc,
            header_index,
            apply_worker,
            acc: Some(acc),
            pollard,
            proof_file,
            proof_index,
            pollard_leaves: BinaryHeap::new(),
            pollard_memory_limit,
            height,
            bootstrap_height,
            shutdown_flag,
            block_notification,
            leaf_data: HashMap::new(),
            block_hash_cache,
            pending_apply: None,
            journal,
            tip_hash,
        };
        prover.verify_durable_tip()?;
        Ok(prover)
    }

    fn enforce_pollard_memory_limit(&mut self) -> anyhow::Result<()> {
        if self.pollard.estimated_memory_usage() < self.pollard_memory_limit {
            return Ok(());
        }
        // Once cached Pollard leaves are forgotten, a later miss falls back to the flat forest.
        // Make that durable state authoritative before reclaiming anything from the Pollard.
        self.drain_pending_apply()?;
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

    fn drain_pending_apply(&mut self) -> anyhow::Result<()> {
        if let Some(pending) = self.pending_apply.take() {
            let result = pending
                .completion
                .recv()
                .map_err(|_| anyhow::anyhow!("journal apply worker stopped"))?;
            let (forest, timings) = result?;
            if self.acc.replace(forest).is_some() {
                anyhow::bail!("background apply returned a forest while one was already present");
            }
            let height_commit_started = Instant::now();
            self.proof_index.update_height(pending.height as usize)?;
            let height_commit = height_commit_started.elapsed();
            debug!(
                "background-journal-apply height={} journal_index={} journal_flush={:?} apply={:?} state_flush={:?} height_commit={height_commit:?}",
                pending.height,
                pending.journal_index,
                timings.journal_flush,
                timings.apply,
                timings.state_flush
            );
        }
        if let Err(error) = self.journal.prune(144) {
            warn!("journal pruning failed; retaining older recovery records: {error:#}");
        }
        self.verify_durable_tip()
    }

    pub(crate) fn forest_rows(&self) -> anyhow::Result<u8> {
        self.acc
            .as_ref()
            .map(SteadyStateForest::forest_rows)
            .context("steady forest unavailable without a pending apply")
    }

    fn truncate_proofs_to(&self, height: u32, tip_hash: BlockHash) -> anyhow::Result<()> {
        let index = if height > self.bootstrap_height {
            Some(
                self.proof_index
                    .get_index(tip_hash)?
                    .ok_or_else(|| anyhow::anyhow!("proof index is missing height {height}"))?,
            )
        } else {
            None
        };
        self.proof_file.truncate_after(index.as_ref())?;
        Ok(())
    }

    fn verify_durable_tip(&self) -> anyhow::Result<()> {
        if self.pending_apply.is_some() {
            return Ok(());
        }
        let proof_height =
            u32::try_from(self.proof_index.load_height()?).context("proof height exceeds u32")?;
        if proof_height != self.height {
            anyhow::bail!(
                "durable forest height {} does not match proof height {proof_height}",
                self.height
            );
        }
        let (journal_height, journal_hash, expected_leaves) = match self.journal.latest_forward() {
            Some((_, record)) => (
                record.entry.height,
                record.entry.block_hash,
                record.entry.num_leaves,
            ),
            None if !self.journal.records().is_empty() => {
                let first = &self.journal.records()[0].entry;
                (
                    first.height.saturating_sub(1),
                    first.previous_block_hash,
                    first.previous_num_leaves()?,
                )
            }
            None => (self.bootstrap_height, self.tip_hash, self.pollard.leaves()),
        };
        if (journal_height, journal_hash) != (self.height, self.tip_hash) {
            anyhow::bail!(
                "journal tip {journal_height}:{journal_hash} does not match prover tip {}:{}",
                self.height,
                self.tip_hash
            );
        }
        let forest = self
            .acc
            .as_ref()
            .context("steady forest unavailable without a pending apply")?;
        if forest.leaves() != expected_leaves
            || forest.leaves() != self.pollard.leaves()
            || forest.roots()? != pollard_stump_roots(&self.pollard)
        {
            anyhow::bail!("durable forest, journal, and Pollard states diverged");
        }
        if self.height > self.bootstrap_height {
            let index = self
                .proof_index
                .get_index(self.tip_hash)?
                .ok_or_else(|| anyhow::anyhow!("proof index is missing height {}", self.height))?;
            if self.proof_file.get(&index).is_none() {
                anyhow::bail!(
                    "proof data for height {} is missing or corrupt",
                    self.height
                );
            }
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
            .as_ref()
            .context("steady forest unavailable during capacity check")?
            .leaf_capacity()?;
        if required_leaves <= current_capacity {
            return Ok(());
        }

        self.drain_pending_apply()?;
        let forest = self
            .acc
            .as_mut()
            .context("steady forest unavailable during resize")?;
        if forest.leaves() != self.pollard.leaves() {
            anyhow::bail!(
                "flat forest has {} leaves before resize, Pollard has {}",
                forest.leaves(),
                self.pollard.leaves()
            );
        }
        forest.ensure_leaf_capacity(required_leaves)?;
        Ok(())
    }

    pub fn keep_up(&mut self) -> anyhow::Result<()> {
        loop {
            if self.shutdown_flag.load(Ordering::Acquire) {
                self.sync()?;
                return Ok(());
            }
            self.sync_to_tip()?;
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }

    fn reconcile_chain(&mut self) -> anyhow::Result<u32> {
        self.drain_pending_apply()?;
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
            let (entry, leaves, roots) = {
                let Some((index, record)) = self.journal.latest_forward() else {
                    anyhow::bail!(
                        "reorg exceeds retained journal at height {}; rebuild from a newer bootstrap",
                        self.height
                    );
                };
                let entry = record.entry.clone();
                if entry.height != self.height || entry.block_hash != self.tip_hash {
                    anyhow::bail!(
                        "journal tip {}:{} does not match prover tip {}:{}",
                        entry.height,
                        entry.block_hash,
                        self.height,
                        self.tip_hash
                    );
                }
                self.journal.mark_rolled_back(index)?;
                let forest = self
                    .acc
                    .as_mut()
                    .context("steady forest unavailable during reorg")?;
                forest.apply_backward(&entry)?;
                self.header_index.remove(entry.height, entry.block_hash)?;
                forest.sync()?;
                self.header_index.sync()?;
                (entry, forest.leaves(), forest.roots()?)
            };
            self.pollard = pollard_from_stump_roots(roots, leaves);
            self.pollard_leaves.clear();
            let previous_height = entry.height.saturating_sub(1);
            let previous_hash = entry.previous_block_hash;
            self.proof_index.remove(entry.block_hash)?;
            self.truncate_proofs_to(previous_height, previous_hash)?;
            self.proof_index.update_height(previous_height as usize)?;
            self.height = previous_height;
            self.tip_hash = previous_hash;
            self.block_hash_cache
                .retain(|height, _| *height <= previous_height);
            self.leaf_data.clear();
            rolled_back += 1;
            info!(
                "rolled back orphaned block height={} hash={} leaves={leaves}",
                entry.height, entry.block_hash
            );
        }
        self.verify_durable_tip()?;
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
            self.drain_pending_apply()?;
            if self.shutdown_flag.load(Ordering::Acquire) {
                break;
            }
            let total_started = Instant::now();
            let mut timings = SteadyBlockTimings::default();
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
            let started = Instant::now();
            let median_time_past = self.rpc.get_mtp(block.header.prev_blockhash)?;
            timings.rpc_mtp = started.elapsed();
            let (
                compact_proof,
                leaf_cache_hits,
                leaf_cache_misses,
                prevout_creation_heights,
                process_timings,
                pending,
            ) = self.process_block(&block, &prevouts, height, median_time_past)?;
            timings.scan_prevouts = process_timings.scan_prevouts;
            timings.positions = process_timings.positions;
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
            timings.journal_append = process_timings.journal_append;
            timings.cache_update = process_timings.cache_update;
            let proof_forest_rows = pending.proof_forest_rows;
            let persistence = (|| -> anyhow::Result<()> {
                let started = Instant::now();
                let mut index = self.proof_file.append(&compact_proof)?;
                if self.proof_file.get(&index).as_ref() != Some(&compact_proof) {
                    anyhow::bail!("failed to read back compact proof for {block_hash}");
                }
                self.proof_file.sync()?;
                index.proof_forest_rows = Some(proof_forest_rows);
                timings.proof_store = started.elapsed();

                let started = Instant::now();
                self.header_index.put(height, &block.header)?;
                self.header_index.sync()?;
                timings.header_store = started.elapsed();

                let started = Instant::now();
                self.proof_index.append(index, block_hash)?;
                timings.proof_index_write = started.elapsed();
                Ok(())
            })();

            if let Err(error) = persistence {
                let apply_result = pending
                    .completion
                    .recv()
                    .map_err(|_| anyhow::anyhow!("journal apply worker stopped"))?;
                let (forest, _) = match apply_result {
                    Ok(applied) => applied,
                    Err(apply_error) => {
                        return Err(error.context(format!(
                            "persistence failed and background apply also failed: {apply_error:#}"
                        )));
                    }
                };
                if self.acc.replace(forest).is_some() {
                    return Err(error.context(
                        "background apply returned a forest while one was already present",
                    ));
                }
                if let Err(rollback) =
                    self.rollback_applied_journal(pending.journal_index, height, block_hash)
                {
                    return Err(error.context(format!(
                        "failed to roll back journal after persistence failure: {rollback:#}"
                    )));
                }
                return Err(error);
            }
            self.pending_apply = Some(pending);
            self.enforce_pollard_memory_limit()?;

            let started = Instant::now();
            self.block_hash_cache.insert(height, block_hash);
            self.height = height;
            self.tip_hash = block_hash;
            timings.cache_update += started.elapsed();

            timings.total = total_started.elapsed();
            let leaves = self.pollard.leaves();
            let _ = self.block_notification.send(block_hash);
            info!(
                "steady-state height={height} hash={block_hash} targets={} proof_hashes={} leaves={leaves}",
                compact_proof.proof.targets.len(),
                compact_proof.proof.hashes.len(),
            );
            debug!(
                "steady-state-cache height={height} leaf_data={} leaf_cache_hits={} leaf_cache_misses={} leaf_cache_entries={} position_cache_hits={} position_cache_misses={} forest_positions_loaded={} prevout_creation_heights={} pollard_cached_nodes={} pollard_ingested_positions={} pollard_bytes={} pollard_quota={}",
                compact_proof.leaves.len(),
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
                "steady-state-timings height={height} hash={block_hash} total={:?} rpc_block_hash={:?} rpc_block_v3={:?} rpc_mtp={:?} scan_prevouts={:?} positions={:?} proof_build={:?} prevout_block_hashes={:?} leaf_resolution={:?} proof_verify={:?} additions={:?} stump_update={:?} plan_update={:?} journal_append={:?} header_store={:?} cache_update={:?} proof_store={:?} proof_index_write={:?}",
                timings.total,
                timings.rpc_block_hash,
                timings.rpc_block,
                timings.rpc_mtp,
                timings.scan_prevouts,
                timings.positions,
                timings.proof_build,
                timings.prevout_block_hashes,
                timings.leaf_resolution,
                timings.proof_verify,
                timings.additions,
                timings.stump_update,
                timings.plan_update,
                timings.journal_append,
                timings.header_store,
                timings.cache_update,
                timings.proof_store,
                timings.proof_index_write
            );
        }
        Ok(())
    }

    fn rollback_applied_journal(
        &mut self,
        journal_index: usize,
        height: u32,
        block_hash: BlockHash,
    ) -> anyhow::Result<()> {
        let entry = {
            let record = self.journal.records().get(journal_index).ok_or_else(|| {
                anyhow::anyhow!("journal rollback index {journal_index} is out of bounds")
            })?;
            if record.entry.height != height || record.entry.block_hash != block_hash {
                anyhow::bail!(
                    "journal rollback entry {}:{} does not match {height}:{block_hash}",
                    record.entry.height,
                    record.entry.block_hash
                );
            }
            let entry = record.entry.clone();
            self.journal.mark_rolled_back(journal_index)?;
            entry
        };
        self.proof_index.remove(block_hash)?;
        self.header_index.remove(height, block_hash)?;
        self.header_index.sync()?;
        let (leaves, roots) = {
            let forest = self
                .acc
                .as_mut()
                .context("steady forest unavailable during rollback")?;
            forest.apply_backward(&entry)?;
            forest.sync()?;
            (forest.leaves(), forest.roots()?)
        };
        self.truncate_proofs_to(self.height, self.tip_hash)?;
        self.proof_index.update_height(self.height as usize)?;
        self.block_hash_cache
            .retain(|height, _| *height <= self.height);
        self.pollard = pollard_from_stump_roots(roots, leaves);
        self.pollard_leaves.clear();
        self.leaf_data.clear();
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
        acc: &SteadyStateForest,
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
        acc: &SteadyStateForest,
        outpoint: OutPoint,
        prevouts: &HashMap<OutPoint, PrevoutInfo>,
        creating_block_hashes: &HashMap<u32, BlockHash>,
    ) -> anyhow::Result<(u64, LeafContext)> {
        let leaf = if let Some(leaf) = self.leaf_data.get(&outpoint) {
            leaf.clone()
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
        median_time_past: u32,
    ) -> anyhow::Result<(
        CompactBlockProof,
        usize,
        usize,
        usize,
        SteadyBlockTimings,
        PendingApply,
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
                    median_time_past,
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

        let cached_leaf_hashes = external_outpoints
            .iter()
            .filter_map(|outpoint| {
                self.leaf_data
                    .get(outpoint)
                    .map(|leaf| (*outpoint, LeafData::get_leaf_hashes(leaf)))
            })
            .collect::<HashMap<_, _>>();
        let cached_bottom_positions = cached_leaf_hashes
            .iter()
            .filter_map(|(outpoint, hash)| {
                self.pollard
                    .leaf_position(hash)
                    .map(|position| (*outpoint, position))
            })
            .collect::<HashMap<_, _>>();
        timings.position_cache_hits = cached_bottom_positions.len();
        timings.position_cache_misses = external_outpoints.len() - timings.position_cache_hits;
        let acc = self
            .acc
            .as_ref()
            .context("steady forest unavailable while planning a block")?;
        let mut deletions = Vec::with_capacity(external_outpoints.len());
        let mut proof_targets = Vec::with_capacity(external_outpoints.len());
        let mut recovered_leaf_data = HashMap::new();
        let mut cached_target_hashes = HashMap::with_capacity(cached_leaf_hashes.len());
        for outpoint in external_outpoints {
            let bottom_position = match cached_bottom_positions.get(&outpoint) {
                Some(position) => *position,
                None => match acc.leaf_position(&outpoint) {
                    Ok(position) => position,
                    Err(map_error) => {
                        let (position, leaf) = self
                            .recover_missing_leaf_position(
                                acc,
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
            let proof_position = acc.proof_position(bottom_position)?;
            if let Some(hash) = cached_leaf_hashes.get(&outpoint) {
                cached_target_hashes.insert(proof_position, *hash);
            }
            deletions.push((outpoint, bottom_position));
            proof_targets.push(proof_position);
        }
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
                        .recover_leaf_position(acc, *outpoint, &leaf)
                        .with_context(|| {
                            format!(
                                "failed to recover {outpoint} after hash mismatch at position {bottom_position}"
                            )
                        })?;
                    acc.repair_leaf_position(outpoint, recovered_position)?;
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
        let journal_entry = acc.plan_update_without_resize(
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

        let started = Instant::now();
        let journal_index = match self.journal.append(journal_entry.clone()) {
            Ok(index) => index,
            Err(error) => {
                self.pollard =
                    pollard_from_stump_roots(original_stump.roots.clone(), original_stump.leaves);
                self.pollard_leaves.clear();
                return Err(error);
            }
        };
        let published_size = self.journal.published_size();
        let forest = self
            .acc
            .take()
            .context("steady forest unavailable before background apply")?;
        let completion =
            match self
                .apply_worker
                .enqueue(journal_entry.clone(), published_size, forest)
            {
                Ok(completion) => completion,
                Err(error) => {
                    let rollback = self.journal.mark_rolled_back(journal_index);
                    self.pollard = pollard_from_stump_roots(
                        original_stump.roots.clone(),
                        original_stump.leaves,
                    );
                    self.pollard_leaves.clear();
                    if let Err(rollback) = rollback {
                        return Err(error.context(format!(
                            "failed to roll back journal after apply enqueue failure: {rollback:#}"
                        )));
                    }
                    return Err(error);
                }
            };
        timings.journal_append = started.elapsed();
        self.pollard_leaves
            .extend(cached_pollard_leaves.into_iter().map(Reverse));
        let pending = PendingApply {
            completion,
            journal_index,
            height,
            proof_forest_rows: tree_rows(original_stump.leaves),
        };
        let started = Instant::now();
        for (outpoint, _) in &deletions {
            self.leaf_data.remove(outpoint);
        }
        self.leaf_data.extend(added_leaf_data);
        let oldest_cached_height = height.saturating_sub(LEAF_CACHE_BLOCKS.saturating_sub(1));
        self.leaf_data
            .retain(|_, leaf| leaf.block_height >= oldest_cached_height);
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

    pub fn sync(&mut self) -> anyhow::Result<()> {
        self.drain_pending_apply()?;
        self.acc
            .as_ref()
            .context("steady forest unavailable during sync")?
            .sync()?;
        let published_size = self.journal.published_size();
        self.journal.flush()?;
        if !self.journal.is_flushed_through(published_size) {
            anyhow::bail!("forest journal did not flush through {published_size}");
        }
        self.proof_file.sync()?;
        Ok(())
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
    cache: &HashMap<OutPoint, LeafContext>,
    outpoint: OutPoint,
    fetch: impl FnOnce() -> anyhow::Result<LeafContext>,
) -> anyhow::Result<(LeafContext, bool)> {
    match cache.get(&outpoint) {
        Some(leaf) => Ok((leaf.clone(), true)),
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
        median_time_past: 0,
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
        median_time_past: 0,
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

    fn leaf(outpoint: OutPoint) -> LeafContext {
        LeafContext {
            block_hash: BlockHash::all_zeros(),
            txid: outpoint.txid,
            vout: outpoint.vout,
            value: 42,
            pk_script: ScriptBuf::new(),
            block_height: 10,
            median_time_past: 0,
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
            HeaderIndex::create(&root.join("headers"), &root.join("header-index"), 13, 1).unwrap();
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
        cache.insert(outpoint, leaf(outpoint));
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
