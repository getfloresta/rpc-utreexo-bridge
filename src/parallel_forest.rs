// SPDX-License-Identifier: MIT

//! Linux-only, parallel construction of a position-addressed Utreexo forest.

use std::cell::UnsafeCell;
use std::collections::hash_map::Entry;
#[cfg(test)]
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::size_of;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::forest_journal::ForestJournal;
use crate::forest_journal::JournalEntry;
use crate::forest_journal::JournalForestDelta;
use crate::forest_journal::JournalIndexDelta;
use crate::forest_journal::JournalNodeState;
use crate::header_index::HeaderBuildWriter;
use crate::header_index::HeaderIndex;
use crate::udata::bitcoin_leaf_data::get_leaf_hash_from_parts;
use ahash::AHashMap;
use ahash::AHashSet;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Txid;
use bitcoinkernel::prelude::BlockHashExt;
use bitcoinkernel::prelude::BlockHeaderExt;
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
use bridge::prefixed_hints::BridgeHints;
use db_experiment::Config as LeafMapConfig;
use db_experiment::Database;
use db_experiment::Mode;
use db_experiment::WriteOnlyWriter;
use log::debug;
use log::info;
use log::warn;
#[cfg(test)]
use memmap2::Mmap;
use memmap2::MmapMut;
use memmap2::MmapOptions;
use memmap2::RemapOptions;
use rayon::prelude::*;
use rustreexo::node_hash::AccumulatorHash;
use rustreexo::node_hash::BitcoinNodeHash;
#[cfg(test)]
use rustreexo::proof::Proof;
const MIN_PARALLEL_PLANNING_NODES: usize = 128;

const READY: u8 = 1 << 0;
const SPENT: u8 = 1 << 1;
const HEIGHT_CHUNK_SIZE: u64 = 4;
const WRITING: u8 = 1 << 2;
const DEFAULT_SPIN_ITERATIONS: usize = 512;
const STEADY_LEAF_MAP_HEADROOM: u64 = 1 << 30;
const RESIZE_MARKER_MAGIC: &[u8; 8] = b"FRSIZE01";
const RESIZE_MARKER_LEN: usize = RESIZE_MARKER_MAGIC.len() + 3;
const RESIZE_STAGE_COPYING: u8 = 0;
const RESIZE_STAGE_CLEARING: u8 = 1;
const BIP30_FIRST_TXID_91722: &str =
    "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468";
const BIP30_FIRST_TXID_91812: &str =
    "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct KernelOutPoint {
    txid: [u8; 32],
    vout: u32,
}

#[derive(Clone, Copy)]
struct LeafOutput<'a> {
    block_hash: [u8; 32],
    txid: [u8; 32],
    vout: u32,
    is_coinbase: bool,
    force_unindexed: bool,
    value: u64,
    script_pubkey: &'a [u8],
}

/// The stable representation of one position in the flat forest file.
///
/// The first 32 bytes are the hash. `flags` contains the spentness bit and the publication state.
/// A zeroed node is uninitialized. The node at position `n` starts at
/// `n * size_of::<ForestNode>()`.
#[repr(C)]
pub struct ForestNode {
    hash: UnsafeCell<[u8; 32]>,
    flags: AtomicU8,
}

/// A copied, synchronized view of a forest node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForestNodeData {
    pub hash: [u8; 32],
    pub spent: bool,
}

/// Configuration for one complete parallel build.
#[derive(Clone, Debug)]
pub struct ParallelForestConfig {
    pub forest_path: PathBuf,
    pub leaf_map_path: PathBuf,
    pub header_file_path: PathBuf,
    pub header_index_path: PathBuf,
    pub minimum_leaf_capacity: Option<u64>,
    pub leaf_workers: usize,
    pub chaser_workers: usize,
    pub spin_iterations: usize,
    pub lock_pages: bool,
}

impl ParallelForestConfig {
    pub fn new(forest_path: PathBuf) -> Self {
        let leaf_map_path = forest_path.with_extension("leaf-map");
        let header_file_path = forest_path.with_extension("headers");
        let header_index_path = forest_path.with_extension("header-index");
        let threads = thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let leaf_workers = (threads / 2).max(1);
        let chaser_workers = threads.saturating_sub(leaf_workers).max(1);
        Self {
            forest_path,
            leaf_map_path,
            leaf_workers,
            header_file_path,
            header_index_path,
            minimum_leaf_capacity: None,
            chaser_workers,
            spin_iterations: DEFAULT_SPIN_ITERATIONS,
            lock_pages: true,
        }
    }
}

/// One populated root in the completed forest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForestRoot {
    pub position: u64,
    pub row: u8,
    pub node: ForestNodeData,
}

/// Observable metadata from a completed build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForestBuildSummary {
    pub leaves: u64,
    pub initialized_nodes: u64,
    pub file_nodes: u64,
    pub leaf_map_entries: u64,
    pub file_bytes: u64,
    pub pages_locked: bool,
    pub roots: Vec<ForestRoot>,
    pub statistics: BuildStatistics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildStatistics {
    pub ranges: u64,
    pub average_range_lock_time: Duration,
    pub average_range_processing_time: Duration,
    pub kernel_blocks: u64,
    pub average_kernel_block_wait: Duration,
    pub index_writes: u64,
    pub average_index_write_time: Duration,
    pub forest_writes: u64,
    pub average_forest_write_time: Duration,
    pub chaser_range_waits: u64,
}

#[derive(Default)]
struct TimingAccumulator {
    total_nanos: AtomicU64,
    samples: AtomicU64,
}

impl TimingAccumulator {
    fn record(&self, elapsed: Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.total_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, Duration) {
        let samples = self.samples.load(Ordering::Relaxed);
        let total_nanos = self.total_nanos.load(Ordering::Relaxed);
        let average = if samples == 0 {
            Duration::ZERO
        } else {
            Duration::from_nanos(total_nanos / samples)
        };
        (samples, average)
    }
}

#[derive(Default)]
struct BuildStats {
    range_lock: TimingAccumulator,
    range_processing: TimingAccumulator,
    kernel_wait: TimingAccumulator,
    index_write: TimingAccumulator,
    forest_write: TimingAccumulator,
    chaser_range_waits: AtomicU64,
}

impl BuildStats {
    fn snapshot(&self) -> BuildStatistics {
        let (ranges, average_range_lock_time) = self.range_lock.snapshot();
        let (_, average_range_processing_time) = self.range_processing.snapshot();
        let (kernel_blocks, average_kernel_block_wait) = self.kernel_wait.snapshot();
        let (index_writes, average_index_write_time) = self.index_write.snapshot();
        let (forest_writes, average_forest_write_time) = self.forest_write.snapshot();
        BuildStatistics {
            ranges,
            average_range_lock_time,
            average_range_processing_time,
            kernel_blocks,
            average_kernel_block_wait,
            index_writes,
            average_index_write_time,
            forest_writes,
            average_forest_write_time,
            chaser_range_waits: self.chaser_range_waits.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
/// Read-only access to a completed flat forest file.
pub struct FlatForestReader {
    map: Mmap,
}

#[cfg(test)]
impl FlatForestReader {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open forest file {}", path.display()))?;
        let len = file
            .metadata()
            .context("failed to inspect forest file")?
            .len();
        if len == 0 || len % size_of::<ForestNode>() as u64 != 0 {
            bail!(
                "forest file length {len} is not a positive multiple of {}",
                size_of::<ForestNode>()
            );
        }
        let map = unsafe { MmapOptions::new().map(&file) }.context("failed to map forest file")?;
        Ok(Self { map })
    }

    pub fn node_count(&self) -> u64 {
        (self.map.len() / size_of::<ForestNode>()) as u64
    }

    pub fn read(&self, position: u64) -> Result<ForestNodeData> {
        if position >= self.node_count() {
            bail!("forest position {position} is outside the mapped file");
        }
        let node = unsafe {
            &*self
                .map
                .as_ptr()
                .add(position as usize * size_of::<ForestNode>())
                .cast::<ForestNode>()
        };
        read_ready_node(node).ok_or_else(|| anyhow!("forest position {position} is uninitialized"))
    }
}

struct FlatForest {
    map: MmapMut,
    file: File,
    path: PathBuf,
    node_count: u64,
    lock_pages: bool,
    pages_locked: bool,
}

#[derive(Clone, Copy)]
struct ResizeMarker {
    old_rows: u8,
    new_rows: u8,
    stage: u8,
}

fn resize_marker_path(forest_path: &Path) -> PathBuf {
    forest_path.with_extension("resize")
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .with_context(|| format!("failed to open directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", parent.display()))
}

fn read_resize_marker(forest_path: &Path) -> Result<Option<ResizeMarker>> {
    let marker_path = resize_marker_path(forest_path);
    let bytes = match std::fs::read(&marker_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", marker_path.display()));
        }
    };
    if bytes.len() != RESIZE_MARKER_LEN
        || &bytes[..RESIZE_MARKER_MAGIC.len()] != RESIZE_MARKER_MAGIC
    {
        bail!("invalid forest resize marker {}", marker_path.display());
    }
    let marker = ResizeMarker {
        old_rows: bytes[RESIZE_MARKER_MAGIC.len()],
        new_rows: bytes[RESIZE_MARKER_MAGIC.len() + 1],
        stage: bytes[RESIZE_MARKER_MAGIC.len() + 2],
    };
    if marker.new_rows <= marker.old_rows
        || !matches!(marker.stage, RESIZE_STAGE_COPYING | RESIZE_STAGE_CLEARING)
    {
        bail!("invalid forest resize state in {}", marker_path.display());
    }
    Ok(Some(marker))
}

fn write_resize_marker(forest_path: &Path, marker: ResizeMarker) -> Result<()> {
    let marker_path = resize_marker_path(forest_path);
    let mut bytes = Vec::with_capacity(RESIZE_MARKER_LEN);
    bytes.extend_from_slice(RESIZE_MARKER_MAGIC);
    bytes.extend_from_slice(&[marker.old_rows, marker.new_rows, marker.stage]);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker_path)
        .with_context(|| format!("failed to create {}", marker_path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to write {}", marker_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", marker_path.display()))?;
    sync_parent_directory(&marker_path)
}

fn update_resize_marker_stage(forest_path: &Path, stage: u8) -> Result<()> {
    let marker_path = resize_marker_path(forest_path);
    let file = OpenOptions::new()
        .write(true)
        .open(&marker_path)
        .with_context(|| format!("failed to open {}", marker_path.display()))?;
    FileExt::write_all_at(&file, &[stage], (RESIZE_MARKER_MAGIC.len() + 2) as u64)
        .with_context(|| format!("failed to update {}", marker_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", marker_path.display()))
}

fn forest_rows_from_node_count(node_count: u64) -> Result<u8> {
    let positional_size = node_count
        .checked_add(1)
        .context("forest position count overflow")?;
    if positional_size < 2 || !positional_size.is_power_of_two() {
        bail!("forest contains {node_count} nodes, not a complete positional space");
    }
    u8::try_from(positional_size.ilog2() - 1).context("forest height exceeds u8")
}

// Each position has exactly one writer. `ForestNode::flags` publishes the non-atomic hash bytes
// with release/acquire ordering before any other thread reads them.
unsafe impl Send for FlatForest {}
unsafe impl Sync for FlatForest {}

impl FlatForest {
    fn create(path: &Path, node_count: u64, lock_pages: bool) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            bail!("parallel flat-forest construction is supported only on Linux");
        }
        if node_count == 0 {
            bail!("cannot map an empty forest");
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create forest directory {}", parent.display())
            })?;
        }

        let resize_marker = resize_marker_path(path);
        match std::fs::remove_file(&resize_marker) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to remove stale forest resize marker {}",
                        resize_marker.display()
                    )
                });
            }
        }

        let byte_len = node_count
            .checked_mul(size_of::<ForestNode>() as u64)
            .context("forest file size overflow")?;
        let map_len =
            usize::try_from(byte_len).context("forest does not fit this address space")?;
        let fallocate_len = libc::off_t::try_from(byte_len)
            .context("forest file is too large for posix_fallocate")?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to create forest file {}", path.display()))?;
        file.set_len(byte_len)
            .context("failed to set forest file length")?;

        let allocation_result =
            unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, fallocate_len) };
        if allocation_result != 0 {
            return Err(std::io::Error::from_raw_os_error(allocation_result))
                .context("failed to preallocate forest file");
        }

        let map = unsafe { MmapOptions::new().len(map_len).map_mut(&file) }
            .context("failed to map forest file")?;
        let mut forest = Self {
            map,
            file,
            path: path.to_path_buf(),
            node_count,
            lock_pages,
            pages_locked: false,
        };
        forest.prepare_residency(lock_pages);
        Ok(forest)
    }

    fn open(path: &Path, lock_pages: bool) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            bail!("flat-forest steady state is supported only on Linux");
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open forest file {}", path.display()))?;
        let byte_len = file.metadata()?.len();
        if byte_len == 0 || byte_len % size_of::<ForestNode>() as u64 != 0 {
            bail!(
                "forest file {} has invalid byte length {byte_len}",
                path.display()
            );
        }
        let node_count = byte_len / size_of::<ForestNode>() as u64;
        let map_len =
            usize::try_from(byte_len).context("forest does not fit this address space")?;
        let map = unsafe { MmapOptions::new().len(map_len).map_mut(&file) }
            .with_context(|| format!("failed to map forest file {}", path.display()))?;
        let mut forest = Self {
            map,
            file,
            path: path.to_path_buf(),
            node_count,
            lock_pages,
            pages_locked: false,
        };
        forest.resume_resize_if_needed()?;
        forest.prepare_residency(lock_pages);
        Ok(forest)
    }

    fn resume_resize_if_needed(&mut self) -> Result<()> {
        let Some(marker) = read_resize_marker(&self.path)? else {
            return Ok(());
        };
        self.resume_resize(marker)
    }

    fn resize_to_rows(&mut self, new_rows: u8) -> Result<()> {
        self.resume_resize_if_needed()?;
        let old_rows = forest_rows_from_node_count(self.node_count)?;
        if new_rows <= old_rows {
            self.prepare_residency(self.lock_pages);
            return Ok(());
        }
        let marker = ResizeMarker {
            old_rows,
            new_rows,
            stage: RESIZE_STAGE_COPYING,
        };
        write_resize_marker(&self.path, marker)?;
        self.resume_resize(marker)?;
        self.prepare_residency(self.lock_pages);
        Ok(())
    }

    fn resume_resize(&mut self, mut marker: ResizeMarker) -> Result<()> {
        let old_node_count = forest_capacity(marker.old_rows)?;
        let new_node_count = forest_capacity(marker.new_rows)?;
        let valid_node_count = match marker.stage {
            RESIZE_STAGE_COPYING => {
                self.node_count == old_node_count || self.node_count == new_node_count
            }
            RESIZE_STAGE_CLEARING => self.node_count == new_node_count,
            _ => false,
        };
        if !valid_node_count {
            bail!(
                "forest resize {} -> {} rows at stage {} found unexpected node count {}",
                marker.old_rows,
                marker.new_rows,
                marker.stage,
                self.node_count
            );
        }

        if marker.stage == RESIZE_STAGE_COPYING {
            self.grow_mapping(old_node_count, new_node_count)?;
            self.copy_internal_rows(marker.old_rows, marker.new_rows)?;
            self.map
                .flush()
                .context("failed to flush relocated forest rows")?;
            self.file
                .sync_data()
                .context("failed to sync relocated forest rows")?;
            update_resize_marker_stage(&self.path, RESIZE_STAGE_CLEARING)?;
            marker.stage = RESIZE_STAGE_CLEARING;
        }

        if marker.stage == RESIZE_STAGE_CLEARING {
            self.clear_new_bottom_range(marker.old_rows, marker.new_rows)?;
            self.map.flush().context("failed to flush resized forest")?;
            self.file
                .sync_data()
                .context("failed to sync resized forest")?;
            let marker_path = resize_marker_path(&self.path);
            std::fs::remove_file(&marker_path)
                .with_context(|| format!("failed to remove {}", marker_path.display()))?;
            sync_parent_directory(&marker_path)?;
        }
        Ok(())
    }

    fn grow_mapping(&mut self, old_node_count: u64, new_node_count: u64) -> Result<()> {
        let node_size = size_of::<ForestNode>() as u64;
        let old_byte_len = old_node_count
            .checked_mul(node_size)
            .context("old forest file size overflow")?;
        let new_byte_len = new_node_count
            .checked_mul(node_size)
            .context("new forest file size overflow")?;
        let allocation_offset = libc::off_t::try_from(old_byte_len)
            .context("forest allocation offset exceeds off_t")?;
        let allocation_len = libc::off_t::try_from(new_byte_len - old_byte_len)
            .context("forest allocation length exceeds off_t")?;

        if self.node_count == old_node_count {
            self.map
                .flush()
                .context("failed to flush forest before resizing")?;
            self.file
                .set_len(new_byte_len)
                .context("failed to extend forest file")?;
        }
        let allocation_result = unsafe {
            libc::posix_fallocate(self.file.as_raw_fd(), allocation_offset, allocation_len)
        };
        if allocation_result != 0 {
            if self.node_count == old_node_count {
                let _ = self.file.set_len(old_byte_len);
            }
            return Err(std::io::Error::from_raw_os_error(allocation_result))
                .context("failed to preallocate forest resize");
        }
        if self.node_count == new_node_count {
            return Ok(());
        }

        self.unlock_pages();
        let map_len = usize::try_from(new_byte_len)
            .context("resized forest does not fit this address space")?;
        // The file is extended and preallocated above, and the forest mutex prevents references
        // into this mapping from surviving a move.
        unsafe { self.map.remap(map_len, RemapOptions::new().may_move(true)) }
            .context("failed to remap resized forest")?;
        self.node_count = new_node_count;
        Ok(())
    }

    fn copy_internal_rows(&mut self, old_rows: u8, new_rows: u8) -> Result<()> {
        let node_size = size_of::<ForestNode>();
        for row in 1..=old_rows {
            let node_count = 1u64 << (old_rows - row);
            let source = start_position_at_row(row, old_rows)?;
            let destination = start_position_at_row(row, new_rows)?;
            let source_byte = usize::try_from(source)
                .context("forest source position exceeds usize")?
                .checked_mul(node_size)
                .context("forest source byte offset overflow")?;
            let byte_len = usize::try_from(node_count)
                .context("forest row length exceeds usize")?
                .checked_mul(node_size)
                .context("forest row byte length overflow")?;
            let destination_byte = usize::try_from(destination)
                .context("forest destination position exceeds usize")?
                .checked_mul(node_size)
                .context("forest destination byte offset overflow")?;
            self.map
                .copy_within(source_byte..source_byte + byte_len, destination_byte);
        }
        Ok(())
    }

    fn clear_new_bottom_range(&mut self, old_rows: u8, new_rows: u8) -> Result<()> {
        let old_capacity = 1u64
            .checked_shl(u32::from(old_rows))
            .context("old forest bottom capacity overflow")?;
        let new_capacity = 1u64
            .checked_shl(u32::from(new_rows))
            .context("new forest bottom capacity overflow")?;
        let node_size = size_of::<ForestNode>() as u64;
        let byte_offset = old_capacity
            .checked_mul(node_size)
            .context("forest clear offset overflow")?;
        let byte_len = (new_capacity - old_capacity)
            .checked_mul(node_size)
            .context("forest clear length overflow")?;
        let offset =
            libc::off_t::try_from(byte_offset).context("forest clear offset exceeds off_t")?;
        let length =
            libc::off_t::try_from(byte_len).context("forest clear length exceeds off_t")?;
        let result = unsafe {
            libc::fallocate(
                self.file.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                offset,
                length,
            )
        };
        if result == 0 {
            let allocation_result =
                unsafe { libc::posix_fallocate(self.file.as_raw_fd(), offset, length) };
            if allocation_result != 0 {
                return Err(std::io::Error::from_raw_os_error(allocation_result))
                    .context("failed to reallocate resized forest bottom row");
            }
            return Ok(());
        }

        warn!(
            "could not punch old forest rows while resizing: {}; zeroing through the mapping",
            std::io::Error::last_os_error()
        );
        let start = usize::try_from(byte_offset).context("forest clear offset exceeds usize")?;
        let len = usize::try_from(byte_len).context("forest clear length exceeds usize")?;
        self.map[start..start + len].fill(0);
        Ok(())
    }

    fn unlock_pages(&mut self) {
        if !self.pages_locked {
            return;
        }
        if unsafe { libc::munlock(self.map.as_mut_ptr().cast::<libc::c_void>(), self.map.len()) }
            != 0
        {
            warn!(
                "failed to unlock forest pages before resizing: {}",
                std::io::Error::last_os_error()
            );
        }
        self.pages_locked = false;
    }

    fn prepare_residency(&mut self, lock_pages: bool) {
        let ptr = self.map.as_mut_ptr().cast::<libc::c_void>();
        let len = self.map.len();
        for advice in [libc::MADV_WILLNEED, libc::MADV_HUGEPAGE] {
            if unsafe { libc::madvise(ptr, len, advice) } != 0 {
                warn!(
                    "madvise({advice}) failed for the forest mapping: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        if !lock_pages {
            return;
        }

        let mut result = unsafe { libc::mlock2(ptr, len, libc::MLOCK_ONFAULT) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
                result = unsafe { libc::mlock(ptr, len) };
            }
        }
        if result == 0 {
            self.pages_locked = true;
        } else {
            warn!(
                "could not lock forest pages in RAM: {}; continuing with the Linux page cache",
                std::io::Error::last_os_error()
            );
        }
    }

    fn node(&self, position: u64) -> Result<&ForestNode> {
        if position >= self.node_count {
            bail!("forest position {position} is outside the mapped file");
        }
        Ok(unsafe {
            &*self
                .map
                .as_ptr()
                .add(position as usize * size_of::<ForestNode>())
                .cast::<ForestNode>()
        })
    }

    fn try_read(&self, position: u64) -> Result<Option<ForestNodeData>> {
        Ok(read_ready_node(self.node(position)?))
    }

    fn write(&self, position: u64, value: ForestNodeData) -> Result<()> {
        let node = self.node(position)?;
        node.flags
            .compare_exchange(0, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|flags| {
                anyhow!("forest position {position} already has flags {flags:#04x}")
            })?;
        unsafe {
            *node.hash.get() = value.hash;
        }
        let flags = READY | if value.spent { SPENT } else { 0 };
        node.flags.store(flags, Ordering::Release);
        Ok(())
    }

    fn journal_state(&self, position: u64) -> Result<JournalNodeState> {
        Ok(match self.try_read(position)? {
            Some(node) => JournalNodeState {
                ready: true,
                spent: node.spent,
                hash: node.hash,
            },
            None => JournalNodeState::UNINITIALIZED,
        })
    }

    fn set_journal_state(&self, position: u64, state: JournalNodeState) -> Result<()> {
        let node = self.node(position)?;
        node.flags.store(WRITING, Ordering::Release);
        unsafe {
            *node.hash.get() = state.hash;
        }
        let flags = if state.ready {
            READY | if state.spent { SPENT } else { 0 }
        } else {
            0
        };
        node.flags.store(flags, Ordering::Release);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.map.flush().context("failed to flush completed forest")
    }
}

impl Drop for FlatForest {
    fn drop(&mut self) {
        if self.pages_locked
            && unsafe {
                libc::munlock(self.map.as_mut_ptr().cast::<libc::c_void>(), self.map.len())
            } != 0
        {
            warn!(
                "failed to unlock forest pages: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn read_ready_node(node: &ForestNode) -> Option<ForestNodeData> {
    let flags = node.flags.load(Ordering::Acquire);
    if flags & READY == 0 {
        return None;
    }
    Some(ForestNodeData {
        hash: unsafe { *node.hash.get() },
        spent: flags & SPENT != 0,
    })
}

struct Availability {
    epoch: Mutex<u64>,
    changed: Condvar,
    aborted: AtomicBool,
}

impl Availability {
    fn new() -> Self {
        Self {
            epoch: Mutex::new(0),
            changed: Condvar::new(),
            aborted: AtomicBool::new(false),
        }
    }

    fn publish(&self) -> Result<()> {
        let mut epoch = self
            .epoch
            .lock()
            .map_err(|_| anyhow!("forest availability mutex poisoned"))?;
        *epoch = epoch.wrapping_add(1);
        self.changed.notify_all();
        Ok(())
    }

    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        if let Ok(mut epoch) = self.epoch.lock() {
            *epoch = epoch.wrapping_add(1);
            self.changed.notify_all();
        }
    }

    fn read_when_ready(
        &self,
        forest: &FlatForest,
        position: u64,
        spin_iterations: usize,
    ) -> Result<(ForestNodeData, bool)> {
        let mut waited = false;
        for _ in 0..spin_iterations {
            if let Some(node) = forest.try_read(position)? {
                return Ok((node, waited));
            }
            waited = true;
            if self.aborted.load(Ordering::Acquire) {
                bail!("forest construction aborted while waiting for position {position}");
            }
            std::hint::spin_loop();
        }

        let mut epoch = self
            .epoch
            .lock()
            .map_err(|_| anyhow!("forest availability mutex poisoned"))?;
        loop {
            if let Some(node) = forest.try_read(position)? {
                return Ok((node, waited));
            }
            waited = true;
            if self.aborted.load(Ordering::Acquire) {
                bail!("forest construction aborted while waiting for position {position}");
            }
            let observed = *epoch;
            epoch = self
                .changed
                .wait_while(epoch, |current| {
                    *current == observed && !self.aborted.load(Ordering::Acquire)
                })
                .map_err(|_| anyhow!("forest availability mutex poisoned"))?;
        }
    }
}

struct BlockVisitResult {
    leaves: u64,
    kernel_wait: Duration,
    header: [u8; 80],
    block_hash: [u8; 32],
}

trait BlockSource: Sync {
    fn visit_leaf_outputs(
        &self,
        height: u32,
        visitor: &mut dyn FnMut(LeafOutput<'_>) -> Result<()>,
    ) -> Result<BlockVisitResult>;
    fn header(&self, height: u32) -> Result<([u8; 80], [u8; 32])>;
}

pub struct KernelBlockSource {
    // Fields drop in declaration order; the manager must be destroyed before its context.
    manager: ChainstateManager,
    _context: KernelContext,
    tip_height: u32,
}

impl KernelBlockSource {
    pub fn open(network: Network) -> Result<Self> {
        let home = env::var("HOME").context("HOME is required to locate Bitcoin Core data")?;
        let bitcoin_data_dir = PathBuf::from(home).join(".bitcoin");
        let network_data_dir = match network {
            Network::Bitcoin => bitcoin_data_dir,
            Network::Testnet => bitcoin_data_dir.join("testnet3"),
            Network::Testnet4 => bitcoin_data_dir.join("testnet4"),
            Network::Signet => bitcoin_data_dir.join("signet"),
            Network::Regtest => bitcoin_data_dir.join("regtest"),
            _ => bail!("unsupported Bitcoin network {network}"),
        };
        let blocks_dir = network_data_dir.join("blocks");
        if !blocks_dir.is_dir() {
            bail!(
                "Bitcoin Core blocks directory {} does not exist",
                blocks_dir.display()
            );
        }
        let chain_type = match network {
            Network::Bitcoin => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Testnet4 => ChainType::Testnet4,
            Network::Signet => ChainType::Signet,
            Network::Regtest => ChainType::Regtest,
            _ => bail!("unsupported Bitcoin network {network}"),
        };
        let context = ContextBuilder::new()
            .chain_type(chain_type)
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
        info!(
            "Opened Bitcoin Core kernel chain at height={} hash={}",
            tip_height,
            chain.tip().block_hash()
        );
        Ok(Self {
            manager,
            _context: context,
            tip_height,
        })
    }

    pub fn tip_height(&self) -> u32 {
        self.tip_height
    }

    fn block_at_height(&self, height: u32) -> Result<KernelBlock> {
        if height > self.tip_height {
            bail!(
                "requested height {height} exceeds kernel tip {}",
                self.tip_height
            );
        }
        let chain = self.manager.active_chain();
        let entry = chain
            .at_height(height as usize)
            .ok_or_else(|| anyhow!("kernel active chain has no block at height {height}"))?;
        self.manager
            .read_block_data(&entry)
            .with_context(|| format!("failed to read block data at height {height}"))
    }
}

impl BlockSource for KernelBlockSource {
    fn visit_leaf_outputs(
        &self,
        height: u32,
        visitor: &mut dyn FnMut(LeafOutput<'_>) -> Result<()>,
    ) -> Result<BlockVisitResult> {
        let started = Instant::now();
        let block = self.block_at_height(height)?;
        let kernel_wait = started.elapsed();
        let header = block.header();
        let header_bytes = header.consensus_encode()?;
        let block_hash = header.hash().to_bytes();
        let leaves = visit_kernel_leaf_outputs(height, &block, visitor)?;
        Ok(BlockVisitResult {
            leaves,
            kernel_wait,
            header: header_bytes,
            block_hash,
        })
    }

    fn header(&self, height: u32) -> Result<([u8; 80], [u8; 32])> {
        let block = self.block_at_height(height)?;
        let header = block.header();
        Ok((header.consensus_encode()?, header.hash().to_bytes()))
    }
}

trait Hints: Sync {
    fn stop_height(&self) -> u32;
    fn leaf_count_at_height(&self, height: u32) -> Option<u32>;
    fn indices_at_height(&self, height: u32) -> Option<Vec<u32>>;
}

impl Hints for BridgeHints {
    fn stop_height(&self) -> u32 {
        BridgeHints::stop_height(self)
    }

    fn leaf_count_at_height(&self, height: u32) -> Option<u32> {
        BridgeHints::leaf_count_at_height(self, height)
    }

    fn indices_at_height(&self, height: u32) -> Option<Vec<u32>> {
        BridgeHints::indices_at_height(self, height)
    }
}

const LEAF_MAP_KEY_SIZE: usize = 36;
const LEAF_MAP_VALUE_SIZE: usize = size_of::<u64>();
const LEAF_MAP_BLOCK_SIZE: u64 = 1 << 20;

fn aligned_leaf_map_capacity(leaves: u64, bytes_per_leaf: u64) -> Result<u64> {
    leaves
        .checked_mul(bytes_per_leaf)
        .context("leaf map capacity overflow")
        .map(|bytes| bytes.max(LEAF_MAP_BLOCK_SIZE))
        .and_then(|bytes| {
            bytes
                .div_ceil(LEAF_MAP_BLOCK_SIZE)
                .checked_mul(LEAF_MAP_BLOCK_SIZE)
                .context("leaf map capacity overflow")
        })
}

fn create_leaf_map(path: &Path, leaves: u64, leaf_workers: usize) -> Result<Database> {
    if path.exists() {
        bail!(
            "leaf map path {} already exists; remove it before rebuilding",
            path.display()
        );
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create leaf map directory {}", parent.display()))?;
    }
    let desired_buckets = leaves.div_ceil(4).max(1_024);
    let bucket_count = desired_buckets
        .checked_next_power_of_two()
        .context("leaf map bucket count overflow")?;
    let max_threads = u16::try_from(leaf_workers.max(1))
        .context("leaf worker count exceeds leaf map thread limit")?;
    let mut config = LeafMapConfig::new(Mode::Map, bucket_count, LEAF_MAP_KEY_SIZE);
    config.inline_value_size = LEAF_MAP_VALUE_SIZE;
    config.body_capacity = aligned_leaf_map_capacity(leaves, 96)?
        .checked_add(STEADY_LEAF_MAP_HEADROOM)
        .context("leaf map steady-state reserve overflow")?;
    config.blob_capacity = 0;
    config.block_size = LEAF_MAP_BLOCK_SIZE;
    config.max_threads = max_threads;
    Database::create(path, config)
        .with_context(|| format!("failed to create leaf map {}", path.display()))
}

fn leaf_map_key(txid: [u8; 32], vout: u32) -> [u8; LEAF_MAP_KEY_SIZE] {
    let mut key = [0u8; LEAF_MAP_KEY_SIZE];
    key[..32].copy_from_slice(&txid);
    key[32..].copy_from_slice(&vout.to_le_bytes());
    key
}

/// A single-threaded mutable view of a completed flat-forest bootstrap.
pub struct SteadyStateForest {
    forest: FlatForest,
    leaf_map: Database,
    leaves: u64,
    forest_rows: u8,
}

struct PlannedNode {
    before: JournalNodeState,
    after: ForestNodeData,
}

impl SteadyStateForest {
    pub fn open(forest_path: &Path, leaf_map_path: &Path, lock_pages: bool) -> Result<Self> {
        let forest = FlatForest::open(forest_path, lock_pages)?;
        let forest_rows = forest_rows_from_node_count(forest.node_count)?;
        let bottom_capacity = 1u64
            .checked_shl(u32::from(forest_rows))
            .context("forest bottom capacity overflow")?;

        // Bootstrap writes every bottom node before `leaves` and leaves the rest zeroed, so the
        // exact count can be recovered without rescanning blocks or adding a file header.
        let mut first = 0u64;
        let mut end = bottom_capacity;
        while first < end {
            let middle = first + (end - first) / 2;
            if forest.try_read(middle)?.is_some() {
                first = middle + 1;
            } else {
                end = middle;
            }
        }
        if first == 0 {
            bail!("flat forest has no initialized leaves");
        }

        if Database::ensure_runtime_body_headroom(leaf_map_path, STEADY_LEAF_MAP_HEADROOM)
            .with_context(|| format!("failed to grow leaf map {}", leaf_map_path.display()))?
        {
            info!(
                "extended leaf map {} with {} bytes of steady-state headroom",
                leaf_map_path.display(),
                STEADY_LEAF_MAP_HEADROOM
            );
        }
        let leaf_map = Database::open_runtime(leaf_map_path)
            .with_context(|| format!("failed to open leaf map {}", leaf_map_path.display()))?;
        Ok(Self {
            forest,
            leaf_map,
            leaves: first,
            forest_rows,
        })
    }

    pub fn leaves(&self) -> u64 {
        self.leaves
    }
    pub(crate) fn forest_rows(&self) -> u8 {
        self.forest_rows
    }

    pub(crate) fn leaf_capacity(&self) -> Result<u64> {
        1u64.checked_shl(u32::from(self.forest_rows))
            .context("forest bottom capacity overflow")
    }

    pub(crate) fn ensure_leaf_capacity(&mut self, required_leaves: u64) -> Result<bool> {
        let current_capacity = self.leaf_capacity()?;
        if required_leaves <= current_capacity {
            return Ok(false);
        }
        let new_rows = tree_rows(required_leaves);
        let new_capacity = 1u64
            .checked_shl(u32::from(new_rows))
            .context("resized forest bottom capacity overflow")?;
        info!(
            "Growing flat forest online: rows={} -> {new_rows} leaf_capacity={current_capacity} -> {new_capacity}",
            self.forest_rows
        );
        self.forest.resize_to_rows(new_rows)?;
        self.forest_rows = new_rows;
        Ok(true)
    }

    pub fn roots(&self) -> Result<Vec<BitcoinNodeHash>> {
        let mut roots = Vec::with_capacity(self.leaves.count_ones() as usize);
        for row in (0..=self.forest_rows).rev() {
            if self.leaves & (1u64 << row) == 0 {
                continue;
            }
            let position = root_position(self.leaves, row, self.forest_rows);
            let node = self
                .forest
                .try_read(position)?
                .ok_or_else(|| anyhow!("root position {position} is uninitialized"))?;
            roots.push(accumulator_hash(node));
        }
        Ok(roots)
    }

    /// Returns the stable bottom-row position stored for an outpoint.
    pub fn leaf_position(&self, outpoint: &OutPoint) -> Result<u64> {
        let key = leaf_map_key(outpoint.txid.to_byte_array(), outpoint.vout);
        let value = self
            .leaf_map
            .get(&key)
            .context("failed to query leaf map")?
            .ok_or_else(|| anyhow!("outpoint {outpoint} is not in the leaf map"))?;
        let value: [u8; LEAF_MAP_VALUE_SIZE] = value
            .try_into()
            .map_err(|value: Vec<u8>| anyhow!("leaf position has {} bytes", value.len()))?;
        let position = u64::from_le_bytes(value);
        if position >= self.leaves {
            bail!(
                "outpoint {outpoint} maps to position {position} beyond {} leaves",
                self.leaves
            );
        }
        let node = self
            .forest
            .try_read(position)?
            .ok_or_else(|| anyhow!("leaf position {position} is uninitialized"))?;
        if node.spent {
            bail!("outpoint {outpoint} maps to spent position {position}");
        }
        Ok(position)
    }

    pub(crate) fn repair_leaf_position(&self, outpoint: &OutPoint, position: u64) -> Result<()> {
        if position >= self.leaves {
            bail!(
                "cannot map {outpoint} to position {position} beyond {} leaves",
                self.leaves
            );
        }
        let key = leaf_map_key(outpoint.txid.to_byte_array(), outpoint.vout);
        self.leaf_map.put(&key, &position.to_le_bytes())?;
        self.leaf_map
            .sync()
            .context("failed to sync repaired leaf map")
    }
    pub(crate) fn recover_leaf_position_from_block(
        &self,
        target: OutPoint,
        target_hash: BitcoinNodeHash,
        block_leaves: &[(OutPoint, BitcoinNodeHash)],
    ) -> Result<u64> {
        let target_index = block_leaves
            .iter()
            .position(|(outpoint, _)| *outpoint == target)
            .map(|index| index as u64)
            .ok_or_else(|| anyhow!("outpoint {target} is not an eligible leaf in its block"))?;

        let mut block_start = None;
        for (local_index, (outpoint, leaf_hash)) in block_leaves.iter().enumerate() {
            let Ok(position) = self.leaf_position(outpoint) else {
                continue;
            };
            if self.leaf_hash(position).ok().as_ref() != Some(leaf_hash) {
                continue;
            }
            let Some(start) = position.checked_sub(local_index as u64) else {
                continue;
            };
            match block_start {
                Some(previous) if previous != start => {
                    block_start = None;
                    break;
                }
                None => block_start = Some(start),
                _ => {}
            }
        }

        if let Some(block_start) = block_start {
            let position = block_start
                .checked_add(target_index)
                .context("recovered leaf position overflow")?;
            if self
                .forest
                .try_read(position)?
                .is_some_and(|node| !node.spent && node.hash == *target_hash)
            {
                return Ok(position);
            }
        }

        for position in 0..self.leaves {
            let Some(node) = self.forest.try_read(position)? else {
                continue;
            };
            if !node.spent && node.hash == *target_hash {
                return Ok(position);
            }
        }
        bail!(
            "could not recover outpoint {target} from its {}-leaf block range",
            block_leaves.len()
        )
    }

    pub fn leaf_hash(&self, bottom_position: u64) -> Result<BitcoinNodeHash> {
        let node = self
            .forest
            .try_read(bottom_position)?
            .ok_or_else(|| anyhow!("leaf position {bottom_position} is uninitialized"))?;
        if node.spent {
            bail!("leaf position {bottom_position} is spent");
        }
        Ok(BitcoinNodeHash::from(node.hash))
    }

    /// Converts a stable bottom position into its position in the promoted, sparse forest.
    pub fn proof_position(&self, bottom_position: u64) -> Result<u64> {
        self.proof_position_with_overlay(bottom_position, self.leaves, &AHashMap::new())
    }

    pub(crate) fn proof_position_with_overlay(
        &self,
        bottom_position: u64,
        leaves: u64,
        overlay: &AHashMap<u64, JournalNodeState>,
    ) -> Result<u64> {
        let mut original_position = bottom_position;
        let mut branch_directions = Vec::new();
        while !is_root_position(original_position, leaves, self.forest_rows) {
            let sibling_position = original_position ^ 1;
            let sibling = self.read_with_overlay(sibling_position, overlay)?;
            if !sibling.spent {
                branch_directions.push(original_position & 1 != 0);
            }
            original_position = parent(original_position, self.forest_rows);
        }

        // Preallocated storage rows are not part of the Utreexo proof coordinate system. Convert
        // the physical root and descent to the canonical row count implied by numleaves.
        let root_row = detect_row(original_position, self.forest_rows);
        let logical_rows = tree_rows(leaves);
        let mut promoted_position = root_position(leaves, root_row, logical_rows);
        for is_right in branch_directions.into_iter().rev() {
            promoted_position = left_child(promoted_position, logical_rows) + u64::from(is_right);
        }
        Ok(promoted_position)
    }

    fn read_with_overlay(
        &self,
        position: u64,
        overlay: &AHashMap<u64, JournalNodeState>,
    ) -> Result<ForestNodeData> {
        if let Some(state) = overlay.get(&position) {
            if !state.ready {
                bail!("forest position {position} is uninitialized");
            }
            return Ok(ForestNodeData {
                hash: state.hash,
                spent: state.spent,
            });
        }
        self.forest
            .try_read(position)?
            .ok_or_else(|| anyhow!("forest position {position} is uninitialized"))
    }

    fn containing_root(&self, position: u64, leaves: u64) -> Result<(u64, u8)> {
        let position_row = detect_row(position, self.forest_rows);
        for root_row in position_row..=self.forest_rows {
            if leaves & (1u64 << root_row) == 0 {
                continue;
            }
            let mut ancestor = position;
            for _ in position_row..root_row {
                ancestor = parent(ancestor, self.forest_rows);
            }
            let root = root_position(leaves, root_row, self.forest_rows);
            if ancestor == root {
                return Ok((root, root_row));
            }
        }
        bail!("position {position} is not below a populated root")
    }

    // Proof positions use the canonical row count; storage positions use the preallocated
    // capacity. Row-local offsets are stable between the two layouts.
    fn compressed_hash(
        &self,
        position: u64,
        logical_rows: u8,
        leaves: u64,
        overlay: &AHashMap<u64, JournalNodeState>,
    ) -> Result<BitcoinNodeHash> {
        let position = translate_position(position, logical_rows, self.forest_rows)?;
        let (root, mut original_row) = self.containing_root(position, leaves)?;
        let mut directions = Vec::new();
        let mut logical_position = position;
        while logical_position != root {
            directions.push(logical_position & 1 != 0);
            logical_position = parent(logical_position, self.forest_rows);
        }

        let mut original_position = root;
        for is_right in directions.into_iter().rev() {
            loop {
                if original_row == 0 {
                    bail!("compressed position {position} descends below the bottom row");
                }
                let left_position = left_child(original_position, self.forest_rows);
                let left = self.read_with_overlay(left_position, overlay)?;
                let right = self.read_with_overlay(left_position + 1, overlay)?;
                original_row -= 1;
                match (left.spent, right.spent) {
                    (true, true) => {
                        bail!("compressed position {position} enters a fully spent subtree")
                    }
                    (true, false) => original_position = left_position + 1,
                    (false, true) => original_position = left_position,
                    (false, false) => {
                        original_position = left_position + u64::from(is_right);
                        break;
                    }
                }
            }
        }

        let node = self.read_with_overlay(original_position, overlay)?;
        if node.spent {
            bail!("compressed position {position} resolves to an empty subtree");
        }
        Ok(BitcoinNodeHash::from(node.hash))
    }

    #[cfg(test)]
    pub fn prove(&self, targets: &[u64]) -> Result<Proof<BitcoinNodeHash>> {
        let logical_rows = tree_rows(self.leaves);
        let overlay = AHashMap::new();
        let hashes = get_proof_positions(targets, self.leaves, logical_rows)
            .into_iter()
            .map(|position| self.compressed_hash(position, logical_rows, self.leaves, &overlay))
            .collect::<Result<Vec<_>>>()?;
        let targets = targets
            .iter()
            .map(|position| translate_position(*position, logical_rows, 63))
            .collect::<Result<Vec<_>>>()?;
        Ok(Proof::new_with_hash(targets, hashes))
    }

    pub(crate) fn position_hash(&self, position: u64) -> Result<BitcoinNodeHash> {
        self.position_hash_with_overlay(position, self.leaves, &AHashMap::new())
    }

    pub(crate) fn position_hash_with_overlay(
        &self,
        position: u64,
        leaves: u64,
        overlay: &AHashMap<u64, JournalNodeState>,
    ) -> Result<BitcoinNodeHash> {
        self.compressed_hash(position, tree_rows(leaves), leaves, overlay)
    }

    fn staged_read(
        forest: &FlatForest,
        overlay: &AHashMap<u64, JournalNodeState>,
        nodes: &AHashMap<u64, PlannedNode>,
        position: u64,
    ) -> Result<ForestNodeData> {
        if let Some(node) = nodes.get(&position) {
            return Ok(node.after);
        }
        if let Some(state) = overlay.get(&position) {
            if !state.ready {
                bail!("forest position {position} is uninitialized");
            }
            return Ok(ForestNodeData {
                hash: state.hash,
                spent: state.spent,
            });
        }
        forest
            .try_read(position)?
            .ok_or_else(|| anyhow!("forest position {position} is uninitialized"))
    }

    fn stage_node(
        forest: &FlatForest,
        overlay: &AHashMap<u64, JournalNodeState>,
        nodes: &mut AHashMap<u64, PlannedNode>,
        position: u64,
        after: ForestNodeData,
    ) -> Result<()> {
        match nodes.entry(position) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().after = after;
            }
            Entry::Vacant(entry) => {
                let before = overlay
                    .get(&position)
                    .copied()
                    .map(Ok)
                    .unwrap_or_else(|| forest.journal_state(position))?;
                entry.insert(PlannedNode { before, after });
            }
        }
        Ok(())
    }

    /// Computes a complete block mutation without writing the forest or leaf map.
    #[cfg(test)]
    pub(crate) fn plan_update(
        &mut self,
        height: u32,
        block_hash: BlockHash,
        previous_block_hash: BlockHash,
        deletions: &[(OutPoint, u64)],
        additions: &[(OutPoint, BitcoinNodeHash)],
    ) -> Result<JournalEntry> {
        let required_leaves = self
            .leaves
            .checked_add(additions.len() as u64)
            .context("leaf count overflow")?;
        self.ensure_leaf_capacity(required_leaves)?;
        self.plan_update_without_resize(
            height,
            block_hash,
            previous_block_hash,
            deletions,
            additions,
        )
    }

    ///
    /// Deletion positions must come from this forest's leaf map in the same serialized update.
    pub(crate) fn plan_update_without_resize(
        &self,
        height: u32,
        block_hash: BlockHash,
        previous_block_hash: BlockHash,
        deletions: &[(OutPoint, u64)],
        additions: &[(OutPoint, BitcoinNodeHash)],
    ) -> Result<JournalEntry> {
        self.plan_update_with_overlay(
            height,
            block_hash,
            previous_block_hash,
            self.leaves,
            &AHashMap::new(),
            deletions,
            additions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_update_with_overlay(
        &self,
        height: u32,
        block_hash: BlockHash,
        previous_block_hash: BlockHash,
        base_leaves: u64,
        overlay: &AHashMap<u64, JournalNodeState>,
        deletions: &[(OutPoint, u64)],
        additions: &[(OutPoint, BitcoinNodeHash)],
    ) -> Result<JournalEntry> {
        let bottom_capacity = 1u64
            .checked_shl(u32::from(self.forest_rows))
            .context("forest bottom capacity overflow")?;
        let final_leaves = base_leaves
            .checked_add(additions.len() as u64)
            .context("leaf count overflow")?;
        if final_leaves > bottom_capacity {
            bail!("flat forest capacity {bottom_capacity} is exhausted by {final_leaves} leaves");
        }

        let estimated_nodes = deletions
            .len()
            .saturating_mul(usize::from(self.forest_rows) + 1)
            .saturating_add(additions.len().saturating_mul(2));
        let mut nodes = AHashMap::with_capacity(estimated_nodes);
        let mut positions = AHashSet::with_capacity(deletions.len());
        let mut removed = Vec::with_capacity(deletions.len());
        for (outpoint, position) in deletions {
            let node = Self::staged_read(&self.forest, overlay, &nodes, *position)?;
            Self::stage_node(
                &self.forest,
                overlay,
                &mut nodes,
                *position,
                ForestNodeData {
                    hash: node.hash,
                    spent: true,
                },
            )?;
            positions.insert(*position);
            removed.push(JournalIndexDelta {
                outpoint: *outpoint,
                position: *position,
            });
        }

        let forest = &self.forest;
        let forest_rows = self.forest_rows;
        while !positions.is_empty() {
            let mut parents: Vec<u64> = positions
                .iter()
                .filter(|position| !is_root_position(**position, base_leaves, forest_rows))
                .map(|position| parent(*position, forest_rows))
                .collect::<AHashSet<_>>()
                .into_iter()
                .collect();
            parents.sort_unstable();
            let staged_parents = if parents.len() >= MIN_PARALLEL_PLANNING_NODES {
                parents
                    .par_iter()
                    .map(|parent_position| {
                        let left_position = left_child(*parent_position, forest_rows);
                        let result = Self::staged_read(forest, overlay, &nodes, left_position)
                            .and_then(|left| {
                                Self::staged_read(forest, overlay, &nodes, left_position + 1)
                                    .map(|right| combine_children(left, right))
                            });
                        (*parent_position, result)
                    })
                    .collect::<Vec<_>>()
            } else {
                parents
                    .iter()
                    .map(|parent_position| {
                        let left_position = left_child(*parent_position, forest_rows);
                        let result = Self::staged_read(forest, overlay, &nodes, left_position)
                            .and_then(|left| {
                                Self::staged_read(forest, overlay, &nodes, left_position + 1)
                                    .map(|right| combine_children(left, right))
                            });
                        (*parent_position, result)
                    })
                    .collect::<Vec<_>>()
            };
            for (parent_position, after) in staged_parents {
                Self::stage_node(&self.forest, overlay, &mut nodes, parent_position, after?)?;
            }
            positions = parents.into_iter().collect();
        }

        let mut leaves = base_leaves;
        let mut added = Vec::with_capacity(additions.len());
        for (outpoint, hash) in additions {
            let bottom_position = leaves;
            Self::stage_node(
                &self.forest,
                overlay,
                &mut nodes,
                bottom_position,
                ForestNodeData {
                    hash: **hash,
                    spent: false,
                },
            )?;
            let mut position = bottom_position;
            let mut row = 0u8;
            while leaves & (1u64 << row) != 0 {
                let left_position = root_position(leaves, row, self.forest_rows);
                let left = Self::staged_read(&self.forest, overlay, &nodes, left_position)?;
                let right = Self::staged_read(&self.forest, overlay, &nodes, position)?;
                position = parent(position, self.forest_rows);
                Self::stage_node(
                    &self.forest,
                    overlay,
                    &mut nodes,
                    position,
                    combine_children(left, right),
                )?;
                row += 1;
            }
            added.push(JournalIndexDelta {
                outpoint: *outpoint,
                position: bottom_position,
            });
            leaves += 1;
        }

        let mut forest = nodes
            .into_iter()
            .map(|(position, node)| JournalForestDelta {
                position,
                before: node.before,
                after: JournalNodeState {
                    ready: true,
                    spent: node.after.spent,
                    hash: node.after.hash,
                },
            })
            .collect::<Vec<_>>();
        forest.sort_unstable_by_key(|delta| delta.position);
        Ok(JournalEntry {
            height,
            block_hash,
            num_leaves: leaves,
            previous_block_hash,
            forest,
            removed,
            added,
        })
    }

    pub fn roots_after(&self, entry: &JournalEntry) -> Result<Vec<BitcoinNodeHash>> {
        self.roots_after_with_overlay(entry, self.leaves, &AHashMap::new())
    }

    pub(crate) fn roots_after_with_overlay(
        &self,
        entry: &JournalEntry,
        base_leaves: u64,
        overlay: &AHashMap<u64, JournalNodeState>,
    ) -> Result<Vec<BitcoinNodeHash>> {
        if entry.previous_num_leaves()? != base_leaves {
            bail!(
                "planned update begins with {} leaves, planner has {base_leaves}",
                entry.previous_num_leaves()?
            );
        }
        let changed: AHashMap<u64, JournalNodeState> = entry
            .forest
            .iter()
            .map(|delta| (delta.position, delta.after))
            .collect();
        let mut roots = Vec::with_capacity(entry.num_leaves.count_ones() as usize);
        for row in (0..=self.forest_rows).rev() {
            if entry.num_leaves & (1u64 << row) == 0 {
                continue;
            }
            let position = root_position(entry.num_leaves, row, self.forest_rows);
            let state = match changed.get(&position).or_else(|| overlay.get(&position)) {
                Some(state) => *state,
                None => self.forest.journal_state(position)?,
            };
            if !state.ready {
                bail!("planned root position {position} is uninitialized");
            }
            roots.push(accumulator_hash(ForestNodeData {
                hash: state.hash,
                spent: state.spent,
            }));
        }
        Ok(roots)
    }

    pub fn apply_forward(&mut self, entry: &JournalEntry) -> Result<()> {
        for delta in &entry.forest {
            self.forest.set_journal_state(delta.position, delta.after)?;
        }
        for delta in &entry.removed {
            let key = leaf_map_key(delta.outpoint.txid.to_byte_array(), delta.outpoint.vout);
            self.leaf_map.delete(&key)?;
        }
        for delta in &entry.added {
            let key = leaf_map_key(delta.outpoint.txid.to_byte_array(), delta.outpoint.vout);
            self.leaf_map.put(&key, &delta.position.to_le_bytes())?;
        }
        self.leaves = entry.num_leaves;
        Ok(())
    }

    pub fn apply_backward(&mut self, entry: &JournalEntry) -> Result<()> {
        for delta in entry.forest.iter().rev() {
            self.forest
                .set_journal_state(delta.position, delta.before)?;
        }
        for delta in &entry.added {
            let key = leaf_map_key(delta.outpoint.txid.to_byte_array(), delta.outpoint.vout);
            self.leaf_map.delete(&key)?;
        }
        for delta in &entry.removed {
            let key = leaf_map_key(delta.outpoint.txid.to_byte_array(), delta.outpoint.vout);
            self.leaf_map.put(&key, &delta.position.to_le_bytes())?;
        }
        self.leaves = entry.previous_num_leaves()?;
        Ok(())
    }

    pub fn replay_journal(&mut self, journal: &ForestJournal) -> Result<()> {
        for record in journal.records().iter().rev() {
            self.apply_backward(&record.entry)?;
        }
        for record in journal.records() {
            if record.status == crate::forest_journal::JournalStatus::Forward {
                self.apply_forward(&record.entry)?;
            }
        }
        if !journal.records().is_empty() {
            self.sync()?;
        }
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        self.forest.flush()?;
        self.leaf_map.sync().context("failed to sync leaf map")
    }
}

/// Build and persist a complete flat forest through the hintsfile's stop height.
pub fn build_parallel_forest(
    source: &KernelBlockSource,
    hints: &BridgeHints,
    config: ParallelForestConfig,
) -> Result<ForestBuildSummary> {
    if hints.stop_height() > source.tip_height() {
        bail!(
            "hints stop height {} exceeds kernel tip {}",
            hints.stop_height(),
            source.tip_height()
        );
    }
    build_with_source(source, hints, config)
}

fn build_with_source<S: BlockSource, H: Hints>(
    source: &S,
    hints: &H,
    config: ParallelForestConfig,
) -> Result<ForestBuildSummary> {
    validate_config(&config)?;
    let stop_height = hints.stop_height();
    if stop_height == 0 {
        bail!("hintsfile stop height must be greater than zero");
    }

    let stats = Arc::new(BuildStats::default());
    let leaf_count_capacity =
        usize::try_from(stop_height).context("hints stop height exceeds usize")?;
    let mut leaf_counts = Vec::with_capacity(leaf_count_capacity);
    for height in 1..=stop_height {
        let count = hints
            .leaf_count_at_height(height)
            .ok_or_else(|| anyhow!("leaf count unavailable at height {height}"))?;
        leaf_counts.push(u64::from(count));
    }
    let mut leaf_offsets = Vec::with_capacity(leaf_counts.len());
    let mut leaves = 0u64;
    for count in &leaf_counts {
        leaf_offsets.push(leaves);
        leaves = leaves
            .checked_add(*count)
            .context("total leaf count overflow")?;
    }
    if leaves == 0 {
        bail!("no Utreexo leaves found through height {stop_height}");
    }
    let live_leaves = count_hinted_leaves(hints, stop_height, config.leaf_workers)?;

    let capacity_leaves = config.minimum_leaf_capacity.unwrap_or(leaves);
    if capacity_leaves < leaves {
        bail!("configured forest capacity {capacity_leaves} is below {leaves} bootstrap leaves");
    }
    let forest_rows = tree_rows(capacity_leaves);
    let file_nodes = forest_capacity(forest_rows)?;
    let leaf_map = Arc::new(create_leaf_map(
        &config.leaf_map_path,
        live_leaves,
        config.leaf_workers,
    )?);
    let header_index = Arc::new(HeaderIndex::create(
        &config.header_file_path,
        &config.header_index_path,
        stop_height,
        config.leaf_workers,
    )?);
    {
        let writer = header_index.build_writer()?;
        let (header, block_hash) = source.header(0)?;
        writer.put(0, header, block_hash)?;
    }
    let forest = Arc::new(FlatForest::create(
        &config.forest_path,
        file_nodes,
        config.lock_pages,
    )?);
    let leaf_map_entries = Arc::new(AtomicU64::new(0));
    let availability = Arc::new(Availability::new());

    info!(
        "building {leaves} leaves ({live_leaves} indexed) with {} leaf workers and {} chaser workers",
        config.leaf_workers, config.chaser_workers
    );
    run_builders(
        source,
        hints,
        stop_height,
        &leaf_counts,
        &leaf_offsets,
        leaves,
        forest_rows,
        &config,
        &forest,
        &availability,
        &leaf_map,
        &leaf_map_entries,
        &header_index,
        &stats,
    )?;

    let (initialized_nodes, roots) = validate_forest(&forest, leaves, forest_rows)?;
    let pages_locked = forest.pages_locked;
    forest.flush()?;
    drop(forest);
    let leaf_map_entries = leaf_map_entries.load(Ordering::Relaxed);
    if leaf_map_entries != live_leaves {
        bail!("leaf map entry mismatch: expected {live_leaves}, indexed {leaf_map_entries}");
    }
    let leaf_map =
        Arc::try_unwrap(leaf_map).map_err(|_| anyhow!("leaf map still has active writers"))?;
    leaf_map.close().context("failed to close leaf map")?;
    info!("closed {leaf_map_entries} leaf positions without checkpointing");
    let header_index = Arc::try_unwrap(header_index)
        .map_err(|_| anyhow!("header index still has active writers"))?;
    header_index
        .close()
        .context("failed to close header index")?;
    let statistics = stats.snapshot();
    debug!(
        "build stats: ranges={} avg_range_lock={:?} avg_range_processing={:?} kernel_blocks={} avg_kernel_wait={:?} index_writes={} avg_index_write={:?} forest_writes={} avg_forest_write={:?} chaser_range_waits={}",
        statistics.ranges,
        statistics.average_range_lock_time,
        statistics.average_range_processing_time,
        statistics.kernel_blocks,
        statistics.average_kernel_block_wait,
        statistics.index_writes,
        statistics.average_index_write_time,
        statistics.forest_writes,
        statistics.average_forest_write_time,
        statistics.chaser_range_waits,
    );
    let file_bytes = file_nodes
        .checked_mul(size_of::<ForestNode>() as u64)
        .context("forest file size overflow")?;
    Ok(ForestBuildSummary {
        leaves,
        initialized_nodes,
        file_nodes,
        leaf_map_entries,
        file_bytes,
        pages_locked,
        roots,
        statistics,
    })
}

fn validate_config(config: &ParallelForestConfig) -> Result<()> {
    if config.leaf_workers == 0 {
        bail!("leaf worker count must be greater than zero");
    }
    if config.chaser_workers == 0 {
        bail!("chaser worker count must be greater than zero");
    }
    Ok(())
}

fn count_hinted_leaves<H: Hints>(hints: &H, stop_height: u32, worker_count: usize) -> Result<u64> {
    let worker_count = worker_count.min(height_chunk_count(stop_height)).max(1);
    let ranges = Arc::new(HeightRangeAllocator::new(stop_height));
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _worker in 0..worker_count {
            let ranges = Arc::clone(&ranges);
            handles.push(scope.spawn(move || -> Result<u64> {
                let mut count = 0u64;
                while let Some(range) = ranges.acquire() {
                    for height in range {
                        let at_height = hints
                            .indices_at_height(height)
                            .ok_or_else(|| anyhow!("hints unavailable at height {height}"))?;
                        count = count
                            .checked_add(at_height.len() as u64)
                            .context("hinted leaf count overflow")?;
                    }
                }
                Ok(count)
            }));
        }
        let mut count = 0u64;
        for handle in handles {
            count = count
                .checked_add(
                    handle
                        .join()
                        .map_err(|_| anyhow!("hint counting worker panicked"))??,
                )
                .context("hinted leaf count overflow")?;
        }
        Ok(count)
    })
}

#[allow(clippy::too_many_arguments)]
fn run_builders<S: BlockSource, H: Hints>(
    source: &S,
    hints: &H,
    stop_height: u32,
    leaf_counts: &[u64],
    leaf_offsets: &[u64],
    leaves: u64,
    forest_rows: u8,
    config: &ParallelForestConfig,
    forest: &Arc<FlatForest>,
    availability: &Arc<Availability>,
    leaf_map: &Arc<Database>,
    leaf_map_entries: &Arc<AtomicU64>,
    header_index: &Arc<HeaderIndex>,
    stats: &Arc<BuildStats>,
) -> Result<()> {
    thread::scope(|scope| {
        let leaf_worker_count = config
            .leaf_workers
            .min(height_chunk_count(stop_height))
            .max(1);
        let mut leaf_handles = Vec::with_capacity(leaf_worker_count);
        let mut chaser_handles = Vec::with_capacity(config.chaser_workers);
        let ranges = Arc::new(HeightRangeAllocator::new(stop_height));

        for worker in 0..config.chaser_workers {
            let context = ChaserContext {
                worker_count: config.chaser_workers,
                leaves,
                forest_rows,
                spin_iterations: config.spin_iterations,
                forest: Arc::clone(forest),
                availability: Arc::clone(availability),
                stats: Arc::clone(stats),
            };
            chaser_handles.push(scope.spawn(move || {
                let result = run_chaser(worker, &context);
                if result.is_err() {
                    context.availability.abort();
                }
                result
            }));
        }

        for worker in 0..leaf_worker_count {
            let outputs = LeafBuildOutputs {
                forest: Arc::clone(forest),
                availability: Arc::clone(availability),
                leaf_map: Arc::clone(leaf_map),
                leaf_map_entries: Arc::clone(leaf_map_entries),
                header_index: Arc::clone(header_index),
                stats: Arc::clone(stats),
            };
            let ranges = Arc::clone(&ranges);
            leaf_handles.push(scope.spawn(move || {
                let result = (|| {
                    loop {
                        let lock_started = Instant::now();
                        let Some(range) = ranges.acquire() else {
                            break;
                        };
                        outputs.stats.range_lock.record(lock_started.elapsed());
                        debug!(
                            "leaf worker {worker} acquired height range {}..={}",
                            range.start,
                            range.end - 1
                        );
                        let writer = outputs
                            .leaf_map
                            .write_only()
                            .context("failed to create range leaf-map writer")?;
                        let header_writer = outputs
                            .header_index
                            .build_writer()
                            .context("failed to create range header-index writer")?;
                        let processing_started = Instant::now();
                        let processed = fill_leaf_range(
                            source,
                            hints,
                            range,
                            leaf_counts,
                            leaf_offsets,
                            &outputs,
                            &writer,
                            &header_writer,
                        );
                        outputs
                            .stats
                            .range_processing
                            .record(processing_started.elapsed());
                        processed?;
                    }
                    Ok(())
                })();
                if result.is_err() {
                    outputs.availability.abort();
                }
                result
            }));
        }

        let mut failure = None;
        for handle in leaf_handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    availability.abort();
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    availability.abort();
                    failure.get_or_insert_with(|| anyhow!("leaf builder panicked"));
                }
            }
        }
        for handle in chaser_handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| anyhow!("chaser worker panicked"));
                }
            }
        }
        failure.map_or(Ok(()), Err)
    })
}

struct LeafBuildOutputs {
    forest: Arc<FlatForest>,
    availability: Arc<Availability>,
    leaf_map: Arc<Database>,
    leaf_map_entries: Arc<AtomicU64>,
    header_index: Arc<HeaderIndex>,
    stats: Arc<BuildStats>,
}

#[allow(clippy::too_many_arguments)]
fn fill_leaf_range<S: BlockSource, H: Hints>(
    source: &S,
    hints: &H,
    heights: Range<u32>,
    leaf_counts: &[u64],
    leaf_offsets: &[u64],
    outputs: &LeafBuildOutputs,
    writer: &WriteOnlyWriter<'_>,
    header_writer: &HeaderBuildWriter<'_>,
) -> Result<()> {
    let publish_nodes = nodes_per_two_pages();
    for height in heights {
        let expected_count = leaf_counts[(height - 1) as usize];
        let block_offset = leaf_offsets[(height - 1) as usize];
        let unspent = hints
            .indices_at_height(height)
            .ok_or_else(|| anyhow!("hints unavailable at height {height}"))?;
        if !unspent.windows(2).all(|pair| pair[0] < pair[1]) {
            bail!("hints at height {height} are not strictly increasing");
        }

        let mut local_position = 0u64;
        let mut hint_leaf_position = 0u64;
        let mut hint_position = 0usize;
        let mut unpublished = 0usize;
        let visited = source.visit_leaf_outputs(height, &mut |leaf| {
            let local_hint = u32::try_from(hint_leaf_position)
                .context("one block contains more than u32::MAX hinted leaves")?;
            if unspent
                .get(hint_position)
                .copied()
                .is_some_and(|hint| hint < local_hint)
            {
                bail!("hint index is duplicated or out of order at height {height}");
            }
            hint_leaf_position += 1;
            let spent = if leaf.force_unindexed {
                if unspent.get(hint_position) == Some(&local_hint) {
                    bail!("hardcoded unspendable leaf is marked in hints at height {height}");
                }
                false
            } else if unspent.get(hint_position) == Some(&local_hint) {
                hint_position += 1;
                false
            } else {
                true
            };
            let hash = get_leaf_hash_from_parts(
                leaf.block_hash,
                leaf.txid,
                leaf.vout,
                (height << 1) | u32::from(leaf.is_coinbase),
                leaf.value,
                leaf.script_pubkey,
            );
            let bottom_position = block_offset + local_position;
            let forest_write_started = Instant::now();
            let forest_write = outputs
                .forest
                .write(bottom_position, ForestNodeData { hash: *hash, spent });
            outputs
                .stats
                .forest_write
                .record(forest_write_started.elapsed());
            forest_write?;
            if !spent && !leaf.force_unindexed {
                let key = leaf_map_key(leaf.txid, leaf.vout);
                let value: [u8; LEAF_MAP_VALUE_SIZE] = bottom_position.to_le_bytes();
                let index_write_started = Instant::now();
                let indexed = writer
                    .put_unique(&key, &value)
                    .context("failed to index unique leaf position");
                outputs
                    .stats
                    .index_write
                    .record(index_write_started.elapsed());
                indexed?;
                outputs.leaf_map_entries.fetch_add(1, Ordering::Relaxed);
            }
            local_position += 1;
            unpublished += 1;
            if unpublished >= publish_nodes {
                outputs.availability.publish()?;
                unpublished = 0;
            }
            Ok(())
        })?;
        header_writer.put(height, visited.header, visited.block_hash)?;
        outputs.stats.kernel_wait.record(visited.kernel_wait);
        if visited.leaves != expected_count || local_position != expected_count {
            bail!(
                "leaf count changed at height {height}: declared {expected_count}, visited {}, built {local_position}",
                visited.leaves
            );
        }
        if hint_position != unspent.len() {
            bail!(
                "hint index {} at height {height} is outside the block's {local_position} leaves",
                unspent[hint_position]
            );
        }
        // Even an empty block/range publication wakes every chaser, as required by the wait path.
        outputs.availability.publish()?;
    }
    Ok(())
}

fn accumulator_hash(node: ForestNodeData) -> BitcoinNodeHash {
    if node.spent {
        BitcoinNodeHash::empty()
    } else {
        BitcoinNodeHash::from(node.hash)
    }
}

fn combine_children(left: ForestNodeData, right: ForestNodeData) -> ForestNodeData {
    match (left.spent, right.spent) {
        (true, true) => ForestNodeData {
            hash: [0; 32],
            spent: true,
        },
        (true, false) => right,
        (false, true) => left,
        (false, false) => {
            let left_hash = BitcoinNodeHash::from(left.hash);
            let right_hash = BitcoinNodeHash::from(right.hash);
            ForestNodeData {
                hash: *BitcoinNodeHash::parent_hash(&left_hash, &right_hash),
                spent: false,
            }
        }
    }
}

struct ChaserContext {
    worker_count: usize,
    leaves: u64,
    forest_rows: u8,
    spin_iterations: usize,
    forest: Arc<FlatForest>,
    availability: Arc<Availability>,
    stats: Arc<BuildStats>,
}

fn run_chaser(worker: usize, context: &ChaserContext) -> Result<()> {
    let worker_count = context.worker_count;
    let leaves = context.leaves;
    let forest_rows = context.forest_rows;
    let spin_iterations = context.spin_iterations;
    let forest = &context.forest;
    let availability = &context.availability;
    let stats = &context.stats;
    let min_parent_batch = parents_per_two_child_pages();
    for row in 0..forest_rows {
        let child_count = leaves >> row;
        let parent_count = child_count / 2;
        if parent_count == 0 {
            break;
        }
        let child_start = start_position_at_row(row, forest_rows)?;
        let parent_start = start_position_at_row(row + 1, forest_rows)?;
        let chunk_count = deterministic_chunk_count(parent_count, min_parent_batch);

        let mut chunk = worker as u64;
        while chunk < chunk_count {
            let parent_range = deterministic_chunk(parent_count, min_parent_batch, chunk)?;
            let last_child = child_start + parent_range.end * 2 - 1;
            let (_, mut range_waited) =
                availability.read_when_ready(forest, last_child, spin_iterations)?;

            for parent_offset in parent_range {
                let left_position = child_start + parent_offset * 2;
                let (left, left_waited) =
                    availability.read_when_ready(forest, left_position, spin_iterations)?;
                let (right, right_waited) =
                    availability.read_when_ready(forest, left_position + 1, spin_iterations)?;
                range_waited |= left_waited || right_waited;
                forest.write(parent_start + parent_offset, combine_children(left, right))?;
            }
            if range_waited {
                stats.chaser_range_waits.fetch_add(1, Ordering::Relaxed);
            }
            availability.publish()?;
            chunk = chunk
                .checked_add(worker_count as u64)
                .context("chaser chunk index overflow")?;
        }
    }
    Ok(())
}

fn validate_forest(
    forest: &FlatForest,
    leaves: u64,
    forest_rows: u8,
) -> Result<(u64, Vec<ForestRoot>)> {
    let mut initialized = 0u64;
    let mut roots = Vec::with_capacity(leaves.count_ones() as usize);
    for row in 0..=forest_rows {
        let row_nodes = leaves >> row;
        if row_nodes == 0 {
            break;
        }
        let row_start = start_position_at_row(row, forest_rows)?;
        for offset in 0..row_nodes {
            forest.try_read(row_start + offset)?.ok_or_else(|| {
                anyhow!("forest position {} is uninitialized", row_start + offset)
            })?;
            initialized += 1;
        }
        if leaves & (1u64 << row) != 0 {
            let position = row_start + row_nodes - 1;
            roots.push(ForestRoot {
                position,
                row,
                node: forest
                    .try_read(position)?
                    .expect("root was checked as initialized"),
            });
        }
    }
    roots.sort_unstable_by(|left, right| right.row.cmp(&left.row));
    Ok((initialized, roots))
}

fn visit_kernel_leaf_outputs(
    height: u32,
    block: &KernelBlock,
    visitor: &mut dyn FnMut(LeafOutput<'_>) -> Result<()>,
) -> Result<u64> {
    let spent_in_block = kernel_same_block_spends(block)?;
    let bip30_exclusion = bip30_excluded_outpoint(height);
    let block_hash = block.hash().to_bytes();
    let mut count = 0u64;
    for tx in block.transactions() {
        let txid = tx.txid().to_bytes();
        let is_coinbase = tx.input_count() == 1 && tx.input(0)?.outpoint().is_null();
        for (vout, output) in tx.outputs().enumerate() {
            let outpoint = KernelOutPoint {
                txid,
                vout: u32::try_from(vout).context("transaction output index overflow")?,
            };
            let script_pubkey = output.script_pubkey().to_bytes();
            if script_pubkey.len() > 10_000
                || script_pubkey.first() == Some(&0x6a)
                || spent_in_block.contains(&outpoint)
            {
                continue;
            }
            let value =
                u64::try_from(output.value()).context("transaction output value is negative")?;
            visitor(LeafOutput {
                block_hash,
                txid,
                vout: outpoint.vout,
                is_coinbase,
                force_unindexed: bip30_exclusion == Some(outpoint),
                value,
                script_pubkey: &script_pubkey,
            })?;
            count = count.checked_add(1).context("block leaf count overflow")?;
        }
    }
    Ok(count)
}

fn kernel_same_block_spends(block: &KernelBlock) -> Result<HashSet<KernelOutPoint>> {
    let mut created = HashSet::new();
    let mut spent = HashSet::new();
    for tx in block.transactions() {
        for input in tx.inputs() {
            let outpoint = input.outpoint();
            let outpoint = KernelOutPoint {
                txid: outpoint.txid().to_bytes(),
                vout: outpoint.index(),
            };
            if created.contains(&outpoint) {
                spent.insert(outpoint);
            }
        }
        let txid = tx.txid().to_bytes();
        for vout in 0..tx.output_count() {
            created.insert(KernelOutPoint {
                txid,
                vout: u32::try_from(vout).context("transaction output index overflow")?,
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

fn height_chunk_count(stop_height: u32) -> usize {
    (u64::from(stop_height).div_ceil(HEIGHT_CHUNK_SIZE)) as usize
}

struct HeightRangeAllocator {
    stop_height: u64,
    next_chunk: AtomicU64,
}

impl HeightRangeAllocator {
    fn new(stop_height: u32) -> Self {
        Self {
            stop_height: u64::from(stop_height),
            next_chunk: AtomicU64::new(0),
        }
    }

    fn acquire(&self) -> Option<Range<u32>> {
        let chunk = self.next_chunk.fetch_add(1, Ordering::Relaxed);
        let zero_based_start = chunk.checked_mul(HEIGHT_CHUNK_SIZE)?;
        if zero_based_start >= self.stop_height {
            return None;
        }
        let start = zero_based_start + 1;
        let end = (zero_based_start + HEIGHT_CHUNK_SIZE).min(self.stop_height) + 1;
        Some(start as u32..end as u32)
    }
}

fn deterministic_chunk_count(total: u64, minimum: u64) -> u64 {
    (total / minimum).max(1)
}

fn deterministic_chunk(total: u64, minimum: u64, chunk: u64) -> Result<Range<u64>> {
    let chunk_count = deterministic_chunk_count(total, minimum);
    if chunk >= chunk_count {
        bail!("chunk {chunk} is outside {chunk_count} deterministic chunks");
    }
    let start = chunk
        .checked_mul(minimum)
        .context("chaser chunk offset overflow")?;
    let end = if chunk + 1 == chunk_count {
        total
    } else {
        start + minimum
    };
    Ok(start..end)
}

fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as usize
    } else {
        4096
    }
}

fn nodes_per_two_pages() -> usize {
    (page_size() * 2).div_ceil(size_of::<ForestNode>())
}

fn parents_per_two_child_pages() -> u64 {
    (nodes_per_two_pages().div_ceil(2)).max(1) as u64
}

pub(crate) fn tree_rows(leaves: u64) -> u8 {
    if leaves == 0 {
        0
    } else {
        (u64::BITS - (leaves - 1).leading_zeros()) as u8
    }
}

fn parent(position: u64, forest_rows: u8) -> u64 {
    (position >> 1) | (1 << forest_rows)
}

fn left_child(position: u64, forest_rows: u8) -> u64 {
    let mask = (2 << forest_rows) - 1;
    (position << 1) & mask
}

fn detect_row(position: u64, forest_rows: u8) -> u8 {
    let mut marker = 1 << forest_rows;
    let mut row = 0;
    while position & marker != 0 {
        marker >>= 1;
        row += 1;
    }
    row
}

fn root_position(leaves: u64, row: u8, forest_rows: u8) -> u64 {
    let mask = (2 << forest_rows) - 1;
    let before = leaves & (mask << (row + 1));
    let shifted = (before >> row) | (mask << (forest_rows + 1 - row));
    shifted & mask
}

fn is_root_position(position: u64, leaves: u64, forest_rows: u8) -> bool {
    let row = detect_row(position, forest_rows);
    leaves & (1 << row) != 0 && root_position(leaves, row, forest_rows) == position
}

#[cfg(test)]
fn get_proof_positions(targets: &[u64], leaves: u64, forest_rows: u8) -> Vec<u64> {
    let mut proof_positions = BTreeSet::new();
    let mut known = HashSet::with_capacity(targets.len() * 2);
    let mut computed = targets.to_vec();
    known.extend(targets.iter().copied());

    let mut index = 0;
    while index < computed.len() {
        let position = computed[index];
        if !is_root_position(position, leaves, forest_rows) {
            let sibling = position ^ 1;
            if !known.contains(&sibling) {
                proof_positions.insert(sibling);
            } else {
                proof_positions.remove(&position);
            }
            let parent = parent(position, forest_rows);
            if known.insert(parent) {
                computed.push(parent);
            }
        }
        index += 1;
    }
    proof_positions.into_iter().collect()
}

fn translate_position(position: u64, from_rows: u8, to_rows: u8) -> Result<u64> {
    let row = detect_row(position, from_rows);
    let from_start = start_position_at_row(row, from_rows)?;
    let to_start = start_position_at_row(row, to_rows)?;
    to_start
        .checked_add(position - from_start)
        .context("translated forest position overflow")
}

fn forest_capacity(forest_rows: u8) -> Result<u64> {
    u64::try_from((2u128 << forest_rows) - 1).context("forest position space exceeds u64")
}

fn start_position_at_row(row: u8, forest_rows: u8) -> Result<u64> {
    if row > forest_rows {
        bail!("row {row} exceeds forest height {forest_rows}");
    }
    u64::try_from((2u128 << forest_rows) - (2u128 << (forest_rows - row)))
        .context("forest row position exceeds u64")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::atomic::AtomicU64;

    use bitcoin::absolute;
    use bitcoin::block;
    use bitcoin::block::Header;
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
    use bridge::prefixed_hints::write_leaf_count_prefix;
    use hintsfile::EliasFano;
    use hintsfile::HintsfileBuilder;

    use rustreexo::stump::Stump;

    use super::*;

    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct MockSource {
        blocks: Vec<Block>,
    }

    impl BlockSource for MockSource {
        fn visit_leaf_outputs(
            &self,
            height: u32,
            visitor: &mut dyn FnMut(LeafOutput<'_>) -> Result<()>,
        ) -> Result<BlockVisitResult> {
            let block = self
                .blocks
                .get((height - 1) as usize)
                .ok_or_else(|| anyhow!("missing mock block {height}"))?;
            let mut created = HashSet::new();
            let mut spent_in_block = HashSet::new();
            for tx in &block.txdata {
                for input in &tx.input {
                    let outpoint = KernelOutPoint {
                        txid: input.previous_output.txid.to_byte_array(),
                        vout: input.previous_output.vout,
                    };
                    if created.contains(&outpoint) {
                        spent_in_block.insert(outpoint);
                    }
                }
                let txid = tx.compute_txid().to_byte_array();
                for vout in 0..tx.output.len() {
                    created.insert(KernelOutPoint {
                        txid,
                        vout: u32::try_from(vout)?,
                    });
                }
            }

            let block_hash = block.block_hash().to_byte_array();
            let bip30_exclusion = bip30_excluded_outpoint(height);
            let mut count = 0u64;
            for tx in &block.txdata {
                let txid = tx.compute_txid().to_byte_array();
                for (vout, output) in tx.output.iter().enumerate() {
                    let outpoint = KernelOutPoint {
                        txid,
                        vout: u32::try_from(vout)?,
                    };
                    if output.script_pubkey.len() > 10_000
                        || output.script_pubkey.as_bytes().first() == Some(&0x6a)
                        || spent_in_block.contains(&outpoint)
                    {
                        continue;
                    }
                    visitor(LeafOutput {
                        block_hash,
                        txid,
                        vout: outpoint.vout,
                        is_coinbase: tx.is_coinbase(),
                        force_unindexed: bip30_exclusion == Some(outpoint),
                        value: output.value.to_sat(),
                        script_pubkey: output.script_pubkey.as_bytes(),
                    })?;
                    count += 1;
                }
            }
            let bytes: [u8; 80] = bitcoin::consensus::serialize(&block.header)
                .try_into()
                .expect("header serialization is fixed-size");
            Ok(BlockVisitResult {
                leaves: count,
                kernel_wait: Duration::ZERO,
                header: bytes,
                block_hash: block.header.block_hash().to_byte_array(),
            })
        }

        fn header(&self, height: u32) -> Result<([u8; 80], [u8; 32])> {
            let header = if height == 0 {
                mock_block(0, &[]).header
            } else {
                self.blocks
                    .get((height - 1) as usize)
                    .ok_or_else(|| anyhow!("missing mock block {height}"))?
                    .header
            };
            let bytes: [u8; 80] = bitcoin::consensus::serialize(&header)
                .try_into()
                .expect("header serialization is fixed-size");
            Ok((bytes, header.block_hash().to_byte_array()))
        }
    }

    struct Bip30Source;

    impl BlockSource for Bip30Source {
        fn visit_leaf_outputs(
            &self,
            height: u32,
            visitor: &mut dyn FnMut(LeafOutput<'_>) -> Result<()>,
        ) -> Result<BlockVisitResult> {
            assert_eq!(height, 1);
            visitor(LeafOutput {
                block_hash: [3; 32],
                txid: [1; 32],
                vout: 0,
                is_coinbase: true,
                force_unindexed: true,
                value: 10,
                script_pubkey: &[],
            })?;
            visitor(LeafOutput {
                block_hash: [3; 32],
                txid: [2; 32],
                vout: 0,
                is_coinbase: true,
                force_unindexed: false,
                value: 20,
                script_pubkey: &[],
            })?;
            let header = mock_block(1, &[]).header;
            Ok(BlockVisitResult {
                leaves: 2,
                kernel_wait: Duration::ZERO,
                header: bitcoin::consensus::serialize(&header).try_into().unwrap(),
                block_hash: header.block_hash().to_byte_array(),
            })
        }

        fn header(&self, height: u32) -> Result<([u8; 80], [u8; 32])> {
            let header = mock_block(height, &[]).header;
            Ok((
                bitcoin::consensus::serialize(&header).try_into().unwrap(),
                header.block_hash().to_byte_array(),
            ))
        }
    }

    struct MockHints {
        stop_height: u32,
        leaf_counts: BTreeMap<u32, u32>,
        indices: BTreeMap<u32, Vec<u32>>,
    }

    impl Hints for MockHints {
        fn stop_height(&self) -> u32 {
            self.stop_height
        }

        fn leaf_count_at_height(&self, height: u32) -> Option<u32> {
            self.leaf_counts.get(&height).copied()
        }

        fn indices_at_height(&self, height: u32) -> Option<Vec<u32>> {
            self.indices.get(&height).cloned()
        }
    }

    fn bridge_hints(leaf_counts: &[u32], indices: &[Vec<u32>]) -> BridgeHints {
        assert_eq!(leaf_counts.len(), indices.len());
        let stop_height = u32::try_from(leaf_counts.len() - 1).unwrap();
        let mut encoded = Vec::new();
        write_leaf_count_prefix(&mut encoded, stop_height, leaf_counts).unwrap();
        let mut builder = HintsfileBuilder::new(&mut encoded)
            .initialize(stop_height)
            .unwrap();
        for at_height in &indices[1..] {
            builder.append(EliasFano::compress(at_height)).unwrap();
        }
        builder.finish().unwrap();
        BridgeHints::from_reader(&mut Cursor::new(encoded)).unwrap()
    }

    fn mock_block(nonce: u32, values: &[u64]) -> Block {
        let transaction = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: values
                .iter()
                .map(|value| TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        };
        Block {
            header: Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce,
            },
            txdata: vec![transaction],
        }
    }

    fn temp_forest_path() -> PathBuf {
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "bridge-parallel-forest-{}-{id}.dat",
            std::process::id()
        ))
    }

    fn remove_bootstrap_files(path: &Path, leaf_map_path: &Path) {
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir_all(leaf_map_path).unwrap();
        std::fs::remove_file(path.with_extension("headers")).unwrap();
        std::fs::remove_dir_all(path.with_extension("header-index")).unwrap();
    }

    #[test]
    fn flat_node_layout_is_position_addressable() {
        assert_eq!(size_of::<ForestNode>(), 33);
        assert_eq!(forest_capacity(tree_rows(6)).unwrap(), 15);
        assert_eq!(start_position_at_row(0, 3).unwrap(), 0);
        assert_eq!(start_position_at_row(1, 3).unwrap(), 8);
        assert_eq!(start_position_at_row(2, 3).unwrap(), 12);
        assert_eq!(start_position_at_row(3, 3).unwrap(), 14);
    }

    #[test]
    fn bip30_leaf_stays_live_without_entering_the_leaf_map() {
        let path = temp_forest_path();
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 2)]),
            indices: BTreeMap::from([(1, vec![1])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        let summary = build_with_source(&Bip30Source, &hints, config).unwrap();

        assert_eq!(summary.leaves, 2);
        assert_eq!(summary.leaf_map_entries, 1);
        {
            let reader = FlatForestReader::open(&path).unwrap();
            assert!(!reader.read(0).unwrap().spent);
            assert!(!reader.read(1).unwrap().spent);
            let steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            assert!(steady
                .leaf_position(&OutPoint {
                    txid: Txid::from_byte_array([1; 32]),
                    vout: 0,
                })
                .is_err());
            assert_eq!(
                steady
                    .leaf_position(&OutPoint {
                        txid: Txid::from_byte_array([2; 32]),
                        vout: 0,
                    })
                    .unwrap(),
                1
            );
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn leaf_workers_claim_each_adjacent_chunk_once() {
        let allocator = HeightRangeAllocator::new(16);
        let mut acquired = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _worker in 0..2 {
                let allocator = &allocator;
                handles.push(scope.spawn(move || {
                    let mut ranges = Vec::new();
                    while let Some(range) = allocator.acquire() {
                        ranges.push(range);
                    }
                    ranges
                }));
            }
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        acquired.sort_unstable_by_key(|range| range.start);
        assert_eq!(acquired, vec![1..5, 5..9, 9..13, 13..17]);
        assert_eq!(height_chunk_count(16), 4);
    }

    #[test]
    fn deterministic_chunks_cover_each_row_with_page_sized_work() {
        let minimum = parents_per_two_child_pages();
        let total = minimum * 4 + minimum / 2;
        let chunk_count = deterministic_chunk_count(total, minimum);
        let mut end = 0;
        for chunk in 0..chunk_count {
            let range = deterministic_chunk(total, minimum, chunk).unwrap();
            assert_eq!(range.start, end);
            assert!(range.end - range.start >= minimum || total < minimum);
            end = range.end;
        }
        assert_eq!(end, total);
        assert!(minimum * 2 * size_of::<ForestNode>() as u64 >= (page_size() * 2) as u64);
    }

    #[test]
    fn spent_roots_use_the_accumulator_empty_hash() {
        assert_eq!(
            accumulator_hash(ForestNodeData {
                hash: [0; 32],
                spent: true,
            }),
            BitcoinNodeHash::empty()
        );
    }

    #[test]
    fn deleted_children_promote_surviving_subtrees() {
        let left = ForestNodeData {
            hash: [1; 32],
            spent: false,
        };
        let right = ForestNodeData {
            hash: [2; 32],
            spent: false,
        };
        let deleted_left = ForestNodeData {
            hash: [3; 32],
            spent: true,
        };
        let deleted_right = ForestNodeData {
            hash: [4; 32],
            spent: true,
        };

        assert_eq!(combine_children(deleted_left, right), right);
        assert_eq!(combine_children(left, deleted_right), left);
        let deleted_parent = combine_children(deleted_left, deleted_right);
        assert!(deleted_parent.spent);
        assert_eq!(deleted_parent.hash, [0; 32]);
        assert_eq!(combine_children(deleted_parent, right), right);

        let expected = BitcoinNodeHash::parent_hash(
            &BitcoinNodeHash::from(left.hash),
            &BitcoinNodeHash::from(right.hash),
        );
        assert_eq!(
            combine_children(left, right),
            ForestNodeData {
                hash: *expected,
                spent: false,
            }
        );
    }

    #[test]
    fn preallocated_capacity_accepts_additions_beyond_bootstrap_rows() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30])],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 3)]),
            indices: BTreeMap::from([(1, vec![0, 1, 2])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.minimum_leaf_capacity = Some(8);
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();

        {
            let mut steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            assert_eq!(steady.leaves(), 3);
            assert_eq!(steady.forest_rows, 3);
            let bootstrap_txid = source.blocks[0].txdata[0].compute_txid();
            for vout in 0..3 {
                let outpoint = OutPoint {
                    txid: bootstrap_txid,
                    vout,
                };
                let bottom = steady.leaf_position(&outpoint).unwrap();
                let target = steady.proof_position(bottom).unwrap();
                let proof = steady.prove(&[target]).unwrap();
                let stump = Stump {
                    leaves: steady.leaves(),
                    roots: steady.roots().unwrap(),
                };
                assert!(stump
                    .verify(&proof, &[steady.leaf_hash(bottom).unwrap()])
                    .unwrap());
            }
            let additions = [
                (
                    OutPoint {
                        txid: Txid::from_byte_array([4; 32]),
                        vout: 0,
                    },
                    BitcoinNodeHash::from([4; 32]),
                ),
                (
                    OutPoint {
                        txid: Txid::from_byte_array([5; 32]),
                        vout: 0,
                    },
                    BitcoinNodeHash::from([5; 32]),
                ),
            ];
            let entry = steady
                .plan_update(
                    2,
                    BlockHash::from_byte_array([2; 32]),
                    source.blocks[0].block_hash(),
                    &[],
                    &additions,
                )
                .unwrap();
            let expected_roots = steady.roots_after(&entry).unwrap();
            steady.apply_forward(&entry).unwrap();
            assert_eq!(steady.leaves(), 5);
            assert_eq!(steady.roots().unwrap(), expected_roots);
            steady.sync().unwrap();
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn steady_state_grows_the_forest_online() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30])],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 3)]),
            indices: BTreeMap::from([(1, vec![0, 1, 2])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();

        let expected_roots = {
            let mut steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            assert_eq!(steady.leaf_capacity().unwrap(), 4);
            let roots_before = steady.roots().unwrap();
            let additions = [
                (
                    OutPoint {
                        txid: Txid::from_byte_array([4; 32]),
                        vout: 0,
                    },
                    BitcoinNodeHash::from([4; 32]),
                ),
                (
                    OutPoint {
                        txid: Txid::from_byte_array([5; 32]),
                        vout: 0,
                    },
                    BitcoinNodeHash::from([5; 32]),
                ),
            ];

            let entry = steady
                .plan_update(
                    2,
                    BlockHash::from_byte_array([2; 32]),
                    source.blocks[0].block_hash(),
                    &[],
                    &additions,
                )
                .unwrap();
            assert_eq!(steady.forest_rows(), 3);
            assert_eq!(steady.leaf_capacity().unwrap(), 8);
            assert_eq!(steady.roots().unwrap(), roots_before);
            assert_eq!(FlatForestReader::open(&path).unwrap().node_count(), 15);
            assert!(!resize_marker_path(&path).exists());

            let bootstrap_outpoint = OutPoint {
                txid: source.blocks[0].txdata[0].compute_txid(),
                vout: 1,
            };
            let bottom = steady.leaf_position(&bootstrap_outpoint).unwrap();
            let target = steady.proof_position(bottom).unwrap();
            let proof = steady.prove(&[target]).unwrap();
            assert!(Stump {
                leaves: steady.leaves(),
                roots: roots_before,
            }
            .verify(&proof, &[steady.leaf_hash(bottom).unwrap()])
            .unwrap());

            let expected_roots = steady.roots_after(&entry).unwrap();
            steady.apply_forward(&entry).unwrap();
            steady.sync().unwrap();
            expected_roots
        };

        {
            let steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            assert_eq!(steady.leaves(), 5);
            assert_eq!(steady.forest_rows(), 3);
            assert_eq!(steady.roots().unwrap(), expected_roots);
            assert_eq!(
                steady
                    .leaf_position(&OutPoint {
                        txid: Txid::from_byte_array([5; 32]),
                        vout: 0,
                    })
                    .unwrap(),
                4
            );
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn resumes_an_interrupted_online_forest_resize() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30])],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 3)]),
            indices: BTreeMap::from([(1, vec![0, 1, 2])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();

        let roots_before = {
            let mut steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            let roots = steady.roots().unwrap();
            let marker = ResizeMarker {
                old_rows: 2,
                new_rows: 3,
                stage: RESIZE_STAGE_COPYING,
            };
            write_resize_marker(&path, marker).unwrap();
            steady
                .forest
                .grow_mapping(forest_capacity(2).unwrap(), forest_capacity(3).unwrap())
                .unwrap();
            roots
        };
        assert!(resize_marker_path(&path).exists());

        {
            let steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            assert_eq!(steady.leaves(), 3);
            assert_eq!(steady.forest_rows(), 3);
            assert_eq!(steady.roots().unwrap(), roots_before);
            assert!(!resize_marker_path(&path).exists());
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn plans_against_an_unflushed_forest_overlay() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30])],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 3)]),
            indices: BTreeMap::from([(1, vec![0, 1, 2])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();

        {
            let steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            let first_outpoint = OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: 0,
            };
            let first = steady
                .plan_update_with_overlay(
                    2,
                    BlockHash::from_byte_array([2; 32]),
                    source.blocks[0].block_hash(),
                    steady.leaves(),
                    &AHashMap::new(),
                    &[],
                    &[(first_outpoint, BitcoinNodeHash::from([9; 32]))],
                )
                .unwrap();
            let mut overlay = AHashMap::new();
            for delta in &first.forest {
                overlay.insert(delta.position, delta.after);
            }
            let first_added_state = overlay[&3];
            let second = steady
                .plan_update_with_overlay(
                    3,
                    BlockHash::from_byte_array([3; 32]),
                    BlockHash::from_byte_array([2; 32]),
                    first.num_leaves,
                    &overlay,
                    &[(first_outpoint, 3)],
                    &[],
                )
                .unwrap();
            let second_added_delta = second
                .forest
                .iter()
                .find(|delta| delta.position == 3)
                .unwrap();
            assert_eq!(second_added_delta.before, first_added_state);
            assert!(second_added_delta.after.spent);
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn large_deletion_rows_plan_deterministically_in_parallel() {
        let path = temp_forest_path();
        let values: Vec<u64> = (1..=512).collect();
        let source = MockSource {
            blocks: vec![mock_block(1, &values)],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 512)]),
            indices: BTreeMap::from([(1, (0..512).collect())]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();

        {
            let mut steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            let txid = source.blocks[0].txdata[0].compute_txid();
            let deletions: Vec<_> = (0..256)
                .map(|vout| {
                    let outpoint = OutPoint { txid, vout };
                    let position = steady.leaf_position(&outpoint).unwrap();
                    (outpoint, position)
                })
                .collect();
            let roots_before = steady.roots().unwrap();
            let first = steady
                .plan_update(
                    2,
                    BlockHash::from_byte_array([2; 32]),
                    BlockHash::from_byte_array([1; 32]),
                    &deletions,
                    &[],
                )
                .unwrap();
            let second = steady
                .plan_update(
                    2,
                    BlockHash::from_byte_array([2; 32]),
                    BlockHash::from_byte_array([1; 32]),
                    &deletions,
                    &[],
                )
                .unwrap();
            assert_eq!(first, second);
            assert!(first.forest.len() > deletions.len());
            assert!(first
                .forest
                .windows(2)
                .all(|pair| pair[0].position < pair[1].position));
            assert_eq!(steady.roots().unwrap(), roots_before);
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn proofs_read_hashes_from_promoted_sparse_positions() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30, 40, 50, 60, 70, 80])],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 8)]),
            indices: BTreeMap::from([(1, vec![0, 1, 4, 5])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();

        {
            let steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            let outpoint = OutPoint {
                txid: source.blocks[0].txdata[0].compute_txid(),
                vout: 0,
            };
            let bottom = steady.leaf_position(&outpoint).unwrap();
            let target = steady.proof_position(bottom).unwrap();
            assert_eq!(target, 8);
            let leaf_hash = steady.leaf_hash(bottom).unwrap();
            let proof = steady.prove(&[target]).unwrap();
            assert_eq!(proof.hashes.len(), 2);
            assert_eq!(proof.hashes[0], steady.leaf_hash(1).unwrap());
            let stump = Stump {
                leaves: steady.leaves(),
                roots: steady.roots().unwrap(),
            };
            assert!(stump.verify(&proof, &[leaf_hash]).unwrap());
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn recovers_a_missing_leaf_map_entry_despite_a_corrupt_sibling_hint() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30])],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 3)]),
            indices: BTreeMap::from([(1, vec![0, 1, 2])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();

        {
            let steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            let txid = source.blocks[0].txdata[0].compute_txid();
            let block_leaves = (0..3)
                .map(|vout| {
                    let outpoint = OutPoint { txid, vout };
                    let position = steady.leaf_position(&outpoint).unwrap();
                    (outpoint, steady.leaf_hash(position).unwrap())
                })
                .collect::<Vec<_>>();
            let target = block_leaves[1].0;
            let expected_position = steady.leaf_position(&target).unwrap();
            let target_hash = block_leaves[1].1;
            let misleading = block_leaves[0].0;
            let wrong_position = steady.leaf_position(&block_leaves[2].0).unwrap();
            steady
                .leaf_map
                .put(
                    &leaf_map_key(misleading.txid.to_byte_array(), misleading.vout),
                    &wrong_position.to_le_bytes(),
                )
                .unwrap();
            steady
                .leaf_map
                .delete(&leaf_map_key(target.txid.to_byte_array(), target.vout))
                .unwrap();

            assert!(steady.leaf_position(&target).is_err());
            assert_eq!(
                steady
                    .recover_leaf_position_from_block(target, target_hash, &block_leaves)
                    .unwrap(),
                expected_position
            );
        }

        remove_bootstrap_files(&path, &leaf_map_path);
    }
    #[test]
    fn replay_restores_baseline_after_multiple_interrupted_rollbacks() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30])],
        };
        let hints = MockHints {
            stop_height: 1,
            leaf_counts: BTreeMap::from([(1, 3)]),
            indices: BTreeMap::from([(1, vec![0, 1, 2])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();
        let journal_path = path.with_extension("journal");
        let txid = source.blocks[0].txdata[0].compute_txid();
        let first = OutPoint { txid, vout: 0 };
        let second = OutPoint { txid, vout: 1 };
        let expected_roots;
        {
            let mut forest = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            expected_roots = forest.roots().unwrap();
            let first_position = forest.leaf_position(&first).unwrap();
            let first_entry = forest
                .plan_update(
                    2,
                    BlockHash::from_byte_array([2; 32]),
                    source.blocks[0].block_hash(),
                    &[(first, first_position)],
                    &[],
                )
                .unwrap();
            let mut journal = ForestJournal::open(&journal_path).unwrap();
            let first_index = journal.append(first_entry.clone()).unwrap();
            forest.apply_forward(&first_entry).unwrap();
            let second_position = forest.leaf_position(&second).unwrap();
            let second_entry = forest
                .plan_update(
                    3,
                    BlockHash::from_byte_array([3; 32]),
                    first_entry.block_hash,
                    &[(second, second_position)],
                    &[],
                )
                .unwrap();
            let second_index = journal.append(second_entry.clone()).unwrap();
            forest.apply_forward(&second_entry).unwrap();
            journal.flush().unwrap();
            forest.sync().unwrap();

            journal.mark_rolled_back(second_index).unwrap();
            journal.mark_rolled_back(first_index).unwrap();
            forest.replay_journal(&journal).unwrap();
            assert_eq!(forest.roots().unwrap(), expected_roots);
            assert_eq!(forest.leaf_position(&first).unwrap(), first_position);
            assert_eq!(forest.leaf_position(&second).unwrap(), second_position);
        }

        std::fs::remove_file(journal_path).unwrap();
        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn background_worker_replays_a_durable_journal_entry() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30]), mock_block(2, &[40, 50, 60])],
        };
        let hints = MockHints {
            stop_height: 2,
            leaf_counts: BTreeMap::from([(1, 3), (2, 3)]),
            indices: BTreeMap::from([(1, vec![1]), (2, vec![0, 1, 2])]),
        };
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 1;
        config.chaser_workers = 1;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();
        build_with_source(&source, &hints, config).unwrap();
        let journal_path = path.with_extension("journal");
        let outpoint = OutPoint {
            txid: source.blocks[0].txdata[0].compute_txid(),
            vout: 1,
        };

        let (expected_roots, entry, published_size, flusher) = {
            let mut steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            let position = steady.leaf_position(&outpoint).unwrap();
            let entry = steady
                .plan_update(
                    3,
                    BlockHash::from_byte_array([3; 32]),
                    BlockHash::from_byte_array([2; 32]),
                    &[(outpoint, position)],
                    &[],
                )
                .unwrap();
            let expected = steady.roots_after(&entry).unwrap();
            let mut journal = crate::forest_journal::ForestJournal::open(&journal_path).unwrap();
            journal.append(entry.clone()).unwrap();
            let published_size = journal.published_size();
            let flusher = journal.flusher().unwrap();
            (expected, entry, published_size, flusher)
        };

        let forest = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
        let worker = crate::prover::JournalApplyWorker::new(flusher).unwrap();
        let (forest, timings) = worker
            .enqueue(entry, published_size, forest)
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert!(timings.journal_flush < Duration::from_secs(2));
        assert!(timings.apply < Duration::from_secs(2));
        assert!(timings.state_flush < Duration::from_secs(2));
        assert_eq!(forest.roots().unwrap(), expected_roots);
        assert!(forest.leaf_position(&outpoint).is_err());
        drop(worker);
        drop(forest);

        std::fs::remove_file(journal_path).unwrap();
        remove_bootstrap_files(&path, &leaf_map_path);
    }

    #[test]
    fn builds_and_reopens_a_parallel_forest() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30]), mock_block(2, &[40, 50, 60])],
        };
        let hints = bridge_hints(&[0, 3, 3], &[Vec::new(), vec![1], vec![0, 1, 2]]);
        let mut config = ParallelForestConfig::new(path.clone());
        config.leaf_workers = 2;
        config.chaser_workers = 2;
        config.spin_iterations = 8;
        config.lock_pages = false;
        let leaf_map_path = config.leaf_map_path.clone();

        let summary = build_with_source(&source, &hints, config).unwrap();
        assert_eq!(summary.leaves, 6);
        assert_eq!(summary.initialized_nodes, 10);
        assert_eq!(summary.file_nodes, 15);
        assert_eq!(summary.leaf_map_entries, 4);
        assert_eq!(summary.statistics.ranges, 1);
        assert_eq!(summary.statistics.kernel_blocks, 2);
        assert_eq!(summary.statistics.index_writes, 4);
        assert_eq!(summary.statistics.forest_writes, 6);
        assert_eq!(summary.roots.len(), 2);
        assert_eq!(summary.roots[0].position, 12);
        assert_eq!(summary.roots[1].position, 10);

        {
            let headers = HeaderIndex::open(
                &path.with_extension("headers"),
                &path.with_extension("header-index"),
            )
            .unwrap();
            assert_eq!(
                headers.get_by_height(1).unwrap(),
                Some(source.blocks[0].header)
            );
            assert_eq!(
                headers.get_height(source.blocks[1].block_hash()).unwrap(),
                Some(2)
            );
            headers.close().unwrap();
        }

        {
            let reader = FlatForestReader::open(&path).unwrap();
            assert_eq!(reader.node_count(), 15);
            let leaves = [
                reader.read(0).unwrap(),
                reader.read(1).unwrap(),
                reader.read(2).unwrap(),
                reader.read(3).unwrap(),
                reader.read(4).unwrap(),
                reader.read(5).unwrap(),
            ];
            assert!(leaves[0].spent);
            assert!(!leaves[1].spent);
            assert!(leaves[2].spent);
            assert!(!leaves[3].spent);
            assert!(!leaves[4].spent);
            assert!(!leaves[5].spent);
            assert!(reader.read(6).is_err());

            assert_eq!(reader.read(8).unwrap().hash, leaves[1].hash);
            assert_eq!(reader.read(9).unwrap().hash, leaves[3].hash);
            let largest_root = BitcoinNodeHash::parent_hash(
                &BitcoinNodeHash::from(leaves[1].hash),
                &BitcoinNodeHash::from(leaves[3].hash),
            );
            assert_eq!(reader.read(12).unwrap().hash, *largest_root);
            let small_root = BitcoinNodeHash::parent_hash(
                &BitcoinNodeHash::from(leaves[4].hash),
                &BitcoinNodeHash::from(leaves[5].hash),
            );
            assert_eq!(reader.read(10).unwrap().hash, *small_root);
        }
        assert!(!leaf_map_path.join("blobs").exists());
        {
            let leaf_map = Database::open_runtime(&leaf_map_path).unwrap();
            let first_txid = source.blocks[0].txdata[0].compute_txid().to_byte_array();
            let second_txid = source.blocks[1].txdata[0].compute_txid().to_byte_array();
            let position = |txid, vout| {
                leaf_map
                    .get(&leaf_map_key(txid, vout))
                    .unwrap()
                    .map(|value| u64::from_le_bytes(value.try_into().unwrap()))
            };
            assert_eq!(position(first_txid, 0), None);
            assert_eq!(position(first_txid, 1), Some(1));
            assert_eq!(position(first_txid, 2), None);
            assert_eq!(position(second_txid, 0), Some(3));
            assert_eq!(position(second_txid, 1), Some(4));
            assert_eq!(position(second_txid, 2), Some(5));
        }
        {
            let first_txid = source.blocks[0].txdata[0].compute_txid();
            let spent_outpoint = OutPoint {
                txid: first_txid,
                vout: 1,
            };
            let mut steady = SteadyStateForest::open(&path, &leaf_map_path, false).unwrap();
            assert_eq!(steady.leaves(), 6);
            let bottom = steady.leaf_position(&spent_outpoint).unwrap();
            assert_eq!(bottom, 1);
            let target = steady.proof_position(bottom).unwrap();
            assert_eq!(target, 8);
            let deleted_hash = steady.leaf_hash(bottom).unwrap();
            let proof = steady.prove(&[target]).unwrap();
            let before = Stump {
                leaves: steady.leaves(),
                roots: steady.roots().unwrap(),
            };
            assert!(before.verify(&proof, &[deleted_hash]).unwrap());
            let after_delete = before.modify(&[], &[deleted_hash], &proof).unwrap();
            let delete_entry = steady
                .plan_update(
                    3,
                    BlockHash::from_byte_array([3; 32]),
                    BlockHash::from_byte_array([2; 32]),
                    &[(spent_outpoint, bottom)],
                    &[],
                )
                .unwrap();
            let repeated_plan = steady
                .plan_update(
                    3,
                    BlockHash::from_byte_array([3; 32]),
                    BlockHash::from_byte_array([2; 32]),
                    &[(spent_outpoint, bottom)],
                    &[],
                )
                .unwrap();
            assert_eq!(repeated_plan, delete_entry);
            assert!(delete_entry
                .forest
                .windows(2)
                .all(|pair| pair[0].position < pair[1].position));
            assert_eq!(steady.roots().unwrap(), before.roots);
            assert_eq!(
                steady.roots_after(&delete_entry).unwrap(),
                after_delete.roots
            );
            steady.apply_forward(&delete_entry).unwrap();
            assert_eq!(steady.roots().unwrap(), after_delete.roots);

            let surviving_outpoint = OutPoint {
                txid: source.blocks[1].txdata[0].compute_txid(),
                vout: 0,
            };
            let surviving_bottom = steady.leaf_position(&surviving_outpoint).unwrap();
            assert_eq!(surviving_bottom, 3);
            let surviving_target = steady.proof_position(surviving_bottom).unwrap();
            assert_eq!(surviving_target, 12);
            let surviving_hash = steady.leaf_hash(surviving_bottom).unwrap();
            let empty_sibling_proof = steady.prove(&[surviving_target]).unwrap();
            assert!(after_delete
                .verify(&empty_sibling_proof, &[surviving_hash])
                .unwrap());

            let added_outpoint = OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: 7,
            };
            let added_hash = BitcoinNodeHash::from([7; 32]);
            let after_add = after_delete
                .modify(&[added_hash], &[], &Proof::default())
                .unwrap();
            let add_entry = steady
                .plan_update(
                    4,
                    BlockHash::from_byte_array([4; 32]),
                    BlockHash::from_byte_array([3; 32]),
                    &[],
                    &[(added_outpoint, added_hash)],
                )
                .unwrap();
            assert_eq!(steady.roots_after(&add_entry).unwrap(), after_add.roots);
            steady.apply_forward(&add_entry).unwrap();
            assert_eq!(steady.leaves(), 7);
            assert_eq!(steady.leaf_position(&added_outpoint).unwrap(), 6);
            assert_eq!(steady.roots().unwrap(), after_add.roots);
            let second_outpoint = OutPoint {
                txid: Txid::from_byte_array([10; 32]),
                vout: 8,
            };
            let second_hash = BitcoinNodeHash::from([8; 32]);
            let after_second = after_add
                .modify(&[second_hash], &[], &Proof::default())
                .unwrap();
            let second_entry = steady
                .plan_update(
                    5,
                    BlockHash::from_byte_array([5; 32]),
                    BlockHash::from_byte_array([4; 32]),
                    &[],
                    &[(second_outpoint, second_hash)],
                )
                .unwrap();
            steady.apply_forward(&second_entry).unwrap();
            assert_eq!(steady.roots().unwrap(), after_second.roots);

            steady.apply_backward(&second_entry).unwrap();
            steady.apply_backward(&add_entry).unwrap();
            assert_eq!(steady.leaves(), 6);
            assert!(steady.leaf_position(&added_outpoint).is_err());
            assert!(steady.leaf_position(&second_outpoint).is_err());
            assert_eq!(steady.roots().unwrap(), after_delete.roots);
            steady.apply_forward(&add_entry).unwrap();
            steady.apply_forward(&second_entry).unwrap();
            assert_eq!(steady.roots().unwrap(), after_second.roots);
            steady.sync().unwrap();
        }
        remove_bootstrap_files(&path, &leaf_map_path);
    }
}
