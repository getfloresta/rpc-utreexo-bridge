// SPDX-License-Identifier: MIT

//! Linux-only, parallel construction of a position-addressed Utreexo forest.

use std::cell::UnsafeCell;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::ops::Range;
use std::os::fd::AsRawFd;
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

use crate::udata::bitcoin_leaf_data::get_leaf_hash_from_parts;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Txid;
use bitcoinkernel::prelude::BlockHashExt;
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
use db_experiment::Config as LeafMapConfig;
use db_experiment::Database;
use db_experiment::Mode;
use db_experiment::WriteOnlyWriter;
use hintsfile::Hintsfile;
use log::info;
use log::warn;
#[cfg(test)]
use memmap2::Mmap;
use memmap2::MmapMut;
use memmap2::MmapOptions;
use rustreexo::accumulator::node_hash::AccumulatorHash;
use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use rustreexo::accumulator::proof::Proof;

const READY: u8 = 1 << 0;
const SPENT: u8 = 1 << 1;
const HEIGHT_CHUNK_SIZE: u64 = 4;
const WRITING: u8 = 1 << 2;
const DEFAULT_SPIN_ITERATIONS: usize = 512;
const STEADY_LEAF_MAP_HEADROOM: u64 = 1 << 30;
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
    pub leaf_workers: usize,
    pub chaser_workers: usize,
    pub spin_iterations: usize,
    pub lock_pages: bool,
}

impl ParallelForestConfig {
    pub fn new(forest_path: PathBuf) -> Self {
        let leaf_map_path = forest_path.with_extension("leaf-map");
        let threads = thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let leaf_workers = (threads / 2).max(1);
        let chaser_workers = threads.saturating_sub(leaf_workers).max(1);
        Self {
            forest_path,
            leaf_map_path,
            leaf_workers,
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
    _file: File,
    node_count: u64,
    pages_locked: bool,
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
            _file: file,
            node_count,
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
            _file: file,
            node_count,
            pages_locked: false,
        };
        forest.prepare_residency(lock_pages);
        Ok(forest)
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

    fn overwrite(&self, position: u64, value: ForestNodeData) -> Result<()> {
        let node = self.node(position)?;
        let previous = node.flags.swap(WRITING, Ordering::AcqRel);
        if previous & READY == 0 || previous & WRITING != 0 {
            node.flags.store(previous, Ordering::Release);
            bail!("forest position {position} cannot be overwritten from flags {previous:#04x}");
        }
        unsafe {
            *node.hash.get() = value.hash;
        }
        let flags = READY | if value.spent { SPENT } else { 0 };
        node.flags.store(flags, Ordering::Release);
        Ok(())
    }

    fn store(&self, position: u64, value: ForestNodeData) -> Result<()> {
        if self.try_read(position)?.is_some() {
            self.overwrite(position, value)
        } else {
            self.write(position, value)
        }
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
}

trait BlockSource: Sync {
    fn visit_leaf_outputs(
        &self,
        height: u32,
        visitor: &mut dyn FnMut(LeafOutput<'_>) -> Result<()>,
    ) -> Result<BlockVisitResult>;
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
        let leaves = visit_kernel_leaf_outputs(height, &block, visitor)?;
        Ok(BlockVisitResult {
            leaves,
            kernel_wait,
        })
    }
}

trait Hints: Sync {
    fn stop_height(&self) -> u32;
    fn indices_at_height(&self, height: u32) -> Option<Vec<u32>>;
}

impl Hints for Hintsfile {
    fn stop_height(&self) -> u32 {
        Hintsfile::stop_height(self)
    }

    fn indices_at_height(&self, height: u32) -> Option<Vec<u32>> {
        Hintsfile::indices_at_height(self, height)
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

impl SteadyStateForest {
    pub fn open(forest_path: &Path, leaf_map_path: &Path, lock_pages: bool) -> Result<Self> {
        let forest = FlatForest::open(forest_path, lock_pages)?;
        let positional_size = forest
            .node_count
            .checked_add(1)
            .context("forest position count overflow")?;
        if positional_size < 2 || !positional_size.is_power_of_two() {
            bail!(
                "forest contains {} nodes, not a complete positional space",
                forest.node_count
            );
        }
        let forest_rows =
            u8::try_from(positional_size.ilog2() - 1).context("forest height exceeds u8")?;
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
            roots.push(BitcoinNodeHash::from(node.hash));
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
        let mut original_position = bottom_position;
        let mut branch_directions = Vec::new();
        while !is_root_position(original_position, self.leaves, self.forest_rows) {
            let sibling_position = original_position ^ 1;
            let sibling = self
                .forest
                .try_read(sibling_position)?
                .ok_or_else(|| anyhow!("sibling position {sibling_position} is uninitialized"))?;
            if !sibling.spent {
                branch_directions.push(original_position & 1 != 0);
            }
            original_position = parent(original_position, self.forest_rows);
        }

        let mut promoted_position = original_position;
        for is_right in branch_directions.into_iter().rev() {
            promoted_position =
                left_child(promoted_position, self.forest_rows) + u64::from(is_right);
        }
        Ok(promoted_position)
    }

    fn containing_root(&self, position: u64) -> Result<(u64, u8)> {
        let position_row = detect_row(position, self.forest_rows);
        for root_row in position_row..=self.forest_rows {
            if self.leaves & (1u64 << root_row) == 0 {
                continue;
            }
            let mut ancestor = position;
            for _ in position_row..root_row {
                ancestor = parent(ancestor, self.forest_rows);
            }
            let root = root_position(self.leaves, root_row, self.forest_rows);
            if ancestor == root {
                return Ok((root, root_row));
            }
        }
        bail!("position {position} is not below a populated root")
    }

    fn compressed_hash(&self, position: u64) -> Result<BitcoinNodeHash> {
        let (root, mut original_row) = self.containing_root(position)?;
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
                let left = self
                    .forest
                    .try_read(left_position)?
                    .ok_or_else(|| anyhow!("left child {left_position} is uninitialized"))?;
                let right = self
                    .forest
                    .try_read(left_position + 1)?
                    .ok_or_else(|| anyhow!("right child {} is uninitialized", left_position + 1))?;
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

        let node = self
            .forest
            .try_read(original_position)?
            .ok_or_else(|| anyhow!("compressed node {original_position} is uninitialized"))?;
        if node.spent {
            bail!("compressed position {position} resolves to an empty subtree");
        }
        Ok(BitcoinNodeHash::from(node.hash))
    }

    pub fn prove(&self, targets: &[u64]) -> Result<Proof<BitcoinNodeHash>> {
        let proof_positions = get_proof_positions(targets, self.leaves, self.forest_rows);
        let hashes = proof_positions
            .into_iter()
            .map(|position| self.compressed_hash(position))
            .collect::<Result<Vec<_>>>()?;
        Ok(Proof::new_with_hash(targets.to_vec(), hashes))
    }

    pub fn delete(&mut self, deletions: &[(OutPoint, u64)]) -> Result<()> {
        let mut positions = BTreeSet::new();
        for (outpoint, position) in deletions {
            let indexed = self.leaf_position(outpoint)?;
            if indexed != *position {
                bail!("outpoint {outpoint} moved from requested position {position} to {indexed}");
            }
            let node = self
                .forest
                .try_read(*position)?
                .expect("leaf_position checked initialization");
            self.forest.overwrite(
                *position,
                ForestNodeData {
                    hash: node.hash,
                    spent: true,
                },
            )?;
            positions.insert(*position);
        }

        while !positions.is_empty() {
            let parents: BTreeSet<u64> = positions
                .iter()
                .filter(|position| !is_root_position(**position, self.leaves, self.forest_rows))
                .map(|position| parent(*position, self.forest_rows))
                .collect();
            for parent_position in &parents {
                let left_position = left_child(*parent_position, self.forest_rows);
                let left = self
                    .forest
                    .try_read(left_position)?
                    .ok_or_else(|| anyhow!("left child {left_position} is uninitialized"))?;
                let right = self
                    .forest
                    .try_read(left_position + 1)?
                    .ok_or_else(|| anyhow!("right child {} is uninitialized", left_position + 1))?;
                self.forest
                    .overwrite(*parent_position, combine_children(left, right))?;
            }
            positions = parents;
        }

        for (outpoint, _) in deletions {
            let key = leaf_map_key(outpoint.txid.to_byte_array(), outpoint.vout);
            if !self
                .leaf_map
                .delete(&key)
                .context("failed to delete leaf-map entry")?
            {
                bail!("outpoint {outpoint} disappeared from the leaf map");
            }
        }
        Ok(())
    }

    pub fn add(&mut self, additions: &[(OutPoint, BitcoinNodeHash)]) -> Result<()> {
        let bottom_capacity = 1u64
            .checked_shl(u32::from(self.forest_rows))
            .context("forest bottom capacity overflow")?;
        let final_leaves = self
            .leaves
            .checked_add(additions.len() as u64)
            .context("leaf count overflow")?;
        if final_leaves > bottom_capacity {
            bail!("flat forest capacity {bottom_capacity} is exhausted by {final_leaves} leaves");
        }

        for (outpoint, hash) in additions {
            let bottom_position = self.leaves;
            self.forest.store(
                bottom_position,
                ForestNodeData {
                    hash: **hash,
                    spent: false,
                },
            )?;

            let mut position = bottom_position;
            let mut row = 0u8;
            while self.leaves & (1u64 << row) != 0 {
                let left_position = root_position(self.leaves, row, self.forest_rows);
                let left = self
                    .forest
                    .try_read(left_position)?
                    .ok_or_else(|| anyhow!("addition root {left_position} is uninitialized"))?;
                let right = self
                    .forest
                    .try_read(position)?
                    .ok_or_else(|| anyhow!("addition node {position} is uninitialized"))?;
                position = parent(position, self.forest_rows);
                self.forest.store(position, combine_children(left, right))?;
                row += 1;
            }

            let key = leaf_map_key(outpoint.txid.to_byte_array(), outpoint.vout);
            if !self
                .leaf_map
                .put_new(&key, &bottom_position.to_le_bytes())
                .context("failed to insert leaf-map entry")?
            {
                bail!("outpoint {outpoint} already exists in the leaf map");
            }
            self.leaves += 1;
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
    hints: &Hintsfile,
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
    info!("indexing leaf counts through height {stop_height}");
    let leaf_counts = index_leaf_counts(source, stop_height, config.leaf_workers, &stats)?;
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

    let forest_rows = tree_rows(leaves);
    let file_nodes = forest_capacity(forest_rows)?;
    let leaf_map = Arc::new(create_leaf_map(
        &config.leaf_map_path,
        live_leaves,
        config.leaf_workers,
    )?);
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
    let statistics = stats.snapshot();
    info!(
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

fn index_leaf_counts<S: BlockSource>(
    source: &S,
    stop_height: u32,
    worker_count: usize,
    stats: &BuildStats,
) -> Result<Vec<u64>> {
    let worker_count = worker_count.min(height_chunk_count(stop_height)).max(1);
    let ranges = Arc::new(HeightRangeAllocator::new(stop_height));
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _worker in 0..worker_count {
            let ranges = Arc::clone(&ranges);
            handles.push(scope.spawn(move || -> Result<Vec<(u32, u64)>> {
                let mut counts = Vec::new();
                while let Some(range) = ranges.acquire() {
                    counts.reserve(range.len());
                    for height in range {
                        let visit = source.visit_leaf_outputs(height, &mut |_| Ok(()))?;
                        stats.kernel_wait.record(visit.kernel_wait);
                        counts.push((height, visit.leaves));
                    }
                }
                Ok(counts)
            }));
        }

        let mut counts = vec![0; stop_height as usize];
        for handle in handles {
            let values = handle
                .join()
                .map_err(|_| anyhow!("leaf indexing worker panicked"))??;
            for (height, count) in values {
                counts[(height - 1) as usize] = count;
            }
        }
        Ok(counts)
    })
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
                        info!(
                            "leaf worker {worker} acquired height range {}..={}",
                            range.start,
                            range.end - 1
                        );
                        let writer = outputs
                            .leaf_map
                            .write_only()
                            .context("failed to create range leaf-map writer")?;
                        let processing_started = Instant::now();
                        let processed = fill_leaf_range(
                            source,
                            hints,
                            range,
                            leaf_counts,
                            leaf_offsets,
                            &outputs,
                            &writer,
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
    stats: Arc<BuildStats>,
}

fn fill_leaf_range<S: BlockSource, H: Hints>(
    source: &S,
    hints: &H,
    heights: Range<u32>,
    leaf_counts: &[u64],
    leaf_offsets: &[u64],
    outputs: &LeafBuildOutputs,
    writer: &WriteOnlyWriter<'_>,
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
        let mut hint_position = 0usize;
        let mut unpublished = 0usize;
        let visited = source.visit_leaf_outputs(height, &mut |leaf| {
            let local_hint = u32::try_from(local_position)
                .context("one block contains more than u32::MAX leaves")?;
            if unspent
                .get(hint_position)
                .copied()
                .is_some_and(|hint| hint < local_hint)
            {
                bail!("hint index is duplicated or out of order at height {height}");
            }
            let spent = if unspent.get(hint_position) == Some(&local_hint) {
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
            if !spent {
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
        outputs.stats.kernel_wait.record(visited.kernel_wait);
        if visited.leaves != expected_count || local_position != expected_count {
            bail!(
                "leaf count changed at height {height}: indexed {expected_count}, visited {}, built {local_position}",
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
                || bip30_exclusion == Some(outpoint)
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

fn tree_rows(leaves: u64) -> u8 {
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

    use rustreexo::accumulator::stump::Stump;

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
                        || bip30_exclusion == Some(outpoint)
                    {
                        continue;
                    }
                    visitor(LeafOutput {
                        block_hash,
                        txid,
                        vout: outpoint.vout,
                        is_coinbase: tx.is_coinbase(),
                        value: output.value.to_sat(),
                        script_pubkey: output.script_pubkey.as_bytes(),
                    })?;
                    count += 1;
                }
            }
            Ok(BlockVisitResult {
                leaves: count,
                kernel_wait: Duration::ZERO,
            })
        }
    }

    struct MockHints {
        stop_height: u32,
        indices: BTreeMap<u32, Vec<u32>>,
    }

    impl Hints for MockHints {
        fn stop_height(&self) -> u32 {
            self.stop_height
        }

        fn indices_at_height(&self, height: u32) -> Option<Vec<u32>> {
            self.indices.get(&height).cloned()
        }
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
    fn proofs_read_hashes_from_promoted_sparse_positions() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30, 40, 50, 60, 70, 80])],
        };
        let hints = MockHints {
            stop_height: 1,
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

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir_all(leaf_map_path).unwrap();
    }

    #[test]
    fn builds_and_reopens_a_parallel_forest() {
        let path = temp_forest_path();
        let source = MockSource {
            blocks: vec![mock_block(1, &[10, 20, 30]), mock_block(2, &[40, 50, 60])],
        };
        let hints = MockHints {
            stop_height: 2,
            indices: BTreeMap::from([(1, vec![1]), (2, vec![0, 1, 2])]),
        };
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
        assert_eq!(summary.statistics.kernel_blocks, 4);
        assert_eq!(summary.statistics.index_writes, 4);
        assert_eq!(summary.statistics.forest_writes, 6);
        assert_eq!(summary.roots.len(), 2);
        assert_eq!(summary.roots[0].position, 12);
        assert_eq!(summary.roots[1].position, 10);

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
            let after_delete = before.modify(&[], &[deleted_hash], &proof).unwrap().0;
            steady.delete(&[(spent_outpoint, bottom)]).unwrap();
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
                .unwrap()
                .0;
            steady.add(&[(added_outpoint, added_hash)]).unwrap();
            assert_eq!(steady.leaves(), 7);
            assert_eq!(steady.leaf_position(&added_outpoint).unwrap(), 6);
            assert_eq!(steady.roots().unwrap(), after_add.roots);
            steady.sync().unwrap();
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir_all(leaf_map_path).unwrap();
    }
}
