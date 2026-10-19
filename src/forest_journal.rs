// SPDX-License-Identifier: MIT

//! Unsynced block WAL with explicitly published, crash-recoverable prefixes.
//!
//! Appenders only write complete records. A detached publisher flushes the WAL, advances an
//! alternating checksummed marker, then flushes that marker before exposing the prefix.
//! Recovery discards everything past the marker, including valid, previously flushed records.
//! Each published block carries its header and compact proof as well as the forest delta.
//! Pruning advances both marker slots' replay floors before sparse reclamation; offsets never
//! move while producers and publishers are alive. Legacy files are imported only at startup.

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::block::Header;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Txid;
use parking_lot::Mutex;
use sha2::Digest;
use sha2::Sha256;

use crate::udata::CompactBlockProof;

const RECORD_MAGIC: [u8; 8] = *b"BRJNL001";
const PRUNED_MAGIC: [u8; 8] = *b"PRUNED01";
const RECORD_TRAILER: [u8; 8] = *b"ENDJNL01";
const LEGACY_RECORD_VERSION: u16 = 1;
const REPLAY_RECORD_VERSION: u16 = 2;
const RECORD_VERSION: u16 = 3;
const RECORD_HEADER_SIZE: usize = 64;
const STATUS_OFFSET: u64 = 10;
const WAL_MAGIC: [u8; 8] = *b"BRWAL002";
const PUBLICATION_MAGIC: [u8; 8] = *b"BRPUB001";
const PUBLICATION_SUFFIX: &str = ".published";
const INITIALIZE_SUFFIX: &str = ".initialize";
const FOREST_ROWS_SUFFIX: &str = ".forest-rows";
const PUBLICATION_SLOT_SIZE: u64 = 4096;
const PUBLICATION_BYTES: usize = 172;
const MAX_RECORD_BYTES: usize = 512 * 1024 * 1024;
const CLEAN_SHUTDOWN_MARKER: &[u8] = b"BRJNL-CLEAN-1";
const CLEAN_SHUTDOWN_SUFFIX: &str = ".clean";
const CLEAN_SHUTDOWN_TEMP_SUFFIX: &str = ".tmp";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalNodeState {
    pub ready: bool,
    pub spent: bool,
    pub hash: [u8; 32],
}

impl JournalNodeState {
    pub const UNINITIALIZED: Self = Self {
        ready: false,
        spent: false,
        hash: [0; 32],
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalForestDelta {
    pub position: u64,
    pub before: JournalNodeState,
    pub after: JournalNodeState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalIndexDelta {
    pub outpoint: OutPoint,
    pub position: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalEntry {
    pub height: u32,
    pub block_hash: BlockHash,
    pub num_leaves: u64,
    pub previous_block_hash: BlockHash,
    pub forest: Vec<JournalForestDelta>,
    pub removed: Vec<JournalIndexDelta>,
    pub added: Vec<JournalIndexDelta>,
    /// Physical forest layout used by delta positions; absent in legacy records.
    pub forest_rows: Option<u8>,
}

impl JournalEntry {
    pub fn previous_num_leaves(&self) -> Result<u64> {
        self.num_leaves
            .checked_sub(self.added.len() as u64)
            .context("journal addition count exceeds numleaves")
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_entry(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_entry(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalStatus {
    Forward,
    RolledBack,
}

impl JournalStatus {
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Self::Forward),
            1 => Ok(Self::RolledBack),
            _ => bail!("unknown journal status {byte}"),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::Forward => 0,
            Self::RolledBack => 1,
        }
    }
}

/// Everything needed to reconstruct the non-forest stores after publication.
#[derive(Clone, Debug)]
pub struct JournalReplayPayload {
    pub header: Header,
    pub proof: Arc<CompactBlockProof>,
    pub proof_forest_rows: u8,
}

#[derive(Clone, Debug)]
pub struct JournalRecord {
    pub entry: Arc<JournalEntry>,
    pub status: JournalStatus,
    /// Absent only for imported legacy entries and forest-only test fixtures.
    pub replay: Option<Arc<JournalReplayPayload>>,
    offset: u64,
    span: u64,
    checksum: [u8; 32],
}

/// An immutable, complete append boundary, never the file's changing length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalBoundary {
    journal_id: [u8; 32],
    epoch: u64,
    end: u64,
    offset: u64,
    height: u32,
    block_hash: BlockHash,
    checksum: [u8; 32],
}

#[derive(Clone, Copy)]
struct PublicationMarker {
    generation: u64,
    replay_start: u64,
    boundary: JournalBoundary,
}

struct PublicationState {
    marker: Mutex<PublicationMarker>,
    appended_end: AtomicU64,
    published_end: AtomicU64,
    epoch: AtomicU64,
    poisoned: AtomicBool,
}

/// Owns independent descriptors so publication never holds the producer's journal lock.
pub struct JournalPublisher {
    file: File,
    marker_file: File,
    page_size: u64,
    journal_id: [u8; 32],
    shared: Arc<PublicationState>,
}

/// Detached pruning work; the durable replay floor advances before any hole is punched.
pub struct JournalPrune {
    publisher: JournalPublisher,
    replay_start: u64,
    count: usize,
}

pub struct ForestJournal {
    file: File,
    marker_file: File,
    path: PathBuf,
    page_size: u64,
    journal_id: [u8; 32],
    records: Vec<JournalRecord>,
    shared: Arc<PublicationState>,
    needs_replay: bool,
}

impl ForestJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let needs_replay = !take_clean_shutdown_marker(path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open forest journal {}", path.display()))?;
        let mut magic = [0u8; 8];
        let initialized = file.read_exact_at(&mut magic, 0).is_ok() && magic == WAL_MAGIC;
        if !initialized {
            let initializing = append_path_suffix(path, INITIALIZE_SUFFIX).try_exists()?;
            if append_path_suffix(path, PUBLICATION_SUFFIX).try_exists()? && !initializing {
                bail!("publication journal is missing its initialization header");
            }
            file = initialize_journal(path, &file)?;
        }
        let (page_size, journal_id) = read_superblock(&file)?;
        let marker_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(append_path_suffix(path, PUBLICATION_SUFFIX))
            .context("initialized journal is missing its publication marker")?;
        let marker = read_publication_marker(&marker_file, journal_id, page_size)?;
        let file_len = file.metadata()?.len();
        if file_len < marker.boundary.end {
            bail!("published journal data is truncated");
        }
        // Validate only the eligible prefix before mutating the file. A corrupt
        // published record must not cause even a speculative suffix to be lost.
        let records = scan_published(&file, page_size, &marker)?;
        if file_len != marker.boundary.end {
            file.set_len(marker.boundary.end)?;
        }
        let shared = Arc::new(PublicationState {
            marker: Mutex::new(marker),
            appended_end: AtomicU64::new(marker.boundary.end),
            published_end: AtomicU64::new(marker.boundary.end),
            epoch: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
        });
        Ok(Self {
            file,
            marker_file,
            path: path.to_path_buf(),
            page_size,
            journal_id,
            records,
            shared,
            needs_replay,
        })
    }

    /// Only published entries are visible to recovery and rollback consumers.
    pub fn records(&self) -> &[JournalRecord] {
        let end = self.shared.published_end.load(Ordering::Acquire);
        let count = self
            .records
            .partition_point(|record| record.offset + record.span <= end);
        &self.records[..count]
    }

    /// Opening consumes the clean marker, so an interruption always requires recovery.
    pub fn needs_replay(&self) -> bool {
        self.needs_replay
    }

    /// Binds legacy physical positions before the forest can grow. The binding is
    /// immutable for this WAL identity and survives subsequent layout changes.
    /// Call at startup before replay and before exposing the journal to producers.
    pub fn bind_legacy_forest_rows(&mut self, rows: u8) -> Result<()> {
        if rows > 63 {
            bail!("invalid legacy forest rows {rows}");
        }
        if !self
            .records
            .iter()
            .any(|record| record.entry.forest_rows.is_none())
        {
            return Ok(());
        }
        let path = append_path_suffix(&self.path, FOREST_ROWS_SUFFIX);
        let rows = match File::open(&path) {
            Ok(file) => {
                let mut bytes = [0u8; 65];
                if file.metadata()?.len() != bytes.len() as u64 {
                    bail!("invalid legacy forest layout binding length");
                }
                file.read_exact_at(&mut bytes, 0)?;
                if bytes[..32] != self.journal_id
                    || bytes[32] > 63
                    || Sha256::digest(&bytes[..33]).as_slice() != &bytes[33..]
                {
                    bail!("invalid legacy forest layout binding");
                }
                bytes[32]
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary_path = append_path_suffix(&path, CLEAN_SHUTDOWN_TEMP_SUFFIX);
                let file = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&temporary_path)?;
                let mut bytes = [0u8; 65];
                bytes[..32].copy_from_slice(&self.journal_id);
                bytes[32] = rows;
                let checksum = Sha256::digest(&bytes[..33]);
                bytes[33..].copy_from_slice(&checksum);
                file.write_all_at(&bytes, 0)?;
                file.sync_all()?;
                std::fs::rename(&temporary_path, &path)?;
                sync_parent_directory(&path)?;
                rows
            }
            Err(error) => return Err(error.into()),
        };
        for record in &mut self.records {
            if record.entry.forest_rows.is_none() {
                Arc::make_mut(&mut record.entry).forest_rows = Some(rows);
            }
        }
        Ok(())
    }

    /// Records that every journal entry has been reflected in the durable forest state.
    ///
    /// Callers must first flush the forest, leaf map, journal, and all related durable state.
    pub fn mark_clean_shutdown(&self) -> Result<()> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            bail!("cannot mark a failed publication clean; reopen the journal");
        }
        if self.shared.appended_end.load(Ordering::Acquire)
            != self.shared.published_end.load(Ordering::Acquire)
        {
            bail!("cannot mark an unpublished journal tail clean");
        }
        let marker_path = clean_shutdown_marker_path(&self.path);
        let temporary_path = append_path_suffix(&marker_path, CLEAN_SHUTDOWN_TEMP_SUFFIX);
        let mut marker = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary_path)
            .with_context(|| {
                format!(
                    "failed to create clean-shutdown marker {}",
                    temporary_path.display()
                )
            })?;
        marker.write_all(CLEAN_SHUTDOWN_MARKER)?;
        marker.sync_all()?;
        drop(marker);
        std::fs::rename(&temporary_path, &marker_path).with_context(|| {
            format!(
                "failed to install clean-shutdown marker {}",
                marker_path.display()
            )
        })?;
        sync_parent_directory(&marker_path)?;
        Ok(())
    }

    pub fn latest_forward(&self) -> Option<(usize, &JournalRecord)> {
        self.records()
            .iter()
            .enumerate()
            .rev()
            .find(|(_, record)| record.status == JournalStatus::Forward)
    }

    /// Appends the full redo payload without flushing any file or directory.
    pub fn append_block(
        &mut self,
        entry: impl Into<Arc<JournalEntry>>,
        header: Header,
        proof: Arc<CompactBlockProof>,
        proof_forest_rows: u8,
    ) -> Result<JournalBoundary> {
        let entry = entry.into();
        if entry.forest_rows.is_none() || proof_forest_rows > 63 {
            bail!("journal replay requires valid physical and proof forest layouts");
        }
        if header.block_hash() != entry.block_hash
            || header.prev_blockhash != entry.previous_block_hash
        {
            bail!("journal replay header does not match its forest entry");
        }
        let replay = Arc::new(JournalReplayPayload {
            header,
            proof,
            proof_forest_rows,
        });
        let mut payload = vec![0; 4];
        encode_entry_into(&entry, &mut payload)?;
        let entry_len = u32::try_from(payload.len() - 4).context("journal entry exceeds u32")?;
        payload[..4].copy_from_slice(&entry_len.to_le_bytes());
        replay.header.consensus_encode(&mut payload)?;
        payload.push(replay.proof_forest_rows);
        replay.proof.consensus_encode(&mut payload)?;
        self.append_payload(entry, Some(replay), &payload, RECORD_VERSION)?;
        Ok(self.boundary())
    }

    /// Forest-only fixtures must explicitly publish, just like production appenders.
    #[cfg(test)]
    pub fn append(&mut self, entry: impl Into<Arc<JournalEntry>>) -> Result<usize> {
        let entry = entry.into();
        let payload = entry.encode()?;
        self.append_payload(entry, None, &payload, LEGACY_RECORD_VERSION)
    }

    fn append_payload(
        &mut self,
        entry: Arc<JournalEntry>,
        replay: Option<Arc<JournalReplayPayload>>,
        payload: &[u8],
        version: u16,
    ) -> Result<usize> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            bail!("journal publication failed; reopen before appending");
        }
        let offset = self.shared.appended_end.load(Ordering::Acquire);
        let record = match write_record(
            &self.file,
            self.page_size,
            offset,
            entry,
            replay,
            payload,
            version,
        ) {
            Ok(record) => record,
            Err(error) => {
                // Never turn an append failure into a producer-side fsync.
                if let Err(truncate) = self.file.set_len(offset) {
                    self.shared.poisoned.store(true, Ordering::Release);
                    return Err(
                        error.context(format!("also failed to remove partial append: {truncate}"))
                    );
                }
                return Err(error);
            }
        };
        let end = record.offset + record.span;
        self.records.push(record);
        self.shared.appended_end.store(end, Ordering::Release);
        self.needs_replay = true;
        Ok(self.records.len() - 1)
    }

    pub fn boundary(&self) -> JournalBoundary {
        let epoch = self.shared.epoch.load(Ordering::Acquire);
        self.records.last().map_or_else(
            || empty_boundary(self.journal_id, epoch, self.page_size),
            |record| record_boundary(record, self.journal_id, epoch),
        )
    }

    pub fn publisher(&self) -> Result<JournalPublisher> {
        Ok(JournalPublisher {
            file: self.file.try_clone()?,
            marker_file: self.marker_file.try_clone()?,
            page_size: self.page_size,
            journal_id: self.journal_id,
            shared: Arc::clone(&self.shared),
        })
    }

    /// Flushes data only. This deliberately does not publish an appended suffix.
    pub fn flush(&self) -> Result<()> {
        self.file
            .sync_data()
            .with_context(|| format!("failed to flush forest journal {}", self.path.display()))
    }

    /// Reorg barrier: callers first drain publication/application work.
    pub fn discard_unpublished(&mut self) -> Result<()> {
        let marker = self.shared.marker.lock();
        if self.shared.poisoned.load(Ordering::Acquire) {
            bail!("cannot discard after a failed publication; reopen the journal");
        }
        let end = marker.boundary.end;
        self.file.set_len(end)?;
        self.records.truncate(
            self.records
                .partition_point(|record| record.offset + record.span <= end),
        );
        self.shared.appended_end.store(end, Ordering::Release);
        self.shared.epoch.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Durably changes a published entry into an undo operation before state is rolled back.
    pub fn mark_rolled_back(&mut self, index: usize) -> Result<()> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            bail!("cannot roll back after a failed publication; reopen the journal");
        }
        if self.shared.appended_end.load(Ordering::Acquire)
            != self.shared.published_end.load(Ordering::Acquire)
        {
            bail!("discard unpublished entries before rolling back");
        }
        if index >= self.records().len() {
            bail!("journal record index is not published");
        }
        let record = &mut self.records[index];
        let result = self
            .file
            .write_all_at(
                &[JournalStatus::RolledBack.to_byte()],
                record.offset + STATUS_OFFSET,
            )
            .and_then(|()| self.file.sync_data());
        if let Err(error) = result {
            self.shared.poisoned.store(true, Ordering::Release);
            return Err(error).context("failed to publish journal rollback status");
        }
        record.status = JournalStatus::RolledBack;
        self.needs_replay = true;
        Ok(())
    }

    /// Captures pruning under the metadata lock; call `finish` after releasing that lock.
    ///
    /// Keep the last physical record even when all entries are rolled back, because the
    /// publication marker authenticates that record. No runtime compaction moves offsets.
    pub fn prepare_prune(&mut self, keep: usize) -> Result<Option<JournalPrune>> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            bail!("cannot prepare pruning after a failed publication; reopen the journal");
        }
        let records = self.records();
        let mut forward = 0;
        let mut count = 0;
        for (index, record) in records.iter().enumerate().rev() {
            if record.status == JournalStatus::Forward {
                forward += 1;
                if forward >= keep.max(1) {
                    count = index;
                    break;
                }
            }
        }
        if count == 0 {
            return Ok(None);
        }
        let pruning = JournalPrune {
            publisher: self.publisher()?,
            replay_start: records[count].offset,
            count,
        };
        self.records.drain(..count);
        Ok(Some(pruning))
    }
}

impl JournalPublisher {
    /// Makes exactly the captured prefix durable: data flush, marker bump, marker flush.
    ///
    /// A producer may append the next window during either fsync. Neither the file length
    /// nor those newer records are used to choose the published end.
    pub fn publish(&self, boundary: JournalBoundary) -> Result<()> {
        let mut marker = self.shared.marker.lock();
        if self.shared.poisoned.load(Ordering::Acquire) {
            bail!("journal publication previously failed; reopen the journal");
        }
        if boundary.journal_id != self.journal_id
            || boundary.epoch != self.shared.epoch.load(Ordering::Acquire)
            || boundary.end < marker.boundary.end
            || boundary.end > self.shared.appended_end.load(Ordering::Acquire)
        {
            bail!("stale or invalid journal publication boundary");
        }
        if boundary.end == marker.boundary.end {
            let mut current = marker.boundary;
            current.epoch = boundary.epoch;
            if current != boundary {
                bail!("journal publication boundary conflicts with the durable record");
            }
            return Ok(());
        }
        validate_boundary(&self.file, self.page_size, &boundary)?;
        let result = (|| -> Result<()> {
            self.file
                .sync_data()
                .context("failed to flush journal before publication")?;
            let next = PublicationMarker {
                generation: marker
                    .generation
                    .checked_add(1)
                    .context("publication generation overflow")?,
                replay_start: marker.replay_start,
                boundary,
            };
            write_publication_marker(&self.marker_file, &next)?;
            *marker = next;
            self.shared
                .published_end
                .store(boundary.end, Ordering::Release);
            Ok(())
        })();
        if result.is_err() {
            // A failed fsync has an unknown durable outcome. In particular, do not let a
            // later discard truncate a prefix whose marker may actually have reached disk.
            self.shared.poisoned.store(true, Ordering::Release);
        }
        result
    }
}

impl JournalPrune {
    pub fn finish(self) -> Result<usize> {
        let mut marker = self.publisher.shared.marker.lock();
        if self.publisher.shared.poisoned.load(Ordering::Acquire) {
            bail!("cannot prune after a failed publication; reopen the journal");
        }
        if self.replay_start <= marker.replay_start {
            return Ok(self.count);
        }
        if self.replay_start > marker.boundary.offset {
            bail!("pruning would discard the published boundary record");
        }
        let old_start = marker.replay_start;
        let next = PublicationMarker {
            generation: marker
                .generation
                .checked_add(1)
                .context("publication generation overflow")?,
            replay_start: self.replay_start,
            boundary: marker.boundary,
        };
        if let Err(error) = write_publication_marker(&self.publisher.marker_file, &next) {
            self.publisher
                .shared
                .poisoned
                .store(true, Ordering::Release);
            return Err(error);
        }
        *marker = next;
        // Both fallback slots must exclude the prefix before it can be deallocated.
        let next = PublicationMarker {
            generation: marker
                .generation
                .checked_add(1)
                .context("publication generation overflow")?,
            ..*marker
        };
        if let Err(error) = write_publication_marker(&self.publisher.marker_file, &next) {
            self.publisher
                .shared
                .poisoned
                .store(true, Ordering::Release);
            return Err(error);
        }
        *marker = next;
        drop(marker);
        let result = unsafe {
            libc::fallocate(
                std::os::fd::AsRawFd::as_raw_fd(&self.publisher.file),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                old_start as libc::off_t,
                (self.replay_start - old_start) as libc::off_t,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL)
            ) {
                return Err(error).context("failed to reclaim pruned journal pages");
            }
        }
        // Unsupported filesystems retain allocated pages, but recovery still skips them.
        Ok(self.count)
    }
}

fn empty_boundary(journal_id: [u8; 32], epoch: u64, page_size: u64) -> JournalBoundary {
    JournalBoundary {
        journal_id,
        epoch,
        end: page_size,
        offset: 0,
        height: 0,
        block_hash: BlockHash::all_zeros(),
        checksum: [0; 32],
    }
}

fn record_boundary(record: &JournalRecord, journal_id: [u8; 32], epoch: u64) -> JournalBoundary {
    JournalBoundary {
        journal_id,
        epoch,
        end: record.offset + record.span,
        offset: record.offset,
        height: record.entry.height,
        block_hash: record.entry.block_hash,
        checksum: record.checksum,
    }
}

fn write_record(
    file: &File,
    page_size: u64,
    offset: u64,
    entry: Arc<JournalEntry>,
    replay: Option<Arc<JournalReplayPayload>>,
    payload: &[u8],
    version: u16,
) -> Result<JournalRecord> {
    if payload.len() > MAX_RECORD_BYTES {
        bail!("journal entry is too large: {} bytes", payload.len());
    }
    let used = RECORD_HEADER_SIZE
        .checked_add(payload.len())
        .and_then(|length| length.checked_add(RECORD_TRAILER.len()))
        .context("journal record length overflow")?;
    let span = align_up(used as u64, page_size).context("journal span overflow")?;
    let end = offset
        .checked_add(span)
        .context("journal file length overflow")?;
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let mut header = [0u8; RECORD_HEADER_SIZE];
    header[..8].copy_from_slice(&RECORD_MAGIC);
    header[8..10].copy_from_slice(&version.to_le_bytes());
    header[10] = JournalStatus::Forward.to_byte();
    header[16..24].copy_from_slice(&span.to_le_bytes());
    header[24..32].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    header[32..64].copy_from_slice(&checksum);
    file.set_len(end)?;
    file.write_all_at(&header, offset)?;
    file.write_all_at(payload, offset + RECORD_HEADER_SIZE as u64)?;
    file.write_all_at(
        &RECORD_TRAILER,
        offset + RECORD_HEADER_SIZE as u64 + payload.len() as u64,
    )?;
    Ok(JournalRecord {
        entry,
        status: JournalStatus::Forward,
        replay,
        offset,
        span,
        checksum,
    })
}

fn read_record_header(
    file: &File,
    page_size: u64,
    offset: u64,
    end: u64,
) -> Result<[u8; RECORD_HEADER_SIZE]> {
    let mut header = [0u8; RECORD_HEADER_SIZE];
    file.read_exact_at(&mut header, offset)
        .context("published journal header is truncated")?;
    if header[..8] != RECORD_MAGIC {
        bail!("invalid published journal magic at offset {offset}");
    }
    let version = u16::from_le_bytes(header[8..10].try_into().unwrap());
    if !matches!(
        version,
        LEGACY_RECORD_VERSION | REPLAY_RECORD_VERSION | RECORD_VERSION
    ) {
        bail!("unsupported journal version {version}");
    }
    JournalStatus::from_byte(header[10])?;
    let span = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let payload_len = u64::from_le_bytes(header[24..32].try_into().unwrap());
    if payload_len > MAX_RECORD_BYTES as u64
        || align_up(
            RECORD_HEADER_SIZE as u64 + payload_len + RECORD_TRAILER.len() as u64,
            page_size,
        ) != Some(span)
        || offset
            .checked_add(span)
            .is_none_or(|record_end| record_end > end)
    {
        bail!("invalid published journal span at offset {offset}");
    }
    let mut trailer = [0u8; 8];
    file.read_exact_at(
        &mut trailer,
        offset + RECORD_HEADER_SIZE as u64 + payload_len,
    )
    .context("published journal trailer is truncated")?;
    if trailer != RECORD_TRAILER {
        bail!("invalid published journal trailer at offset {offset}");
    }
    Ok(header)
}

fn read_record(file: &File, page_size: u64, offset: u64, end: u64) -> Result<JournalRecord> {
    let header = read_record_header(file, page_size, offset, end)?;
    let payload_len = u64::from_le_bytes(header[24..32].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; payload_len];
    file.read_exact_at(&mut payload, offset + RECORD_HEADER_SIZE as u64)?;
    let checksum: [u8; 32] = Sha256::digest(&payload).into();
    if checksum != header[32..64] {
        bail!("published journal checksum mismatch at offset {offset}");
    }
    let version = u16::from_le_bytes(header[8..10].try_into().unwrap());
    let (entry, replay) = if version == LEGACY_RECORD_VERSION {
        (JournalEntry::decode(&payload)?, None)
    } else {
        let mut reader = payload.as_slice();
        let entry_len = take_u32(&mut reader)? as usize;
        let entry_bytes = reader
            .get(..entry_len)
            .context("journal forest payload is truncated")?;
        let entry = JournalEntry::decode(entry_bytes)?;
        if version == RECORD_VERSION && entry.forest_rows.is_none() {
            bail!("journal replay is missing its physical forest layout");
        }
        reader = &reader[entry_len..];
        let header = Header::consensus_decode(&mut reader)?;
        let proof_forest_rows = take_array::<1>(&mut reader)?[0];
        if proof_forest_rows > 63 {
            bail!("invalid journal proof forest rows {proof_forest_rows}");
        }
        let proof = CompactBlockProof::consensus_decode(&mut reader)?;
        if !reader.is_empty() {
            bail!("journal replay payload has trailing bytes");
        }
        if header.block_hash() != entry.block_hash
            || header.prev_blockhash != entry.previous_block_hash
        {
            bail!("journal replay header does not match its forest entry");
        }
        (
            entry,
            Some(Arc::new(JournalReplayPayload {
                header,
                proof: Arc::new(proof),
                proof_forest_rows,
            })),
        )
    };
    Ok(JournalRecord {
        entry: Arc::new(entry),
        status: JournalStatus::from_byte(header[10])?,
        replay,
        offset,
        span: u64::from_le_bytes(header[16..24].try_into().unwrap()),
        checksum,
    })
}

fn validate_boundary(file: &File, page_size: u64, boundary: &JournalBoundary) -> Result<()> {
    let header = read_record_header(file, page_size, boundary.offset, boundary.end)?;
    let span = u64::from_le_bytes(header[16..24].try_into().unwrap());
    if boundary.offset + span != boundary.end || header[32..64] != boundary.checksum {
        bail!("publication boundary does not match its complete record");
    }
    // Check the captured checksum without allocating or decoding another block/proof.
    let payload_len = u64::from_le_bytes(header[24..32].try_into().unwrap());
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut read = 0;
    while read < payload_len {
        let count = (payload_len - read).min(buffer.len() as u64) as usize;
        file.read_exact_at(
            &mut buffer[..count],
            boundary.offset + RECORD_HEADER_SIZE as u64 + read,
        )?;
        digest.update(&buffer[..count]);
        read += count as u64;
    }
    if digest.finalize().as_slice() != boundary.checksum {
        bail!("publication boundary record checksum mismatch");
    }
    let version = u16::from_le_bytes(header[8..10].try_into().unwrap());
    let entry_offset = boundary.offset
        + RECORD_HEADER_SIZE as u64
        + if version != LEGACY_RECORD_VERSION {
            4
        } else {
            0
        };
    let mut identity = [0u8; 44];
    file.read_exact_at(&mut identity, entry_offset)?;
    if identity[..32] != boundary.block_hash.to_byte_array()
        || u32::from_le_bytes(identity[40..44].try_into().unwrap()) != boundary.height
    {
        bail!("publication boundary height or hash does not match its record");
    }
    Ok(())
}

fn scan_published(
    file: &File,
    page_size: u64,
    marker: &PublicationMarker,
) -> Result<Vec<JournalRecord>> {
    let mut records = Vec::new();
    let mut offset = marker.replay_start;
    while offset < marker.boundary.end {
        let record = read_record(file, page_size, offset, marker.boundary.end)?;
        offset += record.span;
        records.push(record);
    }
    let actual = records.last().map_or_else(
        || empty_boundary(marker.boundary.journal_id, 0, page_size),
        |record| record_boundary(record, marker.boundary.journal_id, 0),
    );
    if actual != marker.boundary {
        bail!("published boundary does not match the final validated journal record");
    }
    Ok(records)
}

fn read_superblock(file: &File) -> Result<(u64, [u8; 32])> {
    let mut bytes = [0u8; 96];
    file.read_exact_at(&mut bytes, 0)
        .context("journal initialization header is truncated")?;
    if bytes[..8] != WAL_MAGIC || Sha256::digest(&bytes[..64]).as_slice() != &bytes[64..96] {
        bail!("journal initialization header is corrupt");
    }
    let page_size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if !(4096..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        bail!("invalid journal page size {page_size}");
    }
    Ok((page_size, bytes[16..48].try_into().unwrap()))
}

fn encode_publication_marker(marker: &PublicationMarker) -> [u8; PUBLICATION_BYTES] {
    let mut bytes = [0u8; PUBLICATION_BYTES];
    bytes[..8].copy_from_slice(&PUBLICATION_MAGIC);
    bytes[8..40].copy_from_slice(&marker.boundary.journal_id);
    bytes[40..48].copy_from_slice(&marker.generation.to_le_bytes());
    bytes[48..56].copy_from_slice(&marker.replay_start.to_le_bytes());
    bytes[56..64].copy_from_slice(&marker.boundary.end.to_le_bytes());
    bytes[64..72].copy_from_slice(&marker.boundary.offset.to_le_bytes());
    bytes[72..76].copy_from_slice(&marker.boundary.height.to_le_bytes());
    bytes[76..108].copy_from_slice(&marker.boundary.block_hash.to_byte_array());
    bytes[108..140].copy_from_slice(&marker.boundary.checksum);
    let checksum = Sha256::digest(&bytes[..140]);
    bytes[140..172].copy_from_slice(&checksum);
    bytes
}

fn write_publication_marker(file: &File, marker: &PublicationMarker) -> Result<()> {
    file.write_all_at(
        &encode_publication_marker(marker),
        (marker.generation % 2) * PUBLICATION_SLOT_SIZE,
    )?;
    file.sync_data()
        .context("failed to flush journal publication marker")
}

fn read_publication_marker(
    file: &File,
    journal_id: [u8; 32],
    page_size: u64,
) -> Result<PublicationMarker> {
    let mut valid = [None; 2];
    for slot in 0..2 {
        let mut bytes = [0u8; PUBLICATION_BYTES];
        if file
            .read_exact_at(&mut bytes, slot * PUBLICATION_SLOT_SIZE)
            .is_err()
            || bytes[..8] != PUBLICATION_MAGIC
            || bytes[8..40] != journal_id
            || Sha256::digest(&bytes[..140]).as_slice() != &bytes[140..172]
        {
            continue;
        }
        let marker = PublicationMarker {
            generation: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            replay_start: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            boundary: JournalBoundary {
                journal_id,
                epoch: 0,
                end: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
                offset: u64::from_le_bytes(bytes[64..72].try_into().unwrap()),
                height: u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
                block_hash: BlockHash::from_byte_array(bytes[76..108].try_into().unwrap()),
                checksum: bytes[108..140].try_into().unwrap(),
            },
        };
        if marker.generation % 2 != slot
            || marker.replay_start < page_size
            || marker.replay_start % page_size != 0
            || marker.boundary.end < marker.replay_start
            || marker.boundary.end % page_size != 0
            || (marker.boundary.end > page_size
                && (marker.boundary.offset < marker.replay_start
                    || marker.boundary.offset >= marker.boundary.end
                    || marker.boundary.offset % page_size != 0))
        {
            bail!("invalid checksummed journal publication boundary");
        }
        valid[slot as usize] = Some(marker);
    }
    if let [Some(first), Some(second)] = valid {
        let (older, newer) = if first.generation < second.generation {
            (first, second)
        } else {
            (second, first)
        };
        if newer.boundary.end < older.boundary.end
            || newer.replay_start < older.replay_start
            || (newer.boundary.end == older.boundary.end && newer.boundary != older.boundary)
        {
            bail!("journal publication slots are not monotonic");
        }
        return Ok(newer);
    }
    valid[0]
        .or(valid[1])
        .context("initialized journal has no valid publication marker")
}

/// Imports legacy records once, without changing the old inode until both new files are durable.
///
/// The temporary inode also identifies an interrupted initialization. A permanently initialized
/// WAL never falls back to legacy scanning when its publication marker is absent or damaged.
fn initialize_journal(path: &Path, legacy: &File) -> Result<File> {
    let page_size = page_size();
    let legacy_records = scan_legacy(legacy, page_size)?;
    let temporary_path = append_path_suffix(path, INITIALIZE_SUFFIX);
    let temporary = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&temporary_path)?;
    let mut journal_id = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut journal_id)?;
    let mut superblock = [0u8; 96];
    superblock[..8].copy_from_slice(&WAL_MAGIC);
    superblock[8..16].copy_from_slice(&page_size.to_le_bytes());
    superblock[16..48].copy_from_slice(&journal_id);
    let checksum = Sha256::digest(&superblock[..64]);
    superblock[64..96].copy_from_slice(&checksum);
    temporary.set_len(page_size)?;
    temporary.write_all_at(&superblock, 0)?;
    let mut boundary = empty_boundary(journal_id, 0, page_size);
    for legacy_record in legacy_records {
        let payload = legacy_record.entry.encode()?;
        let record = write_record(
            &temporary,
            page_size,
            boundary.end,
            legacy_record.entry,
            None,
            &payload,
            LEGACY_RECORD_VERSION,
        )?;
        if legacy_record.status == JournalStatus::RolledBack {
            temporary.write_all_at(
                &[JournalStatus::RolledBack.to_byte()],
                record.offset + STATUS_OFFSET,
            )?;
        }
        boundary = record_boundary(&record, journal_id, 0);
    }
    temporary.sync_all()?;
    // Persist the temporary name before creating a marker which may outlive a crash.
    sync_parent_directory(path)?;
    let marker_path = append_path_suffix(path, PUBLICATION_SUFFIX);
    let marker_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&marker_path)?;
    marker_file.set_len(PUBLICATION_SLOT_SIZE * 2)?;
    for generation in 0..2 {
        write_publication_marker(
            &marker_file,
            &PublicationMarker {
                generation,
                replay_start: page_size,
                boundary,
            },
        )?;
    }
    sync_parent_directory(&marker_path)?;
    std::fs::rename(&temporary_path, path)?;
    sync_parent_directory(path)?;
    Ok(temporary)
}

fn scan_legacy(file: &File, page_size: u64) -> Result<Vec<JournalRecord>> {
    let file_len = file.metadata()?.len();
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < file_len {
        let mut header = [0u8; RECORD_HEADER_SIZE];
        if file.read_exact_at(&mut header, offset).is_err() {
            break;
        }
        if header[..8] == [0; 8] {
            offset += page_size;
            continue;
        }
        if header[..8] == PRUNED_MAGIC {
            let span = u64::from_le_bytes(header[16..24].try_into().unwrap());
            if span == 0
                || span % page_size != 0
                || offset.checked_add(span).is_none_or(|end| end > file_len)
            {
                break;
            }
            offset += span;
            continue;
        }
        if header[..8] != RECORD_MAGIC {
            if offset == 0 {
                bail!("unrecognized journal format; refusing legacy import");
            }
            break;
        }
        if u16::from_le_bytes(header[8..10].try_into().unwrap()) != LEGACY_RECORD_VERSION {
            bail!("publication record without an initialization header");
        }
        match read_record(file, page_size, offset, file_len) {
            Ok(record) => {
                offset += record.span;
                records.push(record);
            }
            Err(error) => {
                let span = u64::from_le_bytes(header[16..24].try_into().unwrap());
                if span != 0 && offset.checked_add(span).is_some_and(|end| end < file_len) {
                    return Err(error).context("corrupt interior legacy journal record");
                }
                // Preserve the legacy format's interrupted-tail semantics only during import.
                break;
            }
        }
    }
    Ok(records)
}

fn take_clean_shutdown_marker(path: &Path) -> Result<bool> {
    let marker_path = clean_shutdown_marker_path(path);
    let marker = match File::open(&marker_path) {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read clean-shutdown marker {}",
                    marker_path.display()
                )
            });
        }
    };
    let valid = if marker.metadata()?.len() == CLEAN_SHUTDOWN_MARKER.len() as u64 {
        let mut bytes = [0u8; CLEAN_SHUTDOWN_MARKER.len()];
        marker.read_exact_at(&mut bytes, 0)?;
        bytes.as_slice() == CLEAN_SHUTDOWN_MARKER
    } else {
        false
    };
    std::fs::remove_file(&marker_path).with_context(|| {
        format!(
            "failed to consume clean-shutdown marker {}",
            marker_path.display()
        )
    })?;
    sync_parent_directory(&marker_path)?;
    Ok(valid)
}

fn clean_shutdown_marker_path(path: &Path) -> PathBuf {
    append_path_suffix(path, CLEAN_SHUTDOWN_SUFFIX)
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .with_context(|| format!("failed to open journal parent {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync journal parent {}", parent.display()))
}

fn encode_entry(entry: &JournalEntry) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    encode_entry_into(entry, &mut bytes)?;
    Ok(bytes)
}

fn encode_entry_into(entry: &JournalEntry, bytes: &mut Vec<u8>) -> Result<()> {
    bytes.extend_from_slice(&entry.block_hash.to_byte_array());
    bytes.extend_from_slice(&entry.num_leaves.to_le_bytes());
    bytes.extend_from_slice(&entry.height.to_le_bytes());
    bytes.extend_from_slice(&entry.previous_block_hash.to_byte_array());
    push_len(bytes, entry.forest.len())?;
    for delta in &entry.forest {
        bytes.extend_from_slice(&delta.position.to_le_bytes());
        encode_state(bytes, delta.before);
        encode_state(bytes, delta.after);
    }
    push_len(bytes, entry.removed.len())?;
    for delta in &entry.removed {
        encode_index_delta(bytes, *delta);
    }
    push_len(bytes, entry.added.len())?;
    for delta in &entry.added {
        encode_index_delta(bytes, *delta);
    }
    if let Some(rows) = entry.forest_rows {
        if rows > 63 {
            bail!("invalid journal forest rows {rows}");
        }
        bytes.push(rows);
    }
    Ok(())
}

fn decode_entry(bytes: &[u8]) -> Result<JournalEntry> {
    let mut reader = bytes;
    let block_hash = BlockHash::from_byte_array(take_array(&mut reader)?);
    let num_leaves = take_u64(&mut reader)?;
    let height = take_u32(&mut reader)?;
    let previous_block_hash = BlockHash::from_byte_array(take_array(&mut reader)?);
    let forest_len = take_len(&mut reader, 74)?;
    let mut forest = Vec::new();
    forest
        .try_reserve_exact(forest_len)
        .context("journal forest delta allocation failed")?;
    for _ in 0..forest_len {
        forest.push(JournalForestDelta {
            position: take_u64(&mut reader)?,
            before: decode_state(&mut reader)?,
            after: decode_state(&mut reader)?,
        });
    }
    let removed_len = take_len(&mut reader, 44)?;
    let mut removed = Vec::new();
    removed
        .try_reserve_exact(removed_len)
        .context("journal removed-index allocation failed")?;
    for _ in 0..removed_len {
        removed.push(decode_index_delta(&mut reader)?);
    }
    let added_len = take_len(&mut reader, 44)?;
    let mut added = Vec::new();
    added
        .try_reserve_exact(added_len)
        .context("journal added-index allocation failed")?;
    for _ in 0..added_len {
        added.push(decode_index_delta(&mut reader)?);
    }
    let forest_rows = match reader {
        [] => None,
        [rows] if *rows <= 63 => Some(*rows),
        _ => bail!("journal entry has invalid forest layout or trailing bytes"),
    };
    Ok(JournalEntry {
        height,
        block_hash,
        num_leaves,
        previous_block_hash,
        forest,
        removed,
        added,
        forest_rows,
    })
}

fn encode_state(bytes: &mut Vec<u8>, state: JournalNodeState) {
    bytes.push(u8::from(state.ready) | (u8::from(state.spent) << 1));
    bytes.extend_from_slice(&state.hash);
}

fn decode_state(reader: &mut &[u8]) -> Result<JournalNodeState> {
    let flags = take_array::<1>(reader)?[0];
    if flags & !0b11 != 0 {
        bail!("journal node has unknown flags {flags:#x}");
    }
    Ok(JournalNodeState {
        ready: flags & 1 != 0,
        spent: flags & 2 != 0,
        hash: take_array(reader)?,
    })
}

fn encode_index_delta(bytes: &mut Vec<u8>, delta: JournalIndexDelta) {
    bytes.extend_from_slice(&delta.outpoint.txid.to_byte_array());
    bytes.extend_from_slice(&delta.outpoint.vout.to_le_bytes());
    bytes.extend_from_slice(&delta.position.to_le_bytes());
}

fn decode_index_delta(reader: &mut &[u8]) -> Result<JournalIndexDelta> {
    Ok(JournalIndexDelta {
        outpoint: OutPoint {
            txid: Txid::from_byte_array(take_array(reader)?),
            vout: take_u32(reader)?,
        },
        position: take_u64(reader)?,
    })
}

fn push_len(bytes: &mut Vec<u8>, length: usize) -> Result<()> {
    bytes.extend_from_slice(
        &u32::try_from(length)
            .context("journal vector exceeds u32")?
            .to_le_bytes(),
    );
    Ok(())
}

fn take_len(reader: &mut &[u8], element_size: usize) -> Result<usize> {
    let length = take_u32(reader)? as usize;
    if length > reader.len() / element_size {
        bail!(
            "journal vector length {length} exceeds remaining {}-byte payload",
            reader.len()
        );
    }
    Ok(length)
}

fn take_u32(reader: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(take_array(reader)?))
}

fn take_u64(reader: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(take_array(reader)?))
}

fn take_array<const N: usize>(reader: &mut &[u8]) -> Result<[u8; N]> {
    let bytes = reader
        .get(..N)
        .context("journal entry ended unexpectedly")?;
    *reader = &reader[N..];
    Ok(bytes.try_into().unwrap())
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|value| value / alignment * alignment)
}

fn page_size() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value > 0 {
        value as u64
    } else {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(height: u32) -> JournalEntry {
        JournalEntry {
            height,
            block_hash: BlockHash::from_byte_array([height as u8; 32]),
            num_leaves: 20 + height as u64,
            previous_block_hash: BlockHash::from_byte_array([height.saturating_sub(1) as u8; 32]),
            forest: vec![JournalForestDelta {
                position: 7,
                before: JournalNodeState::UNINITIALIZED,
                after: JournalNodeState {
                    ready: true,
                    spent: false,
                    hash: [3; 32],
                },
            }],
            removed: vec![JournalIndexDelta {
                outpoint: OutPoint {
                    txid: Txid::from_byte_array([4; 32]),
                    vout: 5,
                },
                position: 6,
            }],
            added: vec![JournalIndexDelta {
                outpoint: OutPoint {
                    txid: Txid::from_byte_array([7; 32]),
                    vout: 8,
                },
                position: 20,
            }],
            forest_rows: None,
        }
    }

    struct Fixture {
        root: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("bridge-journal-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self {
                path: root.join("journal"),
                root,
            }
        }

        fn open(&self) -> ForestJournal {
            ForestJournal::open(&self.path).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn publish(journal: &ForestJournal) {
        journal
            .publisher()
            .unwrap()
            .publish(journal.boundary())
            .unwrap();
    }

    fn proof() -> Arc<CompactBlockProof> {
        Arc::new(CompactBlockProof {
            proof: crate::udata::BatchProof {
                targets: vec![bitcoin::consensus::encode::VarInt(7)],
                hashes: vec![BlockHash::from_byte_array([31; 32])],
            },
            leaves: vec![crate::udata::CompactLeafData {
                header_code: 21,
                amount: 42_000,
                spk_ty: crate::udata::ScriptPubkeyType::Other(vec![0x51].into_boxed_slice()),
            }],
        })
    }

    fn append_block(journal: &mut ForestJournal, height: u32) -> JournalBoundary {
        let mut header =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header;
        header.nonce = height;
        let mut entry = entry(height);
        entry.block_hash = header.block_hash();
        entry.previous_block_hash = header.prev_blockhash;
        entry.forest_rows = Some(8);
        journal.append_block(entry, header, proof(), 8).unwrap()
    }

    #[test]
    fn malformed_entry_counts_are_bounded_by_available_payload() {
        let mut empty = entry(1);
        empty.forest.clear();
        empty.removed.clear();
        empty.added.clear();
        for count_offset in [76, 80, 84] {
            let mut bytes = empty.encode().unwrap();
            bytes[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(JournalEntry::decode(&bytes).is_err());
        }
        let mut bytes = empty.encode().unwrap();
        bytes.push(64);
        assert!(JournalEntry::decode(&bytes).is_err());
    }

    #[test]
    fn failed_rollback_write_requires_reopen() {
        let fixture = Fixture::new("failed-rollback-write");
        let mut journal = fixture.open();
        journal.append(entry(1)).unwrap();
        publish(&journal);
        journal.file = File::open(&fixture.path).unwrap();
        assert!(journal.mark_rolled_back(0).is_err());
        assert!(journal.mark_clean_shutdown().is_err());
        assert!(journal.append(entry(2)).is_err());
        drop(journal);
        assert_eq!(fixture.open().records()[0].status, JournalStatus::Forward);
    }

    #[test]
    fn previous_replay_version_retains_proof_and_binds_legacy_positions() {
        let fixture = Fixture::new("v2-replay");
        let mut journal = fixture.open();
        let header = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header;
        let mut legacy = entry(1);
        legacy.block_hash = header.block_hash();
        legacy.previous_block_hash = header.prev_blockhash;
        let encoded = legacy.encode().unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        payload.extend_from_slice(&encoded);
        header.consensus_encode(&mut payload).unwrap();
        payload.push(8);
        proof().consensus_encode(&mut payload).unwrap();
        journal
            .append_payload(Arc::new(legacy), None, &payload, REPLAY_RECORD_VERSION)
            .unwrap();
        publish(&journal);
        drop(journal);

        let mut journal = fixture.open();
        assert_eq!(journal.records()[0].entry.forest_rows, None);
        assert_eq!(journal.records()[0].replay.as_ref().unwrap().proof, proof());
        journal.bind_legacy_forest_rows(12).unwrap();
        assert_eq!(journal.records()[0].entry.forest_rows, Some(12));
    }

    #[test]
    fn oversized_clean_marker_is_consumed_without_allocation() {
        let fixture = Fixture::new("oversized-clean");
        drop(fixture.open());
        let path = clean_shutdown_marker_path(&fixture.path);
        let file = File::create(&path).unwrap();
        file.set_len(1u64 << 40).unwrap();
        drop(file);
        assert!(fixture.open().needs_replay());
        assert!(!path.exists());
    }

    #[test]
    fn corrupt_published_prefix_does_not_truncate_the_file() {
        let fixture = Fixture::new("corrupt-prefix-with-tail");
        let mut journal = fixture.open();
        append_block(&mut journal, 1);
        publish(&journal);
        let offset = journal.boundary().offset;
        append_block(&mut journal, 2);
        let length = journal.file.metadata().unwrap().len();
        journal
            .file
            .write_all_at(&[0xff], offset + RECORD_HEADER_SIZE as u64)
            .unwrap();
        drop(journal);
        assert!(ForestJournal::open(&fixture.path).is_err());
        assert_eq!(std::fs::metadata(&fixture.path).unwrap().len(), length);
    }

    #[test]
    fn entry_layout_roundtrips_and_legacy_binding_survives_growth() {
        let fixture = Fixture::new("legacy-layout");
        let mut journal = fixture.open();
        journal.append(entry(1)).unwrap();
        publish(&journal);
        journal.bind_legacy_forest_rows(8).unwrap();
        assert_eq!(journal.records()[0].entry.forest_rows, Some(8));
        let mut current = entry(2);
        current.forest_rows = Some(9);
        assert_eq!(
            JournalEntry::decode(&current.encode().unwrap()).unwrap(),
            current
        );
        journal.append(current).unwrap();
        publish(&journal);
        drop(journal);

        let mut journal = fixture.open();
        journal.bind_legacy_forest_rows(10).unwrap();
        assert_eq!(journal.records()[0].entry.forest_rows, Some(8));
        assert_eq!(journal.records()[1].entry.forest_rows, Some(9));
    }

    #[test]
    fn corrupt_legacy_layout_binding_is_not_replaced() {
        let fixture = Fixture::new("corrupt-legacy-layout");
        let mut journal = fixture.open();
        journal.append(entry(1)).unwrap();
        publish(&journal);
        journal.bind_legacy_forest_rows(8).unwrap();
        drop(journal);
        let path = append_path_suffix(&fixture.path, FOREST_ROWS_SUFFIX);
        std::fs::write(&path, [0; 65]).unwrap();
        let mut journal = fixture.open();
        assert!(journal.bind_legacy_forest_rows(9).is_err());
        assert_eq!(std::fs::read(path).unwrap(), [0; 65]);
    }

    #[test]
    fn poisoned_publication_cannot_be_replaced_by_detached_pruning() {
        let fixture = Fixture::new("poisoned-prune");
        let mut journal = fixture.open();
        for height in 0..4 {
            journal.append(entry(height)).unwrap();
        }
        publish(&journal);
        let pruning = journal.prepare_prune(2).unwrap().unwrap();
        let generation = journal.shared.marker.lock().generation;
        journal.shared.poisoned.store(true, Ordering::Release);
        assert!(pruning.finish().is_err());
        assert_eq!(journal.shared.marker.lock().generation, generation);
        assert!(journal.mark_rolled_back(0).is_err());
        assert!(journal.mark_clean_shutdown().is_err());
        drop(journal);
        assert_eq!(fixture.open().records().len(), 4);
    }

    #[test]
    fn failed_prune_marker_write_blocks_further_publication() {
        let fixture = Fixture::new("failed-prune-marker");
        let mut journal = fixture.open();
        for height in 0..4 {
            journal.append(entry(height)).unwrap();
        }
        publish(&journal);
        let mut pruning = journal.prepare_prune(2).unwrap().unwrap();
        pruning.publisher.marker_file =
            File::open(append_path_suffix(&fixture.path, PUBLICATION_SUFFIX)).unwrap();
        assert!(pruning.finish().is_err());
        assert!(journal.shared.poisoned.load(Ordering::Acquire));
        assert!(journal
            .publisher()
            .unwrap()
            .publish(journal.boundary())
            .is_err());
        assert!(journal.discard_unpublished().is_err());
        drop(journal);
        assert_eq!(fixture.open().records().len(), 4);
    }

    #[test]
    fn published_replay_payload_roundtrips_completely() {
        let fixture = Fixture::new("replay-payload");
        let mut journal = fixture.open();
        let boundary = append_block(&mut journal, 1);
        assert!(journal.records().is_empty());
        assert!(journal.latest_forward().is_none());
        journal.publisher().unwrap().publish(boundary).unwrap();
        let entry = Arc::clone(&journal.records()[0].entry);
        let header = journal.records()[0].replay.as_ref().unwrap().header;
        drop(journal);

        let journal = fixture.open();
        assert_eq!(journal.records().len(), 1);
        assert_eq!(journal.records()[0].entry, entry);
        let replay = journal.records()[0].replay.as_ref().unwrap();
        assert_eq!(replay.header, header);
        assert_eq!(replay.proof, proof());
        assert_eq!(replay.proof_forest_rows, 8);
    }

    #[test]
    fn complete_unpublished_records_are_discarded_even_after_data_flush() {
        let fixture = Fixture::new("complete-unpublished");
        let mut journal = fixture.open();
        append_block(&mut journal, 1);
        publish(&journal);
        let published_end = journal.boundary().end;
        append_block(&mut journal, 2);
        journal.flush().unwrap(); // Crash between WAL fsync and marker bump.
        assert_eq!(journal.records().len(), 1);
        drop(journal);

        let journal = fixture.open();
        assert_eq!(journal.records().len(), 1);
        assert_eq!(journal.file.metadata().unwrap().len(), published_end);
    }

    #[test]
    fn torn_unpublished_tail_is_discarded_before_decoding() {
        let fixture = Fixture::new("torn-unpublished");
        let mut journal = fixture.open();
        append_block(&mut journal, 1);
        publish(&journal);
        let published_end = journal.boundary().end;
        append_block(&mut journal, 2);
        journal.file.set_len(published_end + 12).unwrap();
        journal.flush().unwrap();
        drop(journal);

        let journal = fixture.open();
        assert_eq!(journal.records().len(), 1);
        assert_eq!(journal.file.metadata().unwrap().len(), published_end);
    }

    #[test]
    fn first_unpublished_window_reopens_empty() {
        let fixture = Fixture::new("first-unpublished-window");
        let mut journal = fixture.open();
        for height in 1..100 {
            append_block(&mut journal, height);
        }
        journal.flush().unwrap();
        drop(journal);
        let journal = fixture.open();
        assert!(journal.records().is_empty());
        assert_eq!(journal.file.metadata().unwrap().len(), journal.page_size);
    }

    #[test]
    fn immutable_boundaries_exclude_later_appends_and_recover_multiple_publications() {
        let fixture = Fixture::new("multiple-publications");
        let mut journal = fixture.open();
        let first = append_block(&mut journal, 1);
        let publisher = journal.publisher().unwrap();
        let second = append_block(&mut journal, 2);
        publisher.publish(first).unwrap();
        assert_eq!(journal.records().len(), 1);
        publisher.publish(second).unwrap();
        publisher.publish(second).unwrap();
        assert!(publisher.publish(first).is_err());
        append_block(&mut journal, 3);
        journal.flush().unwrap();
        drop(publisher);
        drop(journal);
        let journal = fixture.open();
        assert_eq!(journal.records().len(), 2);
        assert_eq!(journal.latest_forward().unwrap().1.entry.height, 2);
    }

    #[test]
    fn producer_does_not_wait_for_publication_metadata_lock() {
        let fixture = Fixture::new("independent-publisher");
        let journal = Arc::new(Mutex::new(fixture.open()));
        let shared = Arc::clone(&journal.lock().shared);
        let publication_lock = shared.marker.lock();
        let producer = Arc::clone(&journal);
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            append_block(&mut producer.lock(), 1);
            tx.send(()).unwrap();
        });
        let completed = rx.recv_timeout(std::time::Duration::from_secs(5));
        drop(publication_lock);
        thread.join().unwrap();
        completed.unwrap();
    }

    #[test]
    fn torn_marker_keeps_previous_published_prefix() {
        let fixture = Fixture::new("torn-marker");
        let mut journal = fixture.open();
        append_block(&mut journal, 1);
        publish(&journal);
        let first_end = journal.boundary().end;
        let second = append_block(&mut journal, 2);
        journal.flush().unwrap();
        let marker = *journal.shared.marker.lock();
        let attempted = PublicationMarker {
            generation: marker.generation + 1,
            boundary: second,
            ..marker
        };
        let bytes = encode_publication_marker(&attempted);
        journal
            .marker_file
            .write_all_at(
                &bytes[..76],
                (attempted.generation % 2) * PUBLICATION_SLOT_SIZE,
            )
            .unwrap();
        journal.marker_file.sync_data().unwrap();
        drop(journal);
        let journal = fixture.open();
        assert_eq!(journal.records().len(), 1);
        assert_eq!(journal.file.metadata().unwrap().len(), first_end);
    }

    #[test]
    fn missing_or_corrupt_markers_never_import_a_publication_wal_as_legacy() {
        for remove in [false, true] {
            let fixture = Fixture::new(if remove {
                "missing-marker"
            } else {
                "corrupt-marker"
            });
            let mut journal = fixture.open();
            append_block(&mut journal, 1);
            publish(&journal);
            append_block(&mut journal, 2);
            journal.flush().unwrap();
            let file_len = journal.file.metadata().unwrap().len();
            drop(journal);
            let marker_path = append_path_suffix(&fixture.path, PUBLICATION_SUFFIX);
            if remove {
                std::fs::remove_file(marker_path).unwrap();
            } else {
                std::fs::write(marker_path, [0; PUBLICATION_BYTES]).unwrap();
            }
            assert!(ForestJournal::open(&fixture.path).is_err());
            assert_eq!(std::fs::metadata(&fixture.path).unwrap().len(), file_len);
        }
    }

    #[test]
    fn corrupt_or_truncated_published_data_is_an_error_not_tail_recovery() {
        for (name, truncate) in [("corrupt-published", false), ("truncated-published", true)] {
            let fixture = Fixture::new(name);
            let mut journal = fixture.open();
            append_block(&mut journal, 1);
            publish(&journal);
            let boundary = journal.boundary();
            if truncate {
                journal.file.set_len(boundary.end - 1).unwrap();
            } else {
                journal
                    .file
                    .write_all_at(&[0xff], boundary.offset + RECORD_HEADER_SIZE as u64)
                    .unwrap();
            }
            journal.flush().unwrap();
            let file_len = journal.file.metadata().unwrap().len();
            drop(journal);
            assert!(ForestJournal::open(&fixture.path).is_err());
            assert_eq!(std::fs::metadata(&fixture.path).unwrap().len(), file_len);
        }
    }

    #[test]
    fn published_marker_height_and_hash_must_match_last_record() {
        for height in [false, true] {
            let fixture = Fixture::new(if height {
                "marker-height"
            } else {
                "marker-hash"
            });
            let mut journal = fixture.open();
            append_block(&mut journal, 1);
            publish(&journal);
            let mut marker = *journal.shared.marker.lock();
            if height {
                marker.boundary.height += 1;
            } else {
                marker.boundary.block_hash = BlockHash::all_zeros();
            }
            for generation in marker.generation + 1..=marker.generation + 2 {
                marker.generation = generation;
                write_publication_marker(&journal.marker_file, &marker).unwrap();
            }
            drop(journal);
            assert!(ForestJournal::open(&fixture.path).is_err());
        }
    }

    #[test]
    fn discard_rejects_stale_boundaries_and_rollback_ignores_speculative_tail() {
        let fixture = Fixture::new("discard-reorg");
        let mut journal = fixture.open();
        journal.append(entry(1)).unwrap();
        let second = journal.append(entry(2)).unwrap();
        publish(&journal);
        journal.append(entry(3)).unwrap();
        let stale = journal.boundary();
        assert_eq!(journal.latest_forward().unwrap().1.entry.height, 2);
        assert!(journal.mark_rolled_back(second).is_err());
        journal.discard_unpublished().unwrap();
        journal.mark_rolled_back(second).unwrap();
        journal.append(entry(3)).unwrap();
        assert!(journal.publisher().unwrap().publish(stale).is_err());
        publish(&journal);
        drop(journal);
        let journal = fixture.open();
        assert_eq!(journal.records().len(), 3);
        assert_eq!(journal.records()[1].status, JournalStatus::RolledBack);
        assert_eq!(journal.latest_forward().unwrap().1.entry.height, 3);
    }

    #[test]
    fn clean_shutdown_marker_is_consumed_on_open() {
        let fixture = Fixture::new("clean-shutdown");
        let mut journal = fixture.open();
        journal.append(entry(1)).unwrap();
        assert!(journal.mark_clean_shutdown().is_err());
        publish(&journal);
        journal.mark_clean_shutdown().unwrap();
        drop(journal);
        let journal = fixture.open();
        assert!(!journal.needs_replay());
        drop(journal);
        assert!(fixture.open().needs_replay());
    }

    #[test]
    fn pruning_preserves_offsets_and_an_accumulating_publication_window() {
        let fixture = Fixture::new("pruning");
        let mut journal = fixture.open();
        for height in 0..150 {
            journal.append(entry(height)).unwrap();
        }
        publish(&journal);
        journal.append(entry(150)).unwrap();
        let boundary = journal.boundary();
        let pruning = journal.prepare_prune(144).unwrap().unwrap();
        assert_eq!(journal.records().len(), 144);
        assert_eq!(pruning.finish().unwrap(), 6);
        assert_eq!(journal.boundary(), boundary);
        journal.publisher().unwrap().publish(boundary).unwrap();
        drop(journal);
        let journal = fixture.open();
        assert_eq!(journal.records().len(), 145);
        assert_eq!(journal.records()[0].entry.height, 6);
        assert_eq!(journal.boundary(), boundary);
    }

    #[test]
    fn both_marker_slots_exclude_pruned_pages_before_hole_punching() {
        let fixture = Fixture::new("pruning-marker-fallback");
        let mut journal = fixture.open();
        for height in 0..10 {
            journal.append(entry(height)).unwrap();
        }
        publish(&journal);
        journal.prepare_prune(3).unwrap().unwrap().finish().unwrap();
        let marker = *journal.shared.marker.lock();
        journal
            .marker_file
            .write_all_at(&[0; 8], (marker.generation % 2) * PUBLICATION_SLOT_SIZE)
            .unwrap();
        journal.marker_file.sync_data().unwrap();
        drop(journal);
        let journal = fixture.open();
        assert_eq!(journal.records().len(), 3);
        assert_eq!(journal.records()[0].entry.height, 7);
    }

    #[test]
    fn rollback_records_do_not_reduce_forward_retention() {
        let fixture = Fixture::new("forward-retention");
        let mut journal = fixture.open();
        for height in 0..150 {
            journal.append(entry(height)).unwrap();
        }
        publish(&journal);
        for index in (140..150).rev() {
            journal.mark_rolled_back(index).unwrap();
        }
        assert!(journal.prepare_prune(144).unwrap().is_none());
        drop(journal);
        let journal = fixture.open();
        assert_eq!(journal.records().len(), 150);
        assert_eq!(journal.latest_forward().unwrap().1.entry.height, 139);
    }

    fn legacy_file(fixture: &Fixture) {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&fixture.path)
            .unwrap();
        let mut offset = 0;
        for height in 1..=3 {
            let entry = Arc::new(entry(height));
            let payload = entry.encode().unwrap();
            let record = write_record(
                &file,
                page_size(),
                offset,
                entry,
                None,
                &payload,
                LEGACY_RECORD_VERSION,
            )
            .unwrap();
            if height == 1 {
                file.write_all_at(&PRUNED_MAGIC, record.offset).unwrap();
            } else if height == 2 {
                file.write_all_at(
                    &[JournalStatus::RolledBack.to_byte()],
                    record.offset + STATUS_OFFSET,
                )
                .unwrap();
            }
            offset += record.span;
        }
        file.write_all_at(&RECORD_MAGIC, offset).unwrap(); // Interrupted old-format append.
        file.sync_all().unwrap();
    }

    #[test]
    fn legacy_import_preserves_retained_records_and_happens_only_once() {
        let fixture = Fixture::new("legacy-import");
        legacy_file(&fixture);
        let mut journal = fixture.open();
        assert_eq!(journal.records().len(), 2);
        assert_eq!(*journal.records()[0].entry, entry(2));
        assert_eq!(journal.records()[0].status, JournalStatus::RolledBack);
        assert!(journal
            .records()
            .iter()
            .all(|record| record.replay.is_none()));
        let id = journal.journal_id;
        append_block(&mut journal, 4);
        journal.flush().unwrap();
        drop(journal);
        let journal = fixture.open();
        assert_eq!(journal.journal_id, id);
        assert_eq!(journal.records().len(), 2);
        assert_eq!(journal.latest_forward().unwrap().1.entry.height, 3);
    }

    #[test]
    fn interrupted_legacy_initialization_resumes_without_losing_records() {
        let fixture = Fixture::new("interrupted-legacy-import");
        legacy_file(&fixture);
        let saved = fixture.root.join("legacy");
        std::fs::copy(&fixture.path, &saved).unwrap();
        drop(fixture.open());
        // Recreate the crash point: marker and temporary new inode durable, old WAL name.
        std::fs::rename(
            &fixture.path,
            append_path_suffix(&fixture.path, INITIALIZE_SUFFIX),
        )
        .unwrap();
        std::fs::rename(&saved, &fixture.path).unwrap();
        let journal = fixture.open();
        assert_eq!(journal.records().len(), 2);
        assert_eq!(journal.records()[0].entry.height, 2);
        assert_eq!(journal.records()[0].status, JournalStatus::RolledBack);
        assert!(!append_path_suffix(&fixture.path, INITIALIZE_SUFFIX).exists());
    }
}
