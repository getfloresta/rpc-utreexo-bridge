// SPDX-License-Identifier: MIT

//! Page-aligned, append-only recovery journal for steady-state forest updates.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Txid;
use sha2::Digest;
use sha2::Sha256;

const RECORD_MAGIC: [u8; 8] = *b"BRJNL001";
const PRUNED_MAGIC: [u8; 8] = *b"PRUNED01";
const RECORD_TRAILER: [u8; 8] = *b"ENDJNL01";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_SIZE: usize = 64;
const STATUS_OFFSET: u64 = 10;
const COMPACT_ON_OPEN_STALE_BYTES: u64 = 1 << 30;
const COPY_BUFFER_BYTES: usize = 1 << 20;
const MAX_RECORD_BYTES: usize = 512 * 1024 * 1024;

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
}

impl JournalEntry {
    pub fn previous_num_leaves(&self) -> Result<u64> {
        self.num_leaves
            .checked_sub(self.added.len() as u64)
            .context("journal addition count exceeds numleaves")
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

#[derive(Clone, Debug)]
pub struct JournalRecord {
    pub entry: JournalEntry,
    pub status: JournalStatus,
    offset: u64,
    span: u64,
}

pub struct ForestJournal {
    file: File,
    path: PathBuf,
    page_size: u64,
    records: Vec<JournalRecord>,
    published_size: Arc<AtomicU64>,
    flushed_size: Arc<AtomicU64>,
    hole_punch_supported: Option<bool>,
    stale_bytes: u64,
}

pub struct ForestJournalFlusher {
    file: File,
    path: PathBuf,
    published_size: Arc<AtomicU64>,
    flushed_size: Arc<AtomicU64>,
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
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open forest journal {}", path.display()))?;
        let page_size = page_size();
        let mut journal = Self {
            file,
            path: path.to_path_buf(),
            page_size,
            records: Vec::new(),
            published_size: Arc::new(AtomicU64::new(0)),
            flushed_size: Arc::new(AtomicU64::new(0)),
            hole_punch_supported: None,
            stale_bytes: 0,
        };
        journal.scan()?;
        if journal.stale_bytes >= COMPACT_ON_OPEN_STALE_BYTES {
            journal.compact()?;
        }
        let size = journal.file.metadata()?.len();
        journal.published_size.store(size, Ordering::Release);
        journal.flushed_size.store(size, Ordering::Release);
        Ok(journal)
    }

    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    pub fn latest_forward(&self) -> Option<(usize, &JournalRecord)> {
        self.records
            .iter()
            .enumerate()
            .rev()
            .find(|(_, record)| record.status == JournalStatus::Forward)
    }

    /// Appends a complete page-aligned entry without flushing it.
    pub fn append(&mut self, entry: JournalEntry) -> Result<usize> {
        let payload = encode_entry(&entry)?;
        if payload.len() > MAX_RECORD_BYTES {
            bail!("journal entry is too large: {} bytes", payload.len());
        }
        let used = RECORD_HEADER_SIZE
            .checked_add(payload.len())
            .and_then(|length| length.checked_add(RECORD_TRAILER.len()))
            .context("journal record length overflow")?;
        let span = align_up(used as u64, self.page_size).context("journal span overflow")?;
        let offset = align_up(self.file.metadata()?.len(), self.page_size)
            .context("journal offset overflow")?;
        let end = offset
            .checked_add(span)
            .context("journal file length overflow")?;
        let write_result = (|| -> Result<()> {
            self.file.set_len(end)?;
            let mut header = [0u8; RECORD_HEADER_SIZE];
            header[..8].copy_from_slice(&RECORD_MAGIC);
            header[8..10].copy_from_slice(&RECORD_VERSION.to_le_bytes());
            header[10] = JournalStatus::Forward.to_byte();
            header[16..24].copy_from_slice(&span.to_le_bytes());
            header[24..32].copy_from_slice(&(payload.len() as u64).to_le_bytes());
            header[32..64].copy_from_slice(&Sha256::digest(&payload));
            self.file.write_all_at(&header, offset)?;
            self.file
                .write_all_at(&payload, offset + RECORD_HEADER_SIZE as u64)?;
            self.file.write_all_at(
                &RECORD_TRAILER,
                offset + RECORD_HEADER_SIZE as u64 + payload.len() as u64,
            )?;
            Ok(())
        })();
        if let Err(error) = write_result {
            self.file.set_len(offset)?;
            self.file.sync_data()?;
            return Err(error);
        }
        self.records.push(JournalRecord {
            entry,
            status: JournalStatus::Forward,
            offset,
            span,
        });
        self.published_size.store(end, Ordering::Release);
        Ok(self.records.len() - 1)
    }

    pub fn flush(&self) -> Result<()> {
        let published_size = self.published_size.load(Ordering::Acquire);
        self.file
            .sync_data()
            .with_context(|| format!("failed to flush forest journal {}", self.path.display()))?;
        self.flushed_size
            .fetch_max(published_size, Ordering::Release);
        Ok(())
    }

    pub fn published_size(&self) -> u64 {
        self.published_size.load(Ordering::Acquire)
    }

    pub fn is_flushed_through(&self, size: u64) -> bool {
        self.flushed_size.load(Ordering::Acquire) >= size
    }

    pub fn flusher(&self) -> Result<ForestJournalFlusher> {
        Ok(ForestJournalFlusher {
            file: self.file.try_clone()?,
            path: self.path.clone(),
            published_size: Arc::clone(&self.published_size),
            flushed_size: Arc::clone(&self.flushed_size),
        })
    }

    /// Durably changes a committed entry into an undo operation before state is rolled back.
    pub fn mark_rolled_back(&mut self, index: usize) -> Result<()> {
        let record = self
            .records
            .get_mut(index)
            .context("journal record index is out of bounds")?;
        self.file.write_all_at(
            &[JournalStatus::RolledBack.to_byte()],
            record.offset + STATUS_OFFSET,
        )?;
        self.file.sync_data()?;
        record.status = JournalStatus::RolledBack;
        Ok(())
    }

    /// Retains at least the newest `keep` forward records.
    ///
    /// Filesystems without hole punching receive page-aligned tombstones instead. The scanner
    /// skips those spans without reading their payloads.
    pub fn prune(&mut self, keep: usize) -> Result<usize> {
        let prune_count = self.prune_count(keep);
        if prune_count == 0 {
            return Ok(0);
        }
        if self.hole_punch_supported != Some(false) {
            let mut punched = 0usize;
            for record in self.records.iter().take(prune_count) {
                let result = unsafe {
                    libc::fallocate(
                        std::os::fd::AsRawFd::as_raw_fd(&self.file),
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        record.offset as libc::off_t,
                        record.span as libc::off_t,
                    )
                };
                if result == 0 {
                    punched += 1;
                    continue;
                }
                let error = std::io::Error::last_os_error();
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL)
                ) {
                    return Err(error).context("failed to punch pruned journal entry");
                }
                self.hole_punch_supported = Some(false);
                self.write_pruned_tombstones(punched, prune_count)?;
                self.records.drain(..prune_count);
                return Ok(prune_count);
            }
            self.hole_punch_supported = Some(true);
        } else {
            self.write_pruned_tombstones(0, prune_count)?;
        }
        self.records.drain(..prune_count);
        self.file.sync_data()?;
        Ok(prune_count)
    }

    fn prune_count(&self, keep: usize) -> usize {
        if keep == 0 {
            return self.records.len();
        }
        let mut forward = 0usize;
        for (index, record) in self.records.iter().enumerate().rev() {
            if record.status == JournalStatus::Forward {
                forward += 1;
                if forward == keep {
                    return index;
                }
            }
        }
        0
    }

    fn write_pruned_tombstones(&self, start: usize, end: usize) -> Result<()> {
        for record in &self.records[start..end] {
            let mut header = [0u8; RECORD_HEADER_SIZE];
            header[..8].copy_from_slice(&PRUNED_MAGIC);
            header[16..24].copy_from_slice(&record.span.to_le_bytes());
            self.file.write_all_at(&header, record.offset)?;
        }
        self.file.sync_data()?;
        Ok(())
    }

    fn compact(&mut self) -> Result<()> {
        if self.stale_bytes == 0 {
            return Ok(());
        }
        let mut temporary_name = self.path.as_os_str().to_os_string();
        temporary_name.push(".compact");
        let temporary_path = PathBuf::from(temporary_name);
        let temporary = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&temporary_path)?;
        let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
        let mut next_offset = 0u64;
        let mut locations = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let mut copied = 0u64;
            while copied < record.span {
                let remaining = record.span - copied;
                let length = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
                    .context("journal copy length exceeds usize")?;
                self.file
                    .read_exact_at(&mut buffer[..length], record.offset + copied)?;
                temporary.write_all_at(&buffer[..length], next_offset + copied)?;
                copied += length as u64;
            }
            locations.push((next_offset, record.span));
            next_offset = next_offset
                .checked_add(record.span)
                .context("compacted journal length overflow")?;
        }
        temporary.set_len(next_offset)?;
        temporary.sync_data()?;
        std::fs::rename(&temporary_path, &self.path)?;
        for (record, (offset, span)) in self.records.iter_mut().zip(locations) {
            record.offset = offset;
            record.span = span;
        }
        self.file = temporary;
        self.stale_bytes = 0;
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn scan(&mut self) -> Result<()> {
        let file_len = self.file.metadata()?.len();
        let mut offset = 0u64;
        while offset < file_len {
            let mut magic = [0u8; 8];
            if self.file.read_exact_at(&mut magic, offset).is_err() {
                self.file.set_len(offset)?;
                break;
            }
            if magic == PRUNED_MAGIC {
                let mut header = [0u8; RECORD_HEADER_SIZE];
                if self.file.read_exact_at(&mut header, offset).is_err() {
                    self.file.set_len(offset)?;
                    break;
                }
                let span = u64::from_le_bytes(header[16..24].try_into().unwrap());
                if span == 0
                    || span % self.page_size != 0
                    || offset.checked_add(span).is_none_or(|end| end > file_len)
                {
                    self.file.set_len(offset)?;
                    break;
                }
                self.stale_bytes = self
                    .stale_bytes
                    .checked_add(span)
                    .context("stale journal byte count overflow")?;
                offset += span;
                continue;
            }
            if magic == [0; 8] {
                self.stale_bytes = self
                    .stale_bytes
                    .checked_add(self.page_size)
                    .context("stale journal byte count overflow")?;
                offset = offset.saturating_add(self.page_size);
                continue;
            }
            if magic != RECORD_MAGIC {
                self.file.set_len(offset)?;
                break;
            }
            let mut header = [0u8; RECORD_HEADER_SIZE];
            if self.file.read_exact_at(&mut header, offset).is_err() {
                self.file.set_len(offset)?;
                break;
            }
            let span = u64::from_le_bytes(header[16..24].try_into().unwrap());
            let payload_len = u64::from_le_bytes(header[24..32].try_into().unwrap());
            if span == 0
                || span % self.page_size != 0
                || payload_len as usize > MAX_RECORD_BYTES
                || offset.checked_add(span).is_none_or(|end| end > file_len)
            {
                self.file.set_len(offset)?;
                break;
            }
            let version = u16::from_le_bytes(header[8..10].try_into().unwrap());
            if version != RECORD_VERSION {
                bail!("unsupported journal version {version}");
            }
            let status = JournalStatus::from_byte(header[10])?;
            let payload_len = payload_len as usize;
            let mut payload = vec![0u8; payload_len];
            let payload_offset = offset + RECORD_HEADER_SIZE as u64;
            if self
                .file
                .read_exact_at(&mut payload, payload_offset)
                .is_err()
            {
                self.file.set_len(offset)?;
                break;
            }
            if Sha256::digest(&payload).as_slice() != &header[32..64] {
                if offset + span == file_len {
                    self.file.set_len(offset)?;
                    break;
                }
                bail!("journal checksum mismatch at offset {offset}");
            }
            let mut trailer = [0u8; 8];
            if self
                .file
                .read_exact_at(&mut trailer, payload_offset + payload_len as u64)
                .is_err()
                || trailer != RECORD_TRAILER
            {
                self.file.set_len(offset)?;
                break;
            }
            self.records.push(JournalRecord {
                entry: decode_entry(&payload)?,
                status,
                offset,
                span,
            });
            offset += span;
        }
        Ok(())
    }
}
impl ForestJournalFlusher {
    pub fn flush_through(&self, size: u64) -> Result<()> {
        let published_size = self.published_size.load(Ordering::Acquire);
        if published_size < size {
            bail!(
                "journal bytes through {size} are not published; current size is {published_size}"
            );
        }
        self.file
            .sync_data()
            .with_context(|| format!("failed to flush forest journal {}", self.path.display()))?;
        self.flushed_size.fetch_max(size, Ordering::Release);
        Ok(())
    }
}

fn encode_entry(entry: &JournalEntry) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&entry.block_hash.to_byte_array());
    bytes.extend_from_slice(&entry.num_leaves.to_le_bytes());
    bytes.extend_from_slice(&entry.height.to_le_bytes());
    bytes.extend_from_slice(&entry.previous_block_hash.to_byte_array());
    push_len(&mut bytes, entry.forest.len())?;
    for delta in &entry.forest {
        bytes.extend_from_slice(&delta.position.to_le_bytes());
        encode_state(&mut bytes, delta.before);
        encode_state(&mut bytes, delta.after);
    }
    push_len(&mut bytes, entry.removed.len())?;
    for delta in &entry.removed {
        encode_index_delta(&mut bytes, *delta);
    }
    push_len(&mut bytes, entry.added.len())?;
    for delta in &entry.added {
        encode_index_delta(&mut bytes, *delta);
    }
    Ok(bytes)
}

fn decode_entry(bytes: &[u8]) -> Result<JournalEntry> {
    let mut reader = bytes;
    let block_hash = BlockHash::from_byte_array(take_array(&mut reader)?);
    let num_leaves = take_u64(&mut reader)?;
    let height = take_u32(&mut reader)?;
    let previous_block_hash = BlockHash::from_byte_array(take_array(&mut reader)?);
    let forest_len = take_len(&mut reader)?;
    let mut forest = Vec::with_capacity(forest_len);
    for _ in 0..forest_len {
        forest.push(JournalForestDelta {
            position: take_u64(&mut reader)?,
            before: decode_state(&mut reader)?,
            after: decode_state(&mut reader)?,
        });
    }
    let removed_len = take_len(&mut reader)?;
    let mut removed = Vec::with_capacity(removed_len);
    for _ in 0..removed_len {
        removed.push(decode_index_delta(&mut reader)?);
    }
    let added_len = take_len(&mut reader)?;
    let mut added = Vec::with_capacity(added_len);
    for _ in 0..added_len {
        added.push(decode_index_delta(&mut reader)?);
    }
    if !reader.is_empty() {
        bail!("journal entry has {} trailing bytes", reader.len());
    }
    Ok(JournalEntry {
        height,
        block_hash,
        num_leaves,
        previous_block_hash,
        forest,
        removed,
        added,
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

fn take_len(reader: &mut &[u8]) -> Result<usize> {
    Ok(take_u32(reader)? as usize)
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
        }
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bridge-journal-{}-{name}", std::process::id()))
    }

    #[test]
    fn roundtrips_and_marks_entries() {
        let path = path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let mut journal = ForestJournal::open(&path).unwrap();
        let index = journal.append(entry(1)).unwrap();
        journal.flush().unwrap();
        journal.mark_rolled_back(index).unwrap();
        drop(journal);

        let journal = ForestJournal::open(&path).unwrap();
        assert_eq!(journal.records().len(), 1);
        assert_eq!(journal.records()[0].entry, entry(1));
        assert_eq!(journal.records()[0].status, JournalStatus::RolledBack);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn ignores_an_interrupted_tail_record() {
        let path = path("interrupted-tail");
        let _ = std::fs::remove_file(&path);
        let mut journal = ForestJournal::open(&path).unwrap();
        journal.append(entry(1)).unwrap();
        journal.flush().unwrap();
        let valid_len = journal.file.metadata().unwrap().len();
        drop(journal);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(valid_len + 4096).unwrap();
        file.write_all_at(&RECORD_MAGIC, valid_len).unwrap();
        file.sync_data().unwrap();
        drop(file);

        let journal = ForestJournal::open(&path).unwrap();
        assert_eq!(journal.records().len(), 1);
        assert_eq!(journal.file.metadata().unwrap().len(), valid_len);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn tracks_multiple_rolled_back_blocks() {
        let path = path("multiple-rollbacks");
        let _ = std::fs::remove_file(&path);
        let mut journal = ForestJournal::open(&path).unwrap();
        journal.append(entry(1)).unwrap();
        let second = journal.append(entry(2)).unwrap();
        let third = journal.append(entry(3)).unwrap();
        journal.flush().unwrap();
        journal.mark_rolled_back(third).unwrap();
        journal.mark_rolled_back(second).unwrap();
        assert_eq!(journal.latest_forward().unwrap().1.entry.height, 1);
        drop(journal);

        let journal = ForestJournal::open(&path).unwrap();
        assert_eq!(journal.records()[1].status, JournalStatus::RolledBack);
        assert_eq!(journal.records()[2].status, JournalStatus::RolledBack);
        assert_eq!(journal.latest_forward().unwrap().1.entry.height, 1);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn publishes_complete_records_before_background_flush() {
        let path = path("background-flush");
        let _ = std::fs::remove_file(&path);
        let mut journal = ForestJournal::open(&path).unwrap();
        let flusher = journal.flusher().unwrap();

        journal.append(entry(1)).unwrap();
        let published_size = journal.published_size();
        assert!(published_size > 0);
        assert!(!journal.is_flushed_through(published_size));
        assert!(flusher.flush_through(published_size + 1).is_err());
        flusher.flush_through(published_size).unwrap();
        assert!(journal.is_flushed_through(published_size));

        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn prunes_old_entries_by_punching_page_aligned_holes() {
        let path = path("prune");
        let _ = std::fs::remove_file(&path);
        let mut journal = ForestJournal::open(&path).unwrap();
        for height in 0..150 {
            journal.append(entry(height)).unwrap();
        }
        journal.flush().unwrap();
        assert_eq!(journal.prune(144).unwrap(), 6);
        assert_eq!(journal.records().len(), 144);
        drop(journal);

        let journal = ForestJournal::open(&path).unwrap();
        assert_eq!(journal.records().len(), 144);
        assert_eq!(journal.records()[0].entry.height, 6);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn unsupported_hole_punching_uses_durable_tombstones() {
        let path = path("tombstone-prune");
        let _ = std::fs::remove_file(&path);
        let mut journal = ForestJournal::open(&path).unwrap();
        for height in 0..150 {
            journal.append(entry(height)).unwrap();
        }
        journal.flush().unwrap();
        journal.hole_punch_supported = Some(false);
        assert_eq!(journal.prune(144).unwrap(), 6);
        assert_eq!(journal.records().len(), 144);
        drop(journal);

        let mut journal = ForestJournal::open(&path).unwrap();
        assert!(journal.stale_bytes > 0);
        journal.compact().unwrap();
        assert_eq!(journal.records().len(), 144);
        assert_eq!(journal.records()[0].entry.height, 6);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rollback_records_do_not_reduce_forward_retention() {
        let path = path("forward-retention");
        let _ = std::fs::remove_file(&path);
        let mut journal = ForestJournal::open(&path).unwrap();
        for height in 0..150 {
            journal.append(entry(height)).unwrap();
        }
        for index in (140..150).rev() {
            journal.mark_rolled_back(index).unwrap();
        }
        assert_eq!(journal.prune(144).unwrap(), 0);
        assert_eq!(journal.records().len(), 150);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }
}
