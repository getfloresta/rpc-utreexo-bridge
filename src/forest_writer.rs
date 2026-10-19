// SPDX-License-Identifier: MIT

//! Explicit positional forest writes. Consecutive records share io_uring requests;
//! sparse gaps are neither read nor overwritten, and no mapping is faulted to write.

use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use io_uring::opcode;
use io_uring::types;
use io_uring::EnterFlags;
use io_uring::IoUring;
use parking_lot::Mutex;

const RING_ENTRIES: usize = 256;
// CQEs contain signed lengths; smaller filesystem limits produce continuations.
const MAX_WRITE_LEN: usize = i32::MAX as usize;

#[derive(Default)]
struct WriterState {
    ring: Option<IoUring>,
    poisoned: bool,
}

/// A reusable, lazily initialized ring, serialized across complete write batches.
#[derive(Default)]
pub(crate) struct ForestWriter {
    state: Mutex<WriterState>,
}

impl ForestWriter {
    /// Write packed records at sorted, unique positions without reading old bytes.
    ///
    /// The caller excludes overlapping record reads/mutations through completion;
    /// overlay-isolated reads of disjoint records may continue under a shared lock.
    /// Buffered writes update the same page cache as existing shared mappings;
    /// durability still requires the caller's subsequent file synchronization.
    /// Ownership avoids a second serialization copy and protects all unwind/error
    /// paths, including an unrecoverable failure to observe kernel completion.
    pub(crate) fn write_nodes(
        &self,
        file: &File,
        positions: &[u64],
        node_size: usize,
        bytes: Vec<u8>,
    ) -> Result<()> {
        if positions.is_empty() && bytes.is_empty() {
            return Ok(());
        }
        let expected_len = validate_positions(positions, node_size)?;
        if bytes.len() != expected_len {
            bail!("forest write buffer length does not match its positions");
        }
        let mut state = self.state.lock();
        if state.poisoned {
            bail!(
                "forest writer is poisoned after an indeterminate io_uring write; reopen required"
            );
        }
        if state.ring.is_none() {
            state.ring = Some(IoUring::new(RING_ENTRIES as u32).context(
                "forest mutations require Linux io_uring with IORING_OP_WRITE (Linux 5.6+) \
                 and permission for io_uring_setup/io_uring_enter; check \
                 kernel.io_uring_disabled, group permissions, and seccomp",
            )?);
        }
        let mut batch = WriteBatch {
            state: &mut state,
            bytes,
            outstanding: 0,
        };
        if let Err(error) = batch.write(file, WritePlan::new(positions, node_size)) {
            return Err(match batch.drain() {
                Ok(()) => error,
                Err(drain_error) => error.context(format!(
                    "fatal forest io_uring completion-drain failure: {drain_error}; \
                     writer poisoned, ring retired, and write allocation retained"
                )),
            });
        }
        Ok(())
    }
}

fn validate_positions(positions: &[u64], node_size: usize) -> Result<usize> {
    if node_size == 0 {
        bail!("forest write node size must be nonzero");
    }
    if positions.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("forest write positions must be sorted and unique");
    }
    let input_len = positions
        .len()
        .checked_mul(node_size)
        .filter(|&length| length <= isize::MAX as usize)
        .context("forest write buffer length overflow")?;
    let node_size = u64::try_from(node_size).context("forest write node size overflow")?;
    if let Some(&last) = positions.last() {
        last.checked_mul(node_size)
            .and_then(|offset| offset.checked_add(node_size))
            .filter(|&end| end <= i64::MAX as u64)
            .context("forest write file offset overflow")?;
    }
    Ok(input_len)
}

#[derive(Clone, Copy, Default, Debug)]
struct WriteRequest {
    file_offset: u64,
    input_offset: usize,
    remaining: u32,
    pending: bool,
}

/// Streams coalesced runs with bounded descriptors, not a request per forest node.
/// Input validation bounds all arithmetic, including end-of-file positions.
struct WritePlan<'a> {
    positions: &'a [u64],
    node_size: usize,
    next_position: usize,
    input_offset: usize,
    file_offset: u64,
    run_remaining: usize,
}

impl<'a> WritePlan<'a> {
    fn new(positions: &'a [u64], node_size: usize) -> Self {
        Self {
            positions,
            node_size,
            next_position: 0,
            input_offset: 0,
            file_offset: 0,
            run_remaining: 0,
        }
    }
}

impl Iterator for WritePlan<'_> {
    type Item = WriteRequest;

    fn next(&mut self) -> Option<Self::Item> {
        if self.run_remaining == 0 {
            let start = self.next_position;
            let &position = self.positions.get(start)?;
            let mut end = start + 1;
            while end < self.positions.len() && self.positions[end] == self.positions[end - 1] + 1 {
                end += 1;
            }
            self.file_offset = position * self.node_size as u64;
            self.run_remaining = (end - start) * self.node_size;
            self.next_position = end;
        }
        let length = self.run_remaining.min(MAX_WRITE_LEN);
        let request = WriteRequest {
            file_offset: self.file_offset,
            input_offset: self.input_offset,
            remaining: length as u32,
            pending: false,
        };
        self.file_offset += length as u64;
        self.input_offset += length;
        self.run_remaining -= length;
        Some(request)
    }
}

/// Owns the immutable allocation until every consuming SQE has completed. Closing
/// an io_uring is not assumed to cancel work synchronously. Fatal drain failures
/// retain this allocation and poison the writer instead of aborting the process.
/// The caller's File stays borrowed until draining or ring retirement completes;
/// submitted writes hold their own kernel file references after that point.
struct WriteBatch<'a> {
    state: &'a mut WriterState,
    bytes: Vec<u8>,
    // All pushed SQEs not yet reaped, including entries not consumed by the kernel.
    outstanding: usize,
}

impl WriteBatch<'_> {
    fn write(&mut self, file: &File, mut plan: WritePlan<'_>) -> Result<()> {
        let mut requests = [WriteRequest::default(); RING_ENTRIES];
        loop {
            let mut count = 0;
            for request in &mut requests {
                match plan.next() {
                    Some(next) => {
                        *request = next;
                        count += 1;
                    }
                    None => break,
                }
            }
            if count == 0 {
                return Ok(());
            }
            self.write_wave(file, &mut requests[..count])?;
        }
    }

    fn write_wave(&mut self, file: &File, requests: &mut [WriteRequest]) -> Result<()> {
        loop {
            {
                let ring = self
                    .state
                    .ring
                    .as_mut()
                    .expect("initialized forest write ring");
                let mut submission = ring.submission();
                for (index, request) in requests.iter_mut().enumerate() {
                    if request.remaining == 0 {
                        continue;
                    }
                    // SAFETY: validated plan ranges lie within this owned allocation.
                    // The buffer is never moved, mutated, or freed before completion.
                    // Drop drains/retains it on every error and unwind path.
                    let pointer = unsafe { self.bytes.as_ptr().add(request.input_offset) };
                    let entry =
                        opcode::Write::new(types::Fd(file.as_raw_fd()), pointer, request.remaining)
                            .offset(request.file_offset)
                            .build()
                            .user_data(index as u64);
                    // SAFETY: the above buffer and borrowed file outlive the SQE.
                    // The default ring does not use SQPOLL.
                    unsafe { submission.push(&entry) }.map_err(|_| {
                        anyhow!("forest io_uring submission queue unexpectedly full")
                    })?;
                    self.outstanding += 1;
                    request.pending = true;
                }
            }
            if self.outstanding == 0 {
                return Ok(());
            }
            self.complete_wave(requests)?;
            // Finish only the unwritten suffixes of short/interrupted requests.
        }
    }

    fn complete_wave(&mut self, requests: &mut [WriteRequest]) -> Result<()> {
        let ring = self
            .state
            .ring
            .as_mut()
            .expect("initialized forest write ring");
        let mut first_error = None;
        while self.outstanding != 0 {
            {
                let completions = ring.completion();
                for completion in completions {
                    self.outstanding -= 1;
                    let Some(request) = requests.get_mut(completion.user_data() as usize) else {
                        first_error.get_or_insert_with(|| {
                            anyhow!("forest io_uring returned an unknown write identifier")
                        });
                        continue;
                    };
                    if !request.pending {
                        first_error.get_or_insert_with(|| {
                            anyhow!("forest io_uring returned a duplicate write completion")
                        });
                        continue;
                    }
                    request.pending = false;
                    let result = completion.result();
                    if result == -libc::EINTR {
                        continue;
                    }
                    if result < 0 {
                        first_error.get_or_insert_with(|| {
                            anyhow::Error::from(io::Error::from_raw_os_error(-result)).context(
                                format!(
                                    "io_uring forest write at byte {} failed",
                                    request.file_offset
                                ),
                            )
                        });
                    } else if result == 0 {
                        first_error.get_or_insert_with(|| {
                            anyhow::Error::from(io::Error::new(
                                io::ErrorKind::WriteZero,
                                format!(
                                    "io_uring forest write made no progress at byte {} with {} bytes remaining",
                                    request.file_offset, request.remaining
                                ),
                            ))
                        });
                    } else if result as u32 > request.remaining {
                        first_error.get_or_insert_with(|| {
                            anyhow!("forest io_uring write exceeded its requested length")
                        });
                    } else {
                        request.file_offset += result as u64;
                        request.input_offset += result as usize;
                        request.remaining -= result as u32;
                    }
                }
            }
            if self.outstanding == 0 {
                break;
            }
            // enter may consume only a prefix of the SQ, even on error/EINTR.
            // Only CQEs release buffers; submit every remaining entry on success.
            match ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        || error.raw_os_error() == Some(libc::EBUSY) => {}
                Err(error) => {
                    return Err(error).context("submitting/waiting for forest io_uring writes");
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn drain(&mut self) -> io::Result<()> {
        if self.outstanding == 0 {
            return Ok(());
        }
        match self.drain_consumed() {
            Ok(discard_queued) => {
                if discard_queued {
                    // Unsubmitted SQEs must never be submitted by a later caller.
                    self.state.ring.take();
                }
                self.outstanding = 0;
                Ok(())
            }
            Err(error) => {
                // Ring close is NOT a completion barrier. Preserve the allocation
                // even if cancellation is deferred, and reject all further writes.
                mem::forget(mem::take(&mut self.bytes));
                self.state.poisoned = true;
                self.state.ring.take();
                self.outstanding = 0;
                Err(error)
            }
        }
    }

    fn drain_consumed(&mut self) -> io::Result<bool> {
        let ring = self
            .state
            .ring
            .as_mut()
            .expect("initialized forest write ring");
        // No SQPOLL and exclusive ring ownership: only our enter calls consume SQEs.
        let queued = ring.submission().len();
        let mut active = self
            .outstanding
            .checked_sub(queued)
            .ok_or_else(|| io::Error::other("forest io_uring submission accounting mismatch"))?;
        while active != 0 {
            for _ in ring.completion() {
                active = active.checked_sub(1).ok_or_else(|| {
                    io::Error::other("forest io_uring completion accounting mismatch")
                })?;
            }
            if active == 0 {
                break;
            }
            // SAFETY: wait-only GETEVENTS consumes no unsubmitted SQEs after a
            // submission failure. The owned buffer and borrowed file remain alive.
            let result = unsafe {
                ring.submitter()
                    .enter::<libc::sigset_t>(0, 1, EnterFlags::GETEVENTS.bits(), None)
            };
            match result {
                Ok(_) => {}
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        || error.raw_os_error() == Some(libc::EBUSY) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(queued != 0)
    }
}

impl Drop for WriteBatch<'_> {
    fn drop(&mut self) {
        let _ = self.drain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::OpenOptions;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    const NODE_SIZE: usize = 33;
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        file: File,
        path: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "bridge-forest-writer-{}-{name}-{}.dat",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            ));
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            Self { file, path }
        }

        fn read(&self, len: usize) -> Vec<u8> {
            let mut bytes = vec![0; len];
            self.file.read_exact_at(&mut bytes, 0).unwrap();
            bytes
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn record(position: u64) -> [u8; NODE_SIZE] {
        std::array::from_fn(|index| {
            (position.wrapping_mul(37).wrapping_add(index as u64 * 13) % 251) as u8
        })
    }

    fn records(positions: &[u64]) -> Vec<u8> {
        positions
            .iter()
            .flat_map(|&position| record(position))
            .collect()
    }

    #[test]
    fn adjacent_and_sparse_writes_preserve_gaps_and_existing_mappings() {
        let mut fixture = Fixture::new("sparse");
        let len = 300 * NODE_SIZE;
        let mut expected = vec![0xad; len];
        fixture.file.write_all_at(&expected, 0).unwrap();
        let map = unsafe { memmap2::MmapOptions::new().map(&fixture.file) }.unwrap();
        // Fault every old page before the explicit writes, exercising coherency.
        assert_eq!(&map[..], expected.as_slice());
        fixture.file.seek(SeekFrom::Start(19)).unwrap();
        let positions = [0, 1, 2, 5, 8, 9, 123, 124, 255];
        let writer = ForestWriter::default();
        writer
            .write_nodes(&fixture.file, &positions, NODE_SIZE, records(&positions))
            .unwrap();
        for position in positions {
            let offset = position as usize * NODE_SIZE;
            expected[offset..offset + NODE_SIZE].copy_from_slice(&record(position));
        }
        assert_eq!(fixture.file.stream_position().unwrap(), 19);
        assert_eq!(&map[..], expected.as_slice());
        assert_eq!(fixture.read(len), expected);
        fixture.file.sync_data().unwrap();
        let reopened = File::open(&fixture.path).unwrap();
        let mut durable = vec![0; len];
        reopened.read_exact_at(&mut durable, 0).unwrap();
        assert_eq!(durable, expected);
    }

    #[test]
    fn more_than_ring_capacity_writes_reuse_the_ring_and_preserve_unwritten_nodes() {
        let fixture = Fixture::new("waves");
        let positions: Vec<_> = (0..RING_ENTRIES as u64 * 3 + 17).map(|n| n * 2).collect();
        let len = (positions.last().unwrap() + 2) as usize * NODE_SIZE;
        fixture.file.write_all_at(&vec![0x7b; len], 0).unwrap();
        let writer = ForestWriter::default();
        writer
            .write_nodes(&fixture.file, &positions, NODE_SIZE, records(&positions))
            .unwrap();
        let ring_fd = writer.state.lock().ring.as_ref().unwrap().as_raw_fd();
        writer
            .write_nodes(&fixture.file, &[1], NODE_SIZE, record(999).to_vec())
            .unwrap();
        assert_eq!(
            writer.state.lock().ring.as_ref().unwrap().as_raw_fd(),
            ring_fd
        );
        let bytes = fixture.read(len);
        for (position, node) in bytes.chunks_exact(NODE_SIZE).enumerate() {
            if position % 2 == 0 {
                assert_eq!(node, record(position as u64));
            } else if position == 1 {
                assert_eq!(node, record(999));
            } else {
                assert_eq!(node, [0x7b; NODE_SIZE]);
            }
        }
    }

    #[test]
    fn partial_wave_failure_drains_all_writes_before_reuse() {
        let fixture = Fixture::new("failure");
        let positions = [0, 2, 4];
        let len = 6 * NODE_SIZE;
        fixture.file.write_all_at(&vec![0xee; len], 0).unwrap();
        let read_only = File::open(&fixture.path).unwrap();
        let writer = ForestWriter::default();
        writer
            .write_nodes(&fixture.file, &[5], NODE_SIZE, record(5).to_vec())
            .unwrap();
        {
            let mut state = writer.state.lock();
            let mut batch = WriteBatch {
                state: &mut state,
                bytes: records(&positions),
                outstanding: 0,
            };
            let mut requests: Vec<_> = WritePlan::new(&positions, NODE_SIZE).collect();
            for (index, request) in requests.iter_mut().enumerate() {
                let fd = if index == 1 {
                    read_only.as_raw_fd()
                } else {
                    fixture.file.as_raw_fd()
                };
                let pointer = unsafe { batch.bytes.as_ptr().add(request.input_offset) };
                let entry = opcode::Write::new(types::Fd(fd), pointer, request.remaining)
                    .offset(request.file_offset)
                    .build()
                    .user_data(index as u64);
                // SAFETY: the batch owns bytes and both file handles outlive draining.
                unsafe { batch.state.ring.as_mut().unwrap().submission().push(&entry) }.unwrap();
                batch.outstanding += 1;
                request.pending = true;
            }
            let error = batch.complete_wave(&mut requests).unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(libc::EBADF)
            );
            batch.drain().unwrap();
            assert_eq!(batch.outstanding, 0);
        }
        let mut expected = vec![0xee; len];
        for position in [0, 4, 5] {
            expected[position * NODE_SIZE..(position + 1) * NODE_SIZE]
                .copy_from_slice(&record(position as u64));
        }
        assert_eq!(fixture.read(len), expected);
        writer
            .write_nodes(&fixture.file, &positions, NODE_SIZE, records(&positions))
            .unwrap();
        expected[2 * NODE_SIZE..3 * NODE_SIZE].copy_from_slice(&record(2));
        assert_eq!(fixture.read(len), expected);
    }

    #[test]
    fn short_write_failure_preserves_prefix_and_allows_exact_retry() {
        const CHILD: &str = "BRIDGE_FOREST_WRITER_SHORT_WRITE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "forest_writer::tests::short_write_failure_preserves_prefix_and_allows_exact_retry", "--nocapture"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // Resource limits and SIGXFSZ disposition are process-wide, hence the
        // isolated test child rather than changing the parallel runner's state.
        let fixture = Fixture::new("short");
        let mut old_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut old_limit) },
            0
        );
        let limit = libc::rlimit {
            rlim_cur: (NODE_SIZE + 7) as libc::rlim_t,
            rlim_max: old_limit.rlim_max,
        };
        assert_ne!(
            unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) },
            libc::SIG_ERR
        );
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);
        let writer = ForestWriter::default();
        let positions = [0, 1, 2];
        let expected = records(&positions);
        let error = writer
            .write_nodes(&fixture.file, &positions, NODE_SIZE, expected.clone())
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EFBIG)
        );
        assert_eq!(
            fixture.file.metadata().unwrap().len(),
            (NODE_SIZE + 7) as u64
        );
        assert_eq!(fixture.read(NODE_SIZE + 7), expected[..NODE_SIZE + 7]);
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &old_limit) },
            0
        );
        writer
            .write_nodes(&fixture.file, &positions, NODE_SIZE, expected.clone())
            .unwrap();
        assert_eq!(fixture.read(expected.len()), expected);
    }

    #[test]
    fn unwinding_drains_submitted_writes_and_retires_unsubmitted_writes() {
        let fixture = Fixture::new("unwind");
        let writer = ForestWriter::default();
        for submitted in [false, true] {
            writer
                .write_nodes(&fixture.file, &[0], NODE_SIZE, record(0).to_vec())
                .unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut state = writer.state.lock();
                let mut batch = WriteBatch {
                    state: &mut state,
                    bytes: record(1).to_vec(),
                    outstanding: 0,
                };
                let entry = opcode::Write::new(
                    types::Fd(fixture.file.as_raw_fd()),
                    batch.bytes.as_ptr(),
                    NODE_SIZE as u32,
                )
                .offset(0)
                .build();
                // SAFETY: the guard owns the buffer and drains on unwinding.
                unsafe { batch.state.ring.as_mut().unwrap().submission().push(&entry) }.unwrap();
                batch.outstanding = 1;
                if submitted {
                    batch.state.ring.as_ref().unwrap().submit().unwrap();
                }
                panic!("exercise write-buffer lifetime during unwinding");
            }));
            assert!(result.is_err());
            assert_eq!(writer.state.lock().ring.is_some(), submitted);
            assert_eq!(fixture.read(NODE_SIZE), record(u64::from(submitted)));
            writer
                .write_nodes(&fixture.file, &[0], NODE_SIZE, record(2).to_vec())
                .unwrap();
            assert_eq!(fixture.read(NODE_SIZE), record(2));
        }
    }

    #[test]
    fn invalid_inputs_do_not_initialize_the_ring_or_change_the_file() {
        let fixture = Fixture::new("invalid");
        let writer = ForestWriter::default();
        writer
            .write_nodes(&fixture.file, &[], 0, Vec::new())
            .unwrap();
        for (positions, node_size, bytes) in [
            (&[0][..], 0, Vec::new()),
            (&[1, 1][..], NODE_SIZE, vec![0; NODE_SIZE * 2]),
            (&[2, 1][..], NODE_SIZE, vec![0; NODE_SIZE * 2]),
            (&[u64::MAX][..], NODE_SIZE, vec![0; NODE_SIZE]),
            (&[i64::MAX as u64][..], 1, vec![0]),
            (&[0, 1][..], usize::MAX, Vec::new()),
            (&[0][..], NODE_SIZE, vec![0; NODE_SIZE - 1]),
            (&[][..], NODE_SIZE, vec![0]),
        ] {
            assert!(writer
                .write_nodes(&fixture.file, positions, node_size, bytes)
                .is_err());
        }
        assert!(writer.state.lock().ring.is_none());
        assert_eq!(fixture.file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn planning_coalesces_only_adjacent_records_and_bounds_opcode_lengths() {
        let positions = [0, 1, 3, 4];
        validate_positions(&positions, NODE_SIZE).unwrap();
        let requests: Vec<_> = WritePlan::new(&positions, NODE_SIZE).collect();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            (
                requests[0].file_offset,
                requests[0].input_offset,
                requests[0].remaining
            ),
            (0, 0, 66)
        );
        assert_eq!(
            (
                requests[1].file_offset,
                requests[1].input_offset,
                requests[1].remaining
            ),
            (99, 66, 66)
        );
        let node_size = MAX_WRITE_LEN + 7;
        validate_positions(&[0, 2], node_size).unwrap();
        let requests: Vec<_> = WritePlan::new(&[0, 2], node_size).collect();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].remaining as usize, MAX_WRITE_LEN);
        assert_eq!(requests[1].remaining, 7);
        assert_eq!(requests[1].file_offset, MAX_WRITE_LEN as u64);
        assert_eq!(requests[2].file_offset, 2 * node_size as u64);
        assert_eq!(requests[2].input_offset, node_size);
        assert_eq!(requests[3].input_offset, node_size + MAX_WRITE_LEN);
        assert_eq!(requests[3].remaining, 7);
    }
}
