// SPDX-License-Identifier: MIT

//! Explicit, coalesced forest reads. No file data is accessed through mmap or pread.

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
// CQE results are signed 32-bit lengths. Linux may impose a smaller per-read limit;
// such a short read is completed by another request, just like any other short read.
const MAX_READ_LEN: usize = i32::MAX as usize;

/// A lazily initialized ring, shared only between serialized read batches.
#[derive(Default)]
pub(crate) struct ForestReader {
    ring: Mutex<Option<IoUring>>,
}

impl ForestReader {
    /// Read sorted, unique fixed-size records into their corresponding output slots.
    ///
    /// Empty input does not initialize io_uring. Nonempty reads require a nonzero
    /// record size, representable allocation length, and signed Linux file offsets.
    /// Contiguous records share a request, subject to the opcode's length limit.
    pub(crate) fn read_nodes(
        &self,
        file: &File,
        positions: &[u64],
        node_size: usize,
    ) -> Result<Vec<u8>> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let output_len = validate_positions(positions, node_size)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_len)
            .context("cannot allocate forest read buffer")?;

        let mut ring = self.ring.lock();
        if ring.is_none() {
            *ring = Some(IoUring::new(RING_ENTRIES as u32).context(
                "forest proof reads require Linux io_uring with IORING_OP_READ (Linux 5.6+) \
                 and permission for io_uring_setup/io_uring_enter; check \
                 kernel.io_uring_disabled, group permissions, and seccomp",
            )?);
        }

        let mut batch = ReadBatch {
            ring: &mut ring,
            output,
            outstanding: 0,
        };
        if let Err(error) = batch.read(file, ReadPlan::new(positions, node_size)) {
            return Err(match batch.drain() {
                Ok(()) => error,
                Err(drain_error) => error.context(format!(
                    "fatal forest io_uring completion-drain failure: {drain_error}; \
                     ring retired and read allocation retained to protect outstanding I/O"
                )),
            });
        }

        let mut output = mem::take(&mut batch.output);
        // SAFETY: the plan partitions exactly output_len bytes of this allocation.
        // Every request (including short-read continuations) completed successfully,
        // and all CQEs were consumed before any initialized bytes become accessible.
        unsafe { output.set_len(output_len) };
        Ok(output)
    }
}

fn validate_positions(positions: &[u64], node_size: usize) -> Result<usize> {
    if node_size == 0 {
        bail!("forest read node size must be nonzero");
    }
    if positions.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("forest read positions must be sorted and unique");
    }
    let output_len = positions
        .len()
        .checked_mul(node_size)
        .filter(|&length| length <= isize::MAX as usize)
        .context("forest read allocation length overflow")?;
    let node_size = u64::try_from(node_size).context("forest read node size overflow")?;
    if let Some(&last) = positions.last() {
        last.checked_mul(node_size)
            .and_then(|offset| offset.checked_add(node_size))
            .filter(|&end| end <= i64::MAX as u64)
            .context("forest read file offset overflow")?;
    }
    Ok(output_len)
}

#[derive(Clone, Copy, Default, Debug)]
struct ReadRequest {
    file_offset: u64,
    output_offset: usize,
    remaining: u32,
    pending: bool,
}

/// Streams coalesced runs without allocating a descriptor per requested node.
/// Its input has already passed validate_positions, bounding all arithmetic.
struct ReadPlan<'a> {
    positions: &'a [u64],
    node_size: usize,
    next_position: usize,
    output_offset: usize,
    file_offset: u64,
    run_remaining: usize,
}

impl<'a> ReadPlan<'a> {
    fn new(positions: &'a [u64], node_size: usize) -> Self {
        Self {
            positions,
            node_size,
            next_position: 0,
            output_offset: 0,
            file_offset: 0,
            run_remaining: 0,
        }
    }
}

impl Iterator for ReadPlan<'_> {
    type Item = ReadRequest;

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
        let length = self.run_remaining.min(MAX_READ_LEN);
        let request = ReadRequest {
            file_offset: self.file_offset,
            output_offset: self.output_offset,
            remaining: length as u32,
            pending: false,
        };
        self.file_offset += length as u64;
        self.output_offset += length;
        self.run_remaining -= length;
        Some(request)
    }
}

/// Owns the allocation while kernel writes may be outstanding. The Vec's length
/// stays zero until every byte has been initialized by completed read requests.
///
/// Neither closing a ring nor unwinding is assumed to synchronously cancel I/O.
/// Normal errors drain CQEs before freeing memory. If a permanent enter error
/// prevents draining, we deliberately leak this one allocation and retire the
/// ring, including unsubmitted SQEs. Submitted requests hold kernel file references;
/// the caller's File remains borrowed throughout draining and ring retirement.
struct ReadBatch<'a> {
    ring: &'a mut Option<IoUring>,
    output: Vec<u8>,
    // Counts pushed SQEs not yet reaped, including any not consumed by the kernel.
    outstanding: usize,
}

impl ReadBatch<'_> {
    fn read(&mut self, file: &File, mut plan: ReadPlan<'_>) -> Result<()> {
        let mut requests = [ReadRequest::default(); RING_ENTRIES];
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
            self.read_wave(file, &mut requests[..count])?;
        }
    }

    fn read_wave(&mut self, file: &File, requests: &mut [ReadRequest]) -> Result<()> {
        loop {
            let ring = self.ring.as_mut().expect("initialized forest read ring");
            let buffer = self.output.as_mut_ptr();
            {
                let mut submission = ring.submission();
                for (index, request) in requests.iter_mut().enumerate() {
                    if request.remaining == 0 {
                        continue;
                    }
                    // SAFETY: validated plan ranges are disjoint and within the
                    // allocation. Continuations run only after the previous CQE.
                    // This allocation never moves, reallocates, or becomes readable
                    // while requests are outstanding; drain/Drop protect all exits.
                    let pointer = unsafe { buffer.add(request.output_offset) };
                    let entry =
                        opcode::Read::new(types::Fd(file.as_raw_fd()), pointer, request.remaining)
                            .offset(request.file_offset)
                            .build()
                            .user_data(index as u64);
                    // SAFETY: buffer and file lifetimes are described above. The
                    // default ring has no SQPOLL; no work begins before enter.
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

            let mut first_error = None;
            while self.outstanding != 0 {
                {
                    let completions = ring.completion();
                    for completion in completions {
                        self.outstanding -= 1;
                        let Some(request) = requests.get_mut(completion.user_data() as usize)
                        else {
                            first_error.get_or_insert_with(|| {
                                anyhow!("forest io_uring returned an unknown request identifier")
                            });
                            continue;
                        };
                        if !request.pending {
                            first_error.get_or_insert_with(|| {
                                anyhow!("forest io_uring returned a duplicate completion")
                            });
                            continue;
                        }
                        request.pending = false;
                        let result = completion.result();
                        if result == -libc::EINTR {
                            // A completed interrupted read owns no buffer any more;
                            // retry its still-unread suffix in the next round.
                            continue;
                        }
                        if result < 0 {
                            first_error.get_or_insert_with(|| {
                                anyhow::Error::from(io::Error::from_raw_os_error(-result)).context(
                                    format!(
                                        "io_uring forest read at byte {} failed; \
                                         IORING_OP_READ and filesystem support are required",
                                        request.file_offset
                                    ),
                                )
                            });
                        } else if result == 0 {
                            first_error.get_or_insert_with(|| {
                                anyhow::Error::from(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!(
                                        "io_uring forest read reached EOF at byte {} with {} bytes unread",
                                        request.file_offset, request.remaining
                                    ),
                                ))
                            });
                        } else if result as u32 > request.remaining {
                            first_error.get_or_insert_with(|| {
                                anyhow!("forest io_uring read exceeded its requested length")
                            });
                        } else {
                            request.file_offset += result as u64;
                            request.output_offset += result as usize;
                            request.remaining -= result as u32;
                        }
                    }
                }
                if self.outstanding == 0 {
                    break;
                }
                // Do not infer completion from the syscall return count: enter can
                // consume only part of the SQ. Subsequent calls submit the remaining
                // entries, and only matching CQEs release their output regions.
                match ring.submit_and_wait(1) {
                    Ok(_) => {}
                    Err(error)
                        if error.kind() == io::ErrorKind::Interrupted
                            || error.raw_os_error() == Some(libc::EBUSY) => {}
                    Err(error) => {
                        return Err(error).context("submitting/waiting for forest io_uring reads");
                    }
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            // Only short or interrupted requests still have unread bytes. Finish
            // those before advancing to another bounded wave.
        }
    }

    fn drain(&mut self) -> io::Result<()> {
        if self.outstanding == 0 {
            return Ok(());
        }
        match self.drain_consumed() {
            Ok(discard_queued) => {
                if discard_queued {
                    // Never let unsubmitted SQEs outlive the allocation or be
                    // submitted by the next caller using this reader.
                    self.ring.take();
                }
                self.outstanding = 0;
                Ok(())
            }
            Err(error) => {
                // Ring close is NOT a completion barrier. Retain memory before
                // retiring it, so even deferred cancellation cannot cause a UAF.
                mem::forget(mem::take(&mut self.output));
                self.ring.take();
                self.outstanding = 0;
                Err(error)
            }
        }
    }

    fn drain_consumed(&mut self) -> io::Result<bool> {
        let ring = self.ring.as_mut().expect("initialized forest read ring");
        // With no SQPOLL and exclusive ownership, the SQ head cannot advance
        // except during our own enter calls. Count consumed entries using the
        // queue, not an enter return value that may have reported EINTR/error.
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
            // SAFETY: GETEVENTS with no sigmask and no submissions is the normal
            // wait-only enter operation. In particular it cannot consume queued
            // SQEs after an earlier submission error. The owned allocation and
            // caller's file are still alive while previously consumed work drains.
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

impl Drop for ReadBatch<'_> {
    fn drop(&mut self) {
        // Covers unwinding as well as future early-return paths. drain itself
        // retains the allocation if the kernel will not let us observe completion.
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
                "bridge-forest-reader-{}-{name}-{}.dat",
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

        fn populate(&self, positions: &[u64]) -> Vec<u8> {
            let mut expected = Vec::with_capacity(positions.len() * NODE_SIZE);
            for &position in positions {
                let record = record(position);
                self.file
                    .write_all_at(&record, position * NODE_SIZE as u64)
                    .unwrap();
                expected.extend_from_slice(&record);
            }
            expected
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

    fn ring_fd(reader: &ForestReader) -> i32 {
        reader.ring.lock().as_ref().unwrap().as_raw_fd()
    }

    #[test]
    fn sparse_and_adjacent_reads_preserve_data_order_and_file_cursor() {
        let mut fixture = Fixture::new("sparse-adjacent");
        let positions = [0, 1, 2, 17, 18, 4096, 8193, 8194];
        let expected = fixture.populate(&positions);
        fixture.file.seek(SeekFrom::Start(19)).unwrap();
        let reader = ForestReader::default();
        assert_eq!(
            reader
                .read_nodes(&fixture.file, &positions, NODE_SIZE)
                .unwrap(),
            expected
        );
        assert_eq!(fixture.file.stream_position().unwrap(), 19);
    }

    #[test]
    fn sparse_batches_larger_than_the_ring_and_different_files_reuse_it() {
        let fixture = Fixture::new("many-waves");
        let positions: Vec<_> = (0..RING_ENTRIES as u64 * 3 + 17)
            .map(|index| index * 2)
            .collect();
        let expected = fixture.populate(&positions);
        let reader = ForestReader::default();
        assert_eq!(
            reader
                .read_nodes(&fixture.file, &positions, NODE_SIZE)
                .unwrap(),
            expected
        );
        let initial_ring = ring_fd(&reader);
        let other = Fixture::new("other-file");
        other.file.write_all_at(&[91; NODE_SIZE], 0).unwrap();
        assert_eq!(
            reader.read_nodes(&other.file, &[0], NODE_SIZE).unwrap(),
            [91; NODE_SIZE]
        );
        assert_eq!(ring_fd(&reader), initial_ring);
    }

    #[test]
    fn short_read_then_eof_drains_other_requests_and_reuses_ring() {
        let fixture = Fixture::new("short-eof");
        fixture.populate(&[0, 1]);
        fixture
            .file
            .write_all_at(&record(2)[..7], 2 * NODE_SIZE as u64)
            .unwrap();
        let reader = ForestReader::default();
        // This coalesced request first reads 73 bytes, then receives EOF when
        // reading its remaining suffix; it must never expose uninitialized bytes.
        let error = reader
            .read_nodes(&fixture.file, &[0, 1, 2], NODE_SIZE)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let initial_ring = ring_fd(&reader);
        // Also fail with other requests in the same wave, not just a single read.
        let positions: Vec<_> = (0..RING_ENTRIES as u64).map(|index| index * 2).collect();
        let error = reader
            .read_nodes(&fixture.file, &positions, NODE_SIZE)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let expected = fixture.populate(&positions);
        assert_eq!(
            reader
                .read_nodes(&fixture.file, &positions, NODE_SIZE)
                .unwrap(),
            expected
        );
        assert_eq!(ring_fd(&reader), initial_ring);
    }

    #[test]
    fn read_error_drains_the_batch_and_does_not_poison_the_ring() {
        let fixture = Fixture::new("write-only");
        let positions: Vec<_> = (0..RING_ENTRIES as u64).map(|index| index * 2).collect();
        let expected = fixture.populate(&positions);
        let write_only = OpenOptions::new().write(true).open(&fixture.path).unwrap();
        let reader = ForestReader::default();
        // Default io_uring may stop a submission at the first invalid request;
        // every remaining SQE must still be submitted and reaped before reuse.
        let error = reader
            .read_nodes(&write_only, &positions, NODE_SIZE)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EBADF)
        );
        let initial_ring = ring_fd(&reader);
        assert_eq!(
            reader
                .read_nodes(&fixture.file, &positions, NODE_SIZE)
                .unwrap(),
            expected
        );
        assert_eq!(ring_fd(&reader), initial_ring);
    }

    #[test]
    fn unwinding_drains_submitted_reads_and_retires_unsubmitted_reads() {
        let fixture = Fixture::new("unwind");
        let expected = fixture.populate(&[0]);
        let reader = ForestReader::default();
        for submitted in [false, true] {
            assert_eq!(
                reader.read_nodes(&fixture.file, &[0], NODE_SIZE).unwrap(),
                expected
            );
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut ring = reader.ring.lock();
                let mut batch = ReadBatch {
                    ring: &mut ring,
                    output: Vec::with_capacity(NODE_SIZE),
                    outstanding: 0,
                };
                let entry = opcode::Read::new(
                    types::Fd(fixture.file.as_raw_fd()),
                    batch.output.as_mut_ptr(),
                    NODE_SIZE as u32,
                )
                .offset(0)
                .build();
                // SAFETY: the guard owns the allocation and drains/retains it on
                // unwind. The fixture's file outlives this entire scope.
                unsafe {
                    batch
                        .ring
                        .as_mut()
                        .unwrap()
                        .submission()
                        .push(&entry)
                        .unwrap();
                }
                batch.outstanding = 1;
                if submitted {
                    batch.ring.as_ref().unwrap().submit().unwrap();
                }
                panic!("exercise read-buffer lifetime during unwinding");
            }));
            assert!(result.is_err());
            assert_eq!(reader.ring.lock().is_some(), submitted);
            assert_eq!(
                reader.read_nodes(&fixture.file, &[0], NODE_SIZE).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn empty_and_invalid_inputs_do_not_initialize_the_ring() {
        let fixture = Fixture::new("boundaries");
        let reader = ForestReader::default();
        assert!(reader.read_nodes(&fixture.file, &[], 0).unwrap().is_empty());
        for (positions, node_size) in [
            (&[0][..], 0),
            (&[1, 1][..], NODE_SIZE),
            (&[2, 1][..], NODE_SIZE),
            (&[u64::MAX][..], NODE_SIZE),
            (&[i64::MAX as u64][..], 1),
            (&[0, 1][..], usize::MAX),
            (&[0][..], usize::MAX),
        ] {
            assert!(reader
                .read_nodes(&fixture.file, positions, node_size)
                .is_err());
        }
        assert!(reader.ring.lock().is_none());
        assert_eq!(validate_positions(&[i64::MAX as u64 - 1], 1).unwrap(), 1);
    }

    #[test]
    fn planning_coalesces_runs_and_splits_only_at_the_opcode_limit() {
        let positions = [0, 1, 3, 4];
        validate_positions(&positions, NODE_SIZE).unwrap();
        let requests: Vec<_> = ReadPlan::new(&positions, NODE_SIZE).collect();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].file_offset, 0);
        assert_eq!(requests[0].output_offset, 0);
        assert_eq!(requests[0].remaining as usize, NODE_SIZE * 2);
        assert_eq!(requests[1].file_offset, 3 * NODE_SIZE as u64);
        assert_eq!(requests[1].output_offset, 2 * NODE_SIZE);
        assert_eq!(requests[1].remaining as usize, NODE_SIZE * 2);

        let positions = [0, 2];
        let node_size = MAX_READ_LEN + 7;
        validate_positions(&positions, node_size).unwrap();
        let requests: Vec<_> = ReadPlan::new(&positions, node_size).collect();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].remaining as usize, MAX_READ_LEN);
        assert_eq!(requests[1].remaining, 7);
        assert_eq!(requests[1].file_offset, MAX_READ_LEN as u64);
        assert_eq!(requests[2].file_offset, 2 * node_size as u64);
        assert_eq!(requests[2].output_offset, node_size);
        assert_eq!(requests[3].output_offset, node_size + MAX_READ_LEN);
        assert_eq!(requests[3].remaining, 7);
    }
}
