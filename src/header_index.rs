// SPDX-License-Identifier: MIT

//! Position-addressed block headers and a persistent hash-to-height index.
//!
//! Hash keys retain the first 16 internal hash bytes; lookups verify the full
//! header hash. Heights are inline little-endian u64 values. Bootstrap batches
//! append concurrently, while steady replacements and removals exclude readers.

use std::fs::File;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use floresta_db::Config;
use floresta_db::Database;
use floresta_db::Error as DatabaseError;
use floresta_db::Mode;

#[repr(transparent)]
struct SerializedHeader([u8; 80]);

pub const HEADER_SIZE: usize = size_of::<SerializedHeader>();
const RUNTIME_HEADROOM: u64 = 64 << 20;
const HASH_KEY_SIZE: usize = 16;
const HEIGHT_VALUE_SIZE: usize = size_of::<u64>();
const BLOCK_SIZE: u64 = 1 << 20;

pub struct HeaderIndex {
    headers: File,
    // Moving the database out under the exclusive lock closes every mapped handle
    // before its persisted capacity changes. None is a failed-growth state.
    heights: RwLock<Option<Database>>,
    index_path: PathBuf,
}

pub struct HeaderBuildWriter<'index> {
    index: &'index HeaderIndex,
    height_values: Vec<[u8; HEIGHT_VALUE_SIZE]>,
}

impl HeaderIndex {
    pub fn create(header_path: &Path, index_path: &Path, max_height: u32) -> Result<Self> {
        if header_path.exists() {
            bail!("header file {} already exists", header_path.display());
        }
        if index_path.exists() {
            bail!("header index {} already exists", index_path.display());
        }
        if let Some(parent) = header_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        if let Some(parent) = index_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let header_count = u64::from(max_height) + 1;
        let header_bytes = header_count
            .checked_mul(HEADER_SIZE as u64)
            .context("header file size overflow")?;
        let headers = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(header_path)?;
        headers.set_len(header_bytes)?;
        let allocation = unsafe {
            libc::posix_fallocate(
                headers.as_raw_fd(),
                0,
                libc::off_t::try_from(header_bytes).context("header file exceeds off_t")?,
            )
        };
        if allocation != 0 {
            return Err(std::io::Error::from_raw_os_error(allocation))
                .context("failed to allocate header file");
        }

        let desired_buckets = header_count.div_ceil(4).max(1_024);
        let bucket_count = desired_buckets
            .checked_next_power_of_two()
            .context("header index bucket count overflow")?;
        let mut config = Config::new(Mode::Map, bucket_count);
        // Heights are always inline, but map mode requires fallback blob capacity.
        config.blob_capacity = BLOCK_SIZE;
        config.block_size = BLOCK_SIZE;
        config.body_capacity = align_capacity(
            header_count
                .checked_mul(64)
                .and_then(|bytes| bytes.checked_add(RUNTIME_HEADROOM))
                .context("header index capacity overflow")?,
        )?;
        let heights = Database::create(index_path, config)
            .with_context(|| format!("failed to create header index {}", index_path.display()))?;
        Ok(Self {
            headers,
            heights: RwLock::new(Some(heights)),
            index_path: index_path.to_path_buf(),
        })
    }

    pub fn open(header_path: &Path, index_path: &Path) -> Result<Self> {
        let headers = OpenOptions::new()
            .read(true)
            .write(true)
            .open(header_path)
            .with_context(|| format!("failed to open header file {}", header_path.display()))?;
        if headers.metadata()?.len() % HEADER_SIZE as u64 != 0 {
            bail!("header file length is not a multiple of {HEADER_SIZE}");
        }
        Database::ensure_runtime_body_headroom(index_path, RUNTIME_HEADROOM)
            .with_context(|| format!("failed to grow header index {}", index_path.display()))?;
        let heights = Database::open_runtime(index_path)
            .with_context(|| format!("failed to open header index {}", index_path.display()))?;
        Ok(Self {
            headers,
            heights: RwLock::new(Some(heights)),
            index_path: index_path.to_path_buf(),
        })
    }

    pub fn build_writer(&self) -> Result<HeaderBuildWriter<'_>> {
        let heights = self
            .heights
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        available_heights(&heights)?.write_only()?;
        Ok(HeaderBuildWriter {
            index: self,
            height_values: Vec::new(),
        })
    }

    pub fn put(&self, height: u32, header: &Header) -> Result<()> {
        let bytes = serialize(header);
        let bytes: [u8; HEADER_SIZE] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("header serialized to {} bytes", bytes.len())
        })?;
        let mut heights = self
            .heights
            .write()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        let hash = header.block_hash().to_byte_array();
        let key = &hash[..HASH_KEY_SIZE];
        let value = u64::from(height).to_le_bytes();
        match available_heights(&heights)?.put(key, &value) {
            Ok(_) => {}
            Err(error @ DatabaseError::CapacityExhausted("mapped file")) => {
                // Inline heights allocate only body nodes. Retry once, and only
                // after the closed database's body mapping actually grew.
                let grew = match self.grow_heights(&mut heights) {
                    Ok(grew) => grew,
                    Err(growth) => {
                        return Err(error).context(format!(
                            "failed to grow header index after insertion exhausted body capacity: {growth:#}"
                        ));
                    }
                };
                if !grew {
                    return Err(error).context("header index body capacity did not grow");
                }
                available_heights(&heights)?
                    .put(key, &value)
                    .context("failed to insert header height after growing body capacity")?;
            }
            Err(error) => return Err(error.into()),
        }
        // Readers stay excluded until both stores agree. In particular, a
        // failed close/grow/reopen must not overwrite an existing header slot.
        self.ensure_height(height)?;
        self.headers.write_all_at(&bytes, header_offset(height)?)?;
        Ok(())
    }

    fn grow_heights(&self, heights: &mut Option<Database>) -> Result<bool> {
        let database = heights
            .take()
            .context("header index unavailable after failed body capacity growth")?;
        // close consumes and drops the Database, including every mmap, even on
        // failure. Do not change its persisted configuration unless close succeeds.
        database
            .close()
            .context("failed to close header index for body capacity growth; index unavailable")?;
        let grew = Database::ensure_runtime_body_headroom(&self.index_path, RUNTIME_HEADROOM)
            .context("failed to grow header index body capacity; index unavailable")?;
        let database = Database::open_runtime(&self.index_path).context(
            "failed to reopen header index after body capacity growth; index unavailable",
        )?;
        *heights = Some(database);
        if grew {
            log::info!(
                "Grew header index body capacity online: path={} headroom_bytes={RUNTIME_HEADROOM}",
                self.index_path.display()
            );
        }
        Ok(grew)
    }

    pub fn get_by_height(&self, height: u32) -> Result<Option<Header>> {
        let heights = self
            .heights
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        available_heights(&heights)?;
        self.read_header(height)
    }

    fn read_header(&self, height: u32) -> Result<Option<Header>> {
        let offset = header_offset(height)?;
        if offset + HEADER_SIZE as u64 > self.headers.metadata()?.len() {
            return Ok(None);
        }
        let mut bytes = [0u8; HEADER_SIZE];
        self.headers.read_exact_at(&mut bytes, offset)?;
        if bytes == [0; HEADER_SIZE] {
            return Ok(None);
        }
        Ok(Some(deserialize(&bytes)?))
    }

    pub fn get_height(&self, block_hash: BlockHash) -> Result<Option<u32>> {
        let heights = self
            .heights
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        self.read_height(available_heights(&heights)?, block_hash)
    }

    fn read_height(&self, heights: &Database, block_hash: BlockHash) -> Result<Option<u32>> {
        let Some(value) = heights.get(&block_hash.to_byte_array()[..HASH_KEY_SIZE])? else {
            return Ok(None);
        };
        let value: [u8; HEIGHT_VALUE_SIZE] = value.try_into().map_err(|value: Vec<u8>| {
            anyhow::anyhow!("indexed header height has {} bytes", value.len())
        })?;
        let height = u32::try_from(u64::from_le_bytes(value))
            .context("indexed header height exceeds u32")?;
        // The fixed-width key is only a hash prefix; never return a false match.
        Ok(self
            .read_header(height)?
            .filter(|header| header.block_hash() == block_hash)
            .map(|_| height))
    }

    pub fn remove(&self, height: u32, block_hash: BlockHash) -> Result<()> {
        let heights = self
            .heights
            .write()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        let heights = available_heights(&heights)?;
        if self.read_height(heights, block_hash)? == Some(height) {
            heights.delete(&block_hash.to_byte_array()[..HASH_KEY_SIZE])?;
        }
        // Recovery may remove an old branch after its canonical replacement has
        // already been installed at this height. Never erase that replacement.
        if self
            .read_header(height)?
            .is_some_and(|header| header.block_hash() == block_hash)
        {
            self.headers
                .write_all_at(&[0; HEADER_SIZE], header_offset(height)?)?;
        }
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        let heights = self
            .heights
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        let heights = available_heights(&heights)?;
        // The runtime allocator must still be sealed if the header-file flush fails.
        let headers_result = self.headers.sync_data().context("failed to sync headers");
        let heights_result = heights.sync().context("failed to sync header heights");
        match (headers_result, heights_result) {
            (Err(headers), Err(heights)) => Err(headers.context(format!(
                "header-height synchronization also failed: {heights:#}"
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    pub fn close(self) -> Result<()> {
        let headers_result = self.headers.sync_data().context("failed to sync headers");
        let heights_result = self
            .heights
            .into_inner()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?
            .context("header index unavailable after failed body capacity growth")?
            .close();
        headers_result?;
        heights_result?;
        Ok(())
    }

    fn ensure_height(&self, height: u32) -> Result<()> {
        let required = header_offset(height)?
            .checked_add(HEADER_SIZE as u64)
            .context("header file length overflow")?;
        if self.headers.metadata()?.len() < required {
            self.headers.set_len(required)?;
        }
        Ok(())
    }
}

impl HeaderBuildWriter<'_> {
    /// Appends a batch of distinct bootstrap headers to a freshly created index.
    pub fn put_batch(&mut self, entries: &[(u32, [u8; HEADER_SIZE], [u8; 32])]) -> Result<()> {
        let heights = self
            .index
            .heights
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        // Borrow the database only for this batch, under its guard. Keeping a
        // WriteOnlyWriter in this struct would outlive a close/grow/reopen.
        let writer = available_heights(&heights)?.write_only()?;
        self.height_values.clear();
        self.height_values.extend(
            entries
                .iter()
                .map(|(height, _, _)| u64::from(*height).to_le_bytes()),
        );
        for (height, bytes, _) in entries {
            self.index
                .headers
                .write_all_at(bytes, header_offset(*height)?)?;
        }
        writer.put_batch(
            entries
                .iter()
                .zip(&self.height_values)
                .map(|((_, _, hash), height)| (&hash[..HASH_KEY_SIZE], height.as_slice())),
        )?;
        Ok(())
    }
}

fn available_heights(heights: &Option<Database>) -> Result<&Database> {
    heights
        .as_ref()
        .context("header index unavailable after failed body capacity growth")
}

fn header_offset(height: u32) -> Result<u64> {
    u64::from(height)
        .checked_mul(HEADER_SIZE as u64)
        .context("header position overflow")
}

fn align_capacity(bytes: u64) -> Result<u64> {
    bytes
        .max(BLOCK_SIZE)
        .div_ceil(BLOCK_SIZE)
        .checked_mul(BLOCK_SIZE)
        .context("header index capacity overflow")
}

#[cfg(test)]
mod tests {
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;

    use super::*;

    fn paths(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("bridge-header-index-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        (root.join("headers.dat"), root.join("hashes"))
    }

    #[test]
    fn stores_headers_at_height_times_header_size() {
        let (headers, hashes) = paths("positions");
        let index = HeaderIndex::create(&headers, &hashes, 10).unwrap();
        let header = genesis_block(Network::Signet).header;
        index.put(7, &header).unwrap();
        index.sync().unwrap();

        let mut raw = [0u8; HEADER_SIZE];
        index
            .headers
            .read_exact_at(&mut raw, 7 * HEADER_SIZE as u64)
            .unwrap();
        assert_eq!(raw.to_vec(), serialize(&header));
        assert_eq!(index.get_by_height(7).unwrap(), Some(header));
        assert_eq!(index.get_height(header.block_hash()).unwrap(), Some(7));
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn reopens_hash_to_height_index() {
        let (headers, hashes) = paths("reopen");
        let header = genesis_block(Network::Bitcoin).header;
        let mut later = header;
        later.nonce = later.nonce.wrapping_add(1);
        let index = HeaderIndex::create(&headers, &hashes, 1).unwrap();
        index.put(0, &header).unwrap();
        index.put(7, &later).unwrap();
        index.close().unwrap();

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_eq!(index.get_height(header.block_hash()).unwrap(), Some(0));
        assert_eq!(index.get_by_height(0).unwrap(), Some(header));
        assert_eq!(index.get_height(later.block_hash()).unwrap(), Some(7));
        assert_eq!(index.get_by_height(7).unwrap(), Some(later));
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn batches_headers_concurrently_and_reopens_cleanly() {
        let (headers, hashes) = paths("batch-reopen");
        let genesis = genesis_block(Network::Bitcoin).header;
        let entries: Vec<(u32, [u8; HEADER_SIZE], [u8; 32])> = (0..8)
            .map(|height| {
                let mut header = genesis;
                header.nonce = header.nonce.wrapping_add(height);
                (
                    height,
                    serialize(&header).try_into().unwrap(),
                    header.block_hash().to_byte_array(),
                )
            })
            .collect();
        let index = HeaderIndex::create(&headers, &hashes, 7).unwrap();
        std::thread::scope(|scope| {
            for range in entries.chunks(4) {
                let index = &index;
                scope.spawn(move || {
                    let mut writer = index.build_writer().unwrap();
                    writer.put_batch(&[]).unwrap();
                    for batch in range.chunks(2) {
                        writer.put_batch(batch).unwrap();
                    }
                });
            }
        });
        index.close().unwrap();

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        for (height, bytes, hash) in entries {
            assert_eq!(
                index.get_by_height(height).unwrap(),
                Some(deserialize(&bytes).unwrap())
            );
            assert_eq!(
                index.get_height(BlockHash::from_byte_array(hash)).unwrap(),
                Some(height)
            );
            assert_eq!(
                available_heights(&index.heights.read().unwrap())
                    .unwrap()
                    .get(&hash[..HASH_KEY_SIZE])
                    .unwrap(),
                Some(u64::from(height).to_le_bytes().to_vec())
            );
        }
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn rejects_full_hash_mismatches_and_overflowing_heights() {
        let (headers, hashes) = paths("validated-heights");
        let header = genesis_block(Network::Bitcoin).header;
        let index = HeaderIndex::create(&headers, &hashes, 0).unwrap();
        index.put(0, &header).unwrap();
        let mut collision = header.block_hash().to_byte_array();
        collision[31] ^= 1;
        assert_eq!(
            index
                .get_height(BlockHash::from_byte_array(collision))
                .unwrap(),
            None
        );
        assert_eq!(index.get_height(header.block_hash()).unwrap(), Some(0));

        available_heights(&index.heights.write().unwrap())
            .unwrap()
            .put(
                &header.block_hash().to_byte_array()[..HASH_KEY_SIZE],
                &(u64::from(u32::MAX) + 1).to_le_bytes(),
            )
            .unwrap();
        assert!(index.get_height(header.block_hash()).is_err());
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn replaces_steady_headers_without_retaining_duplicates() {
        let (headers, hashes) = paths("replacement");
        let header = genesis_block(Network::Bitcoin).header;
        let index = HeaderIndex::create(&headers, &hashes, 0).unwrap();
        index.put(0, &header).unwrap();
        index.put(0, &header).unwrap();
        index.remove(0, header.block_hash()).unwrap();
        assert_eq!(
            available_heights(&index.heights.read().unwrap())
                .unwrap()
                .get(&header.block_hash().to_byte_array()[..HASH_KEY_SIZE])
                .unwrap(),
            None
        );
        index.close().unwrap();

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_eq!(index.get_by_height(0).unwrap(), None);
        assert_eq!(index.get_height(header.block_hash()).unwrap(), None);
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn removing_replaced_header_preserves_canonical_slot() {
        let (headers, hashes) = paths("remove-replaced");
        let original = test_header(0);
        let replacement = test_header(1);
        let index = HeaderIndex::create(&headers, &hashes, 0).unwrap();
        index.put(0, &original).unwrap();
        index.put(0, &replacement).unwrap();
        index.remove(0, original.block_hash()).unwrap();
        assert_eq!(index.get_by_height(0).unwrap(), Some(replacement));
        assert_eq!(index.get_height(replacement.block_hash()).unwrap(), Some(0));
        assert_eq!(index.get_height(original.block_hash()).unwrap(), None);
        index.close().unwrap();

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_eq!(index.get_by_height(0).unwrap(), Some(replacement));
        assert_eq!(index.get_height(replacement.block_hash()).unwrap(), Some(0));
        index.remove(0, replacement.block_hash()).unwrap();
        assert_eq!(index.get_by_height(0).unwrap(), None);
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn failed_header_flush_still_seals_height_allocator_on_close() {
        let (headers, hashes) = paths("close-header-flush-failure");
        let header = test_header(0);
        let mut index = HeaderIndex::create(&headers, &hashes, 0).unwrap();
        index.put(0, &header).unwrap();
        index.headers.sync_data().unwrap();
        // Linux character devices reject fsync; the height database must still
        // be closed and its allocator sealed before this error is returned.
        index.headers = File::open("/dev/null").unwrap();
        assert!(index.close().is_err());

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_eq!(index.get_by_height(0).unwrap(), Some(header));
        assert_eq!(index.get_height(header.block_hash()).unwrap(), Some(0));
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    fn test_header(height: u32) -> Header {
        let mut header = genesis_block(Network::Bitcoin).header;
        header.nonce = header.nonce.wrapping_add(height);
        header
    }

    fn tiny_index(name: &str) -> (HeaderIndex, PathBuf, PathBuf) {
        let (headers, hashes) = paths(name);
        let mut config = Config::new(Mode::Map, 16);
        config.block_size = 64 << 10;
        config.body_capacity = config.block_size;
        config.blob_capacity = config.block_size;
        let index = HeaderIndex {
            headers: OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&headers)
                .unwrap(),
            heights: RwLock::new(Some(Database::create(&hashes, config).unwrap())),
            index_path: hashes.clone(),
        };
        for height in 0..4 {
            index.put(height, &test_header(height)).unwrap();
        }
        // Sync seals the sole page with live keys, deterministically leaving no
        // reusable page or append capacity, without changing allocator behavior.
        index.sync().unwrap();
        {
            let heights = index.heights.write().expect("header storage lock");
            let database = available_heights(&heights).unwrap();
            assert_eq!(database.stats().unwrap().body.high_water_pages, 1);
            assert!(matches!(
                database.put(
                    &test_header(4).block_hash().to_byte_array()[..HASH_KEY_SIZE],
                    &4u64.to_le_bytes(),
                ),
                Err(DatabaseError::CapacityExhausted("mapped file"))
            ));
        }
        (index, headers, hashes)
    }

    fn assert_headers(index: &HeaderIndex, count: u32) {
        for height in 0..count {
            let header = test_header(height);
            assert_eq!(index.get_by_height(height).unwrap(), Some(header));
            assert_eq!(index.get_height(header.block_hash()).unwrap(), Some(height));
        }
    }

    fn persisted_body_capacity(path: &Path) -> u64 {
        // floresta-db format v7 stores body_capacity at byte 40 of heads.
        let mut bytes = [0u8; size_of::<u64>()];
        File::open(path.join("heads"))
            .unwrap()
            .read_exact_at(&mut bytes, 40)
            .unwrap();
        u64::from_le_bytes(bytes)
    }

    #[test]
    fn grows_exhausted_body_online_and_reopens() {
        let (index, headers, hashes) = tiny_index("online-growth");
        let old_capacity = persisted_body_capacity(&hashes);
        assert_eq!(old_capacity, 64 << 10);
        assert_headers(&index, 4);
        // A bootstrap writer may outlive a remapping, but its borrowed database
        // writer must not. Reusing this handle exercises that lifetime boundary.
        let mut writer = index.build_writer().unwrap();
        index.put(4, &test_header(4)).unwrap();
        let new_capacity = persisted_body_capacity(&hashes);
        assert_eq!(new_capacity, old_capacity + RUNTIME_HEADROOM);
        {
            let heights = index.heights.read().expect("header storage lock");
            assert_eq!(
                available_heights(&heights)
                    .unwrap()
                    .stats()
                    .unwrap()
                    .body
                    .high_water_pages,
                2
            );
        }
        let header = test_header(5);
        writer
            .put_batch(&[(
                5,
                serialize(&header).try_into().unwrap(),
                header.block_hash().to_byte_array(),
            )])
            .unwrap();
        drop(writer);
        index.sync().unwrap();
        assert_headers(&index, 6);
        index.close().unwrap();

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_headers(&index, 6);
        index.put(6, &test_header(6)).unwrap();
        assert_headers(&index, 7);
        index.close().unwrap();
        eprintln!(
            "header-index-growth-smoke old_body_capacity_bytes={old_capacity} \
             new_body_capacity_bytes={new_capacity} same_process_put_and_reads=ok \
             reopen_put_and_reads=ok"
        );
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn readers_and_sync_survive_online_body_growth() {
        let (index, headers, hashes) = tiny_index("concurrent-online-growth");
        let barrier = std::sync::Barrier::new(4);
        const ROUNDS: u32 = 16;
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let index = &index;
                let barrier = &barrier;
                scope.spawn(move || {
                    for round in 0..ROUNDS {
                        assert_headers(index, 4 + round);
                        barrier.wait();
                        for _ in 0..16 {
                            assert_headers(index, 4);
                        }
                        barrier.wait();
                        assert_headers(index, 5 + round);
                    }
                });
            }
            let index_ref = &index;
            let barrier_ref = &barrier;
            scope.spawn(move || {
                for _ in 0..ROUNDS {
                    barrier_ref.wait();
                    index_ref.sync().unwrap();
                    barrier_ref.wait();
                }
            });
            for round in 0..ROUNDS {
                barrier.wait();
                index.put(4 + round, &test_header(4 + round)).unwrap();
                barrier.wait();
            }
        });
        index.close().unwrap();

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_headers(&index, 4 + ROUNDS);
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn failed_body_growth_leaves_index_explicitly_unavailable() {
        let (mut index, headers, hashes) = tiny_index("failed-online-growth");
        index.index_path = headers.parent().unwrap().join("missing-index");
        let error = index.put(0, &test_header(4)).unwrap_err();
        assert!(error.to_string().contains("failed to grow header index"));
        assert!(matches!(
            error.downcast_ref::<DatabaseError>(),
            Some(DatabaseError::CapacityExhausted("mapped file"))
        ));
        assert!(index.heights.read().expect("header storage lock").is_none());
        assert!(index.get_height(test_header(0).block_hash()).is_err());
        assert!(index.get_by_height(0).is_err());
        assert!(index.put(5, &test_header(5)).is_err());
        assert!(index.remove(0, test_header(0).block_hash()).is_err());
        assert!(index.build_writer().is_err());
        assert!(index.sync().is_err());
        assert!(index.close().is_err());
        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_headers(&index, 4);
        assert_eq!(index.get_height(test_header(4).block_hash()).unwrap(), None);
        index.close().unwrap();
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }
}
