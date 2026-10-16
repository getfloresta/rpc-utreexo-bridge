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
use floresta_db::Mode;
use floresta_db::WriteOnlyWriter;

#[repr(transparent)]
struct SerializedHeader([u8; 80]);

pub const HEADER_SIZE: usize = size_of::<SerializedHeader>();
const RUNTIME_HEADROOM: u64 = 64 << 20;
const HASH_KEY_SIZE: usize = 16;
const HEIGHT_VALUE_SIZE: usize = size_of::<u64>();
const BLOCK_SIZE: u64 = 1 << 20;

pub struct HeaderIndex {
    headers: File,
    heights: Database,
    // Deletion/replacement must exclude database readers and bootstrap writers.
    access: RwLock<()>,
}

pub struct HeaderBuildWriter<'index> {
    index: &'index HeaderIndex,
    heights: WriteOnlyWriter<'index>,
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
            heights,
            access: RwLock::new(()),
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
            heights,
            access: RwLock::new(()),
        })
    }

    pub fn build_writer(&self) -> Result<HeaderBuildWriter<'_>> {
        Ok(HeaderBuildWriter {
            index: self,
            heights: self.heights.write_only()?,
            height_values: Vec::new(),
        })
    }

    pub fn put(&self, height: u32, header: &Header) -> Result<()> {
        let bytes = serialize(header);
        let bytes: [u8; HEADER_SIZE] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("header serialized to {} bytes", bytes.len())
        })?;
        let _guard = self
            .access
            .write()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        self.ensure_height(height)?;
        self.headers.write_all_at(&bytes, header_offset(height)?)?;
        self.heights.put(
            &header.block_hash().to_byte_array()[..HASH_KEY_SIZE],
            &u64::from(height).to_le_bytes(),
        )?;
        Ok(())
    }

    pub fn get_by_height(&self, height: u32) -> Result<Option<Header>> {
        let _guard = self
            .access
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
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
        let _guard = self
            .access
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        self.read_height(block_hash)
    }

    fn read_height(&self, block_hash: BlockHash) -> Result<Option<u32>> {
        let Some(value) = self
            .heights
            .get(&block_hash.to_byte_array()[..HASH_KEY_SIZE])?
        else {
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
        let _guard = self
            .access
            .write()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        if self.read_height(block_hash)? == Some(height) {
            self.heights
                .delete(&block_hash.to_byte_array()[..HASH_KEY_SIZE])?;
        }
        let offset = header_offset(height)?;
        if offset + HEADER_SIZE as u64 <= self.headers.metadata()?.len() {
            self.headers.write_all_at(&[0; HEADER_SIZE], offset)?;
        }
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        let _guard = self
            .access
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
        self.headers.sync_data()?;
        self.heights.sync()?;
        Ok(())
    }

    pub fn close(self) -> Result<()> {
        self.headers.sync_data()?;
        self.heights.close()?;
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
        let _guard = self
            .index
            .access
            .read()
            .map_err(|_| anyhow::anyhow!("header index lock poisoned"))?;
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
        self.heights.put_batch(
            entries
                .iter()
                .zip(&self.height_values)
                .map(|((_, _, hash), height)| (&hash[..HASH_KEY_SIZE], height.as_slice())),
        )?;
        Ok(())
    }
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
                index.heights.get(&hash[..HASH_KEY_SIZE]).unwrap(),
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

        index
            .heights
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
            index
                .heights
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
}
