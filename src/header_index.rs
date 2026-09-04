// SPDX-License-Identifier: MIT

//! Position-addressed block headers and a persistent hash-to-height index.

use std::fs::File;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use db_experiment::Config;
use db_experiment::Database;
use db_experiment::Mode;
use db_experiment::WriteOnlyWriter;

#[repr(transparent)]
struct SerializedHeader([u8; 80]);

pub const HEADER_SIZE: usize = size_of::<SerializedHeader>();
const RUNTIME_HEADROOM: u64 = 64 << 20;
const HASH_KEY_SIZE: usize = 32;
const HEIGHT_VALUE_SIZE: usize = size_of::<u32>();
const BLOCK_SIZE: u64 = 1 << 20;

pub struct HeaderIndex {
    headers: File,
    heights: Database,
}

pub struct HeaderBuildWriter<'index> {
    index: &'index HeaderIndex,
    heights: WriteOnlyWriter<'index>,
}

impl HeaderIndex {
    pub fn create(
        header_path: &Path,
        index_path: &Path,
        max_height: u32,
        workers: usize,
    ) -> Result<Self> {
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
        let mut config = Config::new(Mode::Map, bucket_count, HASH_KEY_SIZE);
        config.inline_value_size = HEIGHT_VALUE_SIZE;
        config.blob_capacity = 0;
        config.block_size = BLOCK_SIZE;
        config.body_capacity = align_capacity(
            header_count
                .checked_mul(64)
                .and_then(|bytes| bytes.checked_add(RUNTIME_HEADROOM))
                .context("header index capacity overflow")?,
        )?;
        config.max_threads =
            u16::try_from(workers.max(64)).context("header worker count exceeds u16")?;
        let heights = Database::create(index_path, config)
            .with_context(|| format!("failed to create header index {}", index_path.display()))?;
        Ok(Self { headers, heights })
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
        Ok(Self { headers, heights })
    }

    pub fn build_writer(&self) -> Result<HeaderBuildWriter<'_>> {
        Ok(HeaderBuildWriter {
            index: self,
            heights: self.heights.write_only()?,
        })
    }

    pub fn put(&self, height: u32, header: &Header) -> Result<()> {
        let bytes = serialize(header);
        let bytes: [u8; HEADER_SIZE] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("header serialized to {} bytes", bytes.len())
        })?;
        self.ensure_height(height)?;
        self.headers.write_all_at(&bytes, header_offset(height)?)?;
        self.heights
            .put(&header.block_hash().to_byte_array(), &height.to_le_bytes())?;
        Ok(())
    }

    pub fn get_by_height(&self, height: u32) -> Result<Option<Header>> {
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
        self.heights
            .get(&block_hash.to_byte_array())?
            .map(|height| {
                let height: [u8; HEIGHT_VALUE_SIZE] =
                    height.try_into().map_err(|height: Vec<u8>| {
                        anyhow::anyhow!("indexed header height has {} bytes", height.len())
                    })?;
                Ok(u32::from_le_bytes(height))
            })
            .transpose()
    }

    pub fn remove(&self, height: u32, block_hash: BlockHash) -> Result<()> {
        self.heights.delete(&block_hash.to_byte_array())?;
        let offset = header_offset(height)?;
        if offset + HEADER_SIZE as u64 <= self.headers.metadata()?.len() {
            self.headers.write_all_at(&[0; HEADER_SIZE], offset)?;
        }
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
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
    pub fn put(&self, height: u32, bytes: [u8; HEADER_SIZE], block_hash: [u8; 32]) -> Result<()> {
        self.index
            .headers
            .write_all_at(&bytes, header_offset(height)?)?;
        self.heights
            .put_unique(&block_hash, &height.to_le_bytes())?;
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
        let index = HeaderIndex::create(&headers, &hashes, 10, 1).unwrap();
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
        drop(index);
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }

    #[test]
    fn reopens_hash_to_height_index() {
        let (headers, hashes) = paths("reopen");
        let header = genesis_block(Network::Bitcoin).header;
        let mut later = header;
        later.nonce = later.nonce.wrapping_add(1);
        let index = HeaderIndex::create(&headers, &hashes, 1, 1).unwrap();
        index.put(0, &header).unwrap();
        index.put(7, &later).unwrap();
        index.close().unwrap();

        let index = HeaderIndex::open(&headers, &hashes).unwrap();
        assert_eq!(index.get_height(header.block_hash()).unwrap(), Some(0));
        assert_eq!(index.get_by_height(0).unwrap(), Some(header));
        assert_eq!(index.get_height(later.block_hash()).unwrap(), Some(7));
        assert_eq!(index.get_by_height(7).unwrap(), Some(later));
        drop(index);
        std::fs::remove_dir_all(headers.parent().unwrap()).unwrap();
    }
}
