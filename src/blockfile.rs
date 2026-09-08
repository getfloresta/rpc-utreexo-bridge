// SPDX-License-Identifier: MIT

//! Append-only compact proof storage.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;

use crate::block_index::BlockIndex;
use crate::udata::CompactBlockProof;

/// An append-only file containing compact block proofs without Bitcoin blocks.
pub struct ProofFile {
    file: File,
    writer_pos: AtomicU64,
}

impl ProofFile {
    pub fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let writer_pos = file.metadata()?.len();
        Ok(Self {
            file,
            writer_pos: AtomicU64::new(writer_pos),
        })
    }

    pub fn append(&self, proof: &CompactBlockProof) -> std::io::Result<BlockIndex> {
        let buffer = serialize(proof);
        let length = u64::try_from(buffer.len())
            .map_err(|_| std::io::Error::other("proof length exceeds u64"))?;
        let offset = self
            .writer_pos
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |offset| {
                offset.checked_add(length)
            })
            .map_err(|_| std::io::Error::other("proof file offset overflow"))?;
        self.file.write_all_at(&buffer, offset)?;
        Ok(BlockIndex {
            offset: usize::try_from(offset)
                .map_err(|_| std::io::Error::other("proof offset exceeds usize"))?,
            size: buffer.len(),
            proof_forest_rows: None,
        })
    }

    pub fn contains(&self, index: &BlockIndex) -> bool {
        index
            .offset
            .checked_add(index.size)
            .and_then(|end| u64::try_from(end).ok())
            .zip(self.file.metadata().ok().map(|metadata| metadata.len()))
            .is_some_and(|(end, file_len)| end <= file_len)
    }

    pub fn get(&self, index: &BlockIndex) -> Option<CompactBlockProof> {
        if !self.contains(index) {
            return None;
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(index.size).ok()?;
        bytes.resize(index.size, 0);
        self.file
            .read_exact_at(&mut bytes, index.offset as u64)
            .ok()?;
        deserialize(&bytes).ok()
    }

    pub fn truncate_after(&self, index: Option<&BlockIndex>) -> std::io::Result<()> {
        let end = match index {
            Some(index) => index
                .offset
                .checked_add(index.size)
                .ok_or_else(|| std::io::Error::other("proof index end overflow"))?,
            None => 0,
        };
        let end =
            u64::try_from(end).map_err(|_| std::io::Error::other("proof index exceeds u64"))?;
        if self.file.metadata()?.len() < end {
            return Err(std::io::Error::other(format!(
                "proof file ends before published proof offset {end}"
            )));
        }
        self.file.set_len(end)?;
        self.writer_pos.store(end, Ordering::Release);
        self.file.sync_data()
    }

    pub fn sync(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn concurrent_appends_reserve_disjoint_ranges_without_a_lock() {
        let path =
            std::env::temp_dir().join(format!("bridge-proof-file-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let file = Arc::new(ProofFile::new(path.clone()).unwrap());
        let proof = CompactBlockProof::default();
        let mut indexes = (0..8)
            .map(|_| {
                let file = Arc::clone(&file);
                let proof = proof.clone();
                std::thread::spawn(move || file.append(&proof).unwrap())
            })
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        indexes.sort_unstable_by_key(|index| index.offset);
        assert!(indexes
            .windows(2)
            .all(|pair| pair[0].offset + pair[0].size <= pair[1].offset));
        assert!(indexes
            .iter()
            .all(|index| file.get(index).as_ref() == Some(&proof)));

        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
