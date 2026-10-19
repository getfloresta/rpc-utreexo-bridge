use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

/// We use this index to keep track of information held on flat files. Right now we only store the
/// blocks in the file, but if we build things like compact block filters, we can reuse the
/// indexing logic.
pub enum IndexEntry {
    /// The index of a block in the file.
    Index(BlockIndex),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// The index of a block in a file. Each block have an associated index entry.
pub struct BlockIndex {
    /// The offset of the block in the file counted from the file's begginning, in bytes.
    pub offset: usize,
    /// The size of the block in bytes.
    pub size: usize,
    /// Logical forest rows at proof creation; stored targets already use the 63-row wire layout.
    pub proof_forest_rows: Option<u8>,
}

impl kv::Value for IndexEntry {
    fn from_raw_value(r: kv::Raw) -> Result<Self, kv::Error> {
        if !matches!(r.len(), 16 | 17) {
            return Err(kv::Error::Message(format!(
                "proof index entry has {} bytes, expected 16 or 17",
                r.len()
            )));
        }
        if r.get(16).is_some_and(|rows| *rows > 63) {
            return Err(kv::Error::Message(
                "proof forest rows exceeds 63".to_string(),
            ));
        }
        let size = u64::from_be_bytes(
            r[..8]
                .try_into()
                .map_err(|_| kv::Error::Message("invalid proof size encoding".to_string()))?,
        );
        let offset = u64::from_be_bytes(
            r[8..16]
                .try_into()
                .map_err(|_| kv::Error::Message("invalid proof offset encoding".to_string()))?,
        );
        Ok(IndexEntry::Index(BlockIndex {
            size: usize::try_from(size)
                .map_err(|_| kv::Error::Message("proof size exceeds usize".to_string()))?,
            offset: usize::try_from(offset)
                .map_err(|_| kv::Error::Message("proof offset exceeds usize".to_string()))?,
            proof_forest_rows: r.get(16).copied(),
        }))
    }

    fn to_raw_value(&self) -> Result<kv::Raw, kv::Error> {
        match self {
            IndexEntry::Index(index) => {
                if index.proof_forest_rows.is_some_and(|rows| rows > 63) {
                    return Err(kv::Error::Message(
                        "proof forest rows exceeds 63".to_string(),
                    ));
                }
                let mut buf = Vec::with_capacity(17);
                buf.extend_from_slice(&(index.size as u64).to_be_bytes());
                buf.extend_from_slice(&(index.offset as u64).to_be_bytes());
                if let Some(forest_rows) = index.proof_forest_rows {
                    buf.push(forest_rows);
                }
                Ok(kv::Raw::from(buf))
            }
        }
    }
}

/// An index to help us finding blocks and heights.
///
/// This keeps track of where in the file each block is stored, so we can quickly access them.
pub struct BlocksIndex {
    pub database: kv::Store,
}

impl BlocksIndex {
    /// Returns the index for a block, given its hash. If the block is not found, it returns None.
    #[allow(dead_code)]
    pub fn get_index<'a>(&'a self, block: BlockHash) -> Result<Option<BlockIndex>, kv::Error> {
        let bucket = self
            .database
            .bucket::<&'a [u8], IndexEntry>(Some("index"))?;
        let key: [u8; 32] = *block.as_byte_array();
        match bucket.get(&key.as_slice())? {
            Some(IndexEntry::Index(index)) => Ok(Some(index)),
            None => Ok(None),
        }
    }

    /// Saves the height of the latest block we have in the index.
    pub fn update_height<'a>(&'a self, height: usize) -> Result<(), kv::Error> {
        let bucket = self.database.bucket::<&'a [u8], Vec<u8>>(Some("meta"))?;
        let key = b"height";
        bucket.set(&key.as_slice(), &height.to_be_bytes().to_vec())?;
        bucket.flush()?;
        Ok(())
    }

    /// Returns the height of the latest block we have in the index.
    pub fn load_height<'a>(&'a self) -> Result<usize, kv::Error> {
        let bucket = self.database.bucket::<&'a [u8], Vec<u8>>(Some("meta"))?;
        let key = b"height";
        let Some(height) = bucket.get(&key.as_slice())? else {
            return Ok(0);
        };
        let height: [u8; std::mem::size_of::<usize>()] =
            height.as_slice().try_into().map_err(|_| {
                kv::Error::Message(format!(
                    "proof height has {} bytes, expected {}",
                    height.len(),
                    std::mem::size_of::<usize>()
                ))
            })?;
        Ok(usize::from_be_bytes(height))
    }

    /// Appends a new block entry to the index.
    #[cfg(test)]
    pub fn append<'a>(&'a self, index: BlockIndex, block: BlockHash) -> Result<(), kv::Error> {
        let bucket = self
            .database
            .bucket::<&'a [u8], IndexEntry>(Some("index"))?;
        let key: [u8; 32] = *block.as_byte_array();
        bucket.set(&key.as_slice(), &IndexEntry::Index(index))?;
        bucket.flush()?;
        Ok(())
    }

    /// Publishes a group of proof indexes with a single durability flush.
    pub fn append_batch(&self, indexes: &[(BlockIndex, BlockHash)]) -> Result<(), kv::Error> {
        let bucket = self.database.bucket::<&[u8], IndexEntry>(Some("index"))?;
        for (index, block) in indexes {
            bucket.set(
                &block.as_byte_array().as_slice(),
                &IndexEntry::Index(*index),
            )?;
        }
        bucket.flush()?;
        Ok(())
    }

    pub fn remove<'a>(&'a self, block: BlockHash) -> Result<(), kv::Error> {
        let bucket = self
            .database
            .bucket::<&'a [u8], IndexEntry>(Some("index"))?;
        let key: [u8; 32] = *block.as_byte_array();
        bucket.remove(&key.as_slice())?;
        bucket.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_index_lengths_and_forest_layouts() {
        for length in [0, 15, 18] {
            assert!(
                <IndexEntry as kv::Value>::from_raw_value(kv::Raw::from(vec![0; length])).is_err()
            );
        }
        let mut raw = vec![0; 17];
        raw[16] = 64;
        assert!(<IndexEntry as kv::Value>::from_raw_value(kv::Raw::from(raw)).is_err());
        let entry = IndexEntry::Index(BlockIndex {
            offset: 0,
            size: 1,
            proof_forest_rows: Some(255),
        });
        assert!(<IndexEntry as kv::Value>::to_raw_value(&entry).is_err());
    }

    #[test]
    fn index_entries_preserve_optional_proof_forest_rows() {
        for proof_forest_rows in [None, Some(31)] {
            let entry = IndexEntry::Index(BlockIndex {
                offset: 42,
                size: 24,
                proof_forest_rows,
            });
            let raw = <IndexEntry as kv::Value>::to_raw_value(&entry).unwrap();
            assert_eq!(raw.len(), 16 + usize::from(proof_forest_rows.is_some()));
            let decoded = <IndexEntry as kv::Value>::from_raw_value(raw).unwrap();
            let IndexEntry::Index(decoded) = decoded;
            assert_eq!(decoded.offset, 42);
            assert_eq!(decoded.size, 24);
            assert_eq!(decoded.proof_forest_rows, proof_forest_rows);
        }
    }
}
