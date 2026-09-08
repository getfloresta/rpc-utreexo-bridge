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
    /// Logical forest rows used by compact proof targets, when this is a proof entry.
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

    /// Returns the row count for proof entries written before per-entry metadata existed.
    ///
    /// The first steady-state startup persists this value so a later online resize does not
    /// reinterpret historical proof targets using the enlarged forest.
    pub fn legacy_proof_forest_rows(&self, current_rows: u8) -> Result<u8, kv::Error> {
        let bucket = self.database.bucket::<&[u8], Vec<u8>>(Some("meta"))?;
        let key = b"legacy-proof-forest-rows";
        if let Some(rows) = bucket.get(&key.as_slice())? {
            return match rows.as_slice() {
                [rows] => Ok(*rows),
                _ => Err(kv::Error::Message(format!(
                    "legacy proof forest rows has {} bytes, expected 1",
                    rows.len()
                ))),
            };
        }
        bucket.set(&key.as_slice(), &vec![current_rows])?;
        bucket.flush()?;
        Ok(current_rows)
    }

    /// Appends a new block entry to the index.
    pub fn append<'a>(&'a self, index: BlockIndex, block: BlockHash) -> Result<(), kv::Error> {
        let bucket = self
            .database
            .bucket::<&'a [u8], IndexEntry>(Some("index"))?;
        let key: [u8; 32] = *block.as_byte_array();
        bucket.set(&key.as_slice(), &IndexEntry::Index(index))?;
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
