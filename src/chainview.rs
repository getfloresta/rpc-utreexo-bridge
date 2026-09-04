//SPDX-License-Identifier: MIT

//! Stores our local view of the blockchain. Mostly headers and an index of block heights.

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use kv::Store;

pub struct ChainView {
    storage: Store,
}

impl ChainView {
    pub fn new(storage: Store) -> Self {
        Self { storage }
    }

    pub fn get_acc(&self, hash: BlockHash) -> Result<Option<Vec<u8>>, kv::Error> {
        let bucket = self
            .storage
            .bucket::<&[u8], Vec<u8>>(Some("roots"))
            .unwrap();

        bucket.get(&hash.to_byte_array().as_slice())
    }

    pub fn get_block(&self, hash: BlockHash) -> Result<Option<Vec<u8>>, kv::Error> {
        let bucket = self
            .storage
            .bucket::<&[u8], Vec<u8>>(Some("headers"))
            .unwrap();
        bucket.get(&hash.to_byte_array().as_slice())
    }

    pub fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, kv::Error> {
        let bucket = self
            .storage
            .bucket::<&[u8], Vec<u8>>(Some("index"))
            .unwrap();
        let hash = bucket.get(&height.to_be_bytes().as_slice())?;
        match hash {
            Some(hash) => Ok(Some(BlockHash::from_slice(&hash).unwrap())),
            None => Ok(None),
        }
    }

    pub fn save_header(&self, hash: BlockHash, header: Vec<u8>) -> Result<(), kv::Error> {
        let bucket = self
            .storage
            .bucket::<&[u8], Vec<u8>>(Some("headers"))
            .unwrap();
        bucket.set(&hash.to_byte_array().as_slice(), &header)?;
        Ok(())
    }

    pub fn save_block_hash(&self, height: u32, hash: BlockHash) -> Result<(), kv::Error> {
        let bucket = self
            .storage
            .bucket::<&[u8], Vec<u8>>(Some("index"))
            .unwrap();
        bucket.set(
            &height.to_be_bytes().as_slice(),
            &hash.to_byte_array().to_vec(),
        )?;
        Ok(())
    }

    pub fn get_height(&self, hash: BlockHash) -> Result<Option<u32>, kv::Error> {
        let bucket = self
            .storage
            .bucket::<&[u8], Vec<u8>>(Some("reverse_index"))
            .unwrap();
        let height = bucket.get(&hash.to_byte_array().as_slice())?;
        match height {
            Some(height) => Ok(Some(u32::from_be_bytes(
                height.as_slice().try_into().unwrap(),
            ))),
            None => Ok(None),
        }
    }

    pub fn save_height(&self, hash: BlockHash, height: u32) -> Result<(), kv::Error> {
        let bucket = self
            .storage
            .bucket::<&[u8], Vec<u8>>(Some("reverse_index"))
            .unwrap();
        bucket.set(
            &hash.as_byte_array().as_slice(),
            &height.to_be_bytes().to_vec(),
        )?;
        Ok(())
    }
}
