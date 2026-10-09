// SPDX-License-Identifier: MIT

//! This module holds all blocks and proofs in a file that gets memory-mapped to the process's address space.
//! This allows for fast access to the data without having to read it from disk, giving the OS the
//! oportunity to cache the data in memory. This also allows for accessing the data in a read-only
//! manner without having to use a mutex to synchronize access to the file.

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Seek;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::slice;

use bitcoin::consensus::serialize;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Script;
use bitcoin::VarInt;
use mmap::MapOption;
use mmap::MemoryMap;
use rustreexo::accumulator::mem_forest::MemForest;

use crate::block_index::BlockIndex;
use crate::prover::BlockStorage;
use crate::udata::BatchProof;
use crate::udata::CompactLeafData;
use crate::udata::ScriptPubkeyType;
use crate::udata::UData;
use crate::udata::UtreexoBlock;

/// A file that holds all blocks and proofs in a memory-mapped file.
pub struct BlockFile {
    /// A pointer for the memory-mapped region.
    mmap: MemoryMap,
    /// The file that holds the data.
    file: File,
    /// The current position of the writer in the file.
    writer_pos: usize,
}

unsafe impl Send for BlockFile {}
unsafe impl Sync for BlockFile {}

impl BlockFile {
    /// Creates a new memory-mapped file with the given path and size.
    pub fn new(path: PathBuf, map_size: usize) -> Result<Self, std::io::Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let pos = file.seek(std::io::SeekFrom::End(0))?;
        let mmap = MemoryMap::new(
            map_size,
            &[
                MapOption::MapReadable,
                MapOption::MapReadable,
                MapOption::MapFd(file.as_raw_fd()),
            ],
        )
        .unwrap();

        Ok(Self {
            mmap,
            writer_pos: pos as usize,
            file,
        })
    }

    /// Returns a block at the given position.
    pub fn get_block(&self, index: BlockIndex) -> Option<UtreexoBlock> {
        unsafe {
            UtreexoBlock::consensus_decode(&mut slice::from_raw_parts(
                self.read(&index),
                index.size,
            ))
            .ok()
        }
    }

    /// Appends a block to the file and returns the index of the block.
    pub fn append(&mut self, block: &UtreexoBlock) -> BlockIndex {
        // seek to the end of the file
        self.file.seek(std::io::SeekFrom::End(0)).unwrap();
        let buffer = serialize(block);
        let size = self.file.write(&buffer).unwrap();
        self.writer_pos += size;

        BlockIndex {
            offset: self.writer_pos - size,
            size,
        }
    }

    /// Returns a pointer to the block at the given index.
    ///
    /// This funcion is unsafe because it returns a raw pointer to the memory-mapped region.
    pub unsafe fn read(&self, index: &BlockIndex) -> *mut u8 {
        self.mmap.data().wrapping_add(index.offset)
    }

    /// Returns what spk type this output is. We need this to build a compact leaf data.
    fn get_spk_type(spk: &Script) -> ScriptPubkeyType {
        if spk.is_p2pkh() {
            ScriptPubkeyType::PubKeyHash
        } else if spk.is_p2sh() {
            ScriptPubkeyType::ScriptHash
        } else if spk.is_p2wpkh() {
            ScriptPubkeyType::WitnessV0PubKeyHash
        } else if spk.is_p2wsh() {
            ScriptPubkeyType::WitnessV0ScriptHash
        } else {
            ScriptPubkeyType::Other(spk.to_bytes().into_boxed_slice())
        }
    }
}

impl BlockStorage for BlockFile {
    fn save_block(
        &mut self,
        block: &Block,
        _block_height: u32,
        proof: rustreexo::accumulator::proof::Proof<crate::prover::AccumulatorHash>,
        leaves: Vec<crate::udata::LeafContext>,
        _acc: &MemForest<crate::prover::AccumulatorHash>,
    ) -> BlockIndex {
        let batch_proof = BatchProof {
            targets: proof.targets.iter().map(|x| VarInt(*x)).collect(),
            hashes: proof
                .hashes
                .iter()
                .map(|x| BlockHash::from_byte_array(**x))
                .collect(),
        };

        let leaves = leaves
            .into_iter()
            .map(|leaf| {
                let header_code = (leaf.block_height << 1) | leaf.is_coinbase as u32;

                CompactLeafData {
                    header_code,
                    amount: leaf.value,
                    spk_ty: Self::get_spk_type(&leaf.pk_script),
                }
            })
            .collect();

        let block = UtreexoBlock {
            block: block.clone(),
            udata: Some(UData {
                remember_idx: vec![],
                proof: batch_proof,
                leaves,
            }),
        };

        self.append(&block)
    }

    fn get_block(&self, index: BlockIndex) -> Option<UtreexoBlock> {
        self.get_block(index)
    }
}
