use std::collections::HashMap;
use std::fs;
use std::path::Path;

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::OutPoint;
use log::info;
use redb::Database;
use redb::ReadableDatabase;
use redb::ReadableTable;
use redb::TableDefinition;
use redb::WriteTransaction;

use crate::prover::LeafCache;
use crate::udata::LeafContext;

const LEAF_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("leaves");

pub struct DiskLeafStorage {
    /// In-memory cache of leaf data
    ///
    /// This is used to avoid hitting the disk database too often,
    /// we put things here until it reaches a certain size, then we
    /// flush it to disk.
    /// If we die before flushing, we'll need txindex to rebuild the
    /// cache.
    cache: HashMap<OutPoint, (u32, LeafContext)>,
    /// A disk database of leaf data
    ///
    /// This is used to store leaf data that is not in the cache,
    /// it's a simple redb table with no fancy features.
    database: Database,
    /// A shared transaction for disk deletions, committed by `flush`.
    pending_write: Option<WriteTransaction>,
}

impl LeafCache for DiskLeafStorage {
    fn insert(&mut self, outpoint: OutPoint, leaf_data: LeafContext) -> bool {
        self.cache
            .insert(outpoint, (leaf_data.block_height, leaf_data));
        self.cache.len() > 100_000
    }

    fn get(&self, outpoint: &OutPoint) -> Option<LeafContext> {
        self.cache
            .get(outpoint)
            .map(|(_, leaf_data)| leaf_data.clone())
            .or_else(|| {
                let key = serialize(outpoint);
                if let Some(transaction) = &self.pending_write {
                    let table = transaction.open_table(LEAF_TABLE).ok()?;
                    let leaf = table.get(key.as_slice()).ok()??;
                    return Some(Self::deserialize_leaf_data(leaf.value()));
                }

                let transaction = self.database.begin_read().ok()?;
                let table = transaction.open_table(LEAF_TABLE).ok()?;
                let leaf = table.get(key.as_slice()).ok()??;
                Some(Self::deserialize_leaf_data(leaf.value()))
            })
    }

    fn batch_read(&self, outpoints: &[OutPoint]) -> Vec<Option<LeafContext>> {
        if let Some(transaction) = &self.pending_write {
            let Ok(table) = transaction.open_table(LEAF_TABLE) else {
                return vec![None; outpoints.len()];
            };
            return outpoints
                .iter()
                .map(|outpoint| {
                    self.cache
                        .get(outpoint)
                        .map(|(_, leaf_data)| leaf_data.clone())
                        .or_else(|| {
                            let key = serialize(outpoint);
                            let leaf = table.get(key.as_slice()).ok()??;
                            Some(Self::deserialize_leaf_data(leaf.value()))
                        })
                })
                .collect();
        }

        let Ok(transaction) = self.database.begin_read() else {
            return vec![None; outpoints.len()];
        };
        let Ok(table) = transaction.open_table(LEAF_TABLE) else {
            return vec![None; outpoints.len()];
        };
        outpoints
            .iter()
            .map(|outpoint| {
                self.cache
                    .get(outpoint)
                    .map(|(_, leaf_data)| leaf_data.clone())
                    .or_else(|| {
                        let key = serialize(outpoint);
                        let leaf = table.get(key.as_slice()).ok()??;
                        Some(Self::deserialize_leaf_data(leaf.value()))
                    })
            })
            .collect()
    }

    fn remove(&mut self, outpoint: &OutPoint) -> Option<LeafContext> {
        self.cache
            .remove(outpoint)
            .map(|(_, leaf_data)| leaf_data)
            .or_else(|| {
                if self.pending_write.is_none() {
                    self.pending_write = Some(self.database.begin_write().ok()?);
                }
                let transaction = self.pending_write.as_ref()?;
                let leaf = {
                    let mut table = transaction.open_table(LEAF_TABLE).ok()?;
                    let key = serialize(outpoint);
                    let leaf = table
                        .remove(key.as_slice())
                        .ok()?
                        .map(|leaf| leaf.value().to_vec());
                    leaf
                }?;
                Some(Self::deserialize_leaf_data(&leaf))
            })
    }

    fn flush(&mut self) {
        self.flush();
    }

    fn cache_size(&self) -> usize {
        self.cache_size()
    }
}

impl DiskLeafStorage {
    pub fn new(dir: &str) -> Self {
        fs::create_dir_all(dir).expect("Failed to create leaf cache directory");
        let database = Database::create(Path::new(dir).join("leaf_cache.redb"))
            .expect("Failed to open leaf cache database");
        let transaction = database
            .begin_write()
            .expect("Failed to initialize leaf cache database");
        transaction
            .open_table(LEAF_TABLE)
            .expect("Failed to initialize leaf cache table");
        transaction
            .commit()
            .expect("Failed to initialize leaf cache table");

        Self {
            database,
            pending_write: None,
            cache: HashMap::with_capacity(100_000),
        }
    }

    fn cache_size(&self) -> usize {
        self.cache.len()
    }

    fn serialize_leaf_data(leaf_data: &LeafContext) -> Vec<u8> {
        let mut serialized = serialize(&leaf_data.block_height);
        serialized.extend_from_slice(&serialize(&leaf_data.txid));
        serialized.extend_from_slice(&serialize(&leaf_data.vout));
        serialized.extend_from_slice(&serialize(&leaf_data.value));
        serialized.extend_from_slice(&serialize(&leaf_data.block_hash));
        serialized.extend_from_slice(&serialize(&leaf_data.is_coinbase));
        serialized.extend_from_slice(&serialize(&leaf_data.median_time_past));
        serialized.extend_from_slice(&serialize(&leaf_data.pk_script));
        serialized
    }

    fn deserialize_leaf_data(leaf: &[u8]) -> LeafContext {
        LeafContext {
            block_height: deserialize(&leaf[0..4]).unwrap(),
            txid: deserialize(&leaf[4..36]).unwrap(),
            vout: deserialize(&leaf[36..40]).unwrap(),
            value: deserialize(&leaf[40..48]).unwrap(),
            block_hash: deserialize(&leaf[48..80]).unwrap(),
            is_coinbase: deserialize(&leaf[80..81]).unwrap(),
            median_time_past: deserialize(&leaf[81..85]).unwrap(),
            pk_script: deserialize(&leaf[85..]).unwrap(),
        }
    }

    fn flush(&mut self) {
        info!("Flushing leaf cache to disk, this might take a while");
        let mut new_map = HashMap::new();
        let transaction = self.pending_write.take().unwrap_or_else(|| {
            self.database
                .begin_write()
                .expect("Failed to flush leaf cache")
        });
        {
            let mut table = transaction
                .open_table(LEAF_TABLE)
                .expect("Failed to flush leaf cache");
            for (outpoint, (height, leaf_data)) in self.cache.iter() {
                // Don't uncache things that are too recent
                if *height < 100 {
                    new_map.insert(*outpoint, (*height, leaf_data.clone()));
                }

                let key = serialize(outpoint);
                let serialized = Self::serialize_leaf_data(leaf_data);
                table
                    .insert(key.as_slice(), serialized.as_slice())
                    .expect("Failed to flush leaf cache");
            }
        }
        info!("Applying batch to disk, this might take a while");
        transaction.commit().expect("Failed to flush leaf cache");

        self.cache = new_map;
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use bitcoin::ScriptBuf;
    use bitcoin::Txid;

    use super::*;

    #[test]
    fn persists_and_removes_leaf_data() {
        let dir = std::env::temp_dir().join(format!("leaf-cache-{}", rand::random::<u64>()));
        let outpoint = OutPoint::new(Txid::all_zeros(), 1);
        let leaf = LeafContext {
            block_hash: BlockHash::all_zeros(),
            txid: outpoint.txid,
            vout: outpoint.vout,
            value: 42,
            pk_script: ScriptBuf::from_bytes(vec![0x51]),
            block_height: 100,
            median_time_past: 123,
            is_coinbase: false,
        };

        {
            let mut storage = DiskLeafStorage::new(dir.to_str().unwrap());
            storage.insert(outpoint, leaf.clone());
            storage.flush();
        }

        {
            let mut storage = DiskLeafStorage::new(dir.to_str().unwrap());
            let stored = storage.get(&outpoint).unwrap();
            assert_eq!(
                DiskLeafStorage::serialize_leaf_data(&stored),
                DiskLeafStorage::serialize_leaf_data(&leaf)
            );
            let missing = OutPoint::new(Txid::all_zeros(), 2);
            let batch = storage.batch_read(&[outpoint, missing]);
            assert_eq!(batch.len(), 2);
            assert!(batch[0].is_some());
            assert!(batch[1].is_none());
            storage.remove(&outpoint).unwrap();
            assert!(storage.get(&outpoint).is_none());
            assert!(storage.batch_read(&[outpoint])[0].is_none());
            {
                let transaction = storage.database.begin_read().unwrap();
                let table = transaction.open_table(LEAF_TABLE).unwrap();
                let key = serialize(&outpoint);
                assert!(table.get(key.as_slice()).unwrap().is_some());
            }
            storage.flush();
        }

        {
            let storage = DiskLeafStorage::new(dir.to_str().unwrap());
            assert!(storage.get(&outpoint).is_none());
        }

        fs::remove_dir_all(dir).unwrap();
    }
}
