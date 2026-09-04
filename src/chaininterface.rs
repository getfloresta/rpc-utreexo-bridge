//SPDX License Identifier: MIT

//! A trait that abstracts how we pull data from the blockchain. We need some way to get blocks
//! and transactions from the blockchain, but we don't want to do consensus here. So we just
//! provide a trait that can be implemented by something, or at least talks to something
//! that does.

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::Context;
use anyhow::Ok;
use anyhow::Result;
use bitcoin::block;
use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::Amount;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::CompactTarget;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxMerkleNode;
use bitcoin::Txid;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct PrevoutInfo {
    pub height: u32,
    pub is_coinbase: bool,
    pub value: u64,
    pub script_pubkey: ScriptBuf,
}

#[derive(Debug)]
pub struct BlockWithPrevouts {
    pub block: Block,
    pub prevouts: HashMap<OutPoint, PrevoutInfo>,
}

#[derive(Deserialize)]
struct RpcBlockV3 {
    hash: BlockHash,
    version: i32,
    #[serde(rename = "previousblockhash")]
    previous_block_hash: BlockHash,
    #[serde(rename = "merkleroot")]
    merkle_root: TxMerkleNode,
    time: u32,
    bits: String,
    nonce: u32,
    tx: Vec<RpcTransactionV3>,
}

#[derive(Deserialize)]
struct RpcTransactionV3 {
    hex: String,
    vin: Vec<RpcInputV3>,
}

#[derive(Deserialize)]
struct RpcInputV3 {
    txid: Option<Txid>,
    vout: Option<u32>,
    prevout: Option<RpcPrevoutV3>,
}

#[derive(Deserialize)]
struct RpcPrevoutV3 {
    generated: bool,
    height: u32,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    value: Amount,
    #[serde(rename = "scriptPubKey")]
    script_pubkey: RpcScriptV3,
}

#[derive(Deserialize)]
struct RpcScriptV3 {
    hex: String,
}

fn decode_block_with_prevouts(
    response: RpcBlockV3,
    requested_hash: BlockHash,
) -> Result<BlockWithPrevouts> {
    let bits = u32::from_str_radix(&response.bits, 16).context("invalid block bits")?;
    let mut transactions = Vec::with_capacity(response.tx.len());
    let mut prevouts = HashMap::new();
    for transaction in response.tx {
        let decoded: Transaction =
            deserialize(&hex::decode(&transaction.hex).context("invalid transaction hex")?)
                .context("invalid transaction encoding")?;
        for input in transaction.vin {
            let (Some(txid), Some(vout), Some(prevout)) = (input.txid, input.vout, input.prevout)
            else {
                continue;
            };
            prevouts.insert(
                OutPoint { txid, vout },
                PrevoutInfo {
                    height: prevout.height,
                    is_coinbase: prevout.generated,
                    value: prevout.value.to_sat(),
                    script_pubkey: ScriptBuf::from_bytes(
                        hex::decode(prevout.script_pubkey.hex)
                            .context("invalid prevout script hex")?,
                    ),
                },
            );
        }
        transactions.push(decoded);
    }
    let block = Block {
        header: Header {
            version: block::Version::from_consensus(response.version),
            prev_blockhash: response.previous_block_hash,
            merkle_root: response.merkle_root,
            time: response.time,
            bits: CompactTarget::from_consensus(bits),
            nonce: response.nonce,
        },
        txdata: transactions,
    };
    if block.block_hash() != response.hash || response.hash != requested_hash {
        anyhow::bail!(
            "verbosity-three block hash mismatch: requested {requested_hash}, decoded {}",
            block.block_hash()
        );
    }
    Ok(BlockWithPrevouts { block, prevouts })
}

pub trait Blockchain: Send + Sync {
    /// Returns the entire content of a block, given a block hash.
    fn get_block(&self, block_hash: BlockHash) -> Result<Block>;
    /// Returns the block and input prevouts. Providers without verbosity-three support may
    /// return an empty prevout map and let the caller use its compatibility fallback.
    fn get_block_with_prevouts(&self, block_hash: BlockHash) -> Result<BlockWithPrevouts> {
        Ok(BlockWithPrevouts {
            block: self.get_block(block_hash)?,
            prevouts: HashMap::new(),
        })
    }
    /// Returns the block hash of the block at the given height.
    fn get_block_hash(&self, height: u64) -> Result<BlockHash>;
    /// Returns the height of the block with the given hash.
    fn get_block_height(&self, block_hash: BlockHash) -> Result<u32>;
    /// Returns the block header of the block with the given hash.
    fn get_block_header(&self, block_hash: BlockHash) -> Result<Header>;
    /// Returns how many blocks are in the blockchain.
    fn get_block_count(&self) -> Result<u64>;
    /// Returns the raw transaction info, given a transaction id.
    fn get_raw_transaction_info(&self, txid: &Txid) -> Result<TransactionInfo>;
    /// Returns the median time past of the block with the given hash.
    fn get_mtp(&self, block_hash: BlockHash) -> Result<u32>;
}

impl Blockchain for Client {
    fn get_block(&self, block_hash: BlockHash) -> Result<Block> {
        Ok(<Self as RpcApi>::get_block(self, &block_hash)?)
    }

    fn get_block_with_prevouts(&self, block_hash: BlockHash) -> Result<BlockWithPrevouts> {
        let response: RpcBlockV3 = self.call(
            "getblock",
            &[
                serde_json::json!(block_hash.to_string()),
                serde_json::json!(3),
            ],
        )?;
        decode_block_with_prevouts(response, block_hash)
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        Ok(<Self as RpcApi>::get_block_hash(self, height)?)
    }

    fn get_block_height(&self, block_hash: BlockHash) -> Result<u32> {
        let info = self.get_block_info(&block_hash)?;
        Ok(info.height as u32)
    }

    fn get_block_header(&self, block_hash: BlockHash) -> Result<Header> {
        Ok(<Self as RpcApi>::get_block_header(self, &block_hash)?)
    }

    fn get_block_count(&self) -> Result<u64> {
        Ok(<Self as RpcApi>::get_block_count(self)?)
    }

    fn get_raw_transaction_info(&self, txid: &Txid) -> Result<TransactionInfo> {
        // Deserialize only the fields steady state needs. Bitcoin Core may add new verbose
        // script classifications before bitcoincore-rpc-json learns their enum variants.
        let value: serde_json::Value = self.call(
            "getrawtransaction",
            &[serde_json::json!(txid.to_string()), serde_json::json!(true)],
        )?;
        let transaction_hex = value
            .get("hex")
            .and_then(serde_json::Value::as_str)
            .context("getrawtransaction response has no hex transaction")?;
        let transaction: Transaction =
            deserialize(&hex::decode(transaction_hex).context("invalid transaction hex")?)
                .context("invalid transaction encoding")?;
        let blockhash = value
            .get("blockhash")
            .and_then(serde_json::Value::as_str)
            .map(BlockHash::from_str)
            .transpose()
            .context("invalid transaction block hash")?;
        let height = match blockhash {
            Some(block_hash) => self.get_block_height(block_hash)?,
            None => 0,
        };
        let is_coinbase = transaction.is_coinbase();
        Ok(TransactionInfo {
            tx: transaction,
            height,
            blockhash,
            is_coinbase,
        })
    }

    fn get_mtp(&self, block_hash: BlockHash) -> Result<u32> {
        let info = self.get_block_info(&block_hash)?;
        Ok(info.mediantime.unwrap_or(info.time) as u32)
    }
}
#[derive(Debug)]
pub struct TransactionInfo {
    pub tx: Transaction,
    pub height: u32,
    pub blockhash: Option<BlockHash>,
    pub is_coinbase: bool,
}

impl<T: Blockchain + Sized> Blockchain for Box<T> {
    fn get_block(&self, block_hash: BlockHash) -> Result<Block> {
        (**self).get_block(block_hash)
    }

    fn get_block_with_prevouts(&self, block_hash: BlockHash) -> Result<BlockWithPrevouts> {
        (**self).get_block_with_prevouts(block_hash)
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        (**self).get_block_hash(height)
    }

    fn get_block_height(&self, block_hash: BlockHash) -> Result<u32> {
        (**self).get_block_height(block_hash)
    }

    fn get_block_header(&self, block_hash: BlockHash) -> Result<Header> {
        (**self).get_block_header(block_hash)
    }

    fn get_block_count(&self) -> Result<u64> {
        (**self).get_block_count()
    }

    fn get_raw_transaction_info(&self, txid: &Txid) -> Result<TransactionInfo> {
        (**self).get_raw_transaction_info(txid)
    }

    fn get_mtp(&self, block_hash: BlockHash) -> Result<u32> {
        (**self).get_mtp(block_hash)
    }
}

impl<T: Blockchain> Blockchain for &Box<T> {
    fn get_block(&self, block_hash: BlockHash) -> Result<Block> {
        (**self).get_block(block_hash)
    }

    fn get_block_with_prevouts(&self, block_hash: BlockHash) -> Result<BlockWithPrevouts> {
        (**self).get_block_with_prevouts(block_hash)
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        (**self).get_block_hash(height)
    }

    fn get_block_height(&self, block_hash: BlockHash) -> Result<u32> {
        (**self).get_block_height(block_hash)
    }

    fn get_block_header(&self, block_hash: BlockHash) -> Result<Header> {
        (**self).get_block_header(block_hash)
    }

    fn get_block_count(&self) -> Result<u64> {
        (**self).get_block_count()
    }

    fn get_raw_transaction_info(&self, txid: &Txid) -> Result<TransactionInfo> {
        (**self).get_raw_transaction_info(txid)
    }

    fn get_mtp(&self, block_hash: BlockHash) -> Result<u32> {
        (**self).get_mtp(block_hash)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction;
    use bitcoin::Sequence;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::Witness;

    use super::*;

    #[test]
    fn decodes_verbosity_three_block_and_prevouts() {
        let previous_output = OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 3,
        };
        let transaction = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let header = Header {
            version: block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([4; 32]),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 5,
            bits: CompactTarget::from_consensus(0x1e03_77ae),
            nonce: 6,
        };
        let block_hash = header.block_hash();
        let response = RpcBlockV3 {
            hash: block_hash,
            version: header.version.to_consensus(),
            previous_block_hash: header.prev_blockhash,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: format!("{:08x}", header.bits.to_consensus()),
            nonce: header.nonce,
            tx: vec![RpcTransactionV3 {
                hex: hex::encode(serialize(&transaction)),
                vin: vec![RpcInputV3 {
                    txid: Some(previous_output.txid),
                    vout: Some(previous_output.vout),
                    prevout: Some(RpcPrevoutV3 {
                        generated: true,
                        height: 7,
                        value: Amount::from_sat(8),
                        script_pubkey: RpcScriptV3 {
                            hex: "51".to_string(),
                        },
                    }),
                }],
            }],
        };

        let decoded = decode_block_with_prevouts(response, block_hash).unwrap();
        assert_eq!(decoded.block.header, header);
        assert_eq!(decoded.block.txdata, vec![transaction]);
        let prevout = decoded.prevouts.get(&previous_output).unwrap();
        assert_eq!(prevout.height, 7);
        assert!(prevout.is_coinbase);
        assert_eq!(prevout.value, 8);
        assert_eq!(prevout.script_pubkey.as_bytes(), &[0x51]);
    }
}
