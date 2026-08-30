//SPDX License Identifier: MIT

//! A trait that abstracts how we pull data from the blockchain. We need some way to get blocks
//! and transactions from the blockchain, but we don't want to do consensus here. So we just
//! provide a trait that can be implemented by something, or at least talks to something
//! that does.

use anyhow::Ok;
use anyhow::Result;
use bitcoin::block::Header;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;

pub trait Blockchain {
    /// Returns the entire content of a block, given a block hash.
    fn get_block(&self, block_hash: BlockHash) -> Result<Block>;
    /// Returns the entire content of a transaction, given a transaction id.
    fn get_transaction(&self, txid: Txid) -> Result<Transaction>;
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

    fn get_transaction(&self, txid: Txid) -> Result<Transaction> {
        Ok(self.get_raw_transaction(&txid, None)?)
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
        let tx_data = <Self as RpcApi>::get_raw_transaction_info(self, txid, None)?;
        let height = self.get_block_height(tx_data.blockhash.unwrap()).unwrap();
        Ok(TransactionInfo {
            tx: tx_data.transaction().unwrap(),
            height,
            blockhash: tx_data.blockhash,
            is_coinbase: tx_data.is_coinbase(),
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

    fn get_transaction(&self, txid: Txid) -> Result<Transaction> {
        (**self).get_transaction(txid)
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

    fn get_transaction(&self, txid: Txid) -> Result<Transaction> {
        (**self).get_transaction(txid)
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
