//SPDX license identifier: MIT

//! Use a Esplora server as a backend to get blocks and transactions. You can use this instead
//! of Bitcoin Core. But keep in mind that while doing the initial sync, it will be slower and
//! you risk getting banned from the server if you do too many requests.

use std::fmt::Display;

use anyhow::Result;
use bitcoin::block::Header;
use bitcoin::consensus;
use bitcoin::hashes::Hash;
use bitcoin::Block;
use bitcoin::BlockHash;
use reqwest::blocking::Client;

use crate::chaininterface::Blockchain;
use crate::chaininterface::TransactionInfo;

#[derive(Debug)]
pub struct EsploraBlockchain {
    client: Client,
    url: String,
}

impl EsploraBlockchain {
    pub fn new(url: String) -> Self {
        Self {
            client: Client::new(),
            url,
        }
    }
}

impl Blockchain for EsploraBlockchain {
    fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash> {
        let url = format!("{}/block-height/{}", self.url, height);
        let block = self.client.get(url).send()?.text()?;
        Ok(block.parse().unwrap_or(BlockHash::all_zeros()))
    }

    fn get_block(&self, block_hash: BlockHash) -> Result<Block> {
        let url = format!("{}/block/{}/raw", self.url, block_hash);
        let block = self.client.get(url).send()?.bytes()?;
        Ok(consensus::deserialize::<Block>(&block)?)
    }

    fn get_block_height(&self, block_hash: BlockHash) -> Result<u32> {
        let url = format!("{}/block/{}", self.url, block_hash);
        let block = self.client.get(url).send()?.text()?;
        let block: serde_json::Value = serde_json::from_str(&block)?;
        let Some(height) = block["height"].as_u64() else {
            return Err(anyhow::anyhow!("No header found"));
        };
        Ok(height as u32)
    }

    fn get_block_header(&self, block_hash: BlockHash) -> Result<Header> {
        let url = format!("{}/block/{}/header", self.url, block_hash);
        let header = self.client.get(url).send()?.text()?;
        let header: serde_json::Value = serde_json::from_str(&header)?;
        let Some(header) = header["hex"].as_str() else {
            return Err(anyhow::anyhow!("No header found"));
        };
        let header = hex::decode(header)?;
        Ok(consensus::deserialize::<Header>(&header).unwrap())
    }

    fn get_block_count(&self) -> Result<u64> {
        let url = format!("{}/blocks/tip/height", self.url);
        let height = self.client.get(url).send()?.text()?;
        Ok(height.parse()?)
    }

    fn get_raw_transaction_info(&self, txid: &bitcoin::Txid) -> Result<TransactionInfo> {
        let client = Client::new();
        let url = format!("{}/tx/{}/status", self.url, txid);
        let tx = client.get(url).send()?.text()?;
        let tx: serde_json::Value = serde_json::from_str(&tx)?;

        let tx_hex = client
            .get(format!("{}/tx/{}/hex", self.url, txid))
            .send()?
            .text()?;
        Ok(TransactionInfo {
            is_coinbase: tx["vin"][0]["coinbase"].as_str().is_some(),
            blockhash: tx["block_hash"]
                .as_str()
                .map(|hash| hash.parse())
                .transpose()?,
            height: tx["block_height"].as_u64().unwrap_or(0) as u32,
            tx: consensus::deserialize(&hex::decode(tx_hex)?)?,
        })
    }

    fn get_mtp(&self, _block_hash: BlockHash) -> Result<u32> {
        // esplora does not have a way to get the median time past
        Ok(0)
    }
}
#[derive(Debug)]
pub enum EsploraError {
    Reqwest(reqwest::Error),
    BitcoinCore(bitcoincore_rpc::Error),
    Bitcoin(bitcoin::consensus::encode::Error),
    Hex(hex::FromHexError),
    Json(serde_json::Error),
}

impl From<reqwest::Error> for EsploraError {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}
impl From<serde_json::Error> for EsploraError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<bitcoincore_rpc::Error> for EsploraError {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        Self::BitcoinCore(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for EsploraError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        Self::Bitcoin(e)
    }
}

impl From<hex::FromHexError> for EsploraError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}
impl Display for EsploraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EsploraError::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            EsploraError::BitcoinCore(e) => write!(f, "Bitcoin Core error: {}", e),
            EsploraError::Bitcoin(e) => write!(f, "Bitcoin error: {}", e),
            EsploraError::Hex(e) => write!(f, "Hex error: {}", e),
            EsploraError::Json(e) => write!(f, "Json error: {}", e),
        }
    }
}
impl std::error::Error for EsploraError {}
#[cfg(test)]
mod tests {
    use bitcoin::consensus;
    use bitcoin::Block;
    use bitcoin::BlockHash;

    use super::Client;
    use crate::chaininterface::TransactionInfo;

    #[test]
    fn test_get_block() {
        let url = "https://blockstream.info/api/";
        let client = Client::new();
        let blockhash = "00000000000000000000bdd2ec0c94a35d76c6de2ae29e02dd901ac58373f77d"
            .parse::<BlockHash>()
            .unwrap();
        let url = format!("{}/block/{}/raw", url, blockhash);
        let block = client.get(&url).send().unwrap().bytes().unwrap();
        assert_eq!(
            blockhash,
            consensus::deserialize::<Block>(&block)
                .unwrap()
                .block_hash()
        );
    }
    #[test]
    fn test_get_tx_info() {
        let client = Client::new();
        let base_url = "https://mempool.space/signet/api/";
        let url = format!(
            "{}/tx/{}/status",
            base_url, "5c6574473085c1b25fc53d95f85cfdf3b6ba64fffe88893c62bc5bfd99028e89"
        );
        let tx = client.get(&url).send().unwrap().text().unwrap();
        let tx: serde_json::Value = serde_json::from_str(&tx).unwrap();

        let tx_hex = client
            .get(format!(
                "{}/tx/{}/hex",
                base_url, "5c6574473085c1b25fc53d95f85cfdf3b6ba64fffe88893c62bc5bfd99028e89"
            ))
            .send()
            .unwrap()
            .text()
            .unwrap();

        let _ = TransactionInfo {
            is_coinbase: tx["vin"][0]["coinbase"].as_str().is_some(),
            blockhash: Some(tx["block_hash"].as_str().unwrap().parse().unwrap()),
            height: tx["block_height"].as_u64().unwrap() as u32,
            tx: consensus::deserialize(&hex::decode(tx_hex).unwrap()).unwrap(),
        };
    }
}
