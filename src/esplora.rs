//SPDX license identifier: MIT

//! Use a Esplora server as a backend to get blocks and transactions. You can use this instead
//! of Bitcoin Core. But keep in mind that while doing the initial sync, it will be slower and
//! you risk getting banned from the server if you do too many requests.

use std::fmt::Display;

use anyhow::Result;
use bitcoin::block::Header;
use bitcoin::consensus;
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
        let block = self.client.get(url).send()?.error_for_status()?.text()?;
        Ok(block.trim().parse()?)
    }

    fn get_block(&self, block_hash: BlockHash) -> Result<Block> {
        let url = format!("{}/block/{}/raw", self.url, block_hash);
        let block = self.client.get(url).send()?.error_for_status()?.bytes()?;
        Ok(consensus::deserialize::<Block>(&block)?)
    }

    fn get_block_height(&self, block_hash: BlockHash) -> Result<u32> {
        let url = format!("{}/block/{}", self.url, block_hash);
        let block = self.client.get(url).send()?.error_for_status()?.text()?;
        let block: serde_json::Value = serde_json::from_str(&block)?;
        let Some(height) = block["height"].as_u64() else {
            return Err(anyhow::anyhow!("No header found"));
        };
        Ok(u32::try_from(height)?)
    }

    fn get_block_header(&self, block_hash: BlockHash) -> Result<Header> {
        let url = format!("{}/block/{}/header", self.url, block_hash);
        let header = self.client.get(url).send()?.error_for_status()?.text()?;
        let header = hex::decode(header.trim())?;
        Ok(consensus::deserialize::<Header>(&header)?)
    }

    fn get_block_count(&self) -> Result<u64> {
        let url = format!("{}/blocks/tip/height", self.url);
        let height = self.client.get(url).send()?.error_for_status()?.text()?;
        Ok(height.trim().parse()?)
    }

    fn get_raw_transaction_info(&self, txid: &bitcoin::Txid) -> Result<TransactionInfo> {
        let url = format!("{}/tx/{}/status", self.url, txid);
        let tx = self.client.get(url).send()?.error_for_status()?.text()?;
        let tx: serde_json::Value = serde_json::from_str(&tx)?;

        let tx_hex = self
            .client
            .get(format!("{}/tx/{}/hex", self.url, txid))
            .send()?
            .error_for_status()?
            .text()?;
        let transaction: bitcoin::Transaction =
            consensus::deserialize(&hex::decode(tx_hex.trim())?)?;
        Ok(TransactionInfo {
            is_coinbase: transaction.is_coinbase(),
            blockhash: tx["block_hash"]
                .as_str()
                .map(|hash| hash.parse())
                .transpose()?,
            height: u32::try_from(tx["block_height"].as_u64().unwrap_or(0))?,
            tx: transaction,
        })
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use super::*;

    fn server(responses: Vec<(String, u16, Vec<u8>)>) -> (EsploraBlockchain, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for (path, status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.split_whitespace().nth(1), Some(path.as_str()));
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        (EsploraBlockchain::new(url), handle)
    }

    #[test]
    fn decodes_raw_block_from_esplora() {
        let block = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin);
        let hash = block.block_hash();
        let (backend, server) = server(vec![(
            format!("/block/{hash}/raw"),
            200,
            consensus::serialize(&block),
        )]);
        assert_eq!(backend.get_block(hash).unwrap(), block);
        server.join().unwrap();
    }

    #[test]
    fn decodes_plain_hex_header_from_esplora() {
        let header = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin).header;
        let hash = header.block_hash();
        let (backend, server) = server(vec![(
            format!("/block/{hash}/header"),
            200,
            hex::encode(consensus::serialize(&header)).into_bytes(),
        )]);
        assert_eq!(backend.get_block_header(hash).unwrap(), header);
        server.join().unwrap();
    }

    #[test]
    fn derives_coinbase_from_transaction_not_status_json() {
        let block = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin);
        let tx = &block.txdata[0];
        let txid = tx.compute_txid();
        let status = serde_json::json!({"confirmed": true, "block_height": 42, "block_hash": block.block_hash()});
        let (backend, server) = server(vec![
            (
                format!("/tx/{txid}/status"),
                200,
                status.to_string().into_bytes(),
            ),
            (
                format!("/tx/{txid}/hex"),
                200,
                hex::encode(consensus::serialize(tx)).into_bytes(),
            ),
        ]);
        let info = backend.get_raw_transaction_info(&txid).unwrap();
        assert!(info.is_coinbase);
        assert_eq!(info.tx, *tx);
        assert_eq!(info.height, 42);
        assert_eq!(info.blockhash, Some(block.block_hash()));
        server.join().unwrap();
    }

    #[test]
    fn rejects_invalid_hash_http_error_and_height_overflow() {
        let hash = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin).block_hash();
        let (backend, server) = server(vec![
            ("/block-height/1".into(), 200, b"not a hash".to_vec()),
            ("/block-height/2".into(), 404, hash.to_string().into_bytes()),
            (
                format!("/block/{hash}"),
                200,
                br#"{"height":4294967296}"#.to_vec(),
            ),
        ]);
        assert!(backend.get_block_hash(1).is_err());
        assert!(backend.get_block_hash(2).is_err());
        assert!(backend.get_block_height(hash).is_err());
        server.join().unwrap();
    }
}
