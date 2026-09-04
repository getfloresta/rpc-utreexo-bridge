//SPDX-License-Identifier: MIT

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod blockfile;

#[cfg(feature = "esplora")]
mod esplora;
mod forest_journal;
mod header_index;

mod node;

mod parallel_forest;
mod prover;

mod block_index;
mod chaininterface;
mod chainview;
mod cli;
mod udata;

use std::env;

use anyhow::Result;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use chaininterface::Blockchain;
use dotenv::dotenv;
use jemallocator::Jemalloc;
use log::info;
use simplelog::Config;
use simplelog::SharedLogger;

pub mod bitcoin_bridge;
use crate::bitcoin_bridge::run_bridge;

fn main() -> anyhow::Result<()> {
    dotenv().ok();

    run_bridge()
}

fn subdir(path: &str) -> String {
    let dir = env::var("DATA_DIR").unwrap_or_else(|_| {
        let dir = env::var("HOME").expect("No $HOME env var?");
        dir + "/.bridge"
    });
    dir + "/" + path
}

fn init_logger(log_file: Option<&str>, log_to_term: bool) -> anyhow::Result<()> {
    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();
    if let Some(path) = log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        loggers.push(simplelog::WriteLogger::new(
            log::LevelFilter::Debug,
            Config::default(),
            file,
        ));
    }
    if log_to_term {
        loggers.push(simplelog::TermLogger::new(
            log::LevelFilter::Info,
            Config::default(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        ));
    }
    if !loggers.is_empty() {
        simplelog::CombinedLogger::init(loggers)?;
    }
    Ok(())
}

fn get_chain_provider() -> Result<Box<dyn Blockchain>> {
    #[cfg(feature = "esplora")]
    if let Ok(esplora_url) = env::var("ESPLORA_URL") {
        return Ok(Box::new(esplora::EsploraBlockchain::new(esplora_url)));
    }
    let rpc_url = env::var("BITCOIN_CORE_RPC_URL").unwrap_or_else(|_| "localhost:8332".into());
    // try to use username and password auth first
    if let Ok(username) = env::var("BITCOIN_CORE_RPC_USER") {
        let password = env::var("BITCOIN_CORE_RPC_PASSWORD").map_err(|_| {
            anyhow::anyhow!("BITCOIN_CORE_RPC_PASSWORD must be set if BITCOIN_CORE_RPC_USER is set")
        })?;
        info!(
            "Using bitcoin core at {} with username {}",
            rpc_url, username
        );
        let client = Client::new(&rpc_url, Auth::UserPass(username, password));
        match client {
            Ok(client) => {
                return Ok(Box::new(client));
            }
            Err(e) => return Err(anyhow::anyhow!("Couldn't connect to bitcoin core: {e}")),
        }
    }
    // fallback to cookie auth. This is the default for core, but discouraged for security reasons
    let cookie = env::var("BITCOIN_CORE_COOKIE_FILE").unwrap_or_else(|_| {
        env::var("HOME")
            .map(|home| format!("{}/.bitcoin/.cookie", home))
            .expect("Failed to find $HOME")
    });
    info!("Using cookie file at {}", cookie);
    let client = Client::new(&rpc_url, Auth::CookieFile(cookie.clone().into()));
    match client {
        Ok(client) => {
            info!("Using bitcoin core at {}", rpc_url);
            Ok(Box::new(client))
        }
        Err(e) => Err(anyhow::anyhow!("Couldn't connect to bitcoin core: {e}")),
    }
}
