//SPDX-License-Identifier: MIT

#[cfg(all(feature = "shinigami", feature = "bitcoin"))]
compile_error!("You can't have both shinigami and bitcoin features enabled at the same time");

#[cfg(all(not(feature = "shinigami"), not(feature = "bitcoin")))]
compile_error!("You must enable either the shinigami or the bitcoin feature");

#[cfg(all(feature = "shinigami", feature = "api"))]
compile_error!("This combination is not supported yet");

#[cfg(all(feature = "shinigami", feature = "node"))]
compile_error!("This combination is not supported yet");

#[cfg(all(feature = "shinigami", feature = "esplora"))]
compile_error!("This combination is not supported yet");

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(feature = "api")]
mod api;

#[cfg(not(feature = "shinigami"))]
mod blockfile;

#[cfg(feature = "esplora")]
mod esplora;

#[cfg(feature = "node")]
mod node;

#[cfg(not(feature = "shinigami"))]
mod parallel_forest;
mod prover;

#[cfg(feature = "shinigami")]
mod shinigami_block_storage;

mod block_index;
mod chaininterface;
mod chainview;
mod cli;
mod leaf_cache;
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

#[cfg(feature = "shinigami")]
pub mod shinigami_bridge;

#[cfg(feature = "shinigami")]
use crate::shinigami_bridge::run_bridge;

#[cfg(not(feature = "shinigami"))]
pub mod bitcoin_bridge;

#[cfg(not(feature = "shinigami"))]
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

fn init_logger(log_file: Option<&str>, log_level: log::LevelFilter, log_to_term: bool) {
    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![];
    if let Some(file) = log_file {
        let file_logger = simplelog::WriteLogger::new(
            log_level,
            Config::default(),
            std::fs::File::create(file).unwrap(),
        );
        loggers.push(file_logger);
    }
    if log_to_term {
        let term_logger = simplelog::TermLogger::new(
            log_level,
            Config::default(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        );
        loggers.push(term_logger);
    }
    if loggers.is_empty() {
        eprintln!("No logger specified, logging disabled");
        return;
    }
    let _ = simplelog::CombinedLogger::init(loggers);
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
