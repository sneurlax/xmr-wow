// P2Pool for Monero - Main entry point
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{Context, Result};
use clap::Parser;
use p2pool_config::{Config, HostConfig, NetworkType, SidechainVariant};
use p2pool_lib::{
    block_template::BlockTemplateManager,
    mempool::Mempool,
    p2p::{server::P2PCommand, P2PServer},
    side_chain::{SideChain, SidechainConfig},
    stratum::StratumServer,
    zmq::{reader::ZmqEvent, ZmqReader},
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// P2Pool for Monero – decentralised mining pool
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "p2pool.toml")]
    config: String,

    /// Monero daemon RPC address (overrides config).
    #[arg(long)]
    host: Option<String>,

    /// Monero daemon RPC port (overrides config).
    #[arg(long)]
    rpc_port: Option<u16>,

    /// Monero daemon ZMQ port (overrides config).
    #[arg(long)]
    zmq_port: Option<u16>,

    /// Wallet address for mining rewards (overrides config).
    #[arg(long)]
    wallet: Option<String>,

    /// Use p2pool-mini sidechain (lower min difficulty).
    #[arg(long)]
    mini: bool,

    /// P2P listen address(es), comma-separated.
    #[arg(long)]
    p2p: Option<String>,

    /// Stratum listen address(es), comma-separated.
    #[arg(long)]
    stratum: Option<String>,

    /// Initial peer list, comma-separated host:port entries.
    #[arg(long)]
    peer_list: Option<String>,

    /// Data directory for block cache and peer list.
    #[arg(long)]
    data_dir: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .with_target(false)
        .init();

    // Load config
    let mut config = if std::path::Path::new(&args.config).exists() {
        Config::load(&args.config).context("failed to load config file")?
    } else {
        info!("no config file found at {}, using defaults", args.config);
        Config::default()
    };

    // Apply CLI overrides
    if args.mini {
        config.sidechain = SidechainVariant::Mini;
    }
    if let Some(wallet) = args.wallet {
        config.wallet = wallet;
    }
    if let Some(p2p_addrs) = args.p2p {
        config.p2p.listen_addresses = p2p_addrs.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(stratum_addrs) = args.stratum {
        config.stratum.listen_addresses =
            stratum_addrs.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(peer_list) = args.peer_list {
        config.p2p.peer_list = Some(peer_list);
    }
    if let Some(data_dir) = args.data_dir {
        config.store.data_dir = data_dir;
    }

    // Apply host/port CLI overrides
    if let Some(host) = args.host {
        if config.hosts.is_empty() {
            config.hosts.push(HostConfig::default());
        }
        config.hosts[0].address = host;
    }
    if let Some(rpc_port) = args.rpc_port {
        if config.hosts.is_empty() {
            config.hosts.push(HostConfig::default());
        }
        config.hosts[0].rpc_port = rpc_port;
    }
    if let Some(zmq_port) = args.zmq_port {
        if config.hosts.is_empty() {
            config.hosts.push(HostConfig::default());
        }
        config.hosts[0].zmq_port = zmq_port;
    }

    config.validate().context("invalid configuration")?;

    // Validate wallet
    let miner_wallet = p2pool_monero::wallet::Wallet::decode(&config.wallet)
        .context("invalid wallet address")?;
    info!("mining to wallet: {}", config.wallet);

    // Build core components
    let sidechain_config = SidechainConfig::from_variant(config.sidechain);
    info!("sidechain: {}", sidechain_config.pool_name);

    let sidechain = Arc::new(SideChain::new(sidechain_config.clone()));
    let mempool = Arc::new(Mempool::new());
    let block_template = Arc::new(BlockTemplateManager::new(
        sidechain.clone(),
        mempool.clone(),
    ));

    // ZMQ reader → event channel
    let (zmq_tx, mut zmq_rx) = mpsc::channel::<ZmqEvent>(256);
    let host = config.hosts[0].clone();
    let zmq_url = host.zmq_url();
    let zmq_reader = ZmqReader::new(zmq_url, zmq_tx);
    let _zmq_thread = zmq_reader.spawn();
    info!("ZMQ reader started for {}", host.zmq_url());

    // P2P server
    let consensus_id = sidechain_config.consensus_id.clone();
    let (p2p_server, p2p_cmd_rx) =
        P2PServer::new(config.p2p.clone(), sidechain.clone(), consensus_id);
    let p2p_cmd_tx = p2p_server.command_sender();
    tokio::spawn(async move {
        p2p_server.run(p2p_cmd_rx).await;
    });
    info!("P2P server started");

    // Stratum server
    let stratum_server = StratumServer::new(config.stratum.clone(), block_template.clone());
    let stratum_new_job_fn = {
        let stratum_server = Arc::new(stratum_server);
        let bt = block_template.clone();
        let wallet = miner_wallet.clone();
        move |miner_data| {
            if let Some(job) = bt.update(miner_data, &wallet) {
                stratum_server.on_new_block(job);
            }
        }
    };

    // Main event loop: process ZMQ events
    info!("p2pool starting – waiting for miner data from monerod…");
    while let Some(event) = zmq_rx.recv().await {
        match event {
            ZmqEvent::MinerData(miner_data) => {
                info!(
                    "new miner data: height={} diff={}",
                    miner_data.height, miner_data.difficulty
                );
                stratum_new_job_fn(miner_data);
            }
            ZmqEvent::TxPoolAdd(txs) => {
                for tx in txs {
                    mempool.add(tx);
                }
            }
            ZmqEvent::ChainMain(chain) => {
                info!(
                    "main-chain block at height {} id={}",
                    chain.height, chain.id
                );
            }
            ZmqEvent::FullChainMain(blob) => {
                // Forward raw Monero block blob to P2P peers (v1.4 protocol)
                // TODO: call p2p_cmd_tx.send(P2PCommand::BroadcastMoneroBlock(blob))
            }
        }
    }

    info!("p2pool shutting down");
    let _ = p2p_cmd_tx.send(P2PCommand::Shutdown).await;
    Ok(())
}
