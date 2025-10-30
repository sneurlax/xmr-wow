// P2Pool for Monero - Configuration
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

/// Host configuration for connecting to a Monero daemon.
#[derive(Debug, Clone, Deserialize)]
pub struct HostConfig {
    /// Hostname or IP address of the Monero daemon.
    pub address: String,
    /// RPC port (default: 18081 mainnet, 28081 testnet, 38081 stagenet).
    pub rpc_port: u16,
    /// ZMQ port (default: 18083 mainnet, 28083 testnet, 38083 stagenet).
    pub zmq_port: u16,
    /// Optional RPC login in "user:pass" format.
    pub rpc_login: Option<String>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".to_string(),
            rpc_port: 18081,
            zmq_port: 18083,
            rpc_login: None,
        }
    }
}

impl HostConfig {
    pub fn rpc_url(&self) -> String {
        format!("http://{}:{}/json_rpc", self.address, self.rpc_port)
    }

    pub fn zmq_url(&self) -> String {
        format!("tcp://{}:{}", self.address, self.zmq_port)
    }
}

/// Monero network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Stagenet,
}

impl Default for NetworkType {
    fn default() -> Self {
        Self::Mainnet
    }
}

/// Which sidechain variant to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SidechainVariant {
    /// Standard p2pool sidechain (~10 second blocks, 2160-block PPLNS window).
    Main,
    /// Mini sidechain (~10 second blocks, smaller PPLNS window, lower diff floor).
    Mini,
    /// Nano sidechain (experimental).
    Nano,
}

impl Default for SidechainVariant {
    fn default() -> Self {
        Self::Main
    }
}

/// P2P network configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct P2pConfig {
    /// Addresses to listen on, e.g. "0.0.0.0:37889".
    pub listen_addresses: Vec<String>,
    /// Initial peer list, comma-separated "host:port" entries.
    pub peer_list: Option<String>,
    /// Maximum number of outgoing connections.
    pub max_outgoing_peers: u32,
    /// Maximum number of incoming connections.
    pub max_incoming_peers: u32,
    /// Optional external listen port (for NAT traversal).
    pub external_port: Option<u16>,
    /// SOCKS5 proxy for outgoing connections, e.g. "127.0.0.1:9050".
    pub socks5_proxy: Option<String>,
    /// Our Onion v3 address for Tor connectivity.
    pub onion_address: Option<String>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec!["0.0.0.0:37889".to_string()],
            peer_list: None,
            max_outgoing_peers: 10,
            max_incoming_peers: 450,
            external_port: None,
            socks5_proxy: None,
            onion_address: None,
        }
    }
}

/// Stratum server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct StratumConfig {
    /// Addresses to listen on, e.g. "0.0.0.0:3333".
    pub listen_addresses: Vec<String>,
    /// Ban duration in seconds for invalid shares.
    pub ban_time: u64,
    /// Whether to auto-adjust difficulty per miner.
    pub auto_diff: bool,
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec!["0.0.0.0:3333".to_string()],
            ban_time: 600,
            auto_diff: true,
        }
    }
}

/// Data storage configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
    /// Directory for persistent data (block cache, peer list, etc.).
    pub data_dir: String,
    /// Whether to enable the block cache.
    pub block_cache: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            data_dir: "./p2pool-data".to_string(),
            block_cache: true,
        }
    }
}

/// Optional REST API configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    /// Path to expose the API at, e.g. "/tmp/p2pool-api".
    pub path: Option<String>,
    /// Whether to include per-worker local stats.
    pub local_stats: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            path: None,
            local_stats: false,
        }
    }
}

/// Top-level p2pool configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Monero daemon connections (tried in order, with ping-based selection).
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
    /// Network type.
    #[serde(default)]
    pub network: NetworkType,
    /// Sidechain variant.
    #[serde(default)]
    pub sidechain: SidechainVariant,
    /// Wallet address for mining rewards.
    pub wallet: String,
    /// P2P network settings.
    #[serde(default)]
    pub p2p: P2pConfig,
    /// Stratum server settings.
    #[serde(default)]
    pub stratum: StratumConfig,
    /// Storage settings.
    #[serde(default)]
    pub store: StoreConfig,
    /// API settings.
    #[serde(default)]
    pub api: ApiConfig,
    /// Optional consensus ID for private pools (hex-encoded bytes).
    pub consensus_id: Option<String>,
    /// Disable RandomX (light mode, used only for testing).
    pub light_mode: bool,
    /// Number of miner threads (0 = disabled).
    pub miner_threads: u32,
    /// Log file path.
    pub log_file: Option<String>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("P2POOL").separator("_"))
            .build()?;
        Ok(cfg.try_deserialize()?)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.hosts.is_empty() {
            return Err(ConfigError::InvalidParam(
                "at least one Monero host must be configured".to_string(),
            ));
        }
        if self.wallet.is_empty() {
            return Err(ConfigError::InvalidParam("wallet address is required".to_string()));
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hosts: vec![HostConfig::default()],
            network: NetworkType::default(),
            sidechain: SidechainVariant::default(),
            wallet: String::new(),
            p2p: P2pConfig::default(),
            stratum: StratumConfig::default(),
            store: StoreConfig::default(),
            api: ApiConfig::default(),
            consensus_id: None,
            light_mode: false,
            miner_threads: 0,
            log_file: None,
        }
    }
}
