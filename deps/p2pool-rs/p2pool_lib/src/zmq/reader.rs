// P2Pool for Monero - ZMQ reader
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use p2pool_crypto::Hash;
use p2pool_monero::tx::{AuxChainData, ChainMain, MinerData, TxMempoolData};
use serde::Deserialize;
use std::str::FromStr;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Error)]
pub enum ZmqError {
    #[error("ZMQ error: {0}")]
    Zmq(#[from] zmq::Error),
    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid field: {0}")]
    InvalidField(String),
}

/// Events emitted by the ZMQ reader to the rest of p2pool.
#[derive(Debug)]
pub enum ZmqEvent {
    /// A new transaction arrived in the mempool.
    TxPoolAdd(Vec<TxMempoolData>),
    /// A new main-chain block was mined.
    ChainMain(ChainMain),
    /// New miner data is available (triggers block template update).
    MinerData(MinerData),
    /// A full main-chain block was broadcast (for merge mining / Monero relay).
    FullChainMain(Vec<u8>),
}

/// Minimal JSON structure for "json-minimal-txpool_add" messages.
#[derive(Debug, Deserialize)]
struct ZmqTxEntry {
    id: String,
    blob_size: u64,
    weight: u64,
    fee: u64,
}

/// Minimal JSON structure for "json-minimal-chain_main" messages.
#[derive(Debug, Deserialize)]
struct ZmqChainMain {
    id: String,
    height: u64,
    timestamp: u64,
    reward: u64,
    #[serde(default)]
    wide_difficulty: String,
    difficulty: Option<u64>,
}

/// JSON structure for "json-miner-data" messages.
#[derive(Debug, Deserialize)]
struct ZmqMinerData {
    major_version: u8,
    height: u64,
    prev_id: String,
    seed_hash: String,
    difficulty: String,
    median_weight: u64,
    already_generated_coins: u64,
    median_timestamp: u64,
    #[serde(default)]
    tx_backlog: Vec<ZmqTxEntry>,
}

/// The ZMQ reader subscribes to a monerod ZMQ endpoint and emits events.
///
/// Runs in a dedicated background thread (ZMQ is synchronous).
pub struct ZmqReader {
    zmq_url: String,
    event_tx: mpsc::Sender<ZmqEvent>,
}

impl ZmqReader {
    pub fn new(zmq_url: String, event_tx: mpsc::Sender<ZmqEvent>) -> Self {
        Self { zmq_url, event_tx }
    }

    /// Spawn the ZMQ reader thread.
    ///
    /// Returns a handle that can be used to wait for or cancel the reader.
    pub fn spawn(self) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            if let Err(e) = self.run_blocking() {
                error!("ZMQ reader exited with error: {e}");
            }
        })
    }

    fn run_blocking(self) -> Result<(), ZmqError> {
        let ctx = zmq::Context::new();
        let socket = ctx.socket(zmq::SUB)?;

        socket.connect(&self.zmq_url)?;

        // Subscribe to all relevant topics
        for topic in &[
            "json-minimal-txpool_add",
            "json-minimal-chain_main",
            "json-miner-data",
            "json-full-chain_main",
        ] {
            socket.set_subscribe(topic.as_bytes())?;
        }

        info!("ZMQ connected to {}", self.zmq_url);

        loop {
            // ZMQ messages are multipart: [topic, data]
            let parts = match socket.recv_multipart(0) {
                Ok(p) => p,
                Err(zmq::Error::ETERM) => {
                    info!("ZMQ context terminated");
                    break;
                }
                Err(e) => {
                    warn!("ZMQ recv error: {e}");
                    continue;
                }
            };

            if parts.len() < 2 {
                warn!("ZMQ message with fewer than 2 parts");
                continue;
            }

            let topic = match std::str::from_utf8(&parts[0]) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let data = &parts[1];

            let event = match topic {
                "json-minimal-txpool_add" => {
                    self.parse_txpool_add(data).map(ZmqEvent::TxPoolAdd)
                }
                "json-minimal-chain_main" => {
                    self.parse_chain_main(data).map(ZmqEvent::ChainMain)
                }
                "json-miner-data" => {
                    self.parse_miner_data(data).map(ZmqEvent::MinerData)
                }
                "json-full-chain_main" => {
                    Ok(ZmqEvent::FullChainMain(data.to_vec()))
                }
                other => {
                    debug!("unknown ZMQ topic: {other}");
                    continue;
                }
            };

            match event {
                Ok(evt) => {
                    if self.event_tx.blocking_send(evt).is_err() {
                        info!("ZMQ event receiver dropped, stopping reader");
                        break;
                    }
                }
                Err(e) => warn!("failed to parse ZMQ {topic} message: {e}"),
            }
        }

        Ok(())
    }

    fn parse_txpool_add(&self, data: &[u8]) -> Result<Vec<TxMempoolData>, ZmqError> {
        let entries: Vec<ZmqTxEntry> = serde_json::from_slice(data)?;
        entries
            .into_iter()
            .map(|e| {
                Ok(TxMempoolData {
                    id: Hash::from_str(&e.id)
                        .map_err(|_| ZmqError::InvalidField(format!("bad tx id: {}", e.id)))?,
                    blob_size: e.blob_size,
                    weight: e.weight,
                    fee: e.fee,
                    time_received: 0,
                })
            })
            .collect()
    }

    fn parse_chain_main(&self, data: &[u8]) -> Result<ChainMain, ZmqError> {
        let raw: ZmqChainMain = serde_json::from_slice(data)?;
        let diff = if !raw.wide_difficulty.is_empty() {
            parse_wide_difficulty(&raw.wide_difficulty)?
        } else {
            p2pool_crypto::DifficultyType::from_u64(raw.difficulty.unwrap_or(0))
        };
        Ok(ChainMain {
            difficulty: diff,
            height: raw.height,
            timestamp: raw.timestamp,
            reward: raw.reward,
            id: Hash::from_str(&raw.id)
                .map_err(|_| ZmqError::InvalidField(format!("bad block id: {}", raw.id)))?,
        })
    }

    fn parse_miner_data(&self, data: &[u8]) -> Result<MinerData, ZmqError> {
        let raw: ZmqMinerData = serde_json::from_slice(data)?;
        let prev_id = Hash::from_str(&raw.prev_id)
            .map_err(|_| ZmqError::InvalidField(format!("bad prev_id: {}", raw.prev_id)))?;
        let seed_hash = Hash::from_str(&raw.seed_hash)
            .map_err(|_| ZmqError::InvalidField(format!("bad seed_hash: {}", raw.seed_hash)))?;
        let difficulty = parse_wide_difficulty(&raw.difficulty)?;

        let tx_backlog = raw
            .tx_backlog
            .into_iter()
            .map(|e| {
                Ok(TxMempoolData {
                    id: Hash::from_str(&e.id).map_err(|_| {
                        ZmqError::InvalidField(format!("bad tx id: {}", e.id))
                    })?,
                    blob_size: e.blob_size,
                    weight: e.weight,
                    fee: e.fee,
                    time_received: 0,
                })
            })
            .collect::<Result<Vec<_>, ZmqError>>()?;

        Ok(MinerData {
            major_version: raw.major_version,
            height: raw.height,
            prev_id,
            seed_hash,
            difficulty,
            median_weight: raw.median_weight,
            already_generated_coins: raw.already_generated_coins,
            median_timestamp: raw.median_timestamp,
            tx_backlog,
            aux_chains: Vec::new(),
            aux_nonce: 0,
            time_received: None,
        })
    }
}

/// Parse a wide difficulty string (hex, e.g. "0x000000000000000000000a2a5c...").
fn parse_wide_difficulty(s: &str) -> Result<p2pool_crypto::DifficultyType, ZmqError> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() > 32 {
        return Err(ZmqError::InvalidField(format!("difficulty too wide: {s}")));
    }
    let bytes = hex::decode(s)
        .map_err(|_| ZmqError::InvalidField(format!("invalid difficulty hex: {s}")))?;
    let mut le_bytes = [0u8; 16];
    // monerod sends big-endian; reverse to little-endian
    for (i, &b) in bytes.iter().rev().enumerate() {
        if i < 16 {
            le_bytes[i] = b;
        }
    }
    let lo = u64::from_le_bytes(le_bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(le_bytes[8..].try_into().unwrap());
    Ok(p2pool_crypto::DifficultyType { lo, hi })
}
