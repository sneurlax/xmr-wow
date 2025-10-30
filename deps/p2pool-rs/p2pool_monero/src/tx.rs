// P2Pool for Monero - Transaction and miner data types
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// These types map directly to the C++ `TxMempoolData`, `MinerData`,
// `AuxChainData`, and `ChainMain` structs in common.h.

use p2pool_crypto::{DifficultyType, Hash};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// A transaction from the Monero mempool, as seen via ZMQ or RPC.
///
/// Sorting: higher fee-per-byte first, then smaller weight, then by id.
#[derive(Clone, Debug, Default)]
pub struct TxMempoolData {
    pub id: Hash,
    pub blob_size: u64,
    pub weight: u64,
    pub fee: u64,
    pub time_received: u64,
}

impl TxMempoolData {
    /// Fee-per-byte metric used for mempool ordering (matches C++ ordering).
    pub fn fee_per_weight(&self) -> u64 {
        if self.weight == 0 {
            0
        } else {
            self.fee * 1000 / self.weight
        }
    }
}

impl PartialEq for TxMempoolData {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for TxMempoolData {}

impl PartialOrd for TxMempoolData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxMempoolData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher fee*other_weight first
        let a = self.fee.saturating_mul(other.weight);
        let b = other.fee.saturating_mul(self.weight);
        b.cmp(&a)
            .then(self.weight.cmp(&other.weight))
            .then(self.id.cmp(&other.id))
    }
}

/// Data for one merge-mined auxiliary chain.
///
/// Corresponds to the C++ `AuxChainData` struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxChainData {
    /// Unique identifier for this auxiliary chain.
    pub unique_id: Hash,
    /// The auxiliary chain's current best block hash (data to commit to).
    pub data: Hash,
    /// Difficulty of the auxiliary chain.
    pub difficulty: DifficultyType,
}

/// Data received from the Monero daemon for building the next block template.
///
/// Corresponds to the C++ `MinerData` struct (populated from `get_miner_data` RPC
/// and/or the ZMQ `monerod` stream).
#[derive(Clone, Debug)]
pub struct MinerData {
    pub major_version: u8,
    pub height: u64,
    pub prev_id: Hash,
    pub seed_hash: Hash,
    pub difficulty: DifficultyType,
    pub median_weight: u64,
    pub already_generated_coins: u64,
    pub median_timestamp: u64,
    pub tx_backlog: Vec<TxMempoolData>,
    pub aux_chains: Vec<AuxChainData>,
    pub aux_nonce: u32,
    pub time_received: Option<Instant>,
}

impl Default for MinerData {
    fn default() -> Self {
        Self {
            major_version: 0,
            height: 0,
            prev_id: Hash::ZERO,
            seed_hash: Hash::ZERO,
            difficulty: DifficultyType::ZERO,
            median_weight: 0,
            already_generated_coins: 0,
            median_timestamp: 0,
            tx_backlog: Vec::new(),
            aux_chains: Vec::new(),
            aux_nonce: 0,
            time_received: None,
        }
    }
}

/// A confirmed Monero main-chain block reference.
///
/// Corresponds to the C++ `ChainMain` struct. Used to track the tip and
/// difficulty of the Monero blockchain.
#[derive(Clone, Debug, Default)]
pub struct ChainMain {
    pub difficulty: DifficultyType,
    pub height: u64,
    pub timestamp: u64,
    pub reward: u64,
    pub id: Hash,
}
