// P2Pool for Monero - Side-chain implementation
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// The p2pool side-chain is an independent blockchain with ~10-second block
// times that tracks shares. Miners submit pool blocks as shares, which are
// validated against the side-chain consensus rules and chained together.
// When a pool block's PoW hash also meets the Monero main-chain difficulty,
// p2pool submits the full block to monerod.
//
// Reward distribution uses Pay-Per-Last-N-Shares (PPLNS) with the window
// size determined by `chain_window_size` (2160 for main, 2160 for mini).
//
// Uncle blocks (blocks referencing the same parent) can be included; each
// uncle earns `uncle_penalty`% less reward than a main-chain share.

pub mod difficulty;
pub mod pplns;

use crate::pool_block::{MinerShare, PoolBlock};
use dashmap::DashMap;
use p2pool_config::SidechainVariant;
use p2pool_crypto::{DifficultyType, Hash};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

/// Configuration for a specific sidechain variant.
#[derive(Debug, Clone)]
pub struct SidechainConfig {
    pub pool_name: String,
    pub target_block_time: u64,
    pub min_difficulty: DifficultyType,
    pub chain_window_size: u64,
    pub uncle_penalty: u64,
    /// Consensus ID bytes (never sent over the network, used in handshake).
    pub consensus_id: Vec<u8>,
    pub consensus_hash: Hash,
}

impl SidechainConfig {
    /// Default configuration for `p2pool main`.
    pub fn main() -> Self {
        let consensus_id = b"default consensus ID (main)".to_vec();
        let consensus_hash = p2pool_crypto::keccak256(&consensus_id);
        Self {
            pool_name: "P2Pool main".to_string(),
            target_block_time: 10,
            min_difficulty: DifficultyType::from_u64(100_000),
            chain_window_size: 2160,
            uncle_penalty: 20,
            consensus_id,
            consensus_hash,
        }
    }

    /// Default configuration for `p2pool mini`.
    pub fn mini() -> Self {
        let consensus_id = b"mini consensus ID".to_vec();
        let consensus_hash = p2pool_crypto::keccak256(&consensus_id);
        Self {
            pool_name: "P2Pool mini".to_string(),
            target_block_time: 10,
            min_difficulty: DifficultyType::from_u64(1_000),
            chain_window_size: 2160,
            uncle_penalty: 20,
            consensus_id,
            consensus_hash,
        }
    }

    pub fn from_variant(variant: SidechainVariant) -> Self {
        match variant {
            SidechainVariant::Main => Self::main(),
            SidechainVariant::Mini => Self::mini(),
            SidechainVariant::Nano => {
                let mut cfg = Self::mini();
                cfg.pool_name = "P2Pool nano".to_string();
                cfg.min_difficulty = DifficultyType::from_u64(100);
                cfg
            }
        }
    }
}

/// The side-chain state, shared across the P2P server and block template builder.
///
/// This corresponds to the C++ `SideChain` class. All mutable state is
/// protected by a `RwLock`; reads are cheap, writes happen only on new blocks.
pub struct SideChain {
    config: SidechainConfig,

    /// All known blocks by their sidechain_id.
    blocks_by_id: Arc<RwLock<std::collections::HashMap<Hash, Box<PoolBlock>>>>,

    /// Blocks indexed by sidechain height (multiple blocks may share a height due to uncles).
    blocks_by_height: Arc<RwLock<BTreeMap<u64, Vec<Hash>>>>,

    /// Current chain tip (highest cumulative difficulty).
    chain_tip: Arc<RwLock<Option<Hash>>>,

    /// Recently seen incoming block IDs (for de-duplication of broadcast floods).
    incoming_blocks: Arc<std::sync::Mutex<std::collections::HashMap<[u8; 40], u64>>>,

    /// Seen miner wallet spend-key hashes and the last time they appeared.
    seen_wallets: Arc<RwLock<std::collections::HashMap<Hash, u64>>>,
}

impl SideChain {
    pub fn new(config: SidechainConfig) -> Self {
        Self {
            config,
            blocks_by_id: Arc::new(RwLock::new(std::collections::HashMap::new())),
            blocks_by_height: Arc::new(RwLock::new(BTreeMap::new())),
            chain_tip: Arc::new(RwLock::new(None)),
            incoming_blocks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            seen_wallets: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn config(&self) -> &SidechainConfig {
        &self.config
    }

    pub fn chain_window_size(&self) -> u64 {
        self.config.chain_window_size
    }

    pub fn target_block_time(&self) -> u64 {
        self.config.target_block_time
    }

    pub fn consensus_id(&self) -> &[u8] {
        &self.config.consensus_id
    }

    pub fn consensus_hash(&self) -> Hash {
        self.config.consensus_hash
    }

    /// Return the current chain tip block, if any.
    pub fn chain_tip(&self) -> Option<Hash> {
        *self.chain_tip.read().unwrap()
    }

    /// Return the current sidechain difficulty.
    pub fn difficulty(&self) -> DifficultyType {
        let tip_id = match self.chain_tip() {
            Some(id) => id,
            None => return self.config.min_difficulty,
        };
        self.blocks_by_id
            .read()
            .unwrap()
            .get(&tip_id)
            .map(|b| b.difficulty)
            .unwrap_or(self.config.min_difficulty)
    }

    /// Check whether an incoming block has already been seen (for broadcast de-dup).
    pub fn incoming_block_seen(&self, block: &PoolBlock) -> bool {
        let id = block.full_id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut map = self.incoming_blocks.lock().unwrap();
        if map.contains_key(&id) {
            return true;
        }
        map.insert(id, now);
        false
    }

    /// Remove a block from the incoming-seen set (after processing).
    pub fn forget_incoming_block(&self, block: &PoolBlock) {
        let id = block.full_id();
        self.incoming_blocks.lock().unwrap().remove(&id);
    }

    /// Look up a block by its sidechain_id.
    pub fn find_block(&self, id: &Hash) -> Option<Hash> {
        self.blocks_by_id
            .read()
            .unwrap()
            .contains_key(id)
            .then_some(*id)
    }

    /// Return all missing block hashes (blocks referenced as parents/uncles but not in store).
    pub fn get_missing_blocks(&self) -> HashSet<Hash> {
        let blocks = self.blocks_by_id.read().unwrap();
        let mut missing = HashSet::new();
        for block in blocks.values() {
            if !block.parent.is_zero() && !blocks.contains_key(&block.parent) {
                missing.insert(block.parent);
            }
            for uncle in &block.uncles {
                if !blocks.contains_key(uncle) {
                    missing.insert(*uncle);
                }
            }
        }
        missing
    }

    /// Add and validate a block received from the P2P network.
    ///
    /// Returns `Ok(true)` if the block was accepted and the chain tip changed.
    /// Returns `Ok(false)` if the block was accepted but did not change the tip.
    /// Returns `Err` if the block is invalid.
    pub fn add_block(&self, block: PoolBlock) -> Result<bool, SideChainError> {
        // Basic validation
        if block.sidechain_height > crate::pool_block::MAX_SIDECHAIN_HEIGHT {
            return Err(SideChainError::InvalidHeight(block.sidechain_height));
        }
        if block.cumulative_difficulty > crate::pool_block::MAX_CUMULATIVE_DIFFICULTY {
            return Err(SideChainError::InvalidDifficulty);
        }
        if block.difficulty < self.config.min_difficulty {
            return Err(SideChainError::BelowMinDifficulty);
        }

        let id = block.sidechain_id;
        let height = block.sidechain_height;
        let cum_diff = block.cumulative_difficulty;

        {
            let mut blocks = self.blocks_by_id.write().unwrap();
            if blocks.contains_key(&id) {
                debug!("duplicate block {id}");
                return Ok(false);
            }
            blocks.insert(id, Box::new(block));
        }

        {
            let mut by_height = self.blocks_by_height.write().unwrap();
            by_height.entry(height).or_default().push(id);
        }

        // Check if this block gives us a longer chain
        let tip_changed = {
            let mut tip = self.chain_tip.write().unwrap();
            let current_cum_diff = tip
                .and_then(|tid| {
                    self.blocks_by_id
                        .read()
                        .unwrap()
                        .get(&tid)
                        .map(|b| b.cumulative_difficulty)
                })
                .unwrap_or(DifficultyType::ZERO);

            if cum_diff > current_cum_diff {
                info!("New chain tip: {id} at height {height} (cum_diff={cum_diff})");
                *tip = Some(id);
                true
            } else {
                false
            }
        };

        if tip_changed {
            self.prune_old_blocks();
        }

        Ok(tip_changed)
    }

    /// Compute the PPLNS miner shares for the current chain tip.
    ///
    /// Returns the list of `(wallet, weight)` pairs covering `chain_window_size`
    /// blocks back from the tip (including uncle penalties).
    pub fn get_miner_shares(&self) -> Vec<MinerShare> {
        let tip_id = match self.chain_tip() {
            Some(id) => id,
            None => return Vec::new(),
        };
        pplns::calculate_shares(
            &tip_id,
            &self.blocks_by_id.read().unwrap(),
            self.config.chain_window_size,
            self.config.uncle_penalty,
        )
    }

    /// Split a total `reward` according to PPLNS share weights.
    ///
    /// The algorithm ensures the sum of outputs equals `reward` exactly,
    /// distributing rounding residue to the highest-weight miner.
    pub fn split_reward(reward: u64, shares: &[MinerShare]) -> Vec<u64> {
        if shares.is_empty() {
            return Vec::new();
        }
        let total_weight: u128 = shares
            .iter()
            .map(|s| s.weight.to_u128())
            .fold(0u128, |a, b| a.saturating_add(b));
        if total_weight == 0 {
            return vec![0; shares.len()];
        }
        let reward128 = reward as u128;
        let mut rewards: Vec<u64> = shares
            .iter()
            .map(|s| ((reward128 * s.weight.to_u128()) / total_weight) as u64)
            .collect();
        // Correct rounding error: give remainder to first miner
        let sum: u64 = rewards.iter().sum();
        if sum < reward {
            rewards[0] += reward - sum;
        }
        rewards
    }

    /// Remove blocks that are too old to be part of any PPLNS window.
    fn prune_old_blocks(&self) {
        let tip_height = self.chain_tip().and_then(|id| {
            self.blocks_by_id
                .read()
                .unwrap()
                .get(&id)
                .map(|b| b.sidechain_height)
        });
        let Some(tip_height) = tip_height else { return };
        let window = self.config.chain_window_size;
        if tip_height < window * 2 {
            return;
        }
        let cutoff = tip_height - window * 2;

        let old_ids: Vec<Hash> = {
            let by_height = self.blocks_by_height.read().unwrap();
            by_height
                .range(..cutoff)
                .flat_map(|(_, ids)| ids.iter().copied())
                .collect()
        };

        if !old_ids.is_empty() {
            let mut blocks = self.blocks_by_id.write().unwrap();
            for id in &old_ids {
                blocks.remove(id);
            }
            let mut by_height = self.blocks_by_height.write().unwrap();
            by_height.retain(|h, _| *h >= cutoff);
            debug!("pruned {} old blocks below height {cutoff}", old_ids.len());
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SideChainError {
    #[error("block height {0} exceeds maximum")]
    InvalidHeight(u64),
    #[error("cumulative difficulty exceeds maximum")]
    InvalidDifficulty,
    #[error("block difficulty is below minimum")]
    BelowMinDifficulty,
    #[error("invalid block: {0}")]
    Invalid(String),
}
