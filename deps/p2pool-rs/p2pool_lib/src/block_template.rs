// P2Pool for Monero - Block template builder
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// The BlockTemplateManager combines:
//   - Latest miner data from monerod (via ZMQ)
//   - The current PPLNS shares from the side chain
//   - The local mempool snapshot
//
// to construct the mining job blob that is sent to connected Stratum miners.
//
// A new template is generated whenever:
//   - New miner data arrives from monerod (new Monero block)
//   - The p2pool sidechain tip changes (new share accepted)
//
// The coinbase transaction is constructed to pay each miner in the PPLNS
// window proportional to their accumulated work weight.

use crate::mempool::Mempool;
use crate::pool_block::{MinerShare, PoolBlock, TxOutput};
use crate::side_chain::SideChain;
use crate::stratum::messages::StratumJob;
use p2pool_crypto::{DifficultyType, Hash};
use p2pool_monero::tx::MinerData;
use p2pool_monero::wallet::Wallet;
use std::sync::{Arc, RwLock};

/// Holds the current block template and provides methods for
/// generating per-miner hashing blobs.
pub struct BlockTemplateManager {
    side_chain: Arc<SideChain>,
    mempool: Arc<Mempool>,
    current: RwLock<Option<CurrentTemplate>>,
}

struct CurrentTemplate {
    /// The PoolBlock serving as the template.
    pool_block: PoolBlock,
    /// Serialized main-chain portion (excluding nonce/extra_nonce).
    main_chain_blob: Vec<u8>,
    /// PPLNS shares computed when the template was built.
    shares: Vec<MinerShare>,
    /// The extra-nonce start value for this template (incremented per Stratum client).
    extra_nonce_start: u32,
    /// Unique template ID (monotonically increasing).
    template_id: u32,
    /// Monero block height.
    height: u64,
    /// Sidechain height at which the template was built.
    sidechain_height: u64,
    /// Mainchain difficulty.
    mainchain_difficulty: DifficultyType,
    /// Sidechain difficulty.
    sidechain_difficulty: DifficultyType,
    /// RandomX seed hash.
    seed_hash: Hash,
    /// Total mining reward for this template.
    total_reward: u64,
}

impl BlockTemplateManager {
    pub fn new(side_chain: Arc<SideChain>, mempool: Arc<Mempool>) -> Self {
        Self {
            side_chain,
            mempool,
            current: RwLock::new(None),
        }
    }

    /// Rebuild the block template from `miner_data` and the current sidechain state.
    ///
    /// This is called whenever monerod reports new miner data or the sidechain tip changes.
    pub fn update(&self, miner_data: MinerData, miner_wallet: &Wallet) -> Option<StratumJob> {
        let shares = self.side_chain.get_miner_shares();
        let selected_txs = self
            .mempool
            .select_transactions(miner_data.median_weight.saturating_mul(2));

        // Estimate total reward (base + fees)
        let total_fees: u64 = selected_txs.iter().map(|tx| tx.fee).sum();
        let total_reward = estimate_block_reward(
            miner_data.already_generated_coins,
            miner_data.height,
            miner_data.median_weight,
        ) + total_fees;

        // Split reward among PPLNS shares
        let rewards = if shares.is_empty() {
            vec![total_reward] // solo mining: all to the miner
        } else {
            SideChain::split_reward(total_reward, &shares)
        };

        // Build a PoolBlock template
        let mut block = PoolBlock::default();
        block.major_version = miner_data.major_version;
        block.minor_version = miner_data.major_version;
        block.timestamp = miner_data.median_timestamp + 1;
        block.prev_id = miner_data.prev_id;
        block.txin_gen_height = miner_data.height;
        block.seed = miner_data.seed_hash;
        block.miner_wallet = Some(miner_wallet.clone());

        // Populate outputs (one per miner in the PPLNS window)
        let effective_shares = if shares.is_empty() {
            vec![MinerShare {
                weight: DifficultyType::from_u64(1),
                wallet: miner_wallet.clone(),
            }]
        } else {
            shares.clone()
        };

        block.output_amounts = effective_shares
            .iter()
            .zip(rewards.iter())
            .map(|(_, &amount)| TxOutput { amount, view_tag: 0 })
            .collect();

        // Ephemeral public keys are computed during tx_key derivation (TODO: full impl)
        block.eph_public_keys = vec![Hash::ZERO; block.output_amounts.len()];

        // Fill sidechain fields
        if let Some(tip_id) = self.side_chain.chain_tip() {
            if let Some(_tip) = self.side_chain.find_block(&tip_id) {
                block.parent = tip_id;
                // TODO: fill in sidechain_height, difficulty, cumulative_difficulty from tip
            }
        }
        block.difficulty = self.side_chain.difficulty();

        // Placeholder: compute sidechain_id
        block.sidechain_id = block.calculate_sidechain_id();

        // Include transaction hashes (miner tx at index 0 + selected mempool txs)
        block.transactions = std::iter::once(Hash::ZERO) // miner tx hash (computed later)
            .chain(selected_txs.iter().map(|tx| tx.id))
            .collect();

        let mut guard = self.current.write().unwrap();
        let template_id = guard.as_ref().map(|t| t.template_id + 1).unwrap_or(1);

        let main_blob = block.serialize_mainchain_data(None, None);
        let sidechain_diff = block.difficulty;
        let height = miner_data.height;
        let sidechain_height = block.sidechain_height;
        let mainchain_diff = miner_data.difficulty;
        let seed_hash = miner_data.seed_hash;

        let template = CurrentTemplate {
            pool_block: block,
            main_chain_blob: main_blob,
            shares: effective_shares,
            extra_nonce_start: 0,
            template_id,
            height,
            sidechain_height,
            mainchain_difficulty: mainchain_diff,
            sidechain_difficulty: sidechain_diff,
            seed_hash,
            total_reward,
        };

        // Build a sample stratum job (extra_nonce=0, nonce_offset=39)
        let job = build_stratum_job(&template, 0, 0);
        *guard = Some(template);
        Some(job)
    }

    /// Generate a Stratum job blob for a specific Stratum client.
    ///
    /// `session_id` and `extra_nonce` together uniquely identify this miner's
    /// search space within the current template.
    pub fn make_stratum_job(&self, session_id: u32, extra_nonce: u32) -> Option<StratumJob> {
        let guard = self.current.read().unwrap();
        let t = guard.as_ref()?;
        Some(build_stratum_job(t, session_id, extra_nonce))
    }

    /// Submit a share from a Stratum miner.
    ///
    /// Returns `true` if the share meets the sidechain difficulty.
    /// If it also meets the mainchain difficulty, returns `true` and sets `found_main_block`.
    pub fn submit_share(
        &self,
        template_id: u32,
        nonce: u32,
        extra_nonce: u32,
        pow_hash: Hash,
    ) -> ShareResult {
        let guard = self.current.read().unwrap();
        let Some(t) = guard.as_ref() else {
            return ShareResult::Stale;
        };
        if t.template_id != template_id {
            return ShareResult::Stale;
        }
        if !t.sidechain_difficulty.check_pow(&pow_hash) {
            return ShareResult::LowDifficulty;
        }
        let found_main_block = t.mainchain_difficulty.check_pow(&pow_hash);
        ShareResult::Ok {
            found_main_block,
            nonce,
            extra_nonce,
            template_id,
        }
    }
}

/// Result of a share submission.
#[derive(Debug)]
pub enum ShareResult {
    Stale,
    LowDifficulty,
    Ok {
        found_main_block: bool,
        nonce: u32,
        extra_nonce: u32,
        template_id: u32,
    },
}

fn build_stratum_job(t: &CurrentTemplate, _session_id: u32, extra_nonce: u32) -> StratumJob {
    // Build a hashing blob: serialize_mainchain_data with the given extra_nonce,
    // then truncate to the header portion (nonce at offset ~39, extra_nonce in tx_extra).
    // For now we emit the full main-chain blob; miners adjust nonce at the standard offset.
    let blob = t
        .pool_block
        .serialize_mainchain_data(Some(0), Some(extra_nonce));

    StratumJob::new(
        &blob,
        t.template_id,
        t.sidechain_difficulty,
        t.height,
        t.seed_hash,
    )
}

/// Estimate the Monero block base reward using the emission curve.
///
/// Monero emission: reward = (M - A) * 2^-19 (atomic units)
/// where M = 2^64 - 1 (max supply) and A = already_generated_coins.
/// Tail emission kicks in below a minimum reward of 0.6 XMR.
fn estimate_block_reward(already_generated: u64, _height: u64, _median_weight: u64) -> u64 {
    const M: u128 = u64::MAX as u128;
    const MIN_REWARD: u64 = 600_000_000_000; // 0.6 XMR
    let a = already_generated as u128;
    let reward = ((M - a) >> 19) as u64;
    reward.max(MIN_REWARD)
}
