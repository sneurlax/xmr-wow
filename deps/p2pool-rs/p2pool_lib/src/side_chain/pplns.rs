// P2Pool for Monero - PPLNS share calculation
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// Pay-Per-Last-N-Shares (PPLNS) computes the reward distribution for the
// current block by walking the chain backwards from the tip, collecting miner
// shares weighted by the sidechain difficulty of each block they appear in.
//
// Uncle blocks count at a reduced weight (difficulty * (100 - uncle_penalty) / 100).
// The window covers at most `chain_window_size` blocks of depth.

use crate::pool_block::{MinerShare, PoolBlock};
use p2pool_crypto::{DifficultyType, Hash};
use std::collections::HashMap;

/// Calculate the PPLNS miner shares starting from `tip_id`, walking at most
/// `window` blocks back from the tip.
///
/// Each uncle's shares are counted with reduced weight.
pub fn calculate_shares(
    tip_id: &Hash,
    blocks: &HashMap<Hash, Box<PoolBlock>>,
    window: u64,
    uncle_penalty: u64,
) -> Vec<MinerShare> {
    let mut wallet_weights: HashMap<Hash, (p2pool_monero::Wallet, DifficultyType)> =
        HashMap::new();

    let mut current_id = *tip_id;
    let tip_height = blocks.get(tip_id).map(|b| b.sidechain_height).unwrap_or(0);
    let window_bottom = tip_height.saturating_sub(window);

    let mut depth = 0u64;
    loop {
        let block = match blocks.get(&current_id) {
            Some(b) => b,
            None => break,
        };

        if block.sidechain_height < window_bottom {
            break;
        }
        depth += 1;
        if depth > window * 2 {
            break; // safety guard
        }

        // Count the main share for this block
        if let Some(wallet) = &block.miner_wallet {
            let spend_key = wallet.spend_public_key;
            let entry = wallet_weights
                .entry(spend_key)
                .or_insert_with(|| (wallet.clone(), DifficultyType::ZERO));
            entry.1 += block.difficulty;
        }

        // Count uncle shares at reduced weight
        for uncle_id in &block.uncles {
            if let Some(uncle) = blocks.get(uncle_id) {
                if let Some(wallet) = &uncle.miner_wallet {
                    let spend_key = wallet.spend_public_key;
                    let uncle_weight = uncle.difficulty
                        * (100 - uncle_penalty)
                        / 100;
                    let entry = wallet_weights
                        .entry(spend_key)
                        .or_insert_with(|| (wallet.clone(), DifficultyType::ZERO));
                    entry.1 += uncle_weight;
                }
            }
        }

        if block.parent.is_zero() {
            break;
        }
        current_id = block.parent;
    }

    let mut shares: Vec<MinerShare> = wallet_weights
        .into_values()
        .map(|(wallet, weight)| MinerShare { weight, wallet })
        .collect();

    // Sort by spend key for deterministic output (matches C++ ordering)
    shares.sort_by(|a, b| {
        a.wallet.spend_public_key.cmp(&b.wallet.spend_public_key)
    });

    shares
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_returns_empty_shares() {
        let shares = calculate_shares(&Hash::ZERO, &HashMap::new(), 2160, 20);
        assert!(shares.is_empty());
    }
}
