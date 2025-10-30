// P2Pool for Monero - Side-chain difficulty adjustment
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// P2Pool uses a LWMA (Linearly Weighted Moving Average) difficulty adjustment
// algorithm, identical to the one used by Monero for the main chain, but
// applied to sidechain timestamps.
//
// The algorithm averages the per-block solve time over the last N blocks
// (where N is the difficulty window), weighting recent blocks more heavily.
// The target is `target_block_time` seconds per block.

use crate::pool_block::DifficultyData;
use p2pool_crypto::DifficultyType;

/// Number of blocks in the LWMA window.
pub const DIFFICULTY_WINDOW: usize = 720;

/// Minimum difficulty floor (prevents zero-difficulty exploits).
pub const DIFFICULTY_MIN: u64 = 1;

/// Compute the next sidechain difficulty using LWMA-3.
///
/// `data` is a sliding window of (timestamp, cumulative_difficulty) pairs
/// for the last `DIFFICULTY_WINDOW` + 1 blocks, ordered oldest-first.
/// `target_time` is the desired seconds-per-block.
/// `min_difficulty` is the floor below which difficulty cannot fall.
pub fn calculate_next_difficulty(
    data: &[DifficultyData],
    target_time: u64,
    min_difficulty: DifficultyType,
) -> DifficultyType {
    // Need at least N+1 data points for N intervals
    if data.len() < 2 {
        return min_difficulty;
    }

    let count = (data.len() - 1).min(DIFFICULTY_WINDOW) as u64;

    // LWMA-3: sum weighted solve times
    let mut weighted_time: u64 = 0;
    let mut sum_weights: u64 = 0;
    let mut sum_difficulty = DifficultyType::ZERO;

    let start = data.len() - 1 - count as usize;
    for (i, window) in data[start..].windows(2).enumerate() {
        let solve_time = window[1].timestamp.saturating_sub(window[0].timestamp);
        // clamp solve_time to [1, 6 * target_time]
        let solve_time = solve_time.clamp(1, 6 * target_time);
        let weight = (i as u64 + 1) * 2; // LWMA weight: 2, 4, 6, …
        weighted_time = weighted_time.saturating_add(solve_time.saturating_mul(weight));
        sum_weights = sum_weights.saturating_add(weight);

        let interval_diff =
            window[1].cumulative_difficulty - window[0].cumulative_difficulty;
        sum_difficulty += interval_diff;
    }

    if weighted_time == 0 || sum_weights == 0 {
        return min_difficulty;
    }

    // LWMA formula: next_D = avg_block_diff * T / weighted_avg_solve_time
    //   avg_block_diff       = sum_difficulty / count
    //   weighted_avg_solve  = weighted_time / sum_weights
    //   next_D = (sum_difficulty / count) * T / (weighted_time / sum_weights)
    //          = sum_difficulty * T * sum_weights / (count * weighted_time)
    let next = DifficultyType::from_u128(
        sum_difficulty.to_u128()
            * target_time as u128
            * sum_weights as u128
            / (count as u128 * weighted_time as u128),
    );

    next.max(min_difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool_block::DifficultyData;

    fn make_data(n: usize, target_time: u64, base_diff: u64) -> Vec<DifficultyData> {
        let mut data = Vec::with_capacity(n + 1);
        let mut cum = DifficultyType::from_u64(base_diff);
        for i in 0..=n {
            data.push(DifficultyData {
                timestamp: i as u64 * target_time,
                cumulative_difficulty: cum,
            });
            cum += DifficultyType::from_u64(base_diff);
        }
        data
    }

    #[test]
    fn stable_difficulty_near_target() {
        let target = 10u64;
        let base_diff = 1_000_000u64;
        let data = make_data(DIFFICULTY_WINDOW, target, base_diff);
        let min = DifficultyType::from_u64(100_000);
        let next = calculate_next_difficulty(&data, target, min);
        // Should be approximately base_diff
        let ratio = next.to_f64() / base_diff as f64;
        assert!(ratio > 0.9 && ratio < 1.1, "ratio={ratio:.3}");
    }

    #[test]
    fn returns_minimum_for_empty_data() {
        let min = DifficultyType::from_u64(100_000);
        let next = calculate_next_difficulty(&[], 10, min);
        assert_eq!(next, min);
    }
}
