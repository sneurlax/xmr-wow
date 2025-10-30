// P2Pool for Monero - Stratum client session
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use p2pool_crypto::DifficultyType;
use std::time::Instant;

/// The state of a single miner connection.
#[derive(Debug)]
pub struct StratumSession {
    /// Per-connection numeric ID (used in RPC responses as session identifier string).
    pub rpc_id: u32,
    /// Miner wallet address string.
    pub address: String,
    /// Optional miner-specified fixed difficulty override.
    pub fixed_difficulty: Option<u64>,
    /// Current difficulty for this session (either fixed or auto-adjusted).
    pub current_difficulty: DifficultyType,
    /// Auto-difficulty state: rolling window of (timestamp, cumulative_hashes).
    pub auto_diff_hashes: u64,
    pub auto_diff_window_start: Instant,
    /// Per-connection job counter for generating job_id values.
    pub job_counter: u32,
    /// Ring buffer of recently sent jobs (job_id → extra_nonce, template_id, target).
    pub jobs: [Option<SavedJob>; 4],
    pub job_index: usize,
    /// Custom user string appended to the login address (XMRig worker name).
    pub custom_user: String,
    /// When this session was established.
    pub connected_at: Instant,
    /// Cumulative share statistics.
    pub stratum_shares: u32,
    pub sidechain_shares: u32,
    /// Ban score: negative = good, strongly positive = ban.
    pub score: i32,
}

/// A saved job reference for validating submitted shares.
#[derive(Debug, Clone)]
pub struct SavedJob {
    pub job_id: u32,
    pub extra_nonce: u32,
    pub template_id: u32,
    pub target: u64,
}

impl StratumSession {
    pub fn new(rpc_id: u32, address: String, fixed_difficulty: Option<u64>) -> Self {
        let start_diff = fixed_difficulty.unwrap_or(10_000);
        Self {
            rpc_id,
            address,
            fixed_difficulty,
            current_difficulty: DifficultyType::from_u64(start_diff),
            auto_diff_hashes: 0,
            auto_diff_window_start: Instant::now(),
            job_counter: 0,
            jobs: [None, None, None, None],
            job_index: 0,
            custom_user: String::new(),
            connected_at: Instant::now(),
            stratum_shares: 0,
            sidechain_shares: 0,
            score: 0,
        }
    }

    /// Generate the next job ID for this session.
    pub fn next_job_id(&mut self) -> u32 {
        self.job_counter = self.job_counter.wrapping_add(1);
        self.job_counter
    }

    /// Save a sent job so submitted shares can be validated.
    pub fn save_job(&mut self, job: SavedJob) {
        let i = self.job_index % 4;
        self.jobs[i] = Some(job);
        self.job_index += 1;
    }

    /// Look up a previously sent job by job_id.
    pub fn find_job(&self, job_id: u32) -> Option<&SavedJob> {
        self.jobs.iter().flatten().find(|j| j.job_id == job_id)
    }

    /// Update auto-difficulty based on recent share rate.
    ///
    /// Targets 1 share every 30 seconds (matches C++ auto-diff logic).
    pub fn update_auto_diff(&mut self, now: Instant, hashes_submitted: u64) {
        if self.fixed_difficulty.is_some() {
            return;
        }
        self.auto_diff_hashes += hashes_submitted;
        let elapsed = now.duration_since(self.auto_diff_window_start).as_secs_f64();
        if elapsed >= 30.0 {
            let target_hashes_per_sec = self.current_difficulty.to_f64() / 30.0;
            let actual_hashes_per_sec = self.auto_diff_hashes as f64 / elapsed;
            if actual_hashes_per_sec > 0.0 {
                let new_diff = (target_hashes_per_sec / actual_hashes_per_sec
                    * self.current_difficulty.to_f64()) as u64;
                self.current_difficulty = DifficultyType::from_u64(new_diff.max(1));
            }
            self.auto_diff_hashes = 0;
            self.auto_diff_window_start = now;
        }
    }
}
