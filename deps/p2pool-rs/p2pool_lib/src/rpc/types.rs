// P2Pool for Monero - Monero RPC response types
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use p2pool_crypto::{DifficultyType, Hash};
use serde::{Deserialize, Serialize};

/// Response from `get_info`.
#[derive(Debug, Deserialize)]
pub struct GetInfoResponse {
    pub height: u64,
    pub top_block_hash: String,
    pub difficulty: u64,
    pub wide_difficulty: Option<String>,
    pub status: String,
}

/// Response from `get_miner_data` (added in Monero v0.17.3).
#[derive(Debug, Deserialize)]
pub struct GetMinerDataResponse {
    pub major_version: u8,
    pub height: u64,
    pub prev_id: String,
    pub seed_hash: String,
    pub difficulty: String,
    pub median_weight: u64,
    pub already_generated_coins: u64,
    pub median_timestamp: u64,
    pub tx_backlog: Vec<TxBacklogEntry>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct TxBacklogEntry {
    pub id: String,
    pub weight: u64,
    pub fee: u64,
}

/// Response from `get_block_template`.
#[derive(Debug, Deserialize)]
pub struct GetBlockTemplateResponse {
    pub blocktemplate_blob: String,
    pub blockhashing_blob: String,
    pub difficulty: u64,
    pub expected_reward: u64,
    pub height: u64,
    pub prev_hash: String,
    pub reserved_offset: u32,
    pub seed_hash: String,
    pub next_seed_hash: String,
    pub status: String,
}

/// Response from `submit_block`.
#[derive(Debug, Deserialize)]
pub struct SubmitBlockResponse {
    pub status: String,
    pub error: Option<String>,
}

/// Response from `get_block_headers_range`.
#[derive(Debug, Deserialize)]
pub struct GetBlockHeadersRangeResponse {
    pub headers: Vec<BlockHeader>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockHeader {
    pub block_size: u64,
    pub block_weight: u64,
    pub cumulative_difficulty: u64,
    pub wide_cumulative_difficulty: Option<String>,
    pub depth: u64,
    pub difficulty: u64,
    pub wide_difficulty: Option<String>,
    pub hash: String,
    pub height: u64,
    pub major_version: u8,
    pub minor_version: u8,
    pub nonce: u32,
    pub num_txes: u64,
    pub orphan_status: bool,
    pub prev_hash: String,
    pub reward: u64,
    pub timestamp: u64,
}

/// A generic JSON-RPC 2.0 request body.
#[derive(Serialize)]
pub struct RpcRequest<'a, P: Serialize> {
    pub jsonrpc: &'static str,
    pub id: &'static str,
    pub method: &'a str,
    pub params: P,
}

impl<'a, P: Serialize> RpcRequest<'a, P> {
    pub fn new(method: &'a str, params: P) -> Self {
        Self {
            jsonrpc: "2.0",
            id: "0",
            method,
            params,
        }
    }
}

/// A generic JSON-RPC 2.0 response envelope.
#[derive(Debug, Deserialize)]
pub struct RpcResponse<T> {
    pub result: Option<T>,
    pub error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}
