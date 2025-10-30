// P2Pool for Monero - Stratum JSON-RPC messages
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// p2pool implements the XMRig Stratum protocol over TCP. Miners connect and
// receive mining jobs; when they find a share they submit it. The protocol
// is JSON-RPC 2.0 over newline-delimited TCP.
//
// Login (miner → pool):
//   {"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"<address>[+<difficulty>]","pass":"x","agent":"...","rigid":""}}
//
// Login response (pool → miner):
//   {"id":1,"jsonrpc":"2.0","result":{"id":"<session_id>","job":{<job>},"status":"OK"}}
//
// Job (pool → miner, in login response or "job" notification):
//   {"blob":"<hex>","job_id":"<id>","target":"<8-hex-bytes>","height":<n>,"seed_hash":"<hex>"}
//
// Submit (miner → pool):
//   {"id":<n>,"jsonrpc":"2.0","method":"submit","params":{"id":"<session_id>","job_id":"<job_id>","nonce":"<8-hex>","result":"<64-hex>"}}
//
// Submit response (pool → miner):
//   {"id":<n>,"jsonrpc":"2.0","result":{"status":"OK"}} or {"error":{...}}

use p2pool_crypto::{DifficultyType, Hash};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Stratum mining job sent to miners.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumJob {
    /// Hex-encoded hashing blob (up to 128 bytes).
    pub blob: String,
    /// Unique job identifier (per-connection counter).
    pub job_id: String,
    /// 8-hex-byte target (little-endian 64-bit target derived from difficulty).
    pub target: String,
    /// Monero block height for this job.
    pub height: u64,
    /// Hex-encoded RandomX seed hash.
    pub seed_hash: String,
}

impl StratumJob {
    pub fn new(
        blob: &[u8],
        job_id: u32,
        difficulty: DifficultyType,
        height: u64,
        seed_hash: Hash,
    ) -> Self {
        let target64 = difficulty.target64();
        Self {
            blob: hex::encode(blob),
            job_id: format!("{job_id:08x}"),
            target: hex::encode(target64.to_le_bytes()),
            height,
            seed_hash: hex::encode(seed_hash.as_bytes()),
        }
    }
}

/// A generic Stratum JSON-RPC request.
#[derive(Debug, Clone, Deserialize)]
pub struct StratumRequest {
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

/// Login parameters from the miner.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginParams {
    /// Miner wallet address, optionally followed by "+<difficulty>" for fixed diff.
    pub login: String,
    pub pass: Option<String>,
    pub agent: Option<String>,
}

/// Submit parameters from the miner.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitParams {
    pub id: String,
    pub job_id: String,
    pub nonce: String,
    pub result: String,
}

/// Build a login success response.
pub fn login_response(request_id: &Value, session_id: &str, job: &StratumJob) -> String {
    let result = serde_json::json!({
        "id": session_id,
        "job": job,
        "status": "OK"
    });
    serde_json::json!({
        "id": request_id,
        "jsonrpc": "2.0",
        "result": result
    })
    .to_string()
}

/// Build a job notification (sent when a new block template is available).
pub fn job_notification(job: &StratumJob) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "job",
        "params": job
    })
    .to_string()
}

/// Build a submit OK response.
pub fn submit_ok(request_id: &Value) -> String {
    serde_json::json!({
        "id": request_id,
        "jsonrpc": "2.0",
        "result": {"status": "OK"}
    })
    .to_string()
}

/// Build a submit error response.
pub fn submit_error(request_id: &Value, message: &str) -> String {
    serde_json::json!({
        "id": request_id,
        "jsonrpc": "2.0",
        "error": {"code": -1, "message": message}
    })
    .to_string()
}

/// Parse the login field, extracting the address and optional fixed difficulty.
///
/// Format: `<address>[+<difficulty>]` or `<address>.<rigid>` (XMRig style).
pub fn parse_login(login: &str) -> (String, Option<u64>) {
    if let Some((addr, diff_str)) = login.split_once('+') {
        let diff = diff_str.trim().parse::<u64>().ok();
        (addr.trim().to_string(), diff)
    } else {
        (login.trim().to_string(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_login_with_difficulty() {
        let (addr, diff) = parse_login("4ABCDEF+10000");
        assert_eq!(addr, "4ABCDEF");
        assert_eq!(diff, Some(10000));
    }

    #[test]
    fn parse_login_without_difficulty() {
        let (addr, diff) = parse_login("4ABCDEF");
        assert_eq!(addr, "4ABCDEF");
        assert_eq!(diff, None);
    }
}
