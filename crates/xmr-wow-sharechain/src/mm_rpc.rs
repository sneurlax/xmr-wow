// xmr-wow-sharechain: P2Pool merge-mining JSON-RPC server
//
// Exposes the three method names p2pool v4.0 expects on POST /json_rpc:
//   1. merge_mining_get_chain_id   -> chain ID (genesis keccak hash)
//   2. merge_mining_get_aux_block  -> current aux_hash + pending share blob + difficulty
//   3. merge_mining_submit_solution -> attach MergeMinedProof and add share to chain
//
// Also exposes swap-client RPC methods on the same endpoint:
//   4. get_swap_status   -> EscrowState for a swap_id
//   5. get_chain_height  -> current tip height
//   6. submit_escrow_op  -> submit an EscrowOp for inclusion in the next share

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

use crate::chain::{SwapChain, CONSENSUS_ID};
use crate::escrow::EscrowState;
use crate::share::{
    Difficulty, EscrowOp, Hash, MergeMinedProof, SwapShare,
};

// --- JSON-RPC envelope -------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id:      Value,
    pub method:  String,
    pub params:  Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse<T: Serialize> {
    pub jsonrpc: String,
    pub id:      Value,
    pub result:  T,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub jsonrpc: String,
    pub id:      Value,
    pub error:   RpcErrorBody,
}

#[derive(Debug, Serialize)]
pub struct RpcErrorBody {
    pub code:    i32,
    pub message: String,
}

fn ok<T: Serialize>(id: Value, result: T) -> Json<Value> {
    Json(serde_json::to_value(RpcResponse { jsonrpc: "2.0".into(), id, result }).unwrap())
}

fn err(id: Value, code: i32, msg: impl Into<String>) -> Json<Value> {
    Json(
        serde_json::to_value(RpcError {
            jsonrpc: "2.0".into(),
            id,
            error: RpcErrorBody { code, message: msg.into() },
        })
        .unwrap(),
    )
}

// --- Shared state ------------------------------------------------------------

#[derive(Clone)]
pub struct RpcState {
    pub chain: Arc<SwapChain>,
}

// --- Genesis chain ID (keccak256(CONSENSUS_ID)) ------------------------------

fn genesis_chain_id() -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(CONSENSUS_ID);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

// --- RPC method handlers -----------------------------------------------------

// Method: merge_mining_get_chain_id
// Returns: { "chain_id": "<64 hex chars>" }
fn handle_get_chain_id(id: Value) -> Json<Value> {
    let chain_id = hex::encode(genesis_chain_id());
    ok(id, serde_json::json!({ "chain_id": chain_id }))
}

// Method: merge_mining_get_aux_block
// Params: { "address": "...", "aux_hash": "...", "height": N, "prev_id": "..." }
// Returns: { "aux_hash": "<32 bytes hex>", "aux_blob": "<pending share hex>", "aux_diff": N }
fn handle_get_aux_block(state: &RpcState, id: Value, _params: Option<Value>) -> Json<Value> {
    let aux_hash = state.chain.current_aux_hash();
    let height   = state.chain.tip_height();

    // Build a minimal pending share extending the current tip
    let tip_id  = state.chain.tip_id().unwrap_or([0u8; 32]);
    let tip_diff = state.chain.difficulty_at_tip();
    let pending_diff = if tip_diff.is_zero() {
        Difficulty::from_u64(1000)
    } else {
        tip_diff
    };
    let pending_cum = {
        if let Some(tip) = state.chain.tip_id() {
            if let Some(tip_share) = state.chain.get_share(&tip) {
                tip_share.cumulative_difficulty.wrapping_add(pending_diff)
            } else {
                pending_diff
            }
        } else {
            pending_diff
        }
    };

    // If the chain has no tip yet, produce a genesis share (height 0, parent all-zeros).
    // Otherwise produce a share extending the current tip (height + 1).
    let has_tip = state.chain.tip_id().is_some();
    let pending_height = if has_tip { height + 1 } else { 0 };
    let pending_parent = if has_tip { tip_id } else { [0u8; 32] };

    let pending = SwapShare {
        parent:               pending_parent,
        uncles:               Vec::new(),
        height:               pending_height,
        difficulty:           pending_diff,
        cumulative_difficulty: pending_cum,
        timestamp:            current_timestamp(),
        nonce:                0,
        escrow_ops:          Vec::new(),
        escrow_merkle_root:  aux_hash,
        pow_proof:           None,
    };

    let aux_blob = hex::encode(pending.serialize());
    let aux_diff = pending_diff.lo;

    ok(
        id,
        serde_json::json!({
            "aux_hash": hex::encode(aux_hash),
            "aux_blob": aux_blob,
            "aux_diff": aux_diff,
        }),
    )
}

// Method: merge_mining_submit_solution
// Params:
//   { "aux_blob": "<hex>", "aux_hash": "<hex>", "blob": "<hex>",
//     "merkle_proof": ["<hex>", ...], "path": N, "seed_hash": "<hex>" }
// Returns: { "status": "accepted" } or error
fn handle_submit_solution(state: &RpcState, id: Value, params: Option<Value>) -> Json<Value> {
    let params = match params {
        Some(p) => p,
        None    => return err(id, -32602, "params required"),
    };

    // Decode aux_blob -> SwapShare
    let aux_blob_hex = match params.get("aux_blob").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None    => return err(id, -32602, "aux_blob required"),
    };
    let aux_blob_bytes = match hex::decode(&aux_blob_hex) {
        Ok(b)  => b,
        Err(e) => return err(id, -32602, format!("aux_blob hex decode: {e}")),
    };
    let mut share: SwapShare = match SwapShare::deserialize(&aux_blob_bytes) {
        Ok(s)  => s,
        Err(e) => return err(id, -32602, format!("aux_blob deserialize: {e}")),
    };

    // Decode Monero block blob
    let block_blob_hex = match params.get("blob").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None    => return err(id, -32602, "blob required"),
    };
    let monero_block_blob = match hex::decode(&block_blob_hex) {
        Ok(b)  => b,
        Err(e) => return err(id, -32602, format!("blob hex decode: {e}")),
    };

    // Decode seed_hash
    let seed_hash_hex = match params.get("seed_hash").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None    => return err(id, -32602, "seed_hash required"),
    };
    let seed_hash_bytes = match hex::decode(&seed_hash_hex) {
        Ok(b)  => b,
        Err(e) => return err(id, -32602, format!("seed_hash hex decode: {e}")),
    };
    if seed_hash_bytes.len() != 32 {
        return err(id, -32602, "seed_hash must be 32 bytes");
    }
    let mut seed_hash: Hash = [0u8; 32];
    seed_hash.copy_from_slice(&seed_hash_bytes);

    // Decode merkle_proof
    let merkle_proof: Vec<Hash> = match params.get("merkle_proof").and_then(Value::as_array) {
        Some(arr) => {
            let mut proof = Vec::new();
            for item in arr {
                let hex_str = item.as_str().unwrap_or("");
                let bytes = match hex::decode(hex_str) {
                    Ok(b)  => b,
                    Err(e) => return err(id, -32602, format!("merkle_proof hex: {e}")),
                };
                if bytes.len() != 32 {
                    return err(id, -32602, "each merkle_proof entry must be 32 bytes");
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes);
                proof.push(h);
            }
            proof
        }
        None => Vec::new(),
    };

    let merkle_path = params
        .get("path")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;

    // Attach the merge-mining proof to the share
    share.pow_proof = Some(MergeMinedProof {
        monero_block_blob,
        merkle_proof,
        merkle_path,
        seed_hash,
    });

    // Add to chain
    match state.chain.add_share(share) {
        Ok(_)  => ok(id, serde_json::json!({ "status": "accepted" })),
        Err(e) => err(id, -32000, format!("share rejected: {e}")),
    }
}

// -- Swap-client methods -------------------------------------------------------

// Method: get_swap_status
// Params: { "swap_id": "<64 hex chars>" }
// Returns: { "state": "Open"|"Claimed"|"Refunded", ... }
fn handle_get_swap_status(state: &RpcState, id: Value, params: Option<Value>) -> Json<Value> {
    let params = match params {
        Some(p) => p,
        None    => return err(id, -32602, "params required"),
    };
    let swap_id_hex = match params.get("swap_id").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None    => return err(id, -32602, "swap_id required"),
    };
    let swap_id_bytes = match hex::decode(&swap_id_hex) {
        Ok(b)  => b,
        Err(e) => return err(id, -32602, format!("swap_id hex: {e}")),
    };
    if swap_id_bytes.len() != 32 {
        return err(id, -32602, "swap_id must be 32 bytes");
    }
    let mut swap_id = [0u8; 32];
    swap_id.copy_from_slice(&swap_id_bytes);

    let idx = state.chain.escrow_index.read();
    match idx.get(&swap_id) {
        None => err(id, -32001, "swap not found"),
        Some(EscrowState::Open(c)) => ok(
            id,
            serde_json::json!({
                "state": "Open",
                "amount": c.amount,
                "claim_timelock": c.claim_timelock,
                "refund_timelock": c.refund_timelock,
            }),
        ),
        Some(EscrowState::Claimed { k_b }) => ok(
            id,
            serde_json::json!({
                "state": "Claimed",
                "k_b": hex::encode(k_b),
            }),
        ),
        Some(EscrowState::Refunded) => {
            ok(id, serde_json::json!({ "state": "Refunded" }))
        }
    }
}

// Method: get_chain_height
// Returns: { "height": N }
fn handle_get_chain_height(state: &RpcState, id: Value) -> Json<Value> {
    let height = state.chain.tip_height();
    ok(id, serde_json::json!({ "height": height }))
}

// Method: submit_escrow_op
// Params: { "op": <EscrowOp as JSON> }
// Queues an EscrowOp to be included in the next share.
// For now: immediately applies it and wraps it in a share at height+1.
fn handle_submit_escrow_op(state: &RpcState, id: Value, params: Option<Value>) -> Json<Value> {
    let params = match params {
        Some(p) => p,
        None    => return err(id, -32602, "params required"),
    };
    let op_value = match params.get("op") {
        Some(v) => v.clone(),
        None    => return err(id, -32602, "op required"),
    };
    let op: EscrowOp = match serde_json::from_value(op_value) {
        Ok(o)  => o,
        Err(e) => return err(id, -32602, format!("op deserialize: {e}")),
    };

    // Build a minimal share containing this single op
    let tip_id   = state.chain.tip_id().unwrap_or([0u8; 32]);
    let height   = state.chain.tip_height();
    let tip_diff = state.chain.difficulty_at_tip();
    let diff     = if tip_diff.is_zero() { Difficulty::from_u64(1) } else { tip_diff };
    let cum = {
        if let Some(tip) = state.chain.tip_id() {
            if let Some(ts) = state.chain.get_share(&tip) {
                ts.cumulative_difficulty.wrapping_add(diff)
            } else {
                diff
            }
        } else {
            diff
        }
    };

    let share = SwapShare {
        parent:               tip_id,
        uncles:               Vec::new(),
        height:               if state.chain.tip_id().is_some() { height + 1 } else { 0 },
        difficulty:           diff,
        cumulative_difficulty: cum,
        timestamp:            current_timestamp(),
        nonce:                rand::random(),
        escrow_ops:          vec![op],
        escrow_merkle_root:  state.chain.current_aux_hash(),
        pow_proof:           None,
    };

    match state.chain.add_share(share) {
        Ok(_)  => ok(id, serde_json::json!({ "status": "queued" })),
        Err(e) => err(id, -32000, format!("share rejected: {e}")),
    }
}

// --- Dispatcher ---------------------------------------------------------------

async fn handle_rpc(
    State(state): State<RpcState>,
    Json(req): Json<RpcRequest>,
) -> Json<Value> {
    handle_rpc_inner(state, req, None)
}

async fn handle_rpc_with_connect_info(
    State(state): State<RpcState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RpcRequest>,
) -> Json<Value> {
    handle_rpc_inner(state, req, Some(addr))
}

fn handle_rpc_inner(state: RpcState, req: RpcRequest, caller_addr: Option<SocketAddr>) -> Json<Value> {
    let id = req.id.clone();
    // localhost-only methods are rejected for non-loopback callers
    if is_localhost_only_method(req.method.as_str()) {
        let addr = caller_addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        if let Err(rpc_err) = check_loopback(&addr, id.clone()) {
            return rpc_err;
        }
    }

    match req.method.as_str() {
        "merge_mining_get_chain_id"     => handle_get_chain_id(id),
        "merge_mining_get_aux_block"    => handle_get_aux_block(&state, id, req.params),
        "merge_mining_submit_solution"  => handle_submit_solution(&state, id, req.params),
        "get_swap_status"               => handle_get_swap_status(&state, id, req.params),
        "get_chain_height"              => handle_get_chain_height(&state, id),
        "submit_escrow_op"              => handle_submit_escrow_op(&state, id, req.params),
        other => err(
            id,
            -32601,
            format!("method not found: {other}"),
        ),
    }
}

// --- Localhost gating helpers -------------------------------------------------

/// Returns true iff `method` is restricted to loopback-only callers.
pub fn is_localhost_only_method(method: &str) -> bool {
    method == "submit_escrow_op"
}

/// Returns Ok(()) if the caller address is loopback, or an RPC error Json if not.
pub fn check_loopback(addr: &std::net::SocketAddr, id: serde_json::Value) -> Result<(), Json<Value>> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(err(id, -32003, "submit_escrow_op is restricted to localhost"))
    }
}

// --- Public API ---------------------------------------------------------------

/// Build an Axum router exposing all merge-mining and swap-client RPC endpoints.
///
/// Without ConnectInfo — for unit tests. submit_escrow_op defaults to localhost.
pub fn merge_mining_router(chain: Arc<SwapChain>) -> Router {
    let state = RpcState { chain };
    Router::new()
        .route("/json_rpc", post(handle_rpc))
        .with_state(state)
}

/// With ConnectInfo — gates submit_escrow_op to loopback.
/// Serve with `.into_make_service_with_connect_info::<SocketAddr>()`.
pub fn merge_mining_router_with_connect_info(chain: Arc<SwapChain>) -> Router {
    let state = RpcState { chain };
    Router::new()
        .route("/json_rpc", post(handle_rpc_with_connect_info))
        .with_state(state)
}

// --- Helpers -----------------------------------------------------------------

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `.oneshot()`

    fn make_chain() -> Arc<SwapChain> {
        Arc::new(SwapChain::new(Difficulty::from_u64(1)))
    }

    async fn post_rpc(router: Router, method: &str, params: Value) -> Value {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/json_rpc")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn chain_id_returns_hex() {
        let chain  = make_chain();
        let router = merge_mining_router(chain);
        let resp   = post_rpc(router, "merge_mining_get_chain_id", Value::Null).await;
        let chain_id = resp["result"]["chain_id"].as_str().unwrap().to_string();
        assert_eq!(chain_id.len(), 64, "chain_id should be 64 hex chars");
        // Must be valid hex
        assert!(hex::decode(&chain_id).is_ok(), "chain_id must be valid hex");
    }

    #[tokio::test]
    async fn aux_block_returns_current_hash() {
        let chain  = make_chain();
        let router = merge_mining_router(chain.clone());

        // No tip yet ; aux_hash should be all-zeros
        let resp = post_rpc(router, "merge_mining_get_aux_block", Value::Null).await;
        let aux_hash = resp["result"]["aux_hash"].as_str().unwrap();
        assert_eq!(aux_hash.len(), 64);
        // With an empty chain the merkle root is all-zeros
        assert_eq!(aux_hash, "0".repeat(64));
    }

    #[tokio::test]
    async fn submit_solution_adds_to_chain() {
        let chain  = make_chain();
        let router = merge_mining_router(chain.clone());

        // First get an aux_block to obtain a valid pending share blob
        let aux_resp = post_rpc(
            merge_mining_router(chain.clone()),
            "merge_mining_get_aux_block",
            Value::Null,
        )
        .await;
        let aux_blob_hex = aux_resp["result"]["aux_blob"].as_str().unwrap().to_string();

        // Decode the pending share, grind the nonce to satisfy PoW, and re-encode.
        // (In a real mining setup the miner would grind the Monero block nonce which
        // translates to the share nonce; here we simulate that step directly.)
        let aux_blob_bytes = hex::decode(&aux_blob_hex).unwrap();
        let mut pending = crate::share::SwapShare::deserialize(&aux_blob_bytes).unwrap();
        // Grind nonce until PoW is satisfied
        for n in 0u32..=u32::MAX {
            pending.nonce = n;
            if pending.difficulty.check_pow(&pending.pow_hash()) {
                break;
            }
        }
        let aux_blob_valid = hex::encode(pending.serialize());

        // Submit the solution (with stub proof data and valid nonce)
        let params = serde_json::json!({
            "aux_blob":     aux_blob_valid,
            "aux_hash":     "0".repeat(64),
            "blob":         hex::encode(b"fake monero block"),
            "merkle_proof": [],
            "path":         0,
            "seed_hash":    "0".repeat(64),
        });

        let resp = post_rpc(router, "merge_mining_submit_solution", params).await;
        // Should be accepted (the chain starts empty so genesis-level share is valid)
        let status = resp["result"]["status"].as_str().unwrap_or("");
        assert_eq!(status, "accepted", "unexpected response: {resp:?}");
        assert_eq!(chain.share_count(), 1);
    }

    #[tokio::test]
    async fn get_chain_height_returns_zero_when_empty() {
        let chain  = make_chain();
        let router = merge_mining_router(chain);
        let resp   = post_rpc(router, "get_chain_height", Value::Null).await;
        assert_eq!(resp["result"]["height"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let chain  = make_chain();
        let router = merge_mining_router(chain);
        let resp   = post_rpc(router, "nonexistent_method", Value::Null).await;
        assert!(resp.get("error").is_some(), "should have error field");
    }

    #[test]
    fn submit_escrow_op_rejects_non_loopback() {
        let non_loopback: std::net::SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let id = serde_json::json!(1);
        let result = check_loopback(&non_loopback, id);
        assert!(result.is_err(), "non-loopback caller must be rejected");
    }

    #[test]
    fn submit_escrow_op_accepts_loopback() {
        let loopback_v4: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let id = serde_json::json!(1);
        assert!(check_loopback(&loopback_v4, id).is_ok(), "127.0.0.1 must be accepted");

        let loopback_v6: std::net::SocketAddr = "[::1]:12345".parse().unwrap();
        let id2 = serde_json::json!(2);
        assert!(check_loopback(&loopback_v6, id2).is_ok(), "::1 must be accepted");
    }

    #[test]
    fn is_localhost_only_method_gates_submit_escrow_op() {
        assert!(is_localhost_only_method("submit_escrow_op"));
        assert!(!is_localhost_only_method("merge_mining_get_chain_id"));
        assert!(!is_localhost_only_method("get_chain_height"));
        assert!(!is_localhost_only_method("merge_mining_submit_solution"));
    }
}
