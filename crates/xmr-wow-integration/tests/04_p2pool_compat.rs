/// Integration tests: p2pool merge-mining compatibility.
use std::sync::Arc;
use xmr_wow_sharechain::{SwapChain, Difficulty, CONSENSUS_ID, merge_mining_router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::util::ServiceExt;

async fn call(app: axum::Router, body: Value) -> Value {
    let req = Request::builder()
        .method("POST")
        .uri("/json_rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn merge_mining_rpc_chain_id_is_hex() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let app = merge_mining_router(chain);
    let resp = call(app, json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "merge_mining_get_chain_id",
        "params": null
    })).await;
    let chain_id = resp["result"]["chain_id"].as_str().expect("chain_id must be present");
    // The server returns keccak256(CONSENSUS_ID) as hex -> 32 bytes -> 64 hex chars
    assert_eq!(chain_id.len(), 64, "chain_id hex must be 64 chars (32 bytes keccak256 hash)");
    // All hex chars
    for ch in chain_id.chars() {
        assert!(ch.is_ascii_hexdigit(), "non-hex char in chain_id: {}", ch);
    }
    // Verify it decodes to 32 bytes
    let decoded = hex::decode(chain_id).expect("chain_id must be valid hex");
    assert_eq!(decoded.len(), 32);
}

#[tokio::test]
async fn merge_mining_rpc_aux_block_returns_hash() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let app = merge_mining_router(chain);
    let resp = call(app, json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "merge_mining_get_aux_block",
        "params": null
    })).await;
    let aux_hash = resp["result"]["aux_hash"].as_str().expect("aux_hash must be present");
    assert_eq!(aux_hash.len(), 64, "aux_hash must be 64 hex chars (32 bytes)");
    assert!(resp["result"]["aux_diff"].as_u64().is_some(), "aux_diff must be present");
}

#[tokio::test]
async fn merge_mining_rpc_submit_solution_adds_to_chain() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));

    // First get an aux_block to obtain a valid pending share blob
    let aux_resp = call(
        merge_mining_router(chain.clone()),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "merge_mining_get_aux_block",
            "params": null
        }),
    ).await;
    let aux_blob = aux_resp["result"]["aux_blob"].as_str()
        .expect("aux_blob must be present").to_string();

    let app = merge_mining_router(chain.clone());
    let resp = call(app, json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "merge_mining_submit_solution",
        "params": {
            "aux_blob": aux_blob,
            "aux_hash": "0".repeat(64),
            "blob": hex::encode(b"fake monero block"),
            "merkle_proof": [],
            "path": 0,
            "seed_hash": "0".repeat(64)
        }
    })).await;

    let status = resp["result"]["status"].as_str().unwrap_or("");
    assert_eq!(status, "accepted", "valid share must be accepted; resp={resp:?}");
    assert_eq!(chain.share_count(), 1, "chain share_count must advance to 1");
}

#[test]
fn consensus_id_matches_expected() {
    assert_eq!(CONSENSUS_ID, b"xmr-wow-swap-v1");
    assert_eq!(CONSENSUS_ID.len(), 15);
    // Hex representation of raw bytes (not hash)
    assert_eq!(hex::encode(CONSENSUS_ID), "786d722d776f772d737761702d7631");
}

#[tokio::test]
async fn get_chain_height_initially_zero() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let app = merge_mining_router(chain);
    let resp = call(app, json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get_chain_height",
        "params": null
    })).await;
    assert_eq!(resp["result"]["height"].as_u64(), Some(0));
}

#[tokio::test]
async fn unknown_method_returns_jsonrpc_error() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let app = merge_mining_router(chain);
    let resp = call(app, json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "does_not_exist",
        "params": null
    })).await;
    assert!(resp["error"].is_object(), "unknown method must return error object");
    assert_eq!(resp["error"]["code"].as_i64(), Some(-32601));
}

#[tokio::test]
async fn submit_escrow_op_advances_chain() {
    use xmr_wow_sharechain::{EscrowCommitment, EscrowOp};
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let app = merge_mining_router(chain.clone());

    // Build a valid EscrowOp and serialize it to JSON using serde so the
    // format exactly matches what the RPC handler will deserialize.
    let commitment = EscrowCommitment {
        swap_id:         [1u8; 32],
        alice_sc_pubkey: [2u8; 32],
        bob_sc_pubkey:   [3u8; 32],
        k_b_expected:    [4u8; 32],
        k_b_prime:       [0u8; 32],
        claim_timelock:  1000,
        refund_timelock: 2000,
        amount:          1_000_000_000_000,
    };
    let op = EscrowOp::Open(commitment);
    let op_value: Value = serde_json::to_value(&op).unwrap();

    let resp = call(app, json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "submit_escrow_op",
        "params": { "op": op_value }
    })).await;

    // The server returns {"status": "queued"} on success
    let status = resp["result"]["status"].as_str().unwrap_or("");
    assert_eq!(status, "queued", "submit_escrow_op must return queued; resp={resp:?}");
    assert_eq!(chain.share_count(), 1, "chain must advance after escrow op");
}
