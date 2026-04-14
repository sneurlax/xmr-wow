// xmr-wow-sharechain: merge-mining and swap-client JSON-RPC server (POST /json_rpc)

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Path, State, ws::{WebSocketUpgrade, WebSocket, Message}},
    response::{IntoResponse, Response, sse::{Event, KeepAlive, Sse}},
    routing::{any, get, post},
    Json, Router,
};
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tokio_stream::wrappers::BroadcastStream;
use futures::stream::{self, StreamExt};
use std::convert::Infallible;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

use crate::chain::{SwapChain, CONSENSUS_ID};
use crate::coord_store::{BroadcastRegistry, CoordMessageStore};
use crate::escrow::EscrowState;
use crate::share::{
    Difficulty, EscrowOp, Hash, MergeMinedProof, SwapShare,
};

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

#[derive(Clone)]
pub struct RpcState {
    pub chain:     Arc<SwapChain>,
    pub msg_store: Arc<CoordMessageStore>,
    pub broadcast: Arc<BroadcastRegistry>,
}

fn genesis_chain_id() -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(CONSENSUS_ID);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

fn handle_get_chain_id(id: Value) -> Json<Value> {
    let chain_id = hex::encode(genesis_chain_id());
    ok(id, serde_json::json!({ "chain_id": chain_id }))
}

fn handle_get_aux_block(state: &RpcState, id: Value, _params: Option<Value>) -> Json<Value> {
    let aux_hash = state.chain.current_aux_hash();
    let height   = state.chain.tip_height();

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

fn handle_submit_solution(state: &RpcState, id: Value, params: Option<Value>) -> Json<Value> {
    let params = match params {
        Some(p) => p,
        None    => return err(id, -32602, "params required"),
    };

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

    let block_blob_hex = match params.get("blob").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None    => return err(id, -32602, "blob required"),
    };
    let monero_block_blob = match hex::decode(&block_blob_hex) {
        Ok(b)  => b,
        Err(e) => return err(id, -32602, format!("blob hex decode: {e}")),
    };

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

    share.pow_proof = Some(MergeMinedProof {
        monero_block_blob,
        merkle_proof,
        merkle_path,
        seed_hash,
    });

    match state.chain.add_share(share) {
        Ok(_)  => ok(id, serde_json::json!({ "status": "accepted" })),
        Err(e) => err(id, -32000, format!("share rejected: {e}")),
    }
}

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

fn handle_get_chain_height(state: &RpcState, id: Value) -> Json<Value> {
    let height = state.chain.tip_height();
    ok(id, serde_json::json!({ "height": height }))
}

/// Wraps a single `EscrowOp` in a share and adds it to the chain immediately.
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

fn parse_swap_id_hex(hex_str: &str, id: &Value) -> Result<[u8; 32], Json<Value>> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| err(id.clone(), -32602, format!("swap_id hex decode: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| err(id.clone(), -32602, "swap_id must be 32 bytes"))?;
    Ok(arr)
}

/// Parse hex swap_id without requiring a JSON-RPC id (for WS/SSE handlers).
fn parse_swap_id_hex_no_id(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("swap_id hex decode: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "swap_id must be 32 bytes".to_string())?;
    Ok(arr)
}

/// Build the JSON event payload shared by WS and SSE handlers.
fn make_coord_json(swap_id: &[u8; 32], index: usize, raw: &[u8]) -> String {
    serde_json::json!({
        "swap_id": hex::encode(swap_id),
        "index": index,
        "payload": raw,
    })
    .to_string()
}

async fn ws_coord_handler(
    Path(swap_id_hex): Path<String>,
    State(state): State<RpcState>,
    ws: WebSocketUpgrade,
) -> Response {
    let swap_id = match parse_swap_id_hex_no_id(&swap_id_hex) {
        Ok(id) => id,
        Err(e) => return (axum::http::StatusCode::BAD_REQUEST, e).into_response(),
    };
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state, swap_id))
}

async fn handle_ws_socket(mut socket: WebSocket, state: RpcState, swap_id: [u8; 32]) {
    // Subscribe before reading history to avoid a gap.
    let mut rx = state.broadcast.subscribe(swap_id);

    // Replay history from index 0.
    let history = state.msg_store.get_after(&swap_id, 0);
    let history_len = history.len();
    for (index, raw) in history.iter().enumerate() {
        let msg = make_coord_json(&swap_id, index, raw);
        if socket.send(Message::Text(msg.into())).await.is_err() {
            return;
        }
    }
    drop(history);

    // Live stream with 30s ping heartbeat.
    let mut ping_timer = interval(Duration::from_secs(30));
    ping_timer.tick().await; // consume immediate first tick
    let mut live_index = history_len;

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(raw) => {
                        let msg = make_coord_json(&swap_id, live_index, &raw);
                        live_index += 1;
                        if socket.send(Message::Text(msg.into())).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            "ws swap={} lagged, dropped {} messages",
                            hex::encode(swap_id),
                            n
                        );
                        // Next recv returns the oldest retained message.
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            _ = ping_timer.tick() => {
                if socket.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    return;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Ok(Message::Pong(_))) => {} // heartbeat ack
                    _ => {}
                }
            }
        }
    }
}

async fn sse_coord_handler(
    Path(swap_id_hex): Path<String>,
    State(state): State<RpcState>,
) -> axum::response::Response {
    let swap_id = match parse_swap_id_hex_no_id(&swap_id_hex) {
        Ok(id) => id,
        Err(e) => return (axum::http::StatusCode::BAD_REQUEST, e).into_response(),
    };

    // Subscribe before reading history to avoid a gap.
    let rx = state.broadcast.subscribe(swap_id);

    let history = state.msg_store.get_after(&swap_id, 0);
    let history_len = history.len();

    // Build replay stream
    let replay = stream::iter(history.into_iter().enumerate().map(move |(index, raw)| {
        let data = make_coord_json(&swap_id, index, &raw);
        Ok::<Event, Infallible>(
            Event::default()
                .event("coord_message")
                .id(index.to_string())
                .data(data),
        )
    }));

    // Build live stream from broadcast receiver
    let live = BroadcastStream::new(rx)
        .enumerate()
        .filter_map(move |(i, result)| {
            let index = history_len + i;
            async move {
                match result {
                    Ok(raw) => {
                        let data = make_coord_json(&swap_id, index, &raw);
                        Some(Ok::<Event, Infallible>(
                            Event::default()
                                .event("coord_message")
                                .id(index.to_string())
                                .data(data),
                        ))
                    }
                    Err(_) => {
                        // Lagged: skip lost messages.
                        None
                    }
                }
            }
        });

    Sse::new(replay.chain(live))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn handle_publish_coord_message(state: &RpcState, id: Value, params: Option<Value>) -> Json<Value> {
    let params = match params {
        Some(p) => p,
        None => return err(id, -32602, "params required"),
    };
    let swap_id_hex = match params.get("swap_id").and_then(Value::as_str) {
        Some(s) => s,
        None => return err(id, -32602, "swap_id required"),
    };
    let swap_id = match parse_swap_id_hex(swap_id_hex, &id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let payload_value = match params.get("payload") {
        Some(v) => v.clone(),
        None => return err(id, -32602, "payload required"),
    };
    let raw: Vec<u8> = match serde_json::from_value(payload_value) {
        Ok(v) => v,
        Err(e) => return err(id, -32602, format!("payload deserialize: {e}")),
    };

    let payload_bytes = raw.len();
    let index = state.msg_store.publish(swap_id, raw.clone());
    state.broadcast.send(swap_id, raw);
    // Plan 38.1-08 Task 3: diagnostic tracing for gap-closure iteration 6+.
    // Iteration 5 identified these mm_rpc handlers as a silent instrumentation
    // blind spot. Additive only -- no behavior change. Activation gated on
    // RUST_LOG=xmr_wow_sharechain=trace configured by iteration 5's Task 1a.
    tracing::debug!(
        swap_id = %hex::encode(swap_id),
        payload_bytes,
        index,
        "handle_publish_coord_message accepted"
    );
    ok(id, serde_json::json!({ "accepted": true, "index": index }))
}

fn handle_poll_coord_messages(state: &RpcState, id: Value, params: Option<Value>) -> Json<Value> {
    let params = match params {
        Some(p) => p,
        None => return err(id, -32602, "params required"),
    };
    let swap_id_hex = match params.get("swap_id").and_then(Value::as_str) {
        Some(s) => s,
        None => return err(id, -32602, "swap_id required"),
    };
    let swap_id = match parse_swap_id_hex(swap_id_hex, &id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let after_index = params
        .get("after_index")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;

    let messages = state.msg_store.get_after(&swap_id, after_index);
    let next_index = after_index + messages.len();
    // Plan 38.1-08 Task 3: diagnostic tracing for gap-closure iteration 6+.
    tracing::debug!(
        swap_id = %hex::encode(swap_id),
        after_index,
        message_count = messages.len(),
        next_index,
        "handle_poll_coord_messages returned"
    );
    ok(id, serde_json::json!({ "messages": messages, "next_index": next_index }))
}

fn handle_replay_coord_messages(state: &RpcState, id: Value, params: Option<Value>) -> Json<Value> {
    let params = match params {
        Some(p) => p,
        None => return err(id, -32602, "params required"),
    };
    let swap_id_hex = match params.get("swap_id").and_then(Value::as_str) {
        Some(s) => s,
        None => return err(id, -32602, "swap_id required"),
    };
    let swap_id = match parse_swap_id_hex(swap_id_hex, &id) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let messages = state.msg_store.get_all(&swap_id);
    let count = messages.len();
    ok(id, serde_json::json!({ "messages": messages, "count": count }))
}

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
        "publish_coord_message"         => handle_publish_coord_message(&state, id, req.params),
        "poll_coord_messages"           => handle_poll_coord_messages(&state, id, req.params),
        "replay_coord_messages"         => handle_replay_coord_messages(&state, id, req.params),
        other => err(
            id,
            -32601,
            format!("method not found: {other}"),
        ),
    }
}

pub fn is_localhost_only_method(method: &str) -> bool {
    method == "submit_escrow_op"
}

pub fn check_loopback(addr: &std::net::SocketAddr, id: serde_json::Value) -> Result<(), Json<Value>> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(err(id, -32003, "submit_escrow_op is restricted to localhost"))
    }
}

/// Router without `ConnectInfo`; intended for unit tests (`submit_escrow_op` is unrestricted).
pub fn merge_mining_router(chain: Arc<SwapChain>) -> Router {
    let state = RpcState {
        chain,
        msg_store: Arc::new(CoordMessageStore::new()),
        broadcast: Arc::new(BroadcastRegistry::new()),
    };
    Router::new()
        .route("/json_rpc", post(handle_rpc))
        .route("/ws/coord/{swap_id}", any(ws_coord_handler))
        .route("/sse/coord/{swap_id}", get(sse_coord_handler))
        .with_state(state)
}

/// Router with `ConnectInfo`; gates `submit_escrow_op` to loopback callers.
pub fn merge_mining_router_with_connect_info(chain: Arc<SwapChain>) -> Router {
    let state = RpcState {
        chain,
        msg_store: Arc::new(CoordMessageStore::new()),
        broadcast: Arc::new(BroadcastRegistry::new()),
    };
    Router::new()
        .route("/json_rpc", post(handle_rpc_with_connect_info))
        .route("/ws/coord/{swap_id}", any(ws_coord_handler))
        .route("/sse/coord/{swap_id}", get(sse_coord_handler))
        .with_state(state)
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `.oneshot()`
    use futures_util::StreamExt as FuturesStreamExt;
    use tokio::net::TcpListener;

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
        assert!(hex::decode(&chain_id).is_ok(), "chain_id must be valid hex");
    }

    #[tokio::test]
    async fn aux_block_returns_current_hash() {
        let chain  = make_chain();
        let router = merge_mining_router(chain.clone());

        let resp = post_rpc(router, "merge_mining_get_aux_block", Value::Null).await;
        let aux_hash = resp["result"]["aux_hash"].as_str().unwrap();
        assert_eq!(aux_hash.len(), 64);
        assert_eq!(aux_hash, "0".repeat(64));
    }

    #[tokio::test]
    async fn submit_solution_adds_to_chain() {
        let chain  = make_chain();
        let router = merge_mining_router(chain.clone());

        let aux_resp = post_rpc(
            merge_mining_router(chain.clone()),
            "merge_mining_get_aux_block",
            Value::Null,
        )
        .await;
        let aux_blob_hex = aux_resp["result"]["aux_blob"].as_str().unwrap().to_string();

        let aux_blob_bytes = hex::decode(&aux_blob_hex).unwrap();
        let mut pending = crate::share::SwapShare::deserialize(&aux_blob_bytes).unwrap();
        for n in 0u32..=u32::MAX {
            pending.nonce = n;
            if pending.difficulty.check_pow(&pending.pow_hash()) {
                break;
            }
        }
        let aux_blob_valid = hex::encode(pending.serialize());

        let params = serde_json::json!({
            "aux_blob":     aux_blob_valid,
            "aux_hash":     "0".repeat(64),
            "blob":         hex::encode(b"fake monero block"),
            "merkle_proof": [],
            "path":         0,
            "seed_hash":    "0".repeat(64),
        });

        let resp = post_rpc(router, "merge_mining_submit_solution", params).await;
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
        // coord message methods are public (not localhost-gated)
        assert!(!is_localhost_only_method("publish_coord_message"));
        assert!(!is_localhost_only_method("poll_coord_messages"));
        assert!(!is_localhost_only_method("replay_coord_messages"));
    }

    fn make_swap_id_hex() -> String {
        hex::encode([42u8; 32])
    }

    #[tokio::test]
    async fn publish_rpc_accepted() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let params = serde_json::json!({
            "swap_id": make_swap_id_hex(),
            "payload": [1u8, 2u8, 3u8],
        });
        let resp = post_rpc(router, "publish_coord_message", params).await;
        assert_eq!(resp["result"]["accepted"].as_bool(), Some(true));
        assert_eq!(resp["result"]["index"].as_u64(), Some(0));
    }

    #[tokio::test]
    async fn publish_rpc_index_increments() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let swap_id = make_swap_id_hex();
        for expected_index in 0u64..3 {
            let params = serde_json::json!({
                "swap_id": swap_id,
                "payload": [expected_index as u8],
            });
            let resp = post_rpc(router.clone(), "publish_coord_message", params).await;
            assert_eq!(resp["result"]["index"].as_u64(), Some(expected_index));
        }
    }

    #[tokio::test]
    async fn poll_rpc_returns_messages() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let swap_id = make_swap_id_hex();

        for i in 0u8..3 {
            let params = serde_json::json!({
                "swap_id": swap_id,
                "payload": [i],
            });
            post_rpc(router.clone(), "publish_coord_message", params).await;
        }

        let params = serde_json::json!({ "swap_id": swap_id, "after_index": 0 });
        let resp = post_rpc(router.clone(), "poll_coord_messages", params).await;
        let msgs = resp["result"]["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(resp["result"]["next_index"].as_u64(), Some(3));

        let params = serde_json::json!({ "swap_id": swap_id, "after_index": 2 });
        let resp = post_rpc(router.clone(), "poll_coord_messages", params).await;
        let msgs = resp["result"]["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(resp["result"]["next_index"].as_u64(), Some(3));
    }

    #[tokio::test]
    async fn poll_unknown_swap_returns_empty() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let unknown = hex::encode([0xffu8; 32]);
        let params = serde_json::json!({ "swap_id": unknown, "after_index": 0 });
        let resp = post_rpc(router, "poll_coord_messages", params).await;
        let msgs = resp["result"]["messages"].as_array().unwrap();
        assert!(msgs.is_empty());
        assert_eq!(resp["result"]["next_index"].as_u64(), Some(0));
    }

    #[tokio::test]
    async fn replay_rpc_returns_all() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let swap_id = make_swap_id_hex();

        for i in 0u8..3 {
            let params = serde_json::json!({
                "swap_id": swap_id,
                "payload": [i],
            });
            post_rpc(router.clone(), "publish_coord_message", params).await;
        }

        let params = serde_json::json!({ "swap_id": swap_id });
        let resp = post_rpc(router, "replay_coord_messages", params).await;
        let msgs = resp["result"]["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(resp["result"]["count"].as_u64(), Some(3));
    }

    #[tokio::test]
    async fn replay_unknown_swap_returns_empty() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let unknown = hex::encode([0xaau8; 32]);
        let params = serde_json::json!({ "swap_id": unknown });
        let resp = post_rpc(router, "replay_coord_messages", params).await;
        let msgs = resp["result"]["messages"].as_array().unwrap();
        assert!(msgs.is_empty());
        assert_eq!(resp["result"]["count"].as_u64(), Some(0));
    }

    #[tokio::test]
    async fn publish_rpc_missing_params() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let resp = post_rpc(router, "publish_coord_message", Value::Null).await;
        assert_eq!(resp["error"]["code"].as_i64(), Some(-32602));
    }

    #[tokio::test]
    async fn publish_rpc_invalid_swap_id() {
        let chain = make_chain();
        let router = merge_mining_router(chain);
        let params = serde_json::json!({
            "swap_id": "not-valid-hex!!!",
            "payload": [1u8, 2u8],
        });
        let resp = post_rpc(router, "publish_coord_message", params).await;
        assert_eq!(resp["error"]["code"].as_i64(), Some(-32602));
    }

    // -------------------------------------------------------------------------
    // WebSocket and SSE integration tests.
    // -------------------------------------------------------------------------

    /// Spawn the merge-mining router on a random port; returns (addr, state).
    /// The state is returned so tests can publish messages directly.
    async fn spawn_test_server() -> (std::net::SocketAddr, RpcState) {
        let chain = make_chain();
        let state = RpcState {
            chain,
            msg_store: Arc::new(CoordMessageStore::new()),
            broadcast: Arc::new(BroadcastRegistry::new()),
        };
        let app = Router::new()
            .route("/json_rpc", post(handle_rpc))
            .route("/ws/coord/{swap_id}", any(ws_coord_handler))
            .route("/sse/coord/{swap_id}", get(sse_coord_handler))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, state)
    }

    #[tokio::test]
    async fn ws_replays_history() {
        let (addr, state) = spawn_test_server().await;
        let swap_id = [42u8; 32];
        let swap_id_hex = hex::encode(swap_id);

        // Pre-populate 3 messages
        state.msg_store.publish(swap_id, b"msg0".to_vec());
        state.msg_store.publish(swap_id, b"msg1".to_vec());
        state.msg_store.publish(swap_id, b"msg2".to_vec());

        let url = format!("ws://127.0.0.1:{}/ws/coord/{}", addr.port(), swap_id_hex);
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Should receive 3 replayed messages
        for expected_index in 0usize..3 {
            let msg = tokio::time::timeout(
                Duration::from_secs(5),
                ws.next(),
            )
            .await
            .expect("timeout waiting for WS message")
            .expect("stream ended")
            .expect("WS error");

            let text = msg.into_text().unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed["swap_id"].as_str().unwrap(), swap_id_hex);
            assert_eq!(parsed["index"].as_u64().unwrap(), expected_index as u64);
        }
    }

    #[tokio::test]
    async fn ws_receives_live_event() {
        let (addr, state) = spawn_test_server().await;
        let swap_id = [42u8; 32];
        let swap_id_hex = hex::encode(swap_id);

        let url = format!("ws://127.0.0.1:{}/ws/coord/{}", addr.port(), swap_id_hex);
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Give the handler time to set up subscription
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Publish a live message
        state.msg_store.publish(swap_id, b"live".to_vec());
        state.broadcast.send(swap_id, b"live".to_vec());

        let msg = tokio::time::timeout(
            Duration::from_secs(5),
            ws.next(),
        )
        .await
        .expect("timeout")
        .expect("stream ended")
        .expect("WS error");

        let text = msg.into_text().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["swap_id"].as_str().unwrap(), swap_id_hex);
        assert_eq!(parsed["index"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn ws_isolation_by_swap_id() {
        let (addr, state) = spawn_test_server().await;
        let swap_a = [1u8; 32];
        let swap_b = [2u8; 32];

        let url_b = format!("ws://127.0.0.1:{}/ws/coord/{}", addr.port(), hex::encode(swap_b));
        let (mut ws_b, _) = tokio_tungstenite::connect_async(&url_b).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Publish to swap_a only
        state.msg_store.publish(swap_a, b"for-a".to_vec());
        state.broadcast.send(swap_a, b"for-a".to_vec());

        // ws_b must not receive anything; timeout expected.
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            ws_b.next(),
        )
        .await;
        assert!(result.is_err(), "swap_b subscriber should not receive swap_a messages");
    }

    #[tokio::test]
    async fn sse_replays_then_live() {
        let (addr, state) = spawn_test_server().await;
        let swap_id = [42u8; 32];
        let swap_id_hex = hex::encode(swap_id);

        // Pre-populate 2 messages
        state.msg_store.publish(swap_id, b"hist0".to_vec());
        state.msg_store.publish(swap_id, b"hist1".to_vec());

        // Use tower oneshot on a fresh router wired to the same state
        let app = Router::new()
            .route("/sse/coord/{swap_id}", get(sse_coord_handler))
            .with_state(state.clone());

        let req = Request::builder()
            .method("GET")
            .uri(format!("/sse/coord/{}", swap_id_hex))
            .header("accept", "text/event-stream")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Read the body with a timeout (SSE stream never ends on its own)
        let body_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            axum::body::to_bytes(resp.into_body(), 1024 * 1024),
        )
        .await
        .unwrap_or_else(|_| {
            // Timeout expected once the replay portion is drained.
            Ok(bytes::Bytes::new())
        })
        .unwrap();

        // If we got an empty result due to timeout, use the TCP server approach
        if body_bytes.is_empty() {
            // Use the already-spawned TCP server and read via raw HTTP
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let req_str = format!(
                "GET /sse/coord/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
                swap_id_hex
            );
            stream.write_all(req_str.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; 4096];
            let mut body_text = String::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            body_text.push_str(&String::from_utf8_lossy(&buf[..n]));
                            if body_text.contains("id: 1") {
                                break;
                            }
                        }
                    }
                }
            })
            .await;

            assert!(body_text.contains("event: coord_message"), "missing event type");
            assert!(body_text.contains("id: 0"), "missing id: 0");
            assert!(body_text.contains("id: 1"), "missing id: 1");
            assert!(body_text.contains(&swap_id_hex), "missing swap_id in data");
        } else {
            let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert!(body_text.contains("event: coord_message"), "missing event type");
            assert!(body_text.contains("id: 0"), "missing id: 0");
            assert!(body_text.contains("id: 1"), "missing id: 1");
            assert!(body_text.contains(&swap_id_hex), "missing swap_id in data");
        }
    }

    #[tokio::test]
    async fn sse_event_format() {
        let state = RpcState {
            chain: make_chain(),
            msg_store: Arc::new(CoordMessageStore::new()),
            broadcast: Arc::new(BroadcastRegistry::new()),
        };
        let swap_id = [42u8; 32];
        let swap_id_hex = hex::encode(swap_id);
        state.msg_store.publish(swap_id, vec![1, 2, 3]);

        let app = Router::new()
            .route("/sse/coord/{swap_id}", get(sse_coord_handler))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri(format!("/sse/coord/{}", swap_id_hex))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            axum::body::to_bytes(resp.into_body(), 1024 * 1024),
        )
        .await
        .unwrap_or_else(|_| Ok(bytes::Bytes::new()))
        .unwrap();

        let body_text = if body_bytes.is_empty() {
            // SSE stream blocked; fall back to a TCP check for format.
            let (addr, state2) = spawn_test_server().await;
            state2.msg_store.publish(swap_id, vec![1, 2, 3]);
            tokio::time::sleep(Duration::from_millis(10)).await;

            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let req_str = format!(
                "GET /sse/coord/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
                swap_id_hex
            );
            stream.write_all(req_str.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; 4096];
            let mut result = String::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            result.push_str(&String::from_utf8_lossy(&buf[..n]));
                            if result.contains("\"payload\"") {
                                break;
                            }
                        }
                    }
                }
            })
            .await;
            result
        } else {
            String::from_utf8(body_bytes.to_vec()).unwrap()
        };

        // Verify SSE wire format
        assert!(body_text.contains("event: coord_message"), "missing event: coord_message");
        assert!(body_text.contains("id: 0"), "missing id: 0");
        // Verify JSON data contains expected fields
        assert!(body_text.contains("\"index\":0"), "missing index:0 in JSON");
        assert!(body_text.contains("\"payload\":[1,2,3]"), "missing payload in JSON");
    }

    #[tokio::test]
    async fn sse_isolation_by_swap_id() {
        let state = RpcState {
            chain: make_chain(),
            msg_store: Arc::new(CoordMessageStore::new()),
            broadcast: Arc::new(BroadcastRegistry::new()),
        };
        let swap_a = [1u8; 32];
        let swap_b = [2u8; 32];
        state.msg_store.publish(swap_a, b"for-a".to_vec());
        state.msg_store.publish(swap_b, b"for-b".to_vec());

        let app = Router::new()
            .route("/sse/coord/{swap_id}", get(sse_coord_handler))
            .with_state(state);

        // Request SSE for swap_b only
        let req = Request::builder()
            .method("GET")
            .uri(format!("/sse/coord/{}", hex::encode(swap_b)))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            axum::body::to_bytes(resp.into_body(), 1024 * 1024),
        )
        .await
        .unwrap_or_else(|_| Ok(bytes::Bytes::new()))
        .unwrap();

        if body_bytes.is_empty() {
            // SSE stream blocked; fall back to TCP.
            let (addr, state2) = spawn_test_server().await;
            state2.msg_store.publish(swap_a, b"for-a".to_vec());
            state2.msg_store.publish(swap_b, b"for-b".to_vec());
            tokio::time::sleep(Duration::from_millis(10)).await;

            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let req_str = format!(
                "GET /sse/coord/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
                hex::encode(swap_b)
            );
            stream.write_all(req_str.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; 4096];
            let mut body_text = String::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            body_text.push_str(&String::from_utf8_lossy(&buf[..n]));
                            if body_text.contains(&hex::encode(swap_b)) {
                                break;
                            }
                        }
                    }
                }
            })
            .await;

            assert!(body_text.contains(&hex::encode(swap_b)), "should contain swap_b");
            assert!(!body_text.contains(&hex::encode(swap_a)), "should NOT contain swap_a");
        } else {
            let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert!(body_text.contains(&hex::encode(swap_b)), "should contain swap_b");
            assert!(!body_text.contains(&hex::encode(swap_a)), "should NOT contain swap_a");
        }
    }
}
