//! Wownero-compatible HTTP RPC server backed by a `WowWowSimnetNode`.
//!
//! Exposes the subset of the monerod JSON-RPC and REST endpoints that Monero
//! wallets (monero-sys / monero-serai) actually call during tests.
//!
//! # Supported endpoints
//!
//! ## JSON-RPC (`POST /json_rpc`)
//! - `get_block_count`
//! - `get_last_block_header`
//! - `get_block_header_by_height`
//! - `generate_blocks`
//! - `get_info`
//! - `get_fee_estimate`
//!
//! ## REST endpoints
//! - `POST /get_height`
//! - `POST /send_raw_transaction`
//! - `POST /get_transactions`
//! - `POST /get_outputs.bin`   (binary epee — RCT output queries)
//! - `POST /get_blocks.bin`    (binary epee — block sync)

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::{error::SimnetError, node::WowSimnetNode};

// ─── shared state ─────────────────────────────────────────────────────────────

type SharedNode = Arc<Mutex<WowSimnetNode>>;

// ─── error helpers ────────────────────────────────────────────────────────────

fn jsonrpc_error(id: Value, code: i64, message: impl Into<String>) -> Json<Value> {
    Json(json!({
        "id": id,
        "jsonrpc": "2.0",
        "error": { "code": code, "message": message.into() }
    }))
}

fn jsonrpc_ok(id: Value, result: Value) -> Json<Value> {
    Json(json!({ "id": id, "jsonrpc": "2.0", "result": result }))
}

// ─── JSON-RPC types ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

// ─── /json_rpc dispatcher ─────────────────────────────────────────────────────

async fn json_rpc(
    State(node): State<SharedNode>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let id = req.id.clone();
    match req.method.as_str() {
        "get_block_count" => handle_get_block_count(node, id).await,
        "get_last_block_header" => handle_get_last_block_header(node, id).await,
        "get_block_header_by_height" => {
            handle_get_block_header_by_height(node, id, req.params).await
        }
        "get_block" => handle_get_block(node, id, req.params).await,
        "generate_blocks" => handle_generate_blocks(node, id, req.params).await,
        "get_info" => handle_get_info(node, id).await,
        "get_fee_estimate" => handle_get_fee_estimate(id).await,
        other => jsonrpc_error(id, -32601, format!("method not found: {other}")),
    }
}

async fn handle_get_block_count(node: SharedNode, id: Value) -> Json<Value> {
    let mut n = node.lock().await;
    match n.height().await {
        Ok(h) => jsonrpc_ok(id, json!({ "count": h, "status": "OK", "untrusted": false })),
        Err(e) => jsonrpc_error(id, -1, e.to_string()),
    }
}

async fn handle_get_last_block_header(node: SharedNode, id: Value) -> Json<Value> {
    let mut n = node.lock().await;
    match n.chain_height().await {
        Ok((height, _top_hash)) => {
            let tip = (height as usize).saturating_sub(1);
            match build_block_header_json(&mut n, tip).await {
                Ok(hdr) => jsonrpc_ok(id, json!({ "block_header": hdr, "status": "OK", "untrusted": false })),
                Err(e) => jsonrpc_error(id, -1, e.to_string()),
            }
        }
        Err(e) => jsonrpc_error(id, -1, e.to_string()),
    }
}

async fn handle_get_block_header_by_height(
    node: SharedNode,
    id: Value,
    params: Value,
) -> Json<Value> {
    let height = match params.get("height").and_then(|v| v.as_u64()) {
        Some(h) => h as usize,
        None => return jsonrpc_error(id, -32602, "missing 'height' param"),
    };
    let mut n = node.lock().await;
    match build_block_header_json(&mut n, height).await {
        Ok(hdr) => jsonrpc_ok(id, json!({ "block_header": hdr, "status": "OK", "untrusted": false })),
        Err(e) => jsonrpc_error(id, -1, e.to_string()),
    }
}

/// Build the monerod-shaped block header JSON for a given height.
async fn build_block_header_json(
    n: &mut WowSimnetNode,
    height: usize,
) -> Result<Value, SimnetError> {
    let hdr = n.block_extended_header(height).await?;
    let hash = n.block_hash_at(height).await?;
    let prev_hash = if height > 0 {
        n.block_hash_at(height - 1).await?
    } else {
        [0u8; 32]
    };
    Ok(json!({
        "block_size":  hdr.block_weight,
        "block_weight": hdr.block_weight,
        "cumulative_difficulty": hdr.cumulative_difficulty,
        "depth": 0,
        "difficulty": 1,
        "hash": hex::encode(hash),
        "height": height,
        "long_term_weight": hdr.long_term_weight,
        "major_version": hdr.version as u8,
        "minor_version": hdr.vote,
        "nonce": 0u32,
        "num_txes": 0u64,
        "orphan_status": false,
        "pow_hash": "",
        "prev_hash": hex::encode(prev_hash),
        "reward": 0u64,
        "timestamp": hdr.timestamp,
        "wide_cumulative_difficulty": format!("0x{:x}", hdr.cumulative_difficulty),
        "wide_difficulty": "0x1",
    }))
}

/// Handle `get_block` JSON-RPC — returns the block blob for a given block hash.
///
/// This is called by `monero-serai`'s `HttpRpc::get_block()` which underpins
/// `scan_block_for_outputs` in `monero-rust` / `monero-wallet-rs`.
async fn handle_get_block(node: SharedNode, id: Value, params: Value) -> Json<Value> {
    let hash_hex = match params.get("hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return jsonrpc_error(id, -32602, "missing 'hash' param"),
    };
    let hash_bytes = match hex::decode(&hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return jsonrpc_error(id, -32602, format!("invalid hash: {hash_hex}")),
    };

    let mut n = node.lock().await;
    match n.block_blob_by_hash(hash_bytes).await {
        Ok(blob) => jsonrpc_ok(
            id,
            json!({
                "blob": hex::encode(&blob),
                "status": "OK",
                "untrusted": false,
            }),
        ),
        Err(e) => jsonrpc_error(id, -1, e.to_string()),
    }
}

async fn handle_generate_blocks(
    node: SharedNode,
    id: Value,
    params: Value,
) -> Json<Value> {
    let count = params
        .get("amount_of_blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    // wallet_address is accepted but ignored for coinbase key derivation for now;
    // all blocks use the dummy genesis miner tx.
    // TODO: derive real coinbase outputs to wallet_address

    let mut n = node.lock().await;
    let mut hashes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match n.chain_height().await {
            Ok((_, _)) => {}
            Err(e) => return jsonrpc_error(id, -1, e.to_string()),
        }
        if let Err(e) = n.mine_blocks(1).await {
            return jsonrpc_error(id, -1, e.to_string());
        }
        match n.chain_height().await {
            Ok((_, top_hash)) => hashes.push(hex::encode(top_hash)),
            Err(e) => return jsonrpc_error(id, -1, e.to_string()),
        }
    }
    let new_height = match n.height().await {
        Ok(h) => h,
        Err(e) => return jsonrpc_error(id, -1, e.to_string()),
    };
    jsonrpc_ok(id, json!({ "blocks": hashes, "height": new_height, "status": "OK" }))
}

async fn handle_get_info(node: SharedNode, id: Value) -> Json<Value> {
    let mut n = node.lock().await;
    let (height, top_hash) = match n.chain_height().await {
        Ok(v) => v,
        Err(e) => return jsonrpc_error(id, -1, e.to_string()),
    };
    jsonrpc_ok(id, json!({
        "adjusted_time": 0u64,
        "alt_blocks_count": 0u64,
        "block_size_limit": 600000u64,
        "block_size_median": 300000u64,
        "block_weight_limit": 600000u64,
        "block_weight_median": 300000u64,
        "bootstrap_daemon_address": "",
        "busy_syncing": false,
        "credits": 0u64,
        "cumulative_difficulty": height,
        "cumulative_difficulty_top64": 0u64,
        "database_size": 0u64,
        "difficulty": 1u64,
        "difficulty_top64": 0u64,
        "free_space": 0u64,
        "grey_peerlist_size": 0u64,
        "height": height,
        "height_without_bootstrap": height,
        "incoming_connections_count": 0u64,
        "mainnet": false,
        "nettype": "fakechain",
        "offline": true,
        "outgoing_connections_count": 0u64,
        "rpc_connections_count": 0u64,
        "stagenet": false,
        "start_time": 0u64,
        "status": "OK",
        "synchronized": true,
        "target": 1u64,
        "target_height": 0u64,
        "testnet": false,
        "top_block_hash": hex::encode(top_hash),
        "top_hash": hex::encode(top_hash),
        "tx_count": 0u64,
        "tx_pool_size": 0u64,
        "untrusted": false,
        "update_available": false,
        "version": "0.18.4.0-cuprate-simnet",
        "was_bootstrap_ever_used": false,
        "white_peerlist_size": 0u64,
        "wide_cumulative_difficulty": format!("0x{height:x}"),
        "wide_difficulty": "0x1",
    }))
}

async fn handle_get_fee_estimate(id: Value) -> Json<Value> {
    jsonrpc_ok(id, json!({
        "fee": 20000u64,
        "fees": [20000u64, 80000u64, 320000u64, 4000000u64],
        "quantization_mask": 10000u64,
        "status": "OK",
        "untrusted": false,
    }))
}

// ─── REST: /get_height ────────────────────────────────────────────────────────

async fn get_height(State(node): State<SharedNode>) -> impl IntoResponse {
    let mut n = node.lock().await;
    match n.chain_height().await {
        Ok((h, hash)) => Json(json!({
            "hash": hex::encode(hash),
            "height": h,
            "status": "OK",
            "untrusted": false,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "Error", "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ─── REST: /send_raw_transaction ──────────────────────────────────────────────

#[derive(Deserialize)]
struct SendRawTxRequest {
    tx_as_hex: String,
    #[serde(default)]
    do_not_relay: bool,
    #[serde(default)]
    do_sanity_checks: bool,
}

async fn send_raw_transaction(
    State(node): State<SharedNode>,
    Json(req): Json<SendRawTxRequest>,
) -> impl IntoResponse {
    let blob = match hex::decode(&req.tx_as_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(json!({
                "status": "Failed",
                "reason": format!("hex decode error: {e}"),
                "double_spend": false, "low_mixin": false, "not_relayed": false,
                "overspend": false, "too_big": false, "too_few_outputs": false,
                "tx_extra_too_big": false,
            }))
            .into_response()
        }
    };

    let mut n = node.lock().await;
    let _ = req.do_not_relay;
    let _ = req.do_sanity_checks;
    match n.submit_tx(blob) {
        Ok(hash) => Json(json!({
            "status": "OK",
            "tx_hash": hex::encode(hash),
            "double_spend": false, "low_mixin": false, "not_relayed": false,
            "overspend": false, "too_big": false, "too_few_outputs": false,
            "tx_extra_too_big": false, "reason": "",
        }))
        .into_response(),
        Err(e) => Json(json!({
            "status": "Failed",
            "reason": e.to_string(),
            "double_spend": false, "low_mixin": false, "not_relayed": false,
            "overspend": false, "too_big": false, "too_few_outputs": false,
            "tx_extra_too_big": false,
        }))
        .into_response(),
    }
}

// ─── REST: /get_transactions ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct GetTransactionsRequest {
    txs_hashes: Vec<String>,
    #[serde(default)]
    decode_as_json: bool,
    #[serde(default)]
    prune: bool,
}

async fn get_transactions(
    State(node): State<SharedNode>,
    Json(req): Json<GetTransactionsRequest>,
) -> impl IntoResponse {
    let hashes: Result<Vec<[u8; 32]>, _> = req
        .txs_hashes
        .iter()
        .map(|s| {
            hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or(())
        })
        .collect();

    let hashes = match hashes {
        Ok(h) => h,
        Err(()) => {
            return Json(json!({ "status": "Failed", "reason": "invalid hex hash" }))
                .into_response()
        }
    };

    let mut n = node.lock().await;
    let _ = req.decode_as_json;
    let _ = req.prune;
    match n.transactions(hashes).await {
        Ok(txs) => {
            let txs_as_hex: Vec<String> =
                txs.iter().map(|t| hex::encode(&t.tx_blob)).collect();
            Json(json!({
                "txs_as_hex": txs_as_hex,
                "status": "OK",
                "missed_tx": [],
                "txs": txs.iter().map(|t| json!({
                    "as_hex": hex::encode(&t.tx_blob),
                    "as_json": "",
                    "block_height": t.block_height,
                    "block_timestamp": t.block_timestamp,
                    "confirmations": t.confirmations,
                    "double_spend_seen": false,
                    "in_pool": false,
                    "output_indices": t.output_indices,
                    "prunable_as_hex": hex::encode(&t.prunable_blob),
                    "prunable_hash": hex::encode(t.prunable_hash),
                    "pruned_as_hex": hex::encode(&t.pruned_blob),
                    "tx_hash": hex::encode(t.tx_hash),
                    "weight": t.tx_blob.len(),
                })).collect::<Vec<_>>(),
            }))
            .into_response()
        }
        Err(e) => {
            Json(json!({ "status": "Failed", "reason": e.to_string() })).into_response()
        }
    }
}

// ─── Binary RPC: /get_outputs.bin ─────────────────────────────────────────────
//
// The wallet sends an epee-encoded COMMAND_RPC_GET_OUTPUTS_BIN request and
// expects an epee-encoded response.  We parse the request manually (it's a
// simple fixed structure) and serialize the response the same way.
//
// Wire format for the request body (epee binary object):
//   "outputs" array of { "amount": varint u64, "index": varint u64 }
//
// Wire format for the response:
//   "outs" array of { "key": [u8;32], "mask": [u8;32], "unlocked": bool,
//                     "height": u64, "txid": [u8;32] }
//   "status": "OK"
//
// Rather than pulling in cuprate-epee-encoding as a dependency (which requires
// a workspace restructure), we implement the minimal epee subset we need
// directly.  Epee is a simple tag-length-value binary format; the fields we
// need map cleanly to a hand-rolled parser.

async fn get_outputs_bin(
    State(node): State<SharedNode>,
    body: Bytes,
) -> impl IntoResponse {
    // Parse the request using minimal epee helpers.
    let indexes = match parse_get_outputs_request(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                build_get_outputs_error_response(&format!("parse error: {e}")),
            )
                .into_response();
        }
    };

    let mut n = node.lock().await;
    match n.rct_outputs_at_indexes(indexes).await {
        Ok(outs) => {
            let resp = build_get_outputs_response(&outs);
            ([(header::CONTENT_TYPE, "application/octet-stream")], resp).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            build_get_outputs_error_response(&e.to_string()),
        )
            .into_response(),
    }
}

// ─── Binary RPC: /get_blocks.bin ──────────────────────────────────────────────

async fn get_blocks_bin(
    State(node): State<SharedNode>,
    body: Bytes,
) -> impl IntoResponse {
    let start_height = match parse_get_blocks_request(&body) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                build_error_response_bytes(&format!("parse error: {e}")),
            )
                .into_response();
        }
    };

    let mut n = node.lock().await;
    let (chain_height, _) = match n.chain_height().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                build_error_response_bytes(&e.to_string()),
            )
                .into_response();
        }
    };

    let end = chain_height.min(start_height + 100);
    let mut entries: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();

    for h in start_height..end {
        let block_blob = match n.block_blob_at(h as usize).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("get_blocks_bin: failed to fetch block at {h}: {e}");
                break;
            }
        };

        // Extract non-coinbase tx hashes from the block.
        let tx_hashes: Vec<[u8; 32]> = wownero_oxide::block::Block::read(
            &mut block_blob.as_slice(),
        )
        .map(|b| b.transactions.to_vec())
        .unwrap_or_default();

        let tx_blobs = if tx_hashes.is_empty() {
            vec![]
        } else {
            match n.transactions(tx_hashes).await {
                Ok(txs) => txs.into_iter().map(|t| t.tx_blob).collect(),
                Err(e) => {
                    eprintln!("get_blocks_bin: failed to fetch txs at {h}: {e}");
                    break;
                }
            }
        };

        entries.push((block_blob, tx_blobs));
    }

    let resp = build_get_blocks_response(start_height, chain_height, &entries);
    ([(header::CONTENT_TYPE, "application/octet-stream")], resp).into_response()
}

// ─── Minimal epee binary helpers ─────────────────────────────────────────────
//
// Epee format:
//   header: 0x01 0x11 0x01 0x01 0x01 0x01 0x02 0x01 0x01 (9 bytes)
//   section: varint count of objects, then objects
//   object: varint name_len, name bytes, type byte, value
//
// For our purposes we only need to read/write a small fixed set of fields.
// We use a JSON-like approach: build a flat response with the fields monerod
// sends, encoded as epee binary.

const EPEE_HEADER: &[u8] = &[0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01];

// Epee type tags
const EPEE_STRING: u8 = 0x0A;
const EPEE_UINT64: u8 = 0x08;
const EPEE_UINT32: u8 = 0x06;
const EPEE_BOOL: u8 = 0x01; // actually 0x0B for bool in some versions; use u8 alias
const EPEE_ARRAY_FLAG: u8 = 0x80;
const EPEE_OBJECT: u8 = 0x0C;

/// Write an epee varint (little-endian with 2-bit size tag in low bits).
fn write_varint(v: u64, out: &mut Vec<u8>) {
    if v <= 63 {
        out.push((v << 2) as u8); // 2-bit tag 00 = 1 byte
    } else if v <= 16383 {
        let enc = (v << 2) | 1; // tag 01 = 2 bytes
        out.push((enc & 0xff) as u8);
        out.push(((enc >> 8) & 0xff) as u8);
    } else if v <= 1073741823 {
        let enc = (v << 2) | 2; // tag 10 = 4 bytes
        out.push((enc & 0xff) as u8);
        out.push(((enc >> 8) & 0xff) as u8);
        out.push(((enc >> 16) & 0xff) as u8);
        out.push(((enc >> 24) & 0xff) as u8);
    } else {
        let enc = (v << 2) | 3; // tag 11 = 8 bytes
        for i in 0..8 { out.push(((enc >> (i * 8)) & 0xff) as u8); }
    }
}

/// Read an epee varint from a byte slice.  Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> Result<(u64, usize), &'static str> {
    if data.is_empty() { return Err("empty varint"); }
    let tag = data[0] & 0x03;
    match tag {
        0 => Ok(((data[0] >> 2) as u64, 1)),
        1 => {
            if data.len() < 2 { return Err("varint too short"); }
            let v = (data[0] as u64) | ((data[1] as u64) << 8);
            Ok((v >> 2, 2))
        }
        2 => {
            if data.len() < 4 { return Err("varint too short"); }
            let v = (data[0] as u64) | ((data[1] as u64) << 8)
                | ((data[2] as u64) << 16) | ((data[3] as u64) << 24);
            Ok((v >> 2, 4))
        }
        3 => {
            if data.len() < 8 { return Err("varint too short"); }
            let mut v = 0u64;
            for i in 0..8 { v |= (data[i] as u64) << (i * 8); }
            Ok((v >> 2, 8))
        }
        _ => unreachable!(),
    }
}

/// Write an epee key (1-byte length + ASCII name).
fn write_key(name: &[u8], out: &mut Vec<u8>) {
    assert!(name.len() < 256);
    out.push(name.len() as u8);
    out.extend_from_slice(name);
}

/// Write the 9-byte epee section header and then a varint for the object field count.
fn begin_section(field_count: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(EPEE_HEADER);
    write_varint(field_count, out);
}

/// Write a u64 field.
fn write_u64(name: &[u8], value: u64, out: &mut Vec<u8>) {
    write_key(name, out);
    out.push(EPEE_UINT64);
    out.extend_from_slice(&value.to_le_bytes());
}

/// Write a string field (length-prefixed u32).
fn write_string(name: &[u8], value: &[u8], out: &mut Vec<u8>) {
    write_key(name, out);
    out.push(EPEE_STRING);
    let len = value.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
}

/// Write a bool field.
fn write_bool(name: &[u8], value: bool, out: &mut Vec<u8>) {
    write_key(name, out);
    out.push(EPEE_BOOL);
    out.push(if value { 1 } else { 0 });
}

// ─── parse_get_outputs_request ────────────────────────────────────────────────

/// Parse `COMMAND_RPC_GET_OUTPUTS_BIN::request`.
///
/// The body is an epee binary object with a single field "outputs" which is an
/// array of objects each having "amount" (u64) and "index" (u64).
///
/// We locate the "outputs" array and extract the "index" of each element,
/// ignoring "amount" (always 0 for RCT).
fn parse_get_outputs_request(data: &[u8]) -> Result<Vec<u64>, String> {
    // Skip 9-byte epee header.
    if data.len() < EPEE_HEADER.len() {
        return Err("too short".into());
    }
    if &data[..EPEE_HEADER.len()] != EPEE_HEADER {
        return Err("bad epee header".into());
    }
    let mut pos = EPEE_HEADER.len();

    // Read root object field count.
    let (field_count, n) = read_varint(&data[pos..]).map_err(|e| e.to_string())?;
    pos += n;

    for _ in 0..field_count {
        if pos >= data.len() { break; }
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() { return Err("name oob".into()); }
        let name = &data[pos..pos + name_len];
        pos += name_len;
        if pos >= data.len() { return Err("no type byte".into()); }
        let type_byte = data[pos];
        pos += 1;

        if name == b"outputs" {
            // type byte should be EPEE_OBJECT | EPEE_ARRAY_FLAG = 0x8C
            if type_byte != (EPEE_OBJECT | EPEE_ARRAY_FLAG) {
                return Err(format!("unexpected type for outputs: {type_byte:#x}"));
            }
            let (arr_len, n) = read_varint(&data[pos..]).map_err(|e| e.to_string())?;
            pos += n;
            let mut indexes = Vec::with_capacity(arr_len as usize);
            for _ in 0..arr_len {
                // Each array element is an epee sub-object with "amount" and "index".
                let (obj_fields, n) = read_varint(&data[pos..]).map_err(|e| e.to_string())?;
                pos += n;
                let mut index = 0u64;
                for _ in 0..obj_fields {
                    if pos >= data.len() { break; }
                    let fn_len = data[pos] as usize;
                    pos += 1;
                    if pos + fn_len > data.len() { return Err("field name oob".into()); }
                    let fname = &data[pos..pos + fn_len];
                    pos += fn_len;
                    if pos >= data.len() { return Err("no field type".into()); }
                    let ftype = data[pos];
                    pos += 1;
                    if ftype == EPEE_UINT64 {
                        if pos + 8 > data.len() { return Err("u64 oob".into()); }
                        let val = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
                        pos += 8;
                        if fname == b"index" { index = val; }
                        // "amount" ignored
                    } else {
                        return Err(format!("unexpected field type {ftype:#x} in output entry"));
                    }
                }
                indexes.push(index);
            }
            return Ok(indexes);
        } else {
            // Skip unknown field.
            pos = skip_epee_value(data, pos, type_byte)?;
        }
    }
    Ok(vec![])
}

/// Skip over one epee value of the given type, returning new pos.
fn skip_epee_value(data: &[u8], mut pos: usize, type_byte: u8) -> Result<usize, String> {
    let base_type = type_byte & !EPEE_ARRAY_FLAG;
    let is_array = (type_byte & EPEE_ARRAY_FLAG) != 0;
    if is_array {
        let (count, n) = read_varint(&data[pos..]).map_err(|e| e.to_string())?;
        pos += n;
        for _ in 0..count {
            pos = skip_epee_value(data, pos, base_type)?;
        }
        return Ok(pos);
    }
    match base_type {
        EPEE_UINT64 => { pos += 8; }
        EPEE_UINT32 => { pos += 4; }
        0x05 => { pos += 2; } // u16
        0x04 => { pos += 1; } // u8
        EPEE_BOOL => { pos += 1; }
        0x09 => { pos += 8; } // i64
        0x07 => { pos += 4; } // i32
        EPEE_STRING => {
            if pos + 4 > data.len() { return Err("string len oob".into()); }
            let len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4 + len;
        }
        EPEE_OBJECT => {
            let (fc, n) = read_varint(&data[pos..]).map_err(|e| e.to_string())?;
            pos += n;
            for _ in 0..fc {
                if pos >= data.len() { break; }
                let nl = data[pos] as usize; pos += 1 + nl;
                if pos >= data.len() { break; }
                let ft = data[pos]; pos += 1;
                pos = skip_epee_value(data, pos, ft)?;
            }
        }
        _ => { return Err(format!("unknown type {base_type:#x} in skip")); }
    }
    Ok(pos)
}

// ─── build_get_outputs_response ───────────────────────────────────────────────

fn build_get_outputs_response(
    outs: &[(u64, cuprate_types::OutputOnChain)],
) -> Vec<u8> {
    let mut body = Vec::new();
    // Root object: 2 fields: "outs" (array of objects) and "status" (string)
    begin_section(2, &mut body);

    // "outs" field: array of objects
    write_key(b"outs", &mut body);
    body.push(EPEE_OBJECT | EPEE_ARRAY_FLAG);
    write_varint(outs.len() as u64, &mut body);
    for (_idx, out) in outs {
        // Each out: { "key": [u8;32], "mask": [u8;32], "unlocked": bool, "height": u64, "txid": [u8;32] }
        write_varint(5, &mut body); // 5 fields
        write_string(b"key", out.key.as_bytes(), &mut body);
        write_string(b"mask", out.commitment.as_bytes(), &mut body);
        write_bool(b"unlocked", true, &mut body);
        write_u64(b"height", out.height as u64, &mut body);
        let txid = out.txid.unwrap_or([0u8; 32]);
        write_string(b"txid", &txid, &mut body);
    }

    // "status" field
    write_string(b"status", b"OK", &mut body);

    body
}

fn build_get_outputs_error_response(msg: &str) -> Vec<u8> {
    let mut body = Vec::new();
    begin_section(2, &mut body);
    write_string(b"status", format!("Error: {msg}").as_bytes(), &mut body);
    write_string(b"error", msg.as_bytes(), &mut body);
    body
}

// ─── parse_get_blocks_request ─────────────────────────────────────────────────

/// Parse `COMMAND_RPC_GET_BLOCKS_FAST::request`.
/// We only extract `start_height` for our simplified implementation.
fn parse_get_blocks_request(data: &[u8]) -> Result<u64, String> {
    if data.len() < EPEE_HEADER.len() {
        return Err("too short".into());
    }
    if &data[..EPEE_HEADER.len()] != EPEE_HEADER {
        return Err("bad epee header".into());
    }
    let mut pos = EPEE_HEADER.len();
    let (field_count, n) = read_varint(&data[pos..]).map_err(|e| e.to_string())?;
    pos += n;
    for _ in 0..field_count {
        if pos >= data.len() { break; }
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() { return Err("name oob".into()); }
        let name = &data[pos..pos + name_len];
        pos += name_len;
        if pos >= data.len() { return Err("no type".into()); }
        let type_byte = data[pos];
        pos += 1;
        if name == b"start_height" && type_byte == EPEE_UINT64 {
            if pos + 8 > data.len() { return Err("u64 oob".into()); }
            let v = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
            return Ok(v);
        } else {
            pos = skip_epee_value(data, pos, type_byte)?;
        }
    }
    Ok(0)
}

/// Build a `COMMAND_RPC_GET_BLOCKS_FAST` epee response containing real block data.
///
/// `entries` is a slice of `(block_blob, tx_blobs)` tuples, one per block.
fn build_get_blocks_response(
    start_height: u64,
    current_height: u64,
    entries: &[(Vec<u8>, Vec<Vec<u8>>)],
) -> Vec<u8> {
    let mut body = Vec::new();
    begin_section(4, &mut body);

    // "blocks" — array of BlockCompleteEntry objects
    write_key(b"blocks", &mut body);
    body.push(EPEE_OBJECT | EPEE_ARRAY_FLAG);
    write_varint(entries.len() as u64, &mut body);
    for (block_blob, tx_blobs) in entries {
        // Each BlockCompleteEntry has 2 fields: "block" and "txs".
        write_varint(2u64, &mut body);
        write_string(b"block", block_blob, &mut body);

        // "txs" — array of EPEE_STRING, each element prefixed with u32 LE length.
        write_key(b"txs", &mut body);
        body.push(EPEE_STRING | EPEE_ARRAY_FLAG);
        write_varint(tx_blobs.len() as u64, &mut body);
        for tx_blob in tx_blobs {
            let len = tx_blob.len() as u32;
            body.extend_from_slice(&len.to_le_bytes());
            body.extend_from_slice(tx_blob);
        }
    }

    write_u64(b"start_height", start_height, &mut body);
    write_u64(b"current_height", current_height, &mut body);
    write_string(b"status", b"OK", &mut body);
    body
}

fn build_error_response_bytes(msg: &str) -> Vec<u8> {
    let mut body = Vec::new();
    begin_section(1, &mut body);
    write_string(b"status", format!("Error: {msg}").as_bytes(), &mut body);
    body
}

// ─── server startup ───────────────────────────────────────────────────────────

/// Start the monerod-compatible RPC server in the background.
///
/// Returns the actual bound `SocketAddr`.
pub async fn start_rpc_server(
    node: SharedNode,
    port: u16,
) -> Result<SocketAddr, SimnetError> {
    let app = Router::new()
        .route("/json_rpc", post(json_rpc))
        .route("/get_height", post(get_height))
        .route("/send_raw_transaction", post(send_raw_transaction))
        .route("/get_transactions", post(get_transactions))
        .route("/get_outputs.bin", post(get_outputs_bin))
        .route("/get_blocks.bin", post(get_blocks_bin))
        .with_state(node);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .map_err(SimnetError::Io)?;
    let addr = listener.local_addr().map_err(SimnetError::Io)?;

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("rpc server error");
    });

    Ok(addr)
}
