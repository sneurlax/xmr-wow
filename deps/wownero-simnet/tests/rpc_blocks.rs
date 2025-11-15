use std::sync::Arc;
use tokio::sync::Mutex;

use wownero_simnet::{start_rpc_server, WowSimnetNode};

/// Build a minimal epee-encoded get_blocks.bin request body with start_height=1.
///
/// Wire layout (26 bytes):
///   [9]  epee header
///   [1]  varint(1) = 1 field in root object  (0x04 = 1 << 2 | 0b00)
///   [1]  key length = 12
///   [12] "start_height"
///   [1]  type = EPEE_UINT64 (0x08)
///   [8]  1u64 little-endian
fn build_get_blocks_request(start_height: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    // epee header
    buf.extend_from_slice(&[0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01]);
    // varint(1): 1 field — tag 00 → (1 << 2) = 0x04
    buf.push(0x04);
    // key "start_height"
    let key = b"start_height";
    buf.push(key.len() as u8);
    buf.extend_from_slice(key);
    // type EPEE_UINT64
    buf.push(0x08);
    // value
    buf.extend_from_slice(&start_height.to_le_bytes());
    buf
}

#[tokio::test]
async fn rpc_get_blocks_bin_returns_block_bytes() {
    let mut node = WowSimnetNode::start().await.unwrap();
    node.mine_blocks(5).await.unwrap();

    let node = Arc::new(Mutex::new(node));
    let addr = start_rpc_server(node.clone(), 0).await.unwrap();

    let client = reqwest::Client::new();
    let body = build_get_blocks_request(1);
    let resp = client
        .post(format!("http://{addr}/get_blocks.bin"))
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let ct = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("octet-stream"), "unexpected content-type: {ct}");

    let bytes = resp.bytes().await.expect("body read failed");

    // Must start with the epee header
    assert!(
        bytes.len() >= 9,
        "response too short: {} bytes",
        bytes.len()
    );
    assert_eq!(
        &bytes[..9],
        &[0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01],
        "bad epee header"
    );

    // A response with real block data must be significantly larger than an empty one.
    // The 5 mined blocks each contribute at least ~100 bytes of block blob.
    assert!(
        bytes.len() > 100,
        "response suspiciously small ({} bytes) — blocks likely empty",
        bytes.len()
    );
}
