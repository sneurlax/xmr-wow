use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use simnet_testbed::{
    cuprate_simnet::SimnetWallet, wownero_simnet::WowSimnetWallet, SimnetTestbed,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use xmr_wow_crypto::{combine_public_keys, derive_view_key};
use xmr_wow_wallet::{
    verify_lock, ConfirmationStatus, CryptoNoteWallet, RefundArtifact, RefundChain,
    ReqwestTransport, ScanResult, TxHash, WalletError, WowWallet, XmrWallet,
};

#[derive(Clone)]
struct MockDaemonState {
    block_count: u64,
    txs: Vec<Value>,
    send_status: &'static str,
}

struct TestServer {
    url: String,
    handle: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn_mock_daemon(state: MockDaemonState) -> TestServer {
    async fn handle_json_rpc(
        State(state): State<Arc<MockDaemonState>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let result = match method {
            "get_block_count" => json!({ "count": state.block_count }),
            _ => json!({}),
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }))
    }

    async fn handle_get_transactions(State(state): State<Arc<MockDaemonState>>) -> Json<Value> {
        Json(json!({
            "status": "OK",
            "txs": state.txs,
        }))
    }

    async fn handle_sendrawtransaction(State(state): State<Arc<MockDaemonState>>) -> Json<Value> {
        Json(json!({
            "status": state.send_status,
        }))
    }

    async fn handle_bytes(_body: Bytes) -> &'static str {
        "abcdef"
    }

    let shared = Arc::new(state);
    let app = Router::new()
        .route("/json_rpc", post(handle_json_rpc))
        .route("/get_transactions", post(handle_get_transactions))
        .route("/sendrawtransaction", post(handle_sendrawtransaction))
        .route("/bytes", post(handle_bytes))
        .with_state(shared);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        url: format!("http://{}", addr),
        handle,
    }
}

fn sample_keys() -> (EdwardsPoint, Scalar, Scalar, Scalar) {
    let spend_secret = Scalar::random(&mut OsRng);
    let spend_point = spend_secret * G;
    let view_scalar = Scalar::random(&mut OsRng);
    let sender_spend = Scalar::random(&mut OsRng);
    let sender_view = Scalar::random(&mut OsRng);
    (spend_point, view_scalar, sender_spend, sender_view)
}

fn sample_joint_keys() -> (Scalar, EdwardsPoint, Scalar) {
    let alice_secret = Scalar::random(&mut OsRng);
    let bob_secret = Scalar::random(&mut OsRng);
    let alice_pub = alice_secret * G;
    let bob_pub = bob_secret * G;
    let joint_spend_point = combine_public_keys(&alice_pub, &bob_pub);
    let joint_spend_secret = alice_secret + bob_secret;
    let joint_view_scalar = derive_view_key(&Scalar::from_bytes_mod_order(
        joint_spend_point.compress().to_bytes(),
    ));

    (joint_spend_secret, joint_spend_point, joint_view_scalar)
}

struct FakeWallet {
    chain: RefundChain,
    results: Vec<ScanResult>,
    timelocked_artifact: Option<(TxHash, Vec<u8>)>,
    broadcast_tx_hash: Option<TxHash>,
}

#[async_trait]
impl CryptoNoteWallet for FakeWallet {
    fn refund_chain(&self) -> RefundChain {
        self.chain
    }

    async fn lock(
        &self,
        _spend_point: &EdwardsPoint,
        _view_scalar: &Scalar,
        _amount: u64,
    ) -> Result<TxHash, WalletError> {
        Err(WalletError::RpcRequest("unused".into()))
    }

    async fn sweep(
        &self,
        _spend_secret: &Scalar,
        _view_scalar: &Scalar,
        _destination: &str,
    ) -> Result<TxHash, WalletError> {
        Err(WalletError::RpcRequest("unused".into()))
    }

    async fn scan(
        &self,
        _spend_point: &EdwardsPoint,
        _view_scalar: &Scalar,
        _from_height: u64,
    ) -> Result<Vec<ScanResult>, WalletError> {
        Ok(self.results.clone())
    }

    async fn poll_confirmation(
        &self,
        _tx_hash: &TxHash,
        _required_confirmations: u64,
    ) -> Result<ConfirmationStatus, WalletError> {
        Err(WalletError::RpcRequest("unused".into()))
    }

    async fn sweep_timelocked(
        &self,
        _spend_secret: &Scalar,
        _view_scalar: &Scalar,
        _destination: &str,
        _refund_height: u64,
    ) -> Result<(TxHash, Vec<u8>), WalletError> {
        self.timelocked_artifact
            .clone()
            .ok_or_else(|| WalletError::RpcRequest("unused".into()))
    }

    async fn broadcast_raw_tx(&self, _tx_bytes: &[u8]) -> Result<TxHash, WalletError> {
        self.broadcast_tx_hash
            .ok_or_else(|| WalletError::RpcRequest("unused".into()))
    }

    async fn get_current_height(&self) -> Result<u64, WalletError> {
        Err(WalletError::RpcRequest("unused".into()))
    }
}

#[tokio::test]
async fn reqwest_transport_supports_both_daemon_traits() {
    let server = spawn_mock_daemon(MockDaemonState {
        block_count: 0,
        txs: Vec::new(),
        send_status: "OK",
    })
    .await;
    let transport = ReqwestTransport::new(&server.url);

    let truncated =
        monero_daemon_rpc::HttpTransport::post(&transport, "bytes", b"ignored".to_vec(), Some(4))
            .await
            .unwrap();
    assert_eq!(truncated, b"abcd");

    let full =
        wownero_daemon_rpc::HttpTransport::post(&transport, "bytes", b"ignored".to_vec(), None)
            .await
            .unwrap();
    assert_eq!(full, b"abcdef");
}

#[tokio::test]
async fn verify_lock_returns_largest_matching_output() {
    let wallet = FakeWallet {
        chain: RefundChain::Xmr,
        results: vec![
            ScanResult {
                found: true,
                amount: 5,
                tx_hash: [0x11; 32],
                output_index: 0,
                block_height: 10,
            },
            ScanResult {
                found: true,
                amount: 7,
                tx_hash: [0x22; 32],
                output_index: 1,
                block_height: 11,
            },
        ],
        timelocked_artifact: None,
        broadcast_tx_hash: None,
    };
    let spend_point = Scalar::random(&mut OsRng) * G;
    let view_scalar = Scalar::random(&mut OsRng);

    let result = verify_lock(&wallet, &spend_point, &view_scalar, 10, 0)
        .await
        .unwrap();
    assert_eq!(result.amount, 7);
    assert_eq!(result.tx_hash, [0x22; 32]);
}

#[tokio::test]
async fn verify_lock_fails_when_total_is_too_small() {
    let wallet = FakeWallet {
        chain: RefundChain::Xmr,
        results: vec![ScanResult {
            found: true,
            amount: 3,
            tx_hash: [0x33; 32],
            output_index: 0,
            block_height: 5,
        }],
        timelocked_artifact: None,
        broadcast_tx_hash: None,
    };
    let spend_point = Scalar::random(&mut OsRng) * G;
    let view_scalar = Scalar::random(&mut OsRng);

    let err = verify_lock(&wallet, &spend_point, &view_scalar, 4, 0)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        WalletError::InsufficientFunds { need: 4, have: 3 }
    ));
}

#[tokio::test]
async fn phase14_build_refund_artifact_binds_metadata_and_payload_hash() {
    let wallet = FakeWallet {
        chain: RefundChain::Wow,
        results: Vec::new(),
        timelocked_artifact: Some(([0xAB; 32], b"typed-refund-artifact".to_vec())),
        broadcast_tx_hash: Some([0xAB; 32]),
    };
    let lock_tx_hash = [0x44; 32];
    let destination = "wow-destination";
    let refund_height = 1234;

    let artifact = wallet
        .build_refund_artifact(
            &Scalar::random(&mut OsRng),
            &Scalar::random(&mut OsRng),
            destination,
            refund_height,
            lock_tx_hash,
        )
        .await
        .unwrap();

    assert_eq!(artifact.metadata.chain, RefundChain::Wow);
    assert_eq!(artifact.metadata.lock_tx_hash, lock_tx_hash);
    assert_eq!(artifact.metadata.destination, destination);
    assert_eq!(artifact.metadata.refund_height, refund_height);
    assert_eq!(
        artifact.metadata.payload_hash,
        RefundArtifact::payload_hash(&artifact.tx_bytes)
    );
    assert_eq!(artifact.tx_hash, [0xAB; 32]);
}

#[tokio::test]
async fn phase14_tampered_refund_artifact_is_rejected() {
    let wallet = FakeWallet {
        chain: RefundChain::Xmr,
        results: Vec::new(),
        timelocked_artifact: Some(([0xCD; 32], b"artifact-payload".to_vec())),
        broadcast_tx_hash: Some([0xCD; 32]),
    };
    let base_artifact = wallet
        .build_refund_artifact(
            &Scalar::random(&mut OsRng),
            &Scalar::random(&mut OsRng),
            "xmr-destination",
            777,
            [0x55; 32],
        )
        .await
        .unwrap();

    let mut payload_tampered = base_artifact.clone();
    payload_tampered.tx_bytes.push(0xFF);
    let err = wallet
        .validate_refund_artifact(&payload_tampered)
        .unwrap_err()
        .to_string();
    assert!(err.contains("payload hash mismatch"), "error: {err}");

    let mut metadata_tampered = base_artifact.clone();
    metadata_tampered.metadata.destination = "other-destination".into();
    let err = metadata_tampered
        .validate_binding(RefundChain::Xmr, [0x55; 32], "xmr-destination", 777)
        .unwrap_err()
        .to_string();
    assert!(err.contains("destination mismatch"), "error: {err}");
}

#[tokio::test]
async fn phase14_xmr_and_wow_wallets_share_the_same_artifact_contract() {
    let xmr_wallet = XmrWallet::new("http://127.0.0.1:1");
    let wow_wallet = WowWallet::new("http://127.0.0.1:1");

    let xmr_artifact = RefundArtifact::new(
        RefundChain::Xmr,
        [0x11; 32],
        "xmr-destination",
        100,
        [0x21; 32],
        b"xmr-refund".to_vec(),
    );
    let wow_artifact = RefundArtifact::new(
        RefundChain::Wow,
        [0x12; 32],
        "wow-destination",
        200,
        [0x22; 32],
        b"wow-refund".to_vec(),
    );

    xmr_wallet.validate_refund_artifact(&xmr_artifact).unwrap();
    wow_wallet.validate_refund_artifact(&wow_artifact).unwrap();
    assert_eq!(xmr_wallet.refund_chain(), RefundChain::Xmr);
    assert_eq!(wow_wallet.refund_chain(), RefundChain::Wow);
}

#[tokio::test]
async fn xmr_wallet_methods_are_covered_without_live_daemons() {
    let server = spawn_mock_daemon(MockDaemonState {
        block_count: 15,
        txs: vec![json!({
            "in_pool": false,
            "block_height": 10,
        })],
        send_status: "Failed",
    })
    .await;
    let (spend_point, view_scalar, sender_spend, sender_view) = sample_keys();

    let scan_only = XmrWallet::new(&server.url);
    let err = scan_only
        .lock(&spend_point, &view_scalar, 42)
        .await
        .unwrap_err();
    assert!(matches!(err, WalletError::KeyError(_)));

    let funded =
        XmrWallet::with_sender_keys(&server.url, sender_spend, sender_view).with_scan_from(15);
    let err = funded
        .lock(&spend_point, &view_scalar, 42)
        .await
        .unwrap_err();
    assert!(matches!(err, WalletError::NoOutputsFound));

    let scan_results = funded.scan(&spend_point, &view_scalar, 15).await.unwrap();
    assert!(scan_results.is_empty());

    let sweep_err = funded
        .sweep(&Scalar::random(&mut OsRng), &view_scalar, "unused")
        .await
        .unwrap_err();
    assert!(matches!(sweep_err, WalletError::NoOutputsFound));

    let timelocked_err = funded
        .sweep_timelocked(&Scalar::random(&mut OsRng), &view_scalar, "unused", 99)
        .await
        .unwrap_err();
    assert!(matches!(timelocked_err, WalletError::NoOutputsFound));

    let status = funded.poll_confirmation(&[0x44; 32], 3).await.unwrap();
    assert!(status.confirmed);
    assert_eq!(status.confirmations, 5);
    assert_eq!(status.block_height, Some(10));

    let broadcast_err = funded.broadcast_raw_tx(b"not-a-real-tx").await.unwrap_err();
    assert!(matches!(broadcast_err, WalletError::BroadcastFailed(_)));

    let height = funded.get_current_height().await.unwrap();
    assert_eq!(height, 15);
}

#[tokio::test]
async fn wow_wallet_methods_are_covered_without_live_daemons() {
    let server = spawn_mock_daemon(MockDaemonState {
        block_count: 18,
        txs: vec![json!({
            "in_pool": false,
            "block_height": 14,
        })],
        send_status: "Failed",
    })
    .await;
    let (spend_point, view_scalar, sender_spend, sender_view) = sample_keys();

    let scan_only = WowWallet::new(&server.url);
    let err = scan_only
        .lock(&spend_point, &view_scalar, 42)
        .await
        .unwrap_err();
    assert!(matches!(err, WalletError::KeyError(_)));

    let funded =
        WowWallet::with_sender_keys(&server.url, sender_spend, sender_view).with_scan_from(18);
    let err = funded
        .lock(&spend_point, &view_scalar, 42)
        .await
        .unwrap_err();
    assert!(matches!(err, WalletError::NoOutputsFound));

    let scan_results = funded.scan(&spend_point, &view_scalar, 18).await.unwrap();
    assert!(scan_results.is_empty());

    let sweep_err = funded
        .sweep(&Scalar::random(&mut OsRng), &view_scalar, "unused")
        .await
        .unwrap_err();
    assert!(matches!(sweep_err, WalletError::NoOutputsFound));

    let timelocked_err = funded
        .sweep_timelocked(&Scalar::random(&mut OsRng), &view_scalar, "unused", 99)
        .await
        .unwrap_err();
    assert!(matches!(timelocked_err, WalletError::NoOutputsFound));

    let status = funded.poll_confirmation(&[0x55; 32], 3).await.unwrap();
    assert!(status.confirmed);
    assert_eq!(status.confirmations, 4);
    assert_eq!(status.block_height, Some(14));

    let broadcast_err = funded.broadcast_raw_tx(b"not-a-real-tx").await.unwrap_err();
    assert!(matches!(broadcast_err, WalletError::BroadcastFailed(_)));

    let height = funded.get_current_height().await.unwrap();
    assert_eq!(height, 18);
}

// ----------------------------------------------------------------------------
// Plan 38.1-09 (iteration 7): regression tests for WowWallet::poll_confirmation
// get_transactions response body deserializer. Iteration 6 proved the old
// `resp.json::<Value>()` path returned an opaque reqwest Error::Decode variant
// with zero body visibility, making diagnosis impossible. These tests pin the
// new body-capture-then-parse behavior against a mock daemon.
// ----------------------------------------------------------------------------

/// Mock daemon that lets individual routes return arbitrary (status, content-type, body)
/// tuples so tests can inject non-JSON bodies or wrong content-types into
/// /get_transactions. /json_rpc still returns a valid `get_block_count` so the
/// downstream chain-height query inside `poll_confirmation` works normally.
#[derive(Clone)]
struct RawBodyDaemonState {
    block_count: u64,
    get_transactions_status: StatusCode,
    get_transactions_content_type: &'static str,
    get_transactions_body: &'static str,
}

async fn spawn_mock_daemon_raw_get_transactions(state: RawBodyDaemonState) -> TestServer {
    async fn handle_json_rpc(
        State(state): State<Arc<RawBodyDaemonState>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let result = match method {
            "get_block_count" => json!({ "count": state.block_count }),
            _ => json!({}),
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }))
    }

    async fn handle_raw_get_transactions(
        State(state): State<Arc<RawBodyDaemonState>>,
    ) -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(state.get_transactions_content_type),
        );
        (
            state.get_transactions_status,
            headers,
            state.get_transactions_body,
        )
    }

    let shared = Arc::new(state);
    let app = Router::new()
        .route("/json_rpc", post(handle_json_rpc))
        .route("/get_transactions", post(handle_raw_get_transactions))
        .with_state(shared);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        url: format!("http://{}", addr),
        handle,
    }
}

#[tokio::test]
async fn poll_confirmation_parses_confirmed_tx_response() {
    // Minimal valid wownerod-shaped /get_transactions body: confirmed tx at
    // block_height 3993, current chain tip at 3994 -> 1 confirmation, required
    // 1 -> confirmed=true.
    let server = spawn_mock_daemon(MockDaemonState {
        block_count: 3994,
        txs: vec![json!({
            "tx_hash": "288d815c0a65fb920cdde4d1c41456ceec8e2c58ac41b3c21640703f71f8aede",
            "in_pool": false,
            "block_height": 3993,
            "as_hex": "02000102abcdef",
        })],
        send_status: "OK",
    })
    .await;

    let wallet = WowWallet::new(&server.url);
    let tx_hash = [0x28u8; 32];
    let status = wallet.poll_confirmation(&tx_hash, 1).await.unwrap();

    assert!(
        status.confirmed,
        "confirmed tx should report confirmed=true"
    );
    assert_eq!(status.confirmations, 1, "3994 - 3993 = 1 confirmation");
    assert_eq!(status.block_height, Some(3993));
}

#[tokio::test]
async fn poll_confirmation_tolerates_mempool_only_tx() {
    // Mempool-only tx: in_pool=true and no block_height field. The call should
    // succeed with confirmed=false, confirmations=0, block_height=None so that
    // the client's wait_for_confirmation retry loop keeps polling instead of
    // exhausting retries with a terminal error.
    let server = spawn_mock_daemon(MockDaemonState {
        block_count: 3994,
        txs: vec![json!({
            "tx_hash": "288d815c0a65fb920cdde4d1c41456ceec8e2c58ac41b3c21640703f71f8aede",
            "in_pool": true,
        })],
        send_status: "OK",
    })
    .await;

    let wallet = WowWallet::new(&server.url);
    let tx_hash = [0x28u8; 32];
    let status = wallet.poll_confirmation(&tx_hash, 1).await.unwrap();

    assert!(
        !status.confirmed,
        "mempool-only tx should report confirmed=false"
    );
    assert_eq!(status.confirmations, 0);
    assert_eq!(status.block_height, None);
}

#[tokio::test]
async fn poll_confirmation_surfaces_raw_body_on_parse_failure() {
    // Iteration 7 regression gate for iteration 6's opaque-error defect.
    // Mock daemon returns a non-JSON HTML error body with Content-Type text/html.
    // The pre-fix reqwest `.json()` path refuses to parse this with Error::Decode
    // and no body visibility. The post-fix text-capture path MUST surface the
    // actual body bytes in the RpcRequest error message so iteration 8 diagnosis
    // is trivial if this pattern ever reappears.
    let server = spawn_mock_daemon_raw_get_transactions(RawBodyDaemonState {
        block_count: 3994,
        get_transactions_status: StatusCode::BAD_REQUEST,
        get_transactions_content_type: "text/html",
        get_transactions_body: "<html><body>Bad Request</body></html>",
    })
    .await;

    let wallet = WowWallet::new(&server.url);
    let tx_hash = [0x28u8; 32];
    let err = wallet
        .poll_confirmation(&tx_hash, 1)
        .await
        .expect_err("non-JSON body should produce an error");

    let msg = err.to_string();
    assert!(
        matches!(err, WalletError::RpcRequest(_)),
        "expected RpcRequest variant, got: {err:?}"
    );
    assert!(
        msg.contains("<html>") || msg.contains("Bad Request"),
        "error message must surface the offending body bytes for future diagnosis, got: {msg}"
    );
    assert!(
        msg.contains("parse get_transactions"),
        "error message must identify the failing operation, got: {msg}"
    );
}

#[tokio::test]
async fn poll_confirmation_tolerates_missing_txs_field() {
    // Wownerod error path: JSON body with no `txs` field, e.g. `{"status": "Failed", ...}`.
    // The pre-fix code returned the confusingly-named TxNotFound variant. The
    // post-fix code returns a diagnostic RpcRequest error that names the actual
    // response status. This is NOT a panic and NOT TxNotFound.
    let server = spawn_mock_daemon_raw_get_transactions(RawBodyDaemonState {
        block_count: 3994,
        get_transactions_status: StatusCode::OK,
        get_transactions_content_type: "application/json",
        get_transactions_body: r#"{"status":"Failed","error":"mempool full"}"#,
    })
    .await;

    let wallet = WowWallet::new(&server.url);
    let tx_hash = [0x28u8; 32];
    let err = wallet
        .poll_confirmation(&tx_hash, 1)
        .await
        .expect_err("missing txs field should produce an error");

    assert!(
        matches!(err, WalletError::RpcRequest(_)),
        "expected RpcRequest variant (not TxNotFound), got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("Failed") || msg.contains("txs"),
        "error message must surface the wownerod response status for future diagnosis, got: {msg}"
    );
}

// ----------------------------------------------------------------------------
// Plan 38.1-10 (iteration 8): regression test for non-UTF-8 body bytes.
// Iteration 7 proved reqwest's Response::text() fails on non-UTF-8 content
// from wownerod's /get_transactions (H2 confirmed via diagnostic bisection).
// The body-bytes fix uses resp.bytes() + serde_json::from_slice which
// tolerates non-UTF-8 bytes as long as the JSON portion itself is valid UTF-8.
// This test injects a response body containing a valid JSON object with an
// embedded non-UTF-8 hex blob field (simulating wownerod's as_hex / extra
// fields), verifying poll_confirmation parses it correctly.
// ----------------------------------------------------------------------------

/// Mock daemon that returns raw bytes (including non-UTF-8) for /get_transactions.
/// Uses Bytes response body to bypass axum's String UTF-8 enforcement.
#[derive(Clone)]
struct NonUtf8DaemonState {
    block_count: u64,
    get_transactions_body: Vec<u8>,
}

async fn spawn_mock_daemon_non_utf8(state: NonUtf8DaemonState) -> TestServer {
    async fn handle_json_rpc(
        State(state): State<Arc<NonUtf8DaemonState>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let result = match method {
            "get_block_count" => json!({ "count": state.block_count }),
            _ => json!({}),
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }))
    }

    async fn handle_raw_bytes(State(state): State<Arc<NonUtf8DaemonState>>) -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        (
            StatusCode::OK,
            headers,
            Bytes::from(state.get_transactions_body.clone()),
        )
    }

    let shared = Arc::new(state);
    let app = Router::new()
        .route("/json_rpc", post(handle_json_rpc))
        .route("/get_transactions", post(handle_raw_bytes))
        .with_state(shared);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        url: format!("http://{}", addr),
        handle,
    }
}

#[derive(Clone, Default)]
struct RequestHeaderCapture {
    connection: Arc<Mutex<Option<String>>>,
    accept_encoding: Arc<Mutex<Option<String>>>,
    request_body: Arc<Mutex<Option<Value>>>,
}

#[derive(Clone)]
struct HeaderCaptureDaemonState {
    block_count: u64,
    capture: RequestHeaderCapture,
}

async fn spawn_mock_daemon_header_capture(state: HeaderCaptureDaemonState) -> TestServer {
    async fn handle_json_rpc(
        State(state): State<Arc<HeaderCaptureDaemonState>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let result = match method {
            "get_block_count" => json!({ "count": state.block_count }),
            _ => json!({}),
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }))
    }

    async fn handle_get_transactions(
        State(state): State<Arc<HeaderCaptureDaemonState>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Json<Value> {
        *state.capture.connection.lock().unwrap() = headers
            .get(header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        *state.capture.accept_encoding.lock().unwrap() = headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        *state.capture.request_body.lock().unwrap() = serde_json::from_slice(&body).ok();

        Json(json!({
            "status": "OK",
            "txs": [{
                "in_pool": false,
                "block_height": 100,
            }],
        }))
    }

    let shared = Arc::new(state);
    let app = Router::new()
        .route("/json_rpc", post(handle_json_rpc))
        .route("/get_transactions", post(handle_get_transactions))
        .with_state(shared);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        url: format!("http://{}", addr),
        handle,
    }
}

async fn spawn_manual_chunked_get_transactions_server(block_count: u64) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };

            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let read = socket.read(&mut buf).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }

                let request_text = String::from_utf8_lossy(&request);
                let is_json_rpc = request_text.starts_with("POST /json_rpc ");
                let is_get_transactions = request_text.starts_with("POST /get_transactions ");

                let body = if is_json_rpc {
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"result\":{{\"count\":{}}}}}",
                        block_count
                    )
                } else if is_get_transactions {
                    "{\"status\":\"OK\",\"txs\":[{\"in_pool\":false,\"block_height\":100}]}"
                        .to_string()
                } else {
                    "{\"status\":\"Failed\"}".to_string()
                };

                let response = if is_get_transactions {
                    let split_at = body.len() / 2;
                    let first = &body[..split_at];
                    let second = &body[split_at..];
                    format!(
                        concat!(
                            "HTTP/1.1 200 OK\r\n",
                            "Content-Type: application/json\r\n",
                            "Transfer-Encoding: chunked\r\n",
                            "Connection: close\r\n",
                            "\r\n",
                            "{:X}\r\n{}\r\n",
                            "{:X}\r\n{}\r\n",
                            "0\r\n\r\n"
                        ),
                        first.len(),
                        first,
                        second.len(),
                        second,
                    )
                } else {
                    format!(
                        concat!(
                            "HTTP/1.1 200 OK\r\n",
                            "Content-Type: application/json\r\n",
                            "Content-Length: {}\r\n",
                            "Connection: close\r\n",
                            "\r\n",
                            "{}"
                        ),
                        body.len(),
                        body,
                    )
                };

                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    TestServer {
        url: format!("http://{}", addr),
        handle,
    }
}

#[tokio::test]
async fn poll_confirmation_handles_non_utf8_body_bytes() {
    // Iteration 8 regression gate for iteration 7's H2 diagnosis: wownerod's
    // /get_transactions response body may contain non-UTF-8 bytes (embedded
    // raw hex blobs in as_hex / extra fields). The pre-fix resp.text().await
    // path rejected these entirely. The post-fix resp.bytes().await +
    // serde_json::from_slice path tolerates them because JSON itself is UTF-8
    // but serde_json::from_slice handles the byte buffer directly without a
    // Rust String intermediate. This test constructs a valid JSON response
    // with trailing non-UTF-8 garbage bytes appended AFTER the JSON object -
    // simulating the worst-case scenario where the daemon appends binary
    // framing. The from_slice parser should either parse the valid JSON prefix
    // or return a diagnostic error containing the first 500 bytes.
    //
    // More realistically, the body IS valid JSON (all hex blobs are hex-encoded
    // ASCII strings), but transfer-encoding anomalies can inject non-UTF-8
    // bytes. We test both cases:
    //
    // Case 1: Valid JSON body with non-UTF-8 trailing bytes -> parse error
    //         with diagnostic output (from_slice sees trailing garbage).
    // Case 2: Valid JSON body (no garbage) -> successful parse.

    // Case 1: JSON + trailing non-UTF-8 garbage -> graceful error with diagnostic
    let mut body_with_garbage =
        br#"{"status":"OK","txs":[{"in_pool":false,"block_height":100}]}"#.to_vec();
    body_with_garbage.extend_from_slice(&[0xFF, 0xFE, 0x80, 0x81]); // non-UTF-8 bytes

    let server = spawn_mock_daemon_non_utf8(NonUtf8DaemonState {
        block_count: 105,
        get_transactions_body: body_with_garbage,
    })
    .await;

    let wallet = WowWallet::new(&server.url);
    let tx_hash = [0x28u8; 32];
    let err = wallet
        .poll_confirmation(&tx_hash, 1)
        .await
        .expect_err("JSON with trailing non-UTF-8 garbage should produce a parse error");

    let msg = err.to_string();
    assert!(
        matches!(err, WalletError::RpcRequest(_)),
        "expected RpcRequest variant, got: {err:?}"
    );
    assert!(
        msg.contains("parse get_transactions"),
        "error message must identify the failing operation, got: {msg}"
    );

    // Case 2: Clean valid JSON body (no garbage) -> should parse successfully
    let clean_body = br#"{"status":"OK","txs":[{"in_pool":false,"block_height":100}]}"#.to_vec();

    let server2 = spawn_mock_daemon_non_utf8(NonUtf8DaemonState {
        block_count: 105,
        get_transactions_body: clean_body,
    })
    .await;

    let wallet2 = WowWallet::new(&server2.url);
    let status = wallet2.poll_confirmation(&tx_hash, 1).await.unwrap();
    assert!(
        status.confirmed,
        "clean JSON body should parse and confirm the tx"
    );
    assert_eq!(status.confirmations, 5); // 105 - 100 = 5
    assert_eq!(status.block_height, Some(100));
}

#[tokio::test]
async fn poll_confirmation_uses_identity_encoded_single_request_headers() {
    let capture = RequestHeaderCapture::default();
    let server = spawn_mock_daemon_header_capture(HeaderCaptureDaemonState {
        block_count: 105,
        capture: capture.clone(),
    })
    .await;

    let wallet = WowWallet::new(&server.url);
    let status = wallet.poll_confirmation(&[0x44; 32], 1).await.unwrap();

    assert!(
        status.confirmed,
        "captured-header daemon should still confirm"
    );
    assert_eq!(status.confirmations, 5);
    assert_eq!(status.block_height, Some(100));
    assert_eq!(
        capture.connection.lock().unwrap().as_deref(),
        Some("close"),
        "poll_confirmation must disable connection reuse for /get_transactions"
    );
    assert_eq!(
        capture.accept_encoding.lock().unwrap().as_deref(),
        Some("identity"),
        "poll_confirmation must request an identity-encoded body"
    );
}

#[tokio::test]
async fn poll_confirmation_requests_pruned_binary_get_transactions() {
    let capture = RequestHeaderCapture::default();
    let server = spawn_mock_daemon_header_capture(HeaderCaptureDaemonState {
        block_count: 105,
        capture: capture.clone(),
    })
    .await;

    let wallet = WowWallet::new(&server.url);
    let status = wallet.poll_confirmation(&[0x46; 32], 1).await.unwrap();

    assert!(
        status.confirmed,
        "captured-body daemon should still confirm"
    );

    let body = capture
        .request_body
        .lock()
        .unwrap()
        .clone()
        .expect("request body should be captured");
    assert_eq!(
        body.get("decode_as_json").and_then(Value::as_bool),
        Some(false),
        "poll_confirmation must avoid decoded tx JSON to keep the response small"
    );
    assert_eq!(
        body.get("prune").and_then(Value::as_bool),
        Some(true),
        "poll_confirmation must request pruned transaction data"
    );
}

#[tokio::test]
async fn poll_confirmation_handles_chunked_get_transactions_response() {
    let server = spawn_manual_chunked_get_transactions_server(105).await;
    let wallet = WowWallet::new(&server.url);

    let status = wallet.poll_confirmation(&[0x45; 32], 1).await.unwrap();
    assert!(status.confirmed, "chunked response should still confirm");
    assert_eq!(status.confirmations, 5);
    assert_eq!(status.block_height, Some(100));
}

#[tokio::test]
async fn phase16_xmr_wallet_refund_artifact_round_trip_on_simnet() {
    let testbed = SimnetTestbed::new().await.unwrap();
    let sender = SimnetWallet::generate();
    let destination = SimnetWallet::generate();
    let (joint_spend_secret, joint_spend_point, joint_view_scalar) = sample_joint_keys();
    let lock_amount = 500_000_000_000u64;

    {
        let mut node = testbed.xmr_node().lock().await;
        node.mine_to(&sender.spend_pub, &sender.view_scalar, 2)
            .await
            .unwrap();
        node.mine_blocks(66).await.unwrap();
    }

    let xmr_wallet = XmrWallet::with_sender_keys(
        testbed.xmr_rpc_url(),
        *sender.spend_scalar,
        *sender.view_scalar,
    );
    let lock_tx_hash = xmr_wallet
        .lock(&joint_spend_point, &joint_view_scalar, lock_amount)
        .await
        .unwrap();
    testbed.mine_xmr(1).await.unwrap();

    let refund_height = testbed.xmr_height().await.unwrap() + 5;
    let sweep_wallet = XmrWallet::new(testbed.xmr_rpc_url());
    let destination_addr = destination
        .address(monero_wallet::address::Network::Mainnet)
        .to_string();
    let artifact = sweep_wallet
        .build_refund_artifact(
            &joint_spend_secret,
            &joint_view_scalar,
            &destination_addr,
            refund_height,
            lock_tx_hash,
        )
        .await
        .unwrap();
    sweep_wallet.validate_refund_artifact(&artifact).unwrap();

    let premature = sweep_wallet
        .broadcast_refund_artifact(&artifact)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        premature.contains("unlock_time") || premature.contains("not yet satisfied"),
        "premature error: {premature}"
    );

    testbed.mine_xmr(5).await.unwrap();
    let refund_tx_hash = sweep_wallet
        .broadcast_refund_artifact(&artifact)
        .await
        .unwrap();
    assert_eq!(refund_tx_hash, artifact.tx_hash);

    testbed.mine_xmr(1).await.unwrap();
    let status = sweep_wallet
        .poll_confirmation(&refund_tx_hash, 1)
        .await
        .unwrap();
    assert!(status.confirmed, "refund tx should confirm after mining");

    let verified = verify_lock(
        &XmrWallet::new(testbed.xmr_rpc_url()),
        &destination.spend_pub,
        &destination.view_scalar,
        1,
        0,
    )
    .await
    .unwrap();
    assert_eq!(verified.tx_hash, refund_tx_hash);
}

#[tokio::test]
async fn phase16_wow_wallet_refund_artifact_round_trip_on_simnet() {
    let testbed = SimnetTestbed::new().await.unwrap();
    let sender = WowSimnetWallet::generate();
    let destination = WowSimnetWallet::generate();
    let (joint_spend_secret, joint_spend_point, joint_view_scalar) = sample_joint_keys();
    let lock_amount = 500_000_000_000u64;

    {
        let mut node = testbed.wow_node().lock().await;
        node.mine_to(&sender.spend_pub, &sender.view_scalar, 2)
            .await
            .unwrap();
        node.mine_blocks(100).await.unwrap();
    }

    let wow_wallet = WowWallet::with_sender_keys(
        testbed.wow_rpc_url(),
        *sender.spend_scalar,
        *sender.view_scalar,
    );
    let lock_tx_hash = wow_wallet
        .lock(&joint_spend_point, &joint_view_scalar, lock_amount)
        .await
        .unwrap();
    testbed.mine_wow(1).await.unwrap();

    let refund_height = testbed.wow_height().await.unwrap() + 5;
    let sweep_wallet = WowWallet::new(testbed.wow_rpc_url());
    let destination_addr = destination
        .address(wownero_wallet::address::Network::Mainnet)
        .to_string();
    let artifact = sweep_wallet
        .build_refund_artifact(
            &joint_spend_secret,
            &joint_view_scalar,
            &destination_addr,
            refund_height,
            lock_tx_hash,
        )
        .await
        .unwrap();
    sweep_wallet.validate_refund_artifact(&artifact).unwrap();

    let premature = sweep_wallet
        .broadcast_refund_artifact(&artifact)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        premature.contains("unlock_time") || premature.contains("not yet satisfied"),
        "premature error: {premature}"
    );

    testbed.mine_wow(5).await.unwrap();
    let refund_tx_hash = sweep_wallet
        .broadcast_refund_artifact(&artifact)
        .await
        .unwrap();
    assert_eq!(refund_tx_hash, artifact.tx_hash);

    testbed.mine_wow(1).await.unwrap();
    let status = sweep_wallet
        .poll_confirmation(&refund_tx_hash, 1)
        .await
        .unwrap();
    assert!(status.confirmed, "refund tx should confirm after mining");

    let verified = verify_lock(
        &WowWallet::new(testbed.wow_rpc_url()),
        &destination.spend_pub,
        &destination.view_scalar,
        1,
        0,
    )
    .await
    .unwrap();
    assert_eq!(verified.tx_hash, refund_tx_hash);
}
