use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    routing::post,
    Json, Router,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::EdwardsPoint,
    scalar::Scalar,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use tokio::{net::TcpListener, task::JoinHandle};
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
        let method = body.get("method").and_then(Value::as_str).unwrap_or_default();
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
        State(state): State<Arc<MockDaemonState>>,
    ) -> Json<Value> {
        Json(json!({
            "status": "OK",
            "txs": state.txs,
        }))
    }

    async fn handle_sendrawtransaction(
        State(state): State<Arc<MockDaemonState>>,
    ) -> Json<Value> {
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

    let truncated = monero_daemon_rpc::HttpTransport::post(
        &transport,
        "bytes",
        b"ignored".to_vec(),
        Some(4),
    )
    .await
    .unwrap();
    assert_eq!(truncated, b"abcd");

    let full = wownero_daemon_rpc::HttpTransport::post(
        &transport,
        "bytes",
        b"ignored".to_vec(),
        None,
    )
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

    let result = verify_lock(&wallet, &spend_point, &view_scalar, 10, 0).await.unwrap();
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

    let err = verify_lock(&wallet, &spend_point, &view_scalar, 4, 0).await.unwrap_err();
    assert!(matches!(err, WalletError::InsufficientFunds { need: 4, have: 3 }));
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
    let err = scan_only.lock(&spend_point, &view_scalar, 42).await.unwrap_err();
    assert!(matches!(err, WalletError::KeyError(_)));

    let funded = XmrWallet::with_sender_keys(&server.url, sender_spend, sender_view)
        .with_scan_from(15);
    let err = funded.lock(&spend_point, &view_scalar, 42).await.unwrap_err();
    assert!(matches!(err, WalletError::NoOutputsFound));

    let scan_results = funded.scan(&spend_point, &view_scalar, 15).await.unwrap();
    assert!(scan_results.is_empty());

    let sweep_err = funded.sweep(&Scalar::random(&mut OsRng), &view_scalar, "unused").await.unwrap_err();
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
    let err = scan_only.lock(&spend_point, &view_scalar, 42).await.unwrap_err();
    assert!(matches!(err, WalletError::KeyError(_)));

    let funded = WowWallet::with_sender_keys(&server.url, sender_spend, sender_view)
        .with_scan_from(18);
    let err = funded.lock(&spend_point, &view_scalar, 42).await.unwrap_err();
    assert!(matches!(err, WalletError::NoOutputsFound));

    let scan_results = funded.scan(&spend_point, &view_scalar, 18).await.unwrap();
    assert!(scan_results.is_empty());

    let sweep_err = funded.sweep(&Scalar::random(&mut OsRng), &view_scalar, "unused").await.unwrap_err();
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
