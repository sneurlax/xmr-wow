use std::sync::Arc;

use tokio::{net::TcpListener, task::JoinHandle};
use xmr_wow_client::node_client::NodeClient;
use xmr_wow_sharechain::{merge_mining_router, Difficulty, EscrowCommitment, EscrowOp, SwapChain};

struct TestServer {
    url: String,
    handle: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn_rpc_server(chain: Arc<SwapChain>) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = merge_mining_router(chain);
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    TestServer {
        url: format!("http://{}", addr),
        handle,
    }
}

fn sample_open_op(swap_id: [u8; 32]) -> EscrowOp {
    EscrowOp::Open(EscrowCommitment {
        swap_id,
        alice_sc_pubkey: [0xA1; 32],
        bob_sc_pubkey: [0xB2; 32],
        k_b_expected: [0xC3; 32],
        k_b_prime: [0xD4; 32],
        claim_timelock: 100,
        refund_timelock: 200,
        amount: 12345,
    })
}

#[tokio::test]
async fn node_client_coord_message_round_trip() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let server = spawn_rpc_server(chain).await;
    let client = NodeClient::new(&server.url);
    let swap_id = [0x22u8; 32];

    let idx0 = client
        .publish_coord_message(&swap_id, vec![1])
        .await
        .unwrap();
    assert_eq!(idx0, 0, "first message index must be 0");

    let idx1 = client
        .publish_coord_message(&swap_id, vec![2])
        .await
        .unwrap();
    assert_eq!(idx1, 1, "second message index must be 1");

    let idx2 = client
        .publish_coord_message(&swap_id, vec![3])
        .await
        .unwrap();
    assert_eq!(idx2, 2, "third message index must be 2");

    let (msgs, next) = client.poll_coord_messages(&swap_id, 0).await.unwrap();
    assert_eq!(msgs.len(), 3, "poll from 0 must return all 3 messages");
    assert_eq!(next, 3, "next_index must be 3");

    let (msgs2, next2) = client.poll_coord_messages(&swap_id, 2).await.unwrap();
    assert_eq!(msgs2.len(), 1, "poll from 2 must return 1 message");
    assert_eq!(msgs2[0], vec![3u8], "last message payload must be [3]");
    assert_eq!(next2, 3, "next_index must still be 3");

    let (msgs3, next3) = client.poll_coord_messages(&swap_id, 3).await.unwrap();
    assert_eq!(msgs3.len(), 0, "poll beyond end must return empty");
    assert_eq!(next3, 3, "next_index at end must be 3");

    let replayed = client.replay_coord_messages(&swap_id).await.unwrap();
    assert_eq!(replayed.len(), 3, "replay must return all 3 messages");
    assert_eq!(replayed[0], vec![1u8]);
    assert_eq!(replayed[1], vec![2u8]);
    assert_eq!(replayed[2], vec![3u8]);
}

#[tokio::test]
async fn node_client_round_trips_against_sharechain_rpc() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let server = spawn_rpc_server(chain).await;
    let client = NodeClient::new(&server.url);
    let swap_id = [0x11; 32];

    let height = client.get_chain_height().await.unwrap();
    assert_eq!(height, 0);

    let missing = client
        .get_swap_status(&swap_id)
        .await
        .unwrap_err()
        .to_string();
    assert!(missing.contains("swap not found"));

    client
        .submit_escrow_op(&sample_open_op(swap_id))
        .await
        .unwrap();

    let status = client.get_swap_status(&swap_id).await.unwrap();
    assert_eq!(status.state, "Open");
    assert_eq!(status.k_b, None);

    let claim = EscrowOp::Claim {
        swap_id,
        k_b: [0xC3; 32],
    };
    client.submit_escrow_op(&claim).await.unwrap();

    let claimed = client.get_swap_status(&swap_id).await.unwrap();
    let expected_k_b = hex::encode([0xC3; 32]);
    assert_eq!(claimed.state, "Claimed");
    assert_eq!(claimed.k_b.as_deref(), Some(expected_k_b.as_str()));
}
