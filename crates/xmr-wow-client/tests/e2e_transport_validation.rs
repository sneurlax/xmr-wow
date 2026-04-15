use std::sync::{Arc, Mutex};

use rand::rngs::OsRng;
use tokio::{net::TcpListener, task::JoinHandle};
use xmr_wow_client::{
    node_client::NodeClient, unwrap_protocol_message, wrap_protocol_message, OobMessenger,
    ProtocolMessage, SharechainMessenger, SwapMessenger, SwapStore,
};
use xmr_wow_crypto::{AdaptorSignature, CompletedSignature, DleqProof, KeyContribution};
use xmr_wow_sharechain::{merge_mining_router, Difficulty, SwapChain};

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

fn make_test_messages(_swap_id: [u8; 32]) -> Vec<ProtocolMessage> {
    let contrib_alice = KeyContribution::generate(&mut OsRng);
    let proof_alice = DleqProof::prove(
        &contrib_alice.secret,
        &contrib_alice.public,
        b"xmr-wow-swap-v1",
        &mut OsRng,
    );
    let init = ProtocolMessage::Init {
        pubkey: contrib_alice.public_bytes(),
        proof: proof_alice,
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_height: 2000,
        wow_refund_height: 1000,
        refund_timing: None,
        alice_refund_address: None,
    };

    let contrib_bob = KeyContribution::generate(&mut OsRng);
    let proof_bob = DleqProof::prove(
        &contrib_bob.secret,
        &contrib_bob.public,
        b"xmr-wow-swap-v1",
        &mut OsRng,
    );
    let response = ProtocolMessage::Response {
        pubkey: contrib_bob.public_bytes(),
        proof: proof_bob,
        bob_refund_address: None,
    };

    let adaptor_pre_sig = ProtocolMessage::AdaptorPreSig {
        pre_sig: AdaptorSignature {
            r_plus_t: [0xAA; 32],
            s_prime: [0xBB; 32],
        },
    };

    let claim_proof = ProtocolMessage::ClaimProof {
        completed_sig: CompletedSignature {
            r_t: [0xCC; 32],
            s: [0xDD; 32],
        },
    };

    vec![init, response, adaptor_pre_sig, claim_proof]
}

// SharechainMessenger::send is used on the send side; NodeClient on the receive side
// to track cursor position (SharechainMessenger::receive always polls from index 0).
#[tokio::test]
async fn sharechain_transport_full_message_flow() {
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let server = spawn_rpc_server(chain).await;

    let swap_id = [0x42u8; 32];
    let msgs = make_test_messages(swap_id);
    assert_eq!(
        msgs.len(),
        4,
        "make_test_messages must return exactly 4 variants"
    );

    let alice_store = Arc::new(Mutex::new(SwapStore::open_in_memory().unwrap()));
    let bob_store = Arc::new(Mutex::new(SwapStore::open_in_memory().unwrap()));
    let alice_messenger = SharechainMessenger {
        node_url: server.url.clone(),
        store: alice_store,
    };
    let bob_messenger = SharechainMessenger {
        node_url: server.url.clone(),
        store: bob_store,
    };
    let alice_client = NodeClient::new(&server.url);
    let bob_client = NodeClient::new(&server.url);

    let init_coord = wrap_protocol_message(swap_id, &msgs[0]).expect("wrap Init");
    alice_messenger
        .send(init_coord)
        .await
        .expect("Alice sends Init");

    let (raw_msgs, next_idx) = bob_client.poll_coord_messages(&swap_id, 0).await.unwrap();
    assert_eq!(raw_msgs.len(), 1, "Bob should see 1 message after Init");
    assert_eq!(next_idx, 1, "next_index after 1 message is 1");
    let coord = serde_json::from_slice::<xmr_wow_client::CoordMessage>(&raw_msgs[0]).unwrap();
    let recovered = unwrap_protocol_message(&coord).expect("unwrap Init");
    assert!(
        matches!(recovered, ProtocolMessage::Init { .. }),
        "recovered message must be Init, got variant type mismatch"
    );

    let response_coord = wrap_protocol_message(swap_id, &msgs[1]).expect("wrap Response");
    bob_messenger
        .send(response_coord)
        .await
        .expect("Bob sends Response");

    let (raw_msgs, next_idx) = alice_client.poll_coord_messages(&swap_id, 1).await.unwrap();
    assert_eq!(
        raw_msgs.len(),
        1,
        "Alice should see 1 new message (Response)"
    );
    assert_eq!(next_idx, 2, "next_index after 2 messages is 2");
    let coord = serde_json::from_slice::<xmr_wow_client::CoordMessage>(&raw_msgs[0]).unwrap();
    let recovered = unwrap_protocol_message(&coord).expect("unwrap Response");
    assert!(
        matches!(recovered, ProtocolMessage::Response { .. }),
        "recovered message must be Response"
    );

    let adaptor_coord = wrap_protocol_message(swap_id, &msgs[2]).expect("wrap AdaptorPreSig");
    alice_messenger
        .send(adaptor_coord)
        .await
        .expect("Alice sends AdaptorPreSig");

    let (raw_msgs, next_idx) = bob_client.poll_coord_messages(&swap_id, 2).await.unwrap();
    assert_eq!(
        raw_msgs.len(),
        1,
        "Bob should see 1 new message (AdaptorPreSig)"
    );
    assert_eq!(next_idx, 3, "next_index after 3 messages is 3");
    let coord = serde_json::from_slice::<xmr_wow_client::CoordMessage>(&raw_msgs[0]).unwrap();
    let recovered = unwrap_protocol_message(&coord).expect("unwrap AdaptorPreSig");
    assert!(
        matches!(recovered, ProtocolMessage::AdaptorPreSig { .. }),
        "recovered message must be AdaptorPreSig"
    );

    let claim_coord = wrap_protocol_message(swap_id, &msgs[3]).expect("wrap ClaimProof");
    bob_messenger
        .send(claim_coord)
        .await
        .expect("Bob sends ClaimProof");

    let (raw_msgs, next_idx) = alice_client.poll_coord_messages(&swap_id, 3).await.unwrap();
    assert_eq!(
        raw_msgs.len(),
        1,
        "Alice should see 1 new message (ClaimProof)"
    );
    assert_eq!(next_idx, 4, "next_index after 4 messages is 4");
    let coord = serde_json::from_slice::<xmr_wow_client::CoordMessage>(&raw_msgs[0]).unwrap();
    let recovered = unwrap_protocol_message(&coord).expect("unwrap ClaimProof");
    assert!(
        matches!(recovered, ProtocolMessage::ClaimProof { .. }),
        "recovered message must be ClaimProof"
    );

    let (all_msgs, final_idx) = alice_client.poll_coord_messages(&swap_id, 0).await.unwrap();
    assert_eq!(
        all_msgs.len(),
        4,
        "full replay from index 0 must return all 4 messages"
    );
    assert_eq!(final_idx, 4, "final next_index must be 4");

    let expected_variants = ["Init", "Response", "AdaptorPreSig", "ClaimProof"];
    for (i, raw) in all_msgs.iter().enumerate() {
        let coord = serde_json::from_slice::<xmr_wow_client::CoordMessage>(raw).unwrap();
        let msg = unwrap_protocol_message(&coord).unwrap();
        let variant = match msg {
            ProtocolMessage::Init { .. } => "Init",
            ProtocolMessage::Response { .. } => "Response",
            ProtocolMessage::AdaptorPreSig { .. } => "AdaptorPreSig",
            ProtocolMessage::ClaimProof { .. } => "ClaimProof",
            ProtocolMessage::RefundCooperate { .. } => "RefundCooperate",
        };
        assert_eq!(
            variant, expected_variants[i],
            "replay message {} must be {}",
            i, expected_variants[i]
        );
    }
}

// OobMessenger, CoordMessage, wrap/unwrap, encode/decode: no SharechainMessenger
// or NodeClient in the call path.
#[test]
fn oob_transport_full_message_flow_no_sharechain() {
    use xmr_wow_client::{decode_message, encode_message};

    // ZST means no sharechain connection state can exist.
    assert_eq!(
        std::mem::size_of::<OobMessenger>(),
        0,
        "OobMessenger must be a ZST: no sharechain fields allowed"
    );

    let swap_id = [0xBBu8; 32];
    let msgs = make_test_messages(swap_id);

    let expected_variants = ["Init", "Response", "AdaptorPreSig", "ClaimProof"];

    for (i, msg) in msgs.iter().enumerate() {
        let coord =
            wrap_protocol_message(swap_id, msg).expect("wrap_protocol_message must succeed");

        let encoded_inner = encode_message(msg);
        assert!(
            encoded_inner.starts_with("xmrwow1:"),
            "encoded message must have xmrwow1: prefix"
        );

        let json_bytes = serde_json::to_vec(&coord).expect("CoordMessage must serialize to JSON");
        assert!(
            !json_bytes.is_empty(),
            "serialized CoordMessage must not be empty"
        );

        let deserialized: xmr_wow_client::CoordMessage =
            serde_json::from_slice(&json_bytes).expect("CoordMessage must deserialize from JSON");

        assert_eq!(
            deserialized.swap_id, swap_id,
            "swap_id must survive OOB round-trip for message {}",
            i
        );

        let recovered =
            unwrap_protocol_message(&deserialized).expect("unwrap_protocol_message must succeed");

        let variant = match &recovered {
            ProtocolMessage::Init { .. } => "Init",
            ProtocolMessage::Response { .. } => "Response",
            ProtocolMessage::AdaptorPreSig { .. } => "AdaptorPreSig",
            ProtocolMessage::ClaimProof { .. } => "ClaimProof",
            ProtocolMessage::RefundCooperate { .. } => "RefundCooperate",
        };
        assert_eq!(
            variant, expected_variants[i],
            "OOB recovered variant must match original for message index {}",
            i
        );

        let decoded: ProtocolMessage = decode_message(&encoded_inner)
            .expect("decode_message must succeed on xmrwow1: encoded string");
        let decoded_variant = match &decoded {
            ProtocolMessage::Init { .. } => "Init",
            ProtocolMessage::Response { .. } => "Response",
            ProtocolMessage::AdaptorPreSig { .. } => "AdaptorPreSig",
            ProtocolMessage::ClaimProof { .. } => "ClaimProof",
            ProtocolMessage::RefundCooperate { .. } => "RefundCooperate",
        };
        assert_eq!(
            decoded_variant, expected_variants[i],
            "encode/decode round-trip must preserve variant for message index {}",
            i
        );
    }

    assert_eq!(
        msgs.len(),
        4,
        "all four ProtocolMessage variants must be covered"
    );
}
