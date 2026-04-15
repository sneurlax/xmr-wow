use std::sync::{Arc, Mutex};

use rand::rngs::OsRng;
use tokio::{net::TcpListener, task::JoinHandle};
use xmr_wow_client::{
    build_observed_refund_timing, unwrap_protocol_message, wrap_protocol_message, ProtocolMessage,
    SharechainMessenger, SwapMessenger, SwapParams, SwapRole, SwapState, SwapStore,
};
use xmr_wow_crypto::keccak256;
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

fn sample_params() -> SwapParams {
    let (refund_timing, xmr_refund_height, wow_refund_height) =
        build_observed_refund_timing(100, 200, 500, 800).unwrap();
    SwapParams {
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_height,
        wow_refund_height,
        refund_timing: Some(refund_timing),
        alice_refund_address: Some("alice-refund-addr".into()),
        bob_refund_address: Some("bob-refund-addr".into()),
    }
}

/// Receive exactly the next pending message. Panics if no message is available.
async fn receive_next(messenger: &SharechainMessenger, coord_id: &[u8; 32]) -> ProtocolMessage {
    let coord = messenger
        .receive(coord_id)
        .await
        .expect("receive must not error")
        .expect("a message must be available");
    unwrap_protocol_message(&coord).expect("unwrap_protocol_message must succeed")
}

/// Full sharechain swap integration test: both Alice and Bob reach SwapState::Complete
/// with all coordination messages routed through an in-process axum sharechain node.
///
/// This satisfies TEST-01: proves sharechain transport works end-to-end in automated
/// tests without external daemons.
///
/// Design: Two unidirectional channels avoid self-message cursor issues.
///   alice_channel = keccak256(alice_pub): Alice sends here; Bob receives from here.
///   bob_channel   = keccak256(bob_pub):   Bob sends here; Alice receives from here.
///
/// Each party only polls their counterparty's channel, so they never see their own
/// messages. The SharechainMessenger cursor advances cleanly.
///
/// Message flow:
///   alice_channel@0: Init (alice_pubkey, alice_proof, params)
///   bob_channel@0:   Response (bob_pubkey, bob_proof)
///   alice_channel@1: AdaptorPreSig (alice_pre_sig)
///   bob_channel@1:   AdaptorPreSig (bob_pre_sig)
///   bob_channel@2:   ClaimProof (bob_completed_sig)
///   alice_channel@2: ClaimProof (alice_completed_sig)
#[tokio::test]
async fn sharechain_transport_full_swap_init_through_claim() {
    // 1. Spawn in-process sharechain node 
    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(1)));
    let server = spawn_rpc_server(chain).await;

    // 2. Key generation 
    let params = sample_params();
    let params_for_init = params.clone();
    let (alice, _alice_secret) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, bob_secret) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);

    // Extract pubkeys and proofs before consuming states.
    let (alice_pub, alice_proof) = match &alice {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        _ => panic!("expected Alice in KeyGeneration"),
    };
    let (bob_pub, bob_proof) = match &bob {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        _ => panic!("expected Bob in KeyGeneration"),
    };

    // 3. Two-channel routing: alice_channel and bob_channel 
    // Alice sends to alice_channel; Bob receives from alice_channel.
    // Bob sends to bob_channel; Alice receives from bob_channel.
    // coord_id for sharechain routing is keccak256(alice_pubkey).
    let alice_channel = keccak256(&alice_pub);
    let bob_channel = keccak256(&bob_pub);

    // 4. Create SharechainMessengers 
    // alice_sender: Alice uses this to send to alice_channel.
    // bob_reader:   Bob uses this to receive from alice_channel.
    // bob_sender:   Bob uses this to send to bob_channel.
    // alice_reader: Alice uses this to receive from bob_channel.
    let alice_sender_store = Arc::new(Mutex::new(SwapStore::open_in_memory().unwrap()));
    let bob_reader_store = Arc::new(Mutex::new(SwapStore::open_in_memory().unwrap()));
    let bob_sender_store = Arc::new(Mutex::new(SwapStore::open_in_memory().unwrap()));
    let alice_reader_store = Arc::new(Mutex::new(SwapStore::open_in_memory().unwrap()));

    let alice_sender = SharechainMessenger {
        node_url: server.url.clone(),
        store: alice_sender_store,
    };
    let bob_reader = SharechainMessenger {
        node_url: server.url.clone(),
        store: bob_reader_store,
    };
    let bob_sender = SharechainMessenger {
        node_url: server.url.clone(),
        store: bob_sender_store,
    };
    let alice_reader = SharechainMessenger {
        node_url: server.url.clone(),
        store: alice_reader_store,
    };

    // 5. Alice sends Init; Bob receives.
    let init_msg = ProtocolMessage::Init {
        pubkey: alice_pub,
        proof: alice_proof.clone(),
        amount_xmr: params_for_init.amount_xmr,
        amount_wow: params_for_init.amount_wow,
        xmr_refund_height: params_for_init.xmr_refund_height,
        wow_refund_height: params_for_init.wow_refund_height,
        refund_timing: params_for_init.refund_timing.clone(),
        alice_refund_address: params_for_init.alice_refund_address.clone(),
    };
    let init_coord = wrap_protocol_message(alice_channel, &init_msg).unwrap();
    alice_sender
        .send(init_coord)
        .await
        .expect("Alice sends Init");

    let bob_init = receive_next(&bob_reader, &alice_channel).await;
    let (received_alice_pub, received_alice_proof) = match bob_init {
        ProtocolMessage::Init { pubkey, proof, .. } => (pubkey, proof),
        other => panic!(
            "Bob expected Init, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    assert_eq!(
        received_alice_pub, alice_pub,
        "Bob must receive Alice's pubkey via sharechain"
    );

    // 6. Bob sends Response; Alice receives.
    let response_msg = ProtocolMessage::Response {
        pubkey: bob_pub,
        proof: bob_proof.clone(),
        bob_refund_address: None,
    };
    let response_coord = wrap_protocol_message(bob_channel, &response_msg).unwrap();
    bob_sender
        .send(response_coord)
        .await
        .expect("Bob sends Response");

    let alice_response = receive_next(&alice_reader, &bob_channel).await;
    let received_bob_pub = match alice_response {
        ProtocolMessage::Response { pubkey, .. } => pubkey,
        other => panic!(
            "Alice expected Response, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    assert_eq!(
        received_bob_pub, bob_pub,
        "Alice must receive Bob's pubkey via sharechain"
    );

    // 7. Both advance to JointAddress 
    let bob_joint = bob
        .receive_counterparty_key(received_alice_pub, &received_alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    let alice_joint = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    // 8. Assert swap_id agreement 
    let alice_swap_id = match &alice_joint {
        SwapState::JointAddress { addresses, .. } => addresses.swap_id,
        _ => panic!("expected Alice in JointAddress"),
    };
    let bob_swap_id = match &bob_joint {
        SwapState::JointAddress { addresses, .. } => addresses.swap_id,
        _ => panic!("expected Bob in JointAddress"),
    };
    assert_eq!(
        alice_swap_id, bob_swap_id,
        "Alice and Bob must agree on swap_id"
    );

    // 9. Lock funds 
    // Bob locks WOW first (WOW-first lock order).
    let bob_wow_locked = bob_joint.record_wow_lock([0xBB; 32]).unwrap();
    // Alice locks XMR from JointAddress.
    let alice_xmr_locked = alice_joint.record_xmr_lock([0xAA; 32]).unwrap();

    // Extract adaptor pre-sigs from locked states.
    let alice_pre_sig = match &alice_xmr_locked {
        SwapState::XmrLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected Alice in XmrLocked"),
    };
    let bob_pre_sig = match &bob_wow_locked {
        SwapState::WowLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected Bob in WowLocked"),
    };

    // 10. Alice sends her AdaptorPreSig; Bob receives.
    let alice_presig_msg = ProtocolMessage::AdaptorPreSig {
        pre_sig: alice_pre_sig,
    };
    let alice_presig_coord = wrap_protocol_message(alice_channel, &alice_presig_msg).unwrap();
    alice_sender
        .send(alice_presig_coord)
        .await
        .expect("Alice sends AdaptorPreSig");

    let bob_got_alice_presig = receive_next(&bob_reader, &alice_channel).await;
    let alice_pre_sig_for_bob = match bob_got_alice_presig {
        ProtocolMessage::AdaptorPreSig { pre_sig } => pre_sig,
        other => panic!(
            "Bob expected AdaptorPreSig, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    // 11. Bob sends his AdaptorPreSig; Alice receives.
    let bob_presig_msg = ProtocolMessage::AdaptorPreSig {
        pre_sig: bob_pre_sig,
    };
    let bob_presig_coord = wrap_protocol_message(bob_channel, &bob_presig_msg).unwrap();
    bob_sender
        .send(bob_presig_coord)
        .await
        .expect("Bob sends AdaptorPreSig");

    let alice_got_bob_presig = receive_next(&alice_reader, &bob_channel).await;
    let bob_pre_sig_for_alice = match alice_got_bob_presig {
        ProtocolMessage::AdaptorPreSig { pre_sig } => pre_sig,
        other => panic!(
            "Alice expected AdaptorPreSig, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    // 12. Apply counterparty pre-sigs 
    let bob_with_presig = bob_wow_locked
        .receive_counterparty_pre_sig(alice_pre_sig_for_bob)
        .expect("Bob must accept Alice's pre-sig");

    let alice_with_presig = alice_xmr_locked
        .receive_counterparty_pre_sig(bob_pre_sig_for_alice)
        .expect("Alice must accept Bob's pre-sig");

    // 13. Bob sends ClaimProof; Alice receives and completes.
    let bob_secret_scalar = curve25519_dalek::scalar::Scalar::from_canonical_bytes(bob_secret)
        .into_option()
        .expect("Bob's secret must be a valid scalar");

    let bob_own_pre_sig = match &bob_with_presig {
        SwapState::WowLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected Bob in WowLocked"),
    };
    let bob_completed_sig = bob_own_pre_sig
        .complete(&bob_secret_scalar)
        .expect("Bob must complete his pre-sig");

    let bob_claim_msg = ProtocolMessage::ClaimProof {
        completed_sig: bob_completed_sig,
    };
    let bob_claim_coord = wrap_protocol_message(bob_channel, &bob_claim_msg).unwrap();
    bob_sender
        .send(bob_claim_coord)
        .await
        .expect("Bob sends ClaimProof");

    // Extract Alice's data before consuming alice_with_presig.
    let alice_own_pre_sig = match &alice_with_presig {
        SwapState::XmrLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected Alice in XmrLocked"),
    };
    let alice_secret_scalar = {
        let secret_bytes = match &alice_with_presig {
            SwapState::XmrLocked { secret_bytes, .. } => *secret_bytes,
            _ => panic!("expected XmrLocked"),
        };
        curve25519_dalek::scalar::Scalar::from_canonical_bytes(secret_bytes)
            .into_option()
            .expect("Alice's secret must be a valid scalar")
    };

    let alice_got_claim = receive_next(&alice_reader, &bob_channel).await;
    let bob_completed_sig_for_alice = match alice_got_claim {
        ProtocolMessage::ClaimProof { completed_sig } => completed_sig,
        other => panic!(
            "Alice expected ClaimProof, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    // Alice extracts Bob's secret and reaches Complete.
    let (alice_complete, _bob_secret_extracted) = alice_with_presig
        .complete_with_adaptor_claim(&bob_completed_sig_for_alice)
        .expect("Alice must complete with adaptor claim");

    assert!(
        matches!(alice_complete, SwapState::Complete { .. }),
        "Alice must reach Complete state"
    );

    // 14. Alice sends ClaimProof; Bob receives and completes.
    let alice_completed_sig = alice_own_pre_sig
        .complete(&alice_secret_scalar)
        .expect("Alice must complete her pre-sig");

    let alice_claim_msg = ProtocolMessage::ClaimProof {
        completed_sig: alice_completed_sig,
    };
    let alice_claim_coord = wrap_protocol_message(alice_channel, &alice_claim_msg).unwrap();
    alice_sender
        .send(alice_claim_coord)
        .await
        .expect("Alice sends ClaimProof");

    let bob_got_alice_claim = receive_next(&bob_reader, &alice_channel).await;
    let alice_completed_sig_for_bob = match bob_got_alice_claim {
        ProtocolMessage::ClaimProof { completed_sig } => completed_sig,
        other => panic!(
            "Bob expected ClaimProof, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    // Bob extracts Alice's secret and reaches Complete.
    let alice_pre_sig_in_bob = match &bob_with_presig {
        SwapState::WowLocked {
            counterparty_pre_sig: Some(pre_sig),
            ..
        } => pre_sig.clone(),
        _ => panic!("expected WowLocked with counterparty_pre_sig set"),
    };
    let alice_secret_extracted = alice_pre_sig_in_bob
        .extract_secret(&alice_completed_sig_for_bob)
        .expect("Bob must extract Alice's secret from her completed sig");

    let bob_complete = bob_with_presig
        .complete_with_claim(alice_secret_extracted.to_bytes())
        .expect("Bob must reach Complete state");

    // 15. Final assertions 
    assert!(
        matches!(bob_complete, SwapState::Complete { .. }),
        "Bob must reach Complete state"
    );

    let alice_complete_swap_id = match &alice_complete {
        SwapState::Complete { addresses, .. } => addresses.swap_id,
        _ => unreachable!(),
    };
    let bob_complete_swap_id = match &bob_complete {
        SwapState::Complete { addresses, .. } => addresses.swap_id,
        _ => unreachable!(),
    };
    assert_eq!(
        alice_complete_swap_id, bob_complete_swap_id,
        "Alice and Bob Complete states must have matching swap_id"
    );

    assert!(
        matches!(
            alice_complete,
            SwapState::Complete {
                role: SwapRole::Alice,
                ..
            }
        ),
        "Alice's Complete state must have Alice role"
    );
    assert!(
        matches!(
            bob_complete,
            SwapState::Complete {
                role: SwapRole::Bob,
                ..
            }
        ),
        "Bob's Complete state must have Bob role"
    );

    println!("SHARECHAIN_SWAP_ID={}", hex::encode(alice_complete_swap_id));
}
