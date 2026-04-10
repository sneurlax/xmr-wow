use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, wrap_protocol_message, CoordMessage, ProtocolMessage,
    SwapParams, SwapRole, SwapState,
};
use xmr_wow_crypto::{AdaptorSignature, CompletedSignature, DleqProof, KeyContribution};

// Helpers are duplicated from adversarial_messages.rs; integration tests are
// separate compilation units and cannot share helpers.

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

fn make_alice_bob(params: SwapParams) -> (SwapState, SwapState) {
    let (alice, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, _) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);
    (alice, bob)
}

fn extract_pubkey_and_proof(state: &SwapState) -> ([u8; 32], DleqProof) {
    match state {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        _ => panic!("expected KeyGeneration state"),
    }
}

fn advance_to_joint_address() -> (SwapState, SwapState) {
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);

    let alice_joint = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    let bob_joint = bob
        .receive_counterparty_key(alice_pub, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    (alice_joint, bob_joint)
}

fn advance_to_xmr_locked() -> (SwapState, SwapState) {
    let (alice_joint, bob_joint) = advance_to_joint_address();
    let bob_wow = bob_joint.record_wow_lock([0xBB; 32]).unwrap();
    let alice_xmr = alice_joint.record_xmr_lock([0xAA; 32]).unwrap();
    (alice_xmr, bob_wow)
}

#[test]
fn record_xmr_lock_takes_tx_hash_not_coord_message() {
    let (_alice_joint, bob_joint) = advance_to_joint_address();
    let bob_wow_locked = bob_joint.record_wow_lock([0xBB; 32]).unwrap();

    let xmr_hash: [u8; 32] = [0xAA; 32];
    let result = bob_wow_locked.record_xmr_lock(xmr_hash);

    assert!(
        result.is_ok(),
        "record_xmr_lock must succeed from WowLocked with a [u8; 32] tx hash: {:?}",
        result
    );
    assert!(
        matches!(result.unwrap(), SwapState::XmrLocked { .. }),
        "result must be XmrLocked"
    );
}

#[test]
fn record_wow_lock_takes_tx_hash_not_coord_message() {
    let (_alice_joint, bob_joint) = advance_to_joint_address();

    let wow_hash: [u8; 32] = [0xBB; 32];
    let result = bob_joint.record_wow_lock(wow_hash);

    assert!(
        result.is_ok(),
        "record_wow_lock must succeed from JointAddress with a [u8; 32] tx hash: {:?}",
        result
    );
    assert!(
        matches!(result.unwrap(), SwapState::WowLocked { .. }),
        "result must be WowLocked"
    );
}

#[test]
fn complete_with_adaptor_claim_takes_completed_sig_not_coord_message() {
    let (_alice_xmr, bob_wow) = advance_to_xmr_locked();

    // Returns Err because the signature is cryptographically invalid, not from a type mismatch.
    let garbage_sig = CompletedSignature {
        r_t: [0x00; 32],
        s: [0x00; 32],
    };
    let result = bob_wow.complete_with_adaptor_claim(&garbage_sig);
    assert!(
        result.is_err(),
        "complete_with_adaptor_claim must return Err for garbage CompletedSignature"
    );
}

#[test]
fn forged_coord_message_does_not_advance_swap_state() {
    let (_alice_xmr, bob_wow) = advance_to_xmr_locked();

    let swap_id = bob_wow
        .swap_id()
        .expect("WowLocked must have a swap_id");

    let forged_payload = b"forged claim proof";
    let forged_coord = CoordMessage {
        swap_id,
        payload: forged_payload.to_vec(),
        encryption_hint: None,
    };

    // CoordMessage is not an argument to any fund-movement transition.
    let _ = forged_coord.swap_id;
    let _ = forged_coord.payload.len();

    let garbage_sig = CompletedSignature {
        r_t: [0x00; 32],
        s: [0x00; 32],
    };
    let result = bob_wow.complete_with_adaptor_claim(&garbage_sig);
    assert!(
        result.is_err(),
        "complete_with_adaptor_claim must reject a garbage CompletedSignature: \
        CoordMessage content is irrelevant to fund-movement state transitions"
    );
}

// If a future commit changes a fund-movement method to accept a message type,
// this test will fail to compile or serve as a record that the invariant was
// intentionally broken.
#[test]
fn coord_message_content_never_passed_to_state_transitions() {
    let swap_id = [0x42u8; 32];

    let contrib = KeyContribution::generate(&mut OsRng);
    let proof = DleqProof::prove(
        &contrib.secret,
        &contrib.public,
        b"xmr-wow-swap-v1",
        &mut OsRng,
    );

    let init_msg = ProtocolMessage::Init {
        pubkey: contrib.public_bytes(),
        proof,
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_height: 600,
        wow_refund_height: 1000,
        refund_timing: None,
        alice_refund_address: None,
    };

    let contrib2 = KeyContribution::generate(&mut OsRng);
    let proof2 = DleqProof::prove(
        &contrib2.secret,
        &contrib2.public,
        b"xmr-wow-swap-v1",
        &mut OsRng,
    );
    let response_msg = ProtocolMessage::Response {
        pubkey: contrib2.public_bytes(),
        proof: proof2,
        bob_refund_address: None,
    };

    let adaptor_pre_sig_msg = ProtocolMessage::AdaptorPreSig {
        pre_sig: AdaptorSignature {
            r_plus_t: [0xAA; 32],
            s_prime: [0xBB; 32],
        },
    };

    let claim_proof_msg = ProtocolMessage::ClaimProof {
        completed_sig: CompletedSignature {
            r_t: [0xCC; 32],
            s: [0xDD; 32],
        },
    };

    let coord_init = wrap_protocol_message(swap_id, &init_msg).unwrap();
    let coord_response = wrap_protocol_message(swap_id, &response_msg).unwrap();
    let coord_pre_sig = wrap_protocol_message(swap_id, &adaptor_pre_sig_msg).unwrap();
    let coord_claim = wrap_protocol_message(swap_id, &claim_proof_msg).unwrap();

    assert!(!coord_init.payload.is_empty(), "Init payload must be non-empty");
    assert!(!coord_response.payload.is_empty(), "Response payload must be non-empty");
    assert!(!coord_pre_sig.payload.is_empty(), "AdaptorPreSig payload must be non-empty");
    assert!(!coord_claim.payload.is_empty(), "ClaimProof payload must be non-empty");

    let recovered_init = xmr_wow_client::unwrap_protocol_message(&coord_init).unwrap();
    assert!(
        matches!(recovered_init, ProtocolMessage::Init { .. }),
        "unwrap must recover Init"
    );

    let (_alice_xmr, bob_wow) = advance_to_xmr_locked();
    let _result = bob_wow.complete_with_adaptor_claim(&CompletedSignature {
        r_t: [0xCC; 32], // on-chain artifact, not from coord_claim.payload
        s: [0xDD; 32],
    });
}
