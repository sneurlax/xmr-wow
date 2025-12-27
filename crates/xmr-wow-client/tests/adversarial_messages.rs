//! Adversarial message rejection tests.
//!
//! Exercises the state machine against malformed, replayed, out-of-order,
//! cross-swap, and wrong-adaptor-point inputs.

use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, decode_message, ProtocolMessage, SwapError,
    SwapParams, SwapRole, SwapState,
};
use xmr_wow_crypto::{AdaptorSignature, DleqProof, KeyContribution};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Fresh Alice/Bob KeyGeneration states.
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

/// Advance both parties to JointAddress.
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

/// Advance to XmrLocked (Alice) / WowLocked (Bob).
fn advance_to_xmr_locked() -> (SwapState, SwapState) {
    let (alice_joint, bob_joint) = advance_to_joint_address();

    // Bob locks WOW first
    let bob_wow = bob_joint.record_wow_lock([0xBB; 32]).unwrap();
    // Alice locks XMR
    let alice_xmr = alice_joint.record_xmr_lock([0xAA; 32]).unwrap();

    (alice_xmr, bob_wow)
}

// ---------------------------------------------------------------------------
// Test 1: Malformed / garbage messages are rejected with descriptive errors
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_message_rejected() {
    // garbage input
    let result: Result<ProtocolMessage, SwapError> = decode_message("garbage_bytes_not_valid");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("missing protocol prefix"),
        "expected prefix error, got: {err}"
    );
}

#[test]
fn test_truncated_base64_rejected() {
    // truncated base64
    let result: Result<ProtocolMessage, SwapError> = decode_message("xmrwow1:!!!not-base64!!!");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("base64 decode failed"),
        "expected base64 error, got: {err}"
    );
}

#[test]
fn test_valid_base64_invalid_json_rejected() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    // valid base64 but not JSON
    let bad_json = BASE64.encode(b"\xff\xfe garbage");
    let encoded = format!("xmrwow1:{bad_json}");
    let result: Result<ProtocolMessage, SwapError> = decode_message(&encoded);
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("JSON decode failed"),
        "expected JSON decode error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Wrong-type message at wrong step is rejected (InvalidTransition)
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_type_at_wrong_step_pre_sig_on_keygen() {
    // pre_sig from KeyGeneration must fail
    let params = sample_params();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

    let dummy_pre_sig = AdaptorSignature {
        r_plus_t: [0xAA; 32],
        s_prime: [0xBB; 32],
    };

    let err = alice
        .receive_counterparty_pre_sig(dummy_pre_sig)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition, got: {err}"
    );
}

#[test]
fn test_wrong_type_at_wrong_step_adaptor_claim_on_keygen() {
    // claim from KeyGeneration must fail
    let params = sample_params();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

    use xmr_wow_crypto::CompletedSignature;
    let dummy_completed = CompletedSignature {
        r_t: [0xCC; 32],
        s: [0xDD; 32],
    };

    let err = alice
        .complete_with_adaptor_claim(&dummy_completed)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition, got: {err}"
    );
}

#[test]
fn test_wrong_type_at_wrong_step_adaptor_claim_on_joint_address() {
    // claim only valid from WowLocked/XmrLocked with a stored pre-sig
    let (alice_joint, _bob_joint) = advance_to_joint_address();

    use xmr_wow_crypto::CompletedSignature;
    let dummy_completed = CompletedSignature {
        r_t: [0xCC; 32],
        s: [0xDD; 32],
    };

    let err = alice_joint
        .complete_with_adaptor_claim(&dummy_completed)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition from JointAddress, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Out-of-order state transitions are rejected
// ---------------------------------------------------------------------------

#[test]
fn test_out_of_order_record_wow_lock_from_xmr_locked() {
    // wow_lock from XmrLocked must fail
    let (alice_xmr_locked, _bob) = advance_to_xmr_locked();

    let err = alice_xmr_locked
        .record_wow_lock([0xFF; 32])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition, got: {err}"
    );
}

#[test]
fn test_out_of_order_receive_key_from_dleq_exchange() {
    // replay key exchange after already transitioning to DleqExchange
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let alice_dleq = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap();

    // replay
    let err = alice_dleq
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition on second receive_counterparty_key, got: {err}"
    );
}

#[test]
fn test_out_of_order_record_xmr_lock_from_keygen() {
    // xmr_lock from KeyGeneration must fail
    let params = sample_params();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

    let err = alice
        .record_xmr_lock([0xAA; 32])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition from KeyGeneration, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Replayed message on already-transitioned state fails
// ---------------------------------------------------------------------------

#[test]
fn test_replayed_message_second_key_exchange_fails() {
    // replay of key exchange after transition
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);

    // first call succeeds
    let alice_dleq = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap();

    // second call (replay) must fail
    let err = alice_dleq
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition on replay, got: {err}"
    );
}

#[test]
fn test_replayed_pre_sig_garbage_rejected() {
    // garbage pre-sig to XmrLocked must fail verify
    let (alice_xmr, _bob_wow) = advance_to_xmr_locked();

    // zero r_plus_t: invalid point
    let garbage_pre_sig = AdaptorSignature {
        r_plus_t: [0x00; 32],
        s_prime: [0x00; 32],
    };
    let err = alice_xmr
        .receive_counterparty_pre_sig(garbage_pre_sig)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("pre-sig verification failed") || err.contains("crypto error"),
        "expected pre-sig verification failure on garbage, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Wrong swap_id (cross-swap pre-sig) is rejected
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_swap_id_pre_sig_rejected() {
    // Two independent swaps; feed swap2's pre-sig to swap1.
    let (alice1_xmr, _bob1_wow) = advance_to_xmr_locked();
    let (_alice2_xmr, bob2_wow) = advance_to_xmr_locked();

    // Bob2's pre-sig
    let bob2_pre_sig = match &bob2_wow {
        SwapState::WowLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected WowLocked"),
    };

    // mismatched swap_id -> verify must fail
    let err = alice1_xmr
        .receive_counterparty_pre_sig(bob2_pre_sig)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("pre-sig verification failed") || err.contains("crypto error"),
        "expected pre-sig rejection for wrong swap_id, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Wrong adaptor point (arbitrary pre-sig) is rejected
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_adaptor_point_fails() {
    // Advance to XmrLocked and then inject a pre-sig signed under a random (different)
    // adaptor point.  verify_pre_sig must detect the mismatch and return an error.
    let (alice_xmr, _bob_wow) = advance_to_xmr_locked();

    // Get the swap_id from Alice's state to use the right message bytes,
    // but sign with a completely different adaptor point (not Alice's actual pubkey).
    let swap_id = match &alice_xmr {
        SwapState::XmrLocked { addresses, .. } => addresses.swap_id,
        _ => panic!("expected XmrLocked"),
    };

    // Generate two fresh random contributors: one as the signer, one as the wrong adaptor
    let signer_contrib = KeyContribution::generate(&mut OsRng);
    let wrong_adaptor_contrib = KeyContribution::generate(&mut OsRng);

    // Sign with the correct swap_id message but the wrong adaptor point
    let wrong_adaptor_pre_sig = AdaptorSignature::sign(
        &signer_contrib.secret,
        &signer_contrib.public,
        &swap_id,
        &wrong_adaptor_contrib.public, // wrong adaptor point: not Alice's actual pubkey
        &mut OsRng,
    );

    // Alice's state expects a pre-sig adapted by *her* pubkey; this uses a random adaptor
    let err = alice_xmr
        .receive_counterparty_pre_sig(wrong_adaptor_pre_sig)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("pre-sig verification failed") || err.contains("crypto error"),
        "expected wrong-adaptor rejection, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Wrong-topic: structural prevention via closed enum
// ---------------------------------------------------------------------------
#[test]
fn test_wrong_topic_structural_prevention() {
    // Unknown variants are rejected at deserialization
    let wrong_topic_json = r#"{"UnknownTopic":{"data":"test"}}"#;
    let bad_result: Result<ProtocolMessage, _> = decode_message(wrong_topic_json);
    assert!(bad_result.is_err(), "unknown topic rejected at deserialization layer");

    // A misspelled valid variant also fails
    let misspelled_json = r#"{"AdaptorPresig":{"pre_sig":[0;32]}}"#;
    let bad_result2: Result<ProtocolMessage, _> = decode_message(misspelled_json);
    assert!(bad_result2.is_err(), "misspelled topic rejected at deserialization layer");
}
