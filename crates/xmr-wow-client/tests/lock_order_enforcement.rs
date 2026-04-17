//! WOW-first lock order enforcement tests.

use rand::rngs::OsRng;
use xmr_wow_client::{build_observed_refund_timing, SwapParams, SwapRole, SwapState};
use xmr_wow_crypto::DleqProof;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_params() -> SwapParams {
    let (refund_timing, xmr_refund_delay_seconds, wow_refund_delay_seconds) =
        build_observed_refund_timing(100, 200, 500, 800).unwrap();
    SwapParams {
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_delay_seconds,
        wow_refund_delay_seconds,
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

/// Advance both parties to the JointAddress state.
/// Returns (alice_joint, bob_joint).
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

#[test]
fn test_primary_path_wow_first_enforced() {
    let (_alice_joint, bob_joint) = advance_to_joint_address();

    let bob_wow_locked = bob_joint.record_wow_lock([0x11; 32]).unwrap();

    match &bob_wow_locked {
        SwapState::WowLocked { wow_lock_tx, .. } => {
            assert_eq!(
                wow_lock_tx, &[0x11u8; 32],
                "wow_lock_tx must be the submitted lock tx hash"
            );
        }
        _ => panic!("expected WowLocked state after record_wow_lock"),
    }

    let bob_xmr_locked = bob_wow_locked.record_xmr_lock([0x22; 32]).unwrap();

    match bob_xmr_locked {
        SwapState::XmrLocked {
            wow_lock_tx,
            xmr_lock_tx,
            ..
        } => {
            assert_eq!(
                wow_lock_tx, [0x11u8; 32],
                "wow_lock_tx must be non-zero on primary path (WOW locked first)"
            );
            assert_eq!(
                xmr_lock_tx, [0x22u8; 32],
                "xmr_lock_tx must reflect the submitted XMR lock tx"
            );
            assert_ne!(
                wow_lock_tx, [0u8; 32],
                "wow_lock_tx must NOT be the zero sentinel on primary path"
            );
        }
        _ => panic!("expected XmrLocked state"),
    }
}

#[test]
fn test_fallback_path_xmr_without_wow() {
    let (alice_joint, _bob_joint) = advance_to_joint_address();

    let alice_xmr_locked = alice_joint.record_xmr_lock([0x33; 32]).unwrap();

    match alice_xmr_locked {
        SwapState::XmrLocked {
            wow_lock_tx,
            xmr_lock_tx,
            ..
        } => {
            assert_eq!(
                wow_lock_tx, [0u8; 32],
                "wow_lock_tx must be zero sentinel on fallback path (WOW not locked first)"
            );
            assert_eq!(
                xmr_lock_tx, [0x33u8; 32],
                "xmr_lock_tx must reflect the submitted XMR lock tx"
            );
        }
        _ => panic!("expected XmrLocked state"),
    }
}

#[test]
fn test_xmr_lock_from_keygen_rejected() {
    let params = sample_params();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

    let err = alice.record_xmr_lock([0xAA; 32]).unwrap_err().to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition from KeyGeneration, got: {err}"
    );
}

#[test]
fn test_xmr_lock_from_dleq_rejected() {
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let alice_dleq = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();

    assert!(
        matches!(alice_dleq, SwapState::DleqExchange { .. }),
        "expected DleqExchange state"
    );

    let err = alice_dleq
        .record_xmr_lock([0xAA; 32])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition from DleqExchange, got: {err}"
    );
}

#[test]
fn test_wow_lock_only_from_joint_address() {

    let params = sample_params();
    let (alice, bob) = make_alice_bob(params.clone());
    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);

    // --- KeyGeneration ---
    let (keygen, _) = SwapState::generate(SwapRole::Bob, params.clone(), &mut OsRng);
    let err = keygen.record_wow_lock([0x44; 32]).unwrap_err().to_string();
    assert!(
        err.contains("invalid state transition"),
        "KeyGeneration: expected InvalidTransition, got: {err}"
    );

    // --- DleqExchange ---
    let (alice2, bob2) = make_alice_bob(params.clone());
    let (bob2_pub, bob2_proof) = extract_pubkey_and_proof(&bob2);
    let dleq = alice2
        .receive_counterparty_key(bob2_pub, &bob2_proof)
        .unwrap();
    let err = dleq.record_wow_lock([0x44; 32]).unwrap_err().to_string();
    assert!(
        err.contains("invalid state transition"),
        "DleqExchange: expected InvalidTransition, got: {err}"
    );

    // --- JointAddress (success case) ---
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
    // Bob can call record_wow_lock from JointAddress (success)
    let bob_wow = bob_joint.record_wow_lock([0x44; 32]).unwrap();
    assert!(
        matches!(bob_wow, SwapState::WowLocked { .. }),
        "JointAddress: should succeed and transition to WowLocked"
    );

    // --- WowLocked ---
    // (bob_wow was just transitioned; trying again must fail)
    // Re-derive bob to a fresh WowLocked state
    let (_, bob3) = make_alice_bob(params.clone());
    let (alice3_pub, alice3_proof) = {
        let (a3, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
        extract_pubkey_and_proof(&a3)
    };
    let bob3_wow = bob3
        .receive_counterparty_key(alice3_pub, &alice3_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap()
        .record_wow_lock([0x55; 32])
        .unwrap();
    let err = bob3_wow
        .record_wow_lock([0x66; 32])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "WowLocked: expected InvalidTransition, got: {err}"
    );

    // --- XmrLocked ---
    let xmr_locked = alice_joint.record_xmr_lock([0x77; 32]).unwrap();
    let err = xmr_locked
        .record_wow_lock([0x88; 32])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "XmrLocked: expected InvalidTransition, got: {err}"
    );
}
