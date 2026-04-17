// Integration tests for the proof_harness_checkpoint_allowed helper.
//
// These tests exercise the SwapState::proof_harness_checkpoint_allowed method
// directly, which is the checkpoint-bypass gate used by --proof-harness.
// They do NOT invoke the full CLI (that requires wallet RPC).

use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, RefundCheckpointName, SwapParams, SwapRole, SwapState,
};
use xmr_wow_crypto::DleqProof;

fn sample_params_with_addresses() -> SwapParams {
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

fn sample_params_no_alice_address() -> SwapParams {
    let (refund_timing, xmr_refund_delay_seconds, wow_refund_delay_seconds) =
        build_observed_refund_timing(100, 200, 500, 800).unwrap();

    SwapParams {
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_delay_seconds,
        wow_refund_delay_seconds,
        refund_timing: Some(refund_timing),
        alice_refund_address: None,
        bob_refund_address: Some("bob-refund-addr".into()),
    }
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

/// Build a WowLocked state (Alice perspective) with alice_refund_address set.
/// BeforeXmrLock checkpoint is populated and should allow proof-harness bypass.
fn make_wow_locked_alice(params: SwapParams) -> SwapState {
    let (alice, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, _) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);

    let alice_joint = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    // Bob reaches JointAddress too; Alice then records Bob's WOW lock.
    // We use Bob's side just to derive Alice's WowLocked state via record_wow_lock.
    let _bob_joint = bob
        .receive_counterparty_key(alice_pub, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    // Alice records Bob's wow lock: this triggers build_before_xmr_lock_checkpoint.
    alice_joint.record_wow_lock([0xBB; 32]).unwrap()
}

// Test 1: BeforeXmrLock checkpoint with a refund address no longer matches the
// legacy proof-harness bypass once exchanged VTS artifacts are required.
#[test]
fn proof_harness_helper_rejects_before_xmr_lock_without_exchanged_vts_artifact() {
    let state = make_wow_locked_alice(sample_params_with_addresses());

    // Verify the checkpoint exists and has the expected shape.
    let checkpoint = state
        .before_xmr_lock_checkpoint()
        .expect("BeforeXmrLock checkpoint must exist in WowLocked state");
    assert!(
        checkpoint.refund_address.is_some(),
        "refund_address must be Some for bypass to be possible"
    );

    assert!(
        !state.proof_harness_checkpoint_allowed(RefundCheckpointName::BeforeXmrLock),
        "proof_harness_checkpoint_allowed should return false once BeforeXmrLock depends on an exchanged VTS artifact"
    );
}

// Test 2: BeforeXmrLock checkpoint with refund_address = None: returns false.
#[test]
fn proof_harness_helper_rejects_missing_refund_address() {
    let state = make_wow_locked_alice(sample_params_no_alice_address());

    let checkpoint = state
        .before_xmr_lock_checkpoint()
        .expect("BeforeXmrLock checkpoint must exist");
    assert!(
        checkpoint.refund_address.is_none(),
        "test fixture: refund_address should be None"
    );

    assert!(
        !state.proof_harness_checkpoint_allowed(RefundCheckpointName::BeforeXmrLock),
        "proof_harness_checkpoint_allowed must return false when refund_address is None"
    );
}

// Test 3: BeforeXmrLock checkpoint with wrong status (mutated via JSON): returns false.
#[test]
fn proof_harness_helper_rejects_wrong_status() {
    let state = make_wow_locked_alice(sample_params_with_addresses());

    // Mutate the checkpoint status via JSON round-trip.
    let mut json: serde_json::Value = serde_json::to_value(&state).unwrap();
    // WowLocked state stores before_xmr_lock_checkpoint as a JSON field.
    // Status "Ready" is not the expected status (Blocked), so the helper must return false.
    let cp = &mut json["before_xmr_lock_checkpoint"]["status"];
    *cp = serde_json::Value::String("Ready".into());

    let mutated: SwapState = serde_json::from_value(json).unwrap();

    assert!(
        !mutated.proof_harness_checkpoint_allowed(RefundCheckpointName::BeforeXmrLock),
        "proof_harness_checkpoint_allowed must return false when checkpoint status does not match expected guarantee"
    );
}

// Test 4: No BeforeXmrLock checkpoint (state is JointAddress, not WowLocked): returns false.
#[test]
fn proof_harness_helper_rejects_missing_checkpoint() {
    let params = sample_params_with_addresses();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, _) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);
    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);

    // Alice is in JointAddress: no BeforeXmrLock checkpoint yet.
    let alice_joint = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    assert!(
        alice_joint.before_xmr_lock_checkpoint().is_none(),
        "test fixture: JointAddress(Alice) should have no BeforeXmrLock checkpoint"
    );

    assert!(
        !alice_joint.proof_harness_checkpoint_allowed(RefundCheckpointName::BeforeXmrLock),
        "proof_harness_checkpoint_allowed must return false when checkpoint is absent"
    );
}
