//! XMR refund path state machine tests.
//!
//! Live XMR refund broadcast is blocked by Monero relay policy (unlock_time > 0
//! rejected for non-coinbase); tests cover the state machine and artifact layer.

use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, guarantee_decision, GuaranteeMode, GuaranteeStatus,
    PersistedRefundArtifact, SwapParams, SwapRole, SwapState,
};
use xmr_wow_wallet::{RefundArtifact, RefundChain};

const TEST_VTS_BITS: u32 = 512;
const TEST_SQUARINGS_PER_SECOND: u64 = 10;

fn sample_params() -> SwapParams {
    let (refund_timing, xmr_refund_delay_seconds, wow_refund_delay_seconds) =
        build_observed_refund_timing(100, 200, 500, 800).unwrap();

    SwapParams {
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_delay_seconds,
        wow_refund_delay_seconds,
        refund_timing: Some(refund_timing),
        alice_refund_address: Some("alice-refund-address".into()),
        bob_refund_address: Some("bob-refund-address".into()),
    }
}

fn make_alice_bob(params: SwapParams) -> (SwapState, [u8; 32], SwapState, [u8; 32]) {
    let (alice, alice_secret) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, bob_secret) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);
    (alice, alice_secret, bob, bob_secret)
}

fn extract_pubkey_and_proof(state: &SwapState) -> ([u8; 32], xmr_wow_crypto::DleqProof) {
    match state {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        _ => panic!("expected key generation state"),
    }
}

/// Advance a swap to XmrLocked state via the canonical path:
/// KeyGeneration -> DleqExchange -> JointAddress -> WowLocked (Bob) -> XmrLocked (Alice).
fn make_xmr_locked() -> (SwapState, [u8; 32], [u8; 32]) {
    let params = sample_params();
    let (alice, _alice_secret, bob, bob_secret) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);

    // Both advance to JointAddress
    let alice_joint = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    let _bob_joint = bob
        .receive_counterparty_key(alice_pub, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    // Alice skips WowLocked (uses JointAddress -> XmrLocked fallback path)
    let swap_id = alice_joint.swap_id().unwrap();
    (
        alice_joint.record_xmr_lock([0xBB; 32]).unwrap(),
        bob_secret,
        swap_id,
    )
}

fn sample_xmr_artifact(swap_id: [u8; 32], bob_secret: [u8; 32]) -> PersistedRefundArtifact {
    let params = sample_params();
    RefundArtifact::new_with_bits(
        RefundChain::Xmr,
        swap_id,
        "alice-refund-address",
        params.xmr_refund_delay_seconds,
        &bob_secret,
        TEST_SQUARINGS_PER_SECOND,
        TEST_VTS_BITS,
    )
    .expect("test XMR artifact should build")
    .into()
}

/// Test 1: XMR refund artifact builds from XmrLocked state and has correct fields.
#[test]
fn test_xmr_refund_artifact_builds_from_xmr_locked() {
    let (xmr_locked, bob_secret, swap_id) = make_xmr_locked();

    // Confirm we are in XmrLocked state
    assert!(
        matches!(xmr_locked, SwapState::XmrLocked { .. }),
        "expected XmrLocked state"
    );

    // Build and record a refund artifact
    let artifact = sample_xmr_artifact(swap_id, bob_secret);
    let params = sample_params();

    // Verify artifact fields directly before recording
    assert_eq!(
        artifact.metadata.chain,
        RefundChain::Xmr,
        "artifact chain must be Xmr"
    );
    assert_eq!(
        artifact.metadata.swap_id, swap_id,
        "artifact swap_id must match the swap transcript"
    );
    assert_eq!(
        artifact.metadata.destination, "alice-refund-address",
        "artifact destination must match alice refund address"
    );
    assert!(
        artifact.metadata.refund_delay_seconds > 0,
        "artifact refund_delay_seconds must be > 0"
    );
    assert_eq!(
        artifact.metadata.refund_delay_seconds, params.xmr_refund_delay_seconds,
        "artifact refund_delay_seconds must match swap params"
    );
    assert!(artifact.puzzle.t > 0, "artifact puzzle must require work");

    // Record artifact into state succeeds
    let state_with_artifact = xmr_locked.record_refund_artifact(artifact).unwrap();
    assert!(
        matches!(state_with_artifact, SwapState::XmrLocked { .. }),
        "state must remain XmrLocked after recording artifact"
    );

    // validate_refund_artifact passes
    state_with_artifact.validate_refund_artifact().unwrap();
}

/// Test 2: XMR refund artifact binding validates correctly with right params and
/// rejects with wrong lock_tx_hash.
#[test]
fn test_xmr_refund_artifact_binding_validates() {
    let (_xmr_locked, bob_secret, swap_id) = make_xmr_locked();
    let artifact = sample_xmr_artifact(swap_id, bob_secret);

    // Correct binding validates
    artifact
        .validate_binding(
            RefundChain::Xmr,
            swap_id,
            "alice-refund-address",
            sample_params().xmr_refund_delay_seconds,
            &artifact.metadata.locked_pubkey,
        )
        .expect("binding validation must succeed with correct params");

    // Wrong swap_id is rejected
    let wrong_hash = [0xFF; 32];
    let err = artifact
        .validate_binding(
            RefundChain::Xmr,
            wrong_hash,
            "alice-refund-address",
            sample_params().xmr_refund_delay_seconds,
            &artifact.metadata.locked_pubkey,
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("mismatch") || err.contains("swap_id"),
        "error must mention mismatch or swap_id, got: {err}"
    );
}

/// Test 3: XmrLocked -> Refunded state machine transition (Alice's refund path).
///
/// Alice locked XMR and Bob vanished. She calls complete_with_refund after timelock.
#[test]
fn test_xmr_locked_to_refunded_transition() {
    let (xmr_locked, ..) = make_xmr_locked();
    let refund_tx = [3u8; 32];

    let refunded = xmr_locked.complete_with_refund(refund_tx).unwrap();

    match refunded {
        SwapState::Refunded {
            refund_tx_hash,
            refund_evidence,
            ..
        } => {
            assert_eq!(refund_tx_hash, refund_tx, "refund_tx_hash must match");
            let evidence = refund_evidence.expect("refund_evidence must be Some");
            assert_eq!(
                evidence.chain,
                RefundChain::Xmr,
                "refund evidence chain must be Xmr"
            );
            assert_eq!(
                evidence.refund_tx_hash, refund_tx,
                "evidence refund_tx_hash must match"
            );
        }
        other => panic!(
            "expected Refunded state, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

/// Test 4: complete_with_refund is rejected from wrong states.
///
/// Refund is only valid from XmrLocked or WowLocked. All other states must
/// return Err(SwapError::InvalidTransition).
#[test]
fn test_xmr_refund_from_wrong_state_rejected() {
    let params = sample_params();

    // KeyGeneration state
    let (alice_keygen, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let err = alice_keygen.complete_with_refund([1u8; 32]).unwrap_err();
    assert!(
        err.to_string().contains("invalid state transition"),
        "KeyGeneration refund must fail with InvalidTransition, got: {err}"
    );

    // Build Alice and Bob states for DleqExchange
    let (alice, _alice_secret, bob, _bob_secret) = make_alice_bob(params.clone());
    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);

    let alice_dleq = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();

    let err = alice_dleq.complete_with_refund([1u8; 32]).unwrap_err();
    assert!(
        err.to_string().contains("invalid state transition"),
        "DleqExchange refund must fail with InvalidTransition, got: {err}"
    );

    // JointAddress state
    let (alice2, _alice2_secret, bob2, _bob2_secret) = make_alice_bob(params.clone());
    let (bob_pub2, bob_proof2) = extract_pubkey_and_proof(&bob2);
    let alice_joint = alice2
        .receive_counterparty_key(bob_pub2, &bob_proof2)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    let err = alice_joint.complete_with_refund([1u8; 32]).unwrap_err();
    assert!(
        err.to_string().contains("invalid state transition"),
        "JointAddress refund must fail with InvalidTransition, got: {err}"
    );

    // Complete state: construct via complete_with_refund from XmrLocked, then try to
    // refund again from the resulting Refunded state
    let (xmr_locked, ..) = make_xmr_locked();
    let refunded = xmr_locked.complete_with_refund([2u8; 32]).unwrap();
    let err = refunded.complete_with_refund([3u8; 32]).unwrap_err();
    assert!(
        err.to_string().contains("invalid state transition"),
        "Refunded refund must fail with InvalidTransition, got: {err}"
    );
}

/// Test 5: GuaranteeMode::LiveXmrUnlockTimeRefund returns GuaranteeStatus::Blocked.
///
/// This documents the known Monero relay-policy limitation as a test assertion.
/// Monero relays reject transactions with nonzero unlock_time for non-coinbase
/// transactions, making live XMR unlock-time-enforced refunds impossible to
/// broadcast. The refund path exists at the artifact/state level, but broadcast
/// is blocked by relay policy.
#[test]
fn test_xmr_refund_relay_limitation_documented() {
    let decision = guarantee_decision(GuaranteeMode::LiveXmrUnlockTimeRefund);
    assert_eq!(
        decision.status,
        GuaranteeStatus::Blocked,
        "LiveXmrUnlockTimeRefund must be Blocked (Monero relay policy rejects nonzero unlock_time)"
    );
    assert!(
        !decision.reason.is_empty(),
        "blocking reason must be documented"
    );
    // Confirm the reason mentions the relay policy
    assert!(
        decision.reason.to_lowercase().contains("relay")
            || decision.reason.to_lowercase().contains("unlock"),
        "reason must mention relay policy or unlock_time, got: {}",
        decision.reason
    );
}
