//! VTS refund path integration tests.
//!
//! These tests prove that the VTS time-lock puzzle refund mechanism works
//! end-to-end within the swap state machine, without requiring a running
//! daemon (in-process only).
//!
//! Uses 512-bit RSA moduli for speed in debug-mode tests (production uses 2048-bit).

use curve25519_dalek::scalar::Scalar;
use xmr_wow_client::{
    GuaranteeMode, GuaranteeStatus, PersistedRefundArtifact, SwapParams, SwapRole, SwapState,
};
use xmr_wow_wallet::{RefundArtifact, RefundChain};

/// RSA modulus bit length for test puzzles (fast in debug mode).
const TEST_BITS: u32 = 512;

/// Generate a dummy SwapParams for testing.
fn test_params() -> SwapParams {
    SwapParams {
        amount_xmr: 1_000_000_000,  // 0.001 XMR
        amount_wow: 10_000_000_000, // 10 WOW
        xmr_refund_delay_seconds: 100,
        wow_refund_delay_seconds: 300,
        refund_timing: Some(xmr_wow_client::RefundTimingObservation {
            xmr_base_height: 1_000_000,
            wow_base_height: 500_000,
            xmr_refund_delay_seconds: 100,
            wow_refund_delay_seconds: 300,
            source: xmr_wow_client::RefundTimingSource::DaemonHeightQuery,
        }),
        alice_refund_address: Some("4test_alice_refund_address".to_string()),
        bob_refund_address: Some("Wo3test_bob_refund_address".to_string()),
    }
}

/// Generate a VTS-based refund artifact for testing (small modulus).
fn test_secret(tag: u64) -> [u8; 32] {
    Scalar::from(tag).to_bytes()
}

fn make_vts_artifact(
    chain: RefundChain,
    swap_id: [u8; 32],
    destination: &str,
    refund_delay_seconds: u64,
    secret: [u8; 32],
) -> PersistedRefundArtifact {
    let artifact = RefundArtifact::new_with_bits(
        chain,
        swap_id,
        destination,
        refund_delay_seconds,
        &secret,
        10, // 10 squarings/sec (tiny puzzle for tests)
        TEST_BITS,
    )
    .expect("VTS artifact generation should succeed");

    PersistedRefundArtifact::from(artifact)
}

// VTS puzzle round-trip tests

#[test]
fn vts_puzzle_generate_and_solve_round_trip() {
    let secret = test_secret(11);
    let artifact = RefundArtifact::new_with_bits(
        RefundChain::Xmr,
        [0xAA; 32],
        "destination",
        1,
        &secret,
        10,
        TEST_BITS,
    )
    .unwrap();

    let recovered = artifact.solve().unwrap();
    assert_eq!(recovered, secret.to_vec());
}

#[test]
fn vts_puzzle_validates_solved_secret() {
    let secret = test_secret(12);
    let artifact = RefundArtifact::new_with_bits(
        RefundChain::Wow,
        [0xBB; 32],
        "destination",
        1,
        &secret,
        10,
        TEST_BITS,
    )
    .unwrap();

    let recovered = artifact.solve().unwrap();
    artifact.validate_solved_secret(&recovered).unwrap();
}

#[test]
fn vts_puzzle_rejects_wrong_secret() {
    let secret = test_secret(13);
    let artifact = RefundArtifact::new_with_bits(
        RefundChain::Xmr,
        [0xCC; 32],
        "destination",
        1,
        &secret,
        10,
        TEST_BITS,
    )
    .unwrap();

    let wrong_secret = test_secret(99);
    let result = artifact.validate_solved_secret(&wrong_secret);
    assert!(result.is_err());
}

// Guarantee status tests with VTS artifacts

#[test]
fn vts_refund_artifact_returns_supported_guarantee() {
    let decision = xmr_wow_client::guarantee_decision(GuaranteeMode::VtsRefundArtifact);
    assert_eq!(decision.status, GuaranteeStatus::Supported);
}

#[test]
fn guidance_decision_with_vts_artifact_is_supported() {
    let params = test_params();
    let mut rng = rand::thread_rng();

    // Create a state machine, advance to WowLocked
    let (alice_state, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut rng);
    let (bob_state, bob_secret) = SwapState::generate(SwapRole::Bob, params.clone(), &mut rng);

    let bob_pub = match &bob_state {
        SwapState::KeyGeneration { my_pubkey, .. } => *my_pubkey,
        _ => unreachable!(),
    };
    let bob_proof = match &bob_state {
        SwapState::KeyGeneration { my_proof, .. } => my_proof.clone(),
        _ => unreachable!(),
    };

    let alice = alice_state
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    // Record WOW lock
    let wow_lock_tx = [0x11; 32];
    let alice_wow_locked = alice.record_wow_lock(wow_lock_tx).unwrap();

    // Without VTS artifact: should NOT be Supported
    let decision_without = xmr_wow_client::guidance_decision(&alice_wow_locked);
    assert!(decision_without.is_some());
    assert_ne!(
        decision_without.unwrap().status,
        GuaranteeStatus::Supported,
        "without VTS artifact, guarantee should NOT be Supported"
    );

    // Add VTS refund artifact
    let artifact = make_vts_artifact(
        RefundChain::Xmr,
        alice_wow_locked.swap_id().unwrap(),
        "4test_alice_refund_address",
        test_params().xmr_refund_delay_seconds,
        bob_secret,
    );
    let alice_with_artifact = alice_wow_locked.record_refund_artifact(artifact).unwrap();

    // WITH VTS artifact: should be Supported
    let decision_with = xmr_wow_client::guidance_decision(&alice_with_artifact);
    assert!(decision_with.is_some());
    assert_eq!(
        decision_with.unwrap().status,
        GuaranteeStatus::Supported,
        "with VTS artifact, guarantee MUST be Supported"
    );
}

// Persisted artifact serialization and solve

#[test]
fn persisted_artifact_serialization_round_trip() {
    let artifact = make_vts_artifact(
        RefundChain::Xmr,
        [0xDD; 32],
        "4test_alice_refund_address",
        1,
        test_secret(21),
    );
    let json = serde_json::to_string(&artifact).unwrap();
    let deserialized: PersistedRefundArtifact = serde_json::from_str(&json).unwrap();

    assert_eq!(artifact.metadata.chain, deserialized.metadata.chain);
    assert_eq!(artifact.metadata.swap_id, deserialized.metadata.swap_id);
    assert_eq!(
        artifact.metadata.secret_hash,
        deserialized.metadata.secret_hash
    );
}

#[test]
fn persisted_artifact_solve_recovers_secret() {
    let secret = test_secret(22);
    let artifact = make_vts_artifact(
        RefundChain::Xmr,
        [0xEE; 32],
        "4test_alice_refund_address",
        1,
        secret,
    );

    let recovered = artifact.solve().unwrap();
    assert_eq!(recovered, secret.to_vec());
}

#[test]
fn persisted_artifact_validate_binding_accepts_correct() {
    let swap_id = [0xFF; 32];
    let artifact = make_vts_artifact(
        RefundChain::Xmr,
        swap_id,
        "4test_alice_refund_address",
        1,
        test_secret(23),
    );

    let result = artifact.validate_binding(
        RefundChain::Xmr,
        swap_id,
        "4test_alice_refund_address",
        1,
        &artifact.metadata.locked_pubkey,
    );
    assert!(result.is_ok());
}

#[test]
fn persisted_artifact_validate_binding_rejects_wrong_chain() {
    let swap_id = [0xFF; 32];
    let artifact = make_vts_artifact(
        RefundChain::Xmr,
        swap_id,
        "4test_alice_refund_address",
        1,
        test_secret(24),
    );

    let result = artifact.validate_binding(
        RefundChain::Wow, // wrong chain
        swap_id,
        "4test_alice_refund_address",
        1,
        &artifact.metadata.locked_pubkey,
    );
    assert!(result.is_err());
}
