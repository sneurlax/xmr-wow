use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, PersistedRefundArtifact, RefundCheckpointName,
    RefundCheckpointStatus, RefundEvidence, SwapParams, SwapRole, SwapState,
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

fn make_alice_bob(params: SwapParams) -> (SwapState, SwapState) {
    let (alice, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, _) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);
    (alice, bob)
}

fn make_alice_bob_with_secrets(
    params: SwapParams,
) -> (SwapState, [u8; 32], SwapState, [u8; 32]) {
    let (alice, alice_secret) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, bob_secret) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);
    (alice, alice_secret, bob, bob_secret)
}

fn build_vts_artifact(
    chain: RefundChain,
    swap_id: [u8; 32],
    destination: &str,
    refund_delay_seconds: u64,
    counterparty_secret: [u8; 32],
) -> PersistedRefundArtifact {
    RefundArtifact::new_with_bits(
        chain,
        swap_id,
        destination,
        refund_delay_seconds,
        &counterparty_secret,
        TEST_SQUARINGS_PER_SECOND,
        TEST_VTS_BITS,
    )
    .expect("test VTS artifact should build")
    .into()
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

fn make_joint_address(role: SwapRole) -> SwapState {
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    match role {
        SwapRole::Alice => {
            let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
            alice
                .receive_counterparty_key(bob_pub, &bob_proof)
                .unwrap()
                .derive_joint_addresses()
                .unwrap()
        }
        SwapRole::Bob => {
            let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);
            bob.receive_counterparty_key(alice_pub, &alice_proof)
                .unwrap()
                .derive_joint_addresses()
                .unwrap()
        }
    }
}

#[test]
fn joint_address_persists_before_wow_lock_checkpoint() {
    let state = make_joint_address(SwapRole::Bob);
    let checkpoint = state.before_wow_lock_checkpoint().expect("checkpoint");

    assert_eq!(checkpoint.name, RefundCheckpointName::BeforeWowLock);
    assert_eq!(checkpoint.chain, RefundChain::Wow);
    assert_eq!(
        checkpoint.refund_address.as_deref(),
        Some("bob-refund-address")
    );
    assert_eq!(checkpoint.status, RefundCheckpointStatus::Blocked);
    assert!(!checkpoint.artifact_present);
    assert!(!checkpoint.artifact_validated);
}

#[test]
fn locked_states_persist_before_xmr_lock_checkpoint_and_refund_evidence_shape() {
    let wow_locked = make_joint_address(SwapRole::Bob)
        .record_wow_lock([0xAA; 32])
        .unwrap();
    let checkpoint = wow_locked
        .before_xmr_lock_checkpoint()
        .expect("before_xmr checkpoint");
    assert_eq!(checkpoint.name, RefundCheckpointName::BeforeXmrLock);
    assert_eq!(checkpoint.chain, RefundChain::Xmr);
    assert_eq!(
        checkpoint.refund_address.as_deref(),
        Some("alice-refund-address")
    );
    assert_eq!(checkpoint.status, RefundCheckpointStatus::Blocked);

    let refunded = wow_locked.complete_with_refund([0xCC; 32]).unwrap();
    match refunded {
        SwapState::Refunded {
            refund_tx_hash,
            refund_evidence:
                Some(RefundEvidence {
                    chain,
                    refund_tx_hash: evidence_hash,
                    confirmed_height,
                }),
            ..
        } => {
            assert_eq!(refund_tx_hash, [0xCC; 32]);
            assert_eq!(evidence_hash, [0xCC; 32]);
            assert_eq!(chain, RefundChain::Wow);
            assert_eq!(confirmed_height, None);
        }
        _ => panic!("expected refunded state with evidence"),
    }
}

#[test]
fn lock_commands_fail_before_network_work_when_checkpoint_not_ready() {
    let joint_bob = make_joint_address(SwapRole::Bob);
    let err = joint_bob
        .require_checkpoint_ready(RefundCheckpointName::BeforeWowLock)
        .unwrap_err()
        .to_string();
    assert!(err.contains("blocked"), "error: {err}");

    let wow_locked_alice = make_joint_address(SwapRole::Alice)
        .record_wow_lock([0xAA; 32])
        .unwrap();
    let err = wow_locked_alice
        .require_checkpoint_ready(RefundCheckpointName::BeforeXmrLock)
        .unwrap_err()
        .to_string();
    assert!(err.contains("blocked"), "error: {err}");
}

#[test]
fn show_and_resume_surface_checkpoint_specific_safe_next_actions() {
    let joint_bob = make_joint_address(SwapRole::Bob);
    let bob_action = joint_bob.next_safe_action();
    assert!(
        bob_action.contains("Do not run lock-wow"),
        "action: {bob_action}"
    );
    assert!(
        bob_action.contains("before WOW lock is blocked"),
        "action: {bob_action}"
    );

    let joint_alice = make_joint_address(SwapRole::Alice);
    let alice_action = joint_alice.next_safe_action();
    assert!(
        alice_action.contains("Wait. Bob's before WOW lock checkpoint"),
        "action: {alice_action}"
    );

    let wow_locked_alice = joint_alice.record_wow_lock([0xAA; 32]).unwrap();
    let xmr_action = wow_locked_alice.next_safe_action();
    assert!(
        xmr_action.contains("Do not run lock-xmr"),
        "action: {xmr_action}"
    );
    assert!(
        xmr_action.contains("before XMR lock is blocked"),
        "action: {xmr_action}"
    );
}

#[test]
fn checkpoint_status_survives_restart_style_state_reload() {
    let state = make_joint_address(SwapRole::Bob);
    let checkpoint = state.before_wow_lock_checkpoint().cloned().unwrap();

    let json = serde_json::to_string(&state).unwrap();
    let restored: SwapState = serde_json::from_str(&json).unwrap();
    let restored = restored.refresh_refund_readiness().unwrap();

    assert_eq!(
        restored
            .before_wow_lock_checkpoint()
            .expect("restored checkpoint"),
        &checkpoint
    );
}

#[test]
fn before_wow_lock_becomes_ready_after_bob_records_exchanged_artifact() {
    let params = sample_params();
    let (alice, alice_secret, bob, _bob_secret) = make_alice_bob_with_secrets(params.clone());
    let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);
    let bob_joint = bob
        .receive_counterparty_key(alice_pub, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();
    let swap_id = match &bob_joint {
        SwapState::JointAddress { addresses, .. } => addresses.swap_id,
        _ => panic!("expected joint address"),
    };

    let pre_checkpoint = bob_joint
        .before_wow_lock_checkpoint()
        .expect("pre-artifact checkpoint must be recorded");
    assert_eq!(pre_checkpoint.status, RefundCheckpointStatus::Blocked);
    assert!(!pre_checkpoint.artifact_present);

    let artifact = build_vts_artifact(
        RefundChain::Wow,
        swap_id,
        params.bob_refund_address.as_deref().unwrap(),
        params.wow_refund_delay_seconds,
        alice_secret,
    );

    let bob_with_artifact = bob_joint.record_refund_artifact(artifact).unwrap();
    let ready_checkpoint = bob_with_artifact
        .before_wow_lock_checkpoint()
        .expect("post-exchange checkpoint");

    assert_eq!(ready_checkpoint.status, RefundCheckpointStatus::Ready);
    assert!(ready_checkpoint.artifact_present);
    assert!(ready_checkpoint.artifact_validated);

    // require_checkpoint_ready should accept without the proof-harness shortcut.
    bob_with_artifact
        .require_checkpoint_ready(RefundCheckpointName::BeforeWowLock)
        .unwrap();

    // Reload round-trip: JSON-serialize, deserialize, refresh, and confirm the
    // checkpoint survives as Ready. This matches the SQLite reload path.
    let json = serde_json::to_string(&bob_with_artifact).unwrap();
    let restored: SwapState = serde_json::from_str(&json).unwrap();
    let restored = restored.refresh_refund_readiness().unwrap();
    let restored_checkpoint = restored
        .before_wow_lock_checkpoint()
        .expect("restored checkpoint");
    assert_eq!(restored_checkpoint.status, RefundCheckpointStatus::Ready);
    assert!(restored_checkpoint.artifact_validated);
}

#[test]
fn before_xmr_lock_becomes_ready_after_alice_records_exchanged_artifact() {
    let params = sample_params();
    let (alice, _alice_secret, bob, bob_secret) = make_alice_bob_with_secrets(params.clone());
    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let alice_wow_locked = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap()
        .record_wow_lock([0xAA; 32])
        .unwrap();

    let swap_id = alice_wow_locked.swap_id().unwrap();
    let pre_checkpoint = alice_wow_locked
        .before_xmr_lock_checkpoint()
        .expect("pre-artifact xmr checkpoint");
    assert_eq!(pre_checkpoint.status, RefundCheckpointStatus::Blocked);

    let artifact = build_vts_artifact(
        RefundChain::Xmr,
        swap_id,
        params.alice_refund_address.as_deref().unwrap(),
        params.xmr_refund_delay_seconds,
        bob_secret,
    );

    let alice_with_artifact = alice_wow_locked.record_refund_artifact(artifact).unwrap();
    let ready_checkpoint = alice_with_artifact
        .before_xmr_lock_checkpoint()
        .expect("post-exchange xmr checkpoint");
    assert_eq!(ready_checkpoint.status, RefundCheckpointStatus::Ready);
    assert!(ready_checkpoint.artifact_validated);

    alice_with_artifact
        .require_checkpoint_ready(RefundCheckpointName::BeforeXmrLock)
        .unwrap();

    let json = serde_json::to_string(&alice_with_artifact).unwrap();
    let restored: SwapState = serde_json::from_str(&json).unwrap();
    let restored = restored.refresh_refund_readiness().unwrap();
    let restored_checkpoint = restored
        .before_xmr_lock_checkpoint()
        .expect("restored xmr checkpoint");
    assert_eq!(restored_checkpoint.status, RefundCheckpointStatus::Ready);
    assert!(restored_checkpoint.artifact_validated);
}
