use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, RefundCheckpointName, RefundCheckpointStatus, RefundEvidence,
    SwapParams, SwapRole, SwapState,
};
use xmr_wow_wallet::RefundChain;

fn sample_params() -> SwapParams {
    let (refund_timing, xmr_refund_height, wow_refund_height) =
        build_observed_refund_timing(100, 200, 500, 800).unwrap();

    SwapParams {
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_height,
        wow_refund_height,
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
fn phase15_joint_address_persists_before_wow_lock_checkpoint() {
    let state = make_joint_address(SwapRole::Bob);
    let checkpoint = state.before_wow_lock_checkpoint().expect("checkpoint");

    assert_eq!(checkpoint.name, RefundCheckpointName::BeforeWowLock);
    assert_eq!(checkpoint.chain, RefundChain::Wow);
    assert_eq!(
        checkpoint.refund_address.as_deref(),
        Some("bob-refund-address")
    );
    assert_eq!(
        checkpoint.status,
        RefundCheckpointStatus::UnsupportedForGuarantee
    );
    assert!(!checkpoint.artifact_present);
    assert!(!checkpoint.artifact_validated);
}

#[test]
fn phase15_locked_states_persist_before_xmr_lock_checkpoint_and_refund_evidence_shape() {
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
            refund_evidence: Some(RefundEvidence { chain, refund_tx_hash: evidence_hash, confirmed_height }),
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
fn phase15_lock_commands_fail_before_network_work_when_checkpoint_not_ready() {
    let joint_bob = make_joint_address(SwapRole::Bob);
    let err = joint_bob
        .require_checkpoint_ready(RefundCheckpointName::BeforeWowLock)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unsupported-for-guarantee"), "error: {err}");

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
fn phase15_show_and_resume_surface_checkpoint_specific_safe_next_actions() {
    let joint_bob = make_joint_address(SwapRole::Bob);
    let bob_action = joint_bob.next_safe_action();
    assert!(bob_action.contains("Do not run lock-wow"), "action: {bob_action}");
    assert!(
        bob_action.contains("before WOW lock is unsupported-for-guarantee"),
        "action: {bob_action}"
    );

    let joint_alice = make_joint_address(SwapRole::Alice);
    let alice_action = joint_alice.next_safe_action();
    assert!(alice_action.contains("Wait. Bob's before WOW lock checkpoint"), "action: {alice_action}");

    let wow_locked_alice = joint_alice.record_wow_lock([0xAA; 32]).unwrap();
    let xmr_action = wow_locked_alice.next_safe_action();
    assert!(xmr_action.contains("Do not run lock-xmr"), "action: {xmr_action}");
    assert!(
        xmr_action.contains("before XMR lock is blocked"),
        "action: {xmr_action}"
    );
}

#[test]
fn phase15_checkpoint_status_survives_restart_style_state_reload() {
    let state = make_joint_address(SwapRole::Bob);
    let checkpoint = state.before_wow_lock_checkpoint().cloned().unwrap();

    let json = serde_json::to_string(&state).unwrap();
    let restored: SwapState = serde_json::from_str(&json).unwrap();
    let restored = restored.refresh_refund_readiness().unwrap();

    assert_eq!(
        restored.before_wow_lock_checkpoint().expect("restored checkpoint"),
        &checkpoint
    );
}
