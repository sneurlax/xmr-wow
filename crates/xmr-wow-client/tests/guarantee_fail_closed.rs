use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, guarantee_decision, guidance_decision, validate_pre_risk_entry,
    GuaranteeMode, GuaranteeStatus, SwapParams, SwapRole, SwapState,
};

fn sample_params() -> SwapParams {
    let (refund_timing, xmr_refund_height, wow_refund_height) =
        build_observed_refund_timing(100, 200, 500, 800).unwrap();

    SwapParams {
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_height,
        wow_refund_height,
        refund_timing: Some(refund_timing),
        alice_refund_address: None,
        bob_refund_address: None,
    }
}

fn make_joint_address(role: SwapRole) -> SwapState {
    let params = sample_params();
    let (alice, _, bob, _) = make_alice_bob(params);

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

#[test]
fn phase13_complete_with_refund_requires_tx_hash() {
    let xmr_locked = make_joint_address(SwapRole::Alice)
        .record_xmr_lock([0xAA; 32])
        .unwrap();
    let refunded = xmr_locked.complete_with_refund([0xCC; 32]).unwrap();

    match refunded {
        SwapState::Refunded { refund_tx_hash, .. } => assert_eq!(refund_tx_hash, [0xCC; 32]),
        _ => panic!("expected refunded state"),
    }
}

#[test]
fn phase13_lock_progression_is_blocked_or_labeled_before_risky_steps() {
    let params = sample_params();
    let decision =
        validate_pre_risk_entry(&params, GuaranteeMode::CurrentSingleSignerPreLockArtifact)
            .unwrap();

    assert_eq!(decision.status, GuaranteeStatus::UnsupportedForGuarantee);
}

#[test]
fn phase13_cooperative_refund_commands_are_fail_closed() {
    let decision = guarantee_decision(GuaranteeMode::CooperativeRefundCommands);
    assert_eq!(decision.status, GuaranteeStatus::UnsupportedForGuarantee);
}

#[test]
fn phase13_legacy_refund_command_is_fail_closed() {
    let decision = guarantee_decision(GuaranteeMode::LegacyRefundNoEvidence);
    assert_eq!(decision.status, GuaranteeStatus::Blocked);
}

#[test]
fn phase13_legacy_persisted_swap_without_refund_timing_is_rejected() {
    let mut params = sample_params();
    params.refund_timing = None;

    let err = validate_pre_risk_entry(&params, GuaranteeMode::CurrentSingleSignerPreLockArtifact)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Phase 13 timing basis missing"),
        "error: {err}"
    );
}

#[test]
fn phase13_show_and_resume_surface_blocked_or_unsupported_guidance() {
    let joint_address = make_joint_address(SwapRole::Alice);
    let decision = guidance_decision(&joint_address).expect("guidance decision");
    assert_eq!(decision.status, GuaranteeStatus::UnsupportedForGuarantee);

    let xmr_locked = joint_address.record_xmr_lock([0xAA; 32]).unwrap();
    let decision = guidance_decision(&xmr_locked).expect("guidance decision");
    assert_eq!(decision.status, GuaranteeStatus::Blocked);
}
