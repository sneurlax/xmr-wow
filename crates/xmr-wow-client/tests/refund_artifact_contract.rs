use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, guarantee_decision, guidance_decision, GuaranteeMode,
    GuaranteeStatus, PersistedRefundArtifact, SwapParams, SwapRole, SwapState,
};
use xmr_wow_wallet::{RefundArtifact, RefundChain};

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

fn sample_artifact(
    chain: RefundChain,
    lock_tx_hash: [u8; 32],
    destination: &str,
    refund_height: u64,
    tx_hash: [u8; 32],
) -> PersistedRefundArtifact {
    RefundArtifact::new(
        chain,
        lock_tx_hash,
        destination,
        refund_height,
        tx_hash,
        b"phase14-artifact-payload".to_vec(),
    )
    .into()
}

#[test]
fn phase14_state_persists_symmetric_refund_artifact_record() {
    let wow_locked = make_joint_address(SwapRole::Bob)
        .record_wow_lock([0xAA; 32])
        .unwrap()
        .record_refund_artifact(sample_artifact(
            RefundChain::Wow,
            [0xAA; 32],
            "bob-refund-address",
            sample_params().wow_refund_height,
            [0xBA; 32],
        ))
        .unwrap();
    wow_locked.validate_refund_artifact().unwrap();

    let xmr_locked = make_joint_address(SwapRole::Alice)
        .record_xmr_lock([0xBB; 32])
        .unwrap()
        .record_refund_artifact(sample_artifact(
            RefundChain::Xmr,
            [0xBB; 32],
            "alice-refund-address",
            sample_params().xmr_refund_height,
            [0xCB; 32],
        ))
        .unwrap();
    xmr_locked.validate_refund_artifact().unwrap();

    match wow_locked {
        SwapState::WowLocked {
            refund_artifact: Some(refund_artifact),
            ..
        } => {
            assert_eq!(refund_artifact.metadata.chain, RefundChain::Wow);
            assert_eq!(refund_artifact.metadata.lock_tx_hash, [0xAA; 32]);
        }
        _ => panic!("expected wow locked state"),
    }

    match xmr_locked {
        SwapState::XmrLocked {
            refund_artifact: Some(refund_artifact),
            ..
        } => {
            assert_eq!(refund_artifact.metadata.chain, RefundChain::Xmr);
            assert_eq!(refund_artifact.metadata.lock_tx_hash, [0xBB; 32]);
        }
        _ => panic!("expected xmr locked state"),
    }
}

#[test]
fn phase14_locked_state_rejects_artifact_with_wrong_chain_or_lock_identity() {
    let wow_locked = make_joint_address(SwapRole::Bob)
        .record_wow_lock([0xAA; 32])
        .unwrap();
    let wrong_chain = sample_artifact(
        RefundChain::Xmr,
        [0xAA; 32],
        "bob-refund-address",
        sample_params().wow_refund_height,
        [0xDA; 32],
    );
    let err = wow_locked
        .record_refund_artifact(wrong_chain)
        .unwrap_err()
        .to_string();
    assert!(err.contains("chain mismatch"), "error: {err}");

    let xmr_locked = make_joint_address(SwapRole::Alice)
        .record_xmr_lock([0xBB; 32])
        .unwrap();
    let wrong_lock = sample_artifact(
        RefundChain::Xmr,
        [0xCC; 32],
        "alice-refund-address",
        sample_params().xmr_refund_height,
        [0xEA; 32],
    );
    let err = xmr_locked
        .record_refund_artifact(wrong_lock)
        .unwrap_err()
        .to_string();
    assert!(err.contains("lock tx mismatch"), "error: {err}");
}

#[test]
fn phase14_phase13_fail_closed_guards_still_hold() {
    let wow_locked = make_joint_address(SwapRole::Bob)
        .record_wow_lock([0xAA; 32])
        .unwrap()
        .record_refund_artifact(sample_artifact(
            RefundChain::Wow,
            [0xAA; 32],
            "bob-refund-address",
            sample_params().wow_refund_height,
            [0xFA; 32],
        ))
        .unwrap();
    let xmr_locked = make_joint_address(SwapRole::Alice)
        .record_xmr_lock([0xBB; 32])
        .unwrap()
        .record_refund_artifact(sample_artifact(
            RefundChain::Xmr,
            [0xBB; 32],
            "alice-refund-address",
            sample_params().xmr_refund_height,
            [0xFB; 32],
        ))
        .unwrap();

    assert_eq!(
        guidance_decision(&wow_locked).unwrap().status,
        GuaranteeStatus::UnsupportedForGuarantee
    );
    assert_eq!(
        guidance_decision(&xmr_locked).unwrap().status,
        GuaranteeStatus::Blocked
    );
    assert_eq!(
        guarantee_decision(GuaranteeMode::CooperativeRefundCommands).status,
        GuaranteeStatus::UnsupportedForGuarantee
    );
}
