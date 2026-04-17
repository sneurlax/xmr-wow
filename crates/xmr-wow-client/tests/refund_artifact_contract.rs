use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, guarantee_decision, guidance_decision, GuaranteeMode,
    GuaranteeStatus, PersistedRefundArtifact, SwapParams, SwapRole, SwapState,
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

fn make_joint_address(role: SwapRole) -> (SwapState, [u8; 32]) {
    let params = sample_params();
    let (alice, alice_secret, bob, bob_secret) = make_alice_bob(params);

    match role {
        SwapRole::Alice => {
            let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
            (
                alice
                    .receive_counterparty_key(bob_pub, &bob_proof)
                    .unwrap()
                    .derive_joint_addresses()
                    .unwrap(),
                bob_secret,
            )
        }
        SwapRole::Bob => {
            let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);
            (
                bob.receive_counterparty_key(alice_pub, &alice_proof)
                    .unwrap()
                    .derive_joint_addresses()
                    .unwrap(),
                alice_secret,
            )
        }
    }
}

fn build_artifact(
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

fn sample_artifact(state: &SwapState, counterparty_secret: [u8; 32]) -> PersistedRefundArtifact {
    let (chain, swap_id, destination, refund_delay_seconds) = match state {
        SwapState::JointAddress {
            role,
            params,
            addresses,
            ..
        }
        | SwapState::WowLocked {
            role,
            params,
            addresses,
            ..
        }
        | SwapState::XmrLocked {
            role,
            params,
            addresses,
            ..
        } => match role {
            SwapRole::Alice => (
                RefundChain::Xmr,
                addresses.swap_id,
                params.alice_refund_address.as_deref().unwrap(),
                params.xmr_refund_delay_seconds,
            ),
            SwapRole::Bob => (
                RefundChain::Wow,
                addresses.swap_id,
                params.bob_refund_address.as_deref().unwrap(),
                params.wow_refund_delay_seconds,
            ),
        },
        _ => panic!("expected joint or locked swap state"),
    };

    build_artifact(
        chain,
        swap_id,
        destination,
        refund_delay_seconds,
        counterparty_secret,
    )
}

#[test]
fn state_persists_symmetric_refund_artifact_record() {
    let (bob_joint, alice_secret) = make_joint_address(SwapRole::Bob);
    let bob_artifact = sample_artifact(&bob_joint, alice_secret);
    let wow_locked = bob_joint
        .record_wow_lock([0xAA; 32])
        .unwrap()
        .record_refund_artifact(bob_artifact)
        .unwrap();
    wow_locked.validate_refund_artifact().unwrap();
    let wow_swap_id = wow_locked.swap_id().unwrap();

    let (alice_joint, bob_secret) = make_joint_address(SwapRole::Alice);
    let alice_artifact = sample_artifact(&alice_joint, bob_secret);
    let xmr_locked = alice_joint
        .record_xmr_lock([0xBB; 32])
        .unwrap()
        .record_refund_artifact(alice_artifact)
        .unwrap();
    xmr_locked.validate_refund_artifact().unwrap();
    let xmr_swap_id = xmr_locked.swap_id().unwrap();

    match wow_locked {
        SwapState::WowLocked {
            refund_artifact: Some(refund_artifact),
            ..
        } => {
            assert_eq!(refund_artifact.metadata.chain, RefundChain::Wow);
            assert_eq!(refund_artifact.metadata.swap_id, wow_swap_id);
        }
        _ => panic!("expected wow locked state"),
    }

    match xmr_locked {
        SwapState::XmrLocked {
            refund_artifact: Some(refund_artifact),
            ..
        } => {
            assert_eq!(refund_artifact.metadata.chain, RefundChain::Xmr);
            assert_eq!(refund_artifact.metadata.swap_id, xmr_swap_id);
        }
        _ => panic!("expected xmr locked state"),
    }
}

#[test]
fn locked_state_rejects_artifact_with_wrong_chain_or_lock_identity() {
    let (bob_joint, alice_secret) = make_joint_address(SwapRole::Bob);
    let wow_locked = bob_joint.record_wow_lock([0xAA; 32]).unwrap();
    let wrong_chain = build_artifact(
        RefundChain::Xmr,
        wow_locked.swap_id().unwrap(),
        "bob-refund-address",
        sample_params().wow_refund_delay_seconds,
        alice_secret,
    );
    let err = wow_locked
        .record_refund_artifact(wrong_chain)
        .unwrap_err()
        .to_string();
    assert!(err.contains("chain mismatch"), "error: {err}");

    let (alice_joint, bob_secret) = make_joint_address(SwapRole::Alice);
    let xmr_locked = alice_joint.record_xmr_lock([0xBB; 32]).unwrap();
    let wrong_lock = build_artifact(
        RefundChain::Xmr,
        [0xCC; 32],
        "alice-refund-address",
        sample_params().xmr_refund_delay_seconds,
        bob_secret,
    );
    let err = xmr_locked
        .record_refund_artifact(wrong_lock)
        .unwrap_err()
        .to_string();
    assert!(err.contains("swap_id mismatch"), "error: {err}");
}

#[test]
fn fail_closed_guards_still_hold() {
    let (bob_joint, alice_secret) = make_joint_address(SwapRole::Bob);
    let bob_artifact = sample_artifact(&bob_joint, alice_secret);
    let wow_locked = bob_joint
        .record_wow_lock([0xAA; 32])
        .unwrap()
        .record_refund_artifact(bob_artifact)
        .unwrap();
    let (alice_joint, bob_secret) = make_joint_address(SwapRole::Alice);
    let alice_artifact = sample_artifact(&alice_joint, bob_secret);
    let xmr_locked = alice_joint
        .record_xmr_lock([0xBB; 32])
        .unwrap()
        .record_refund_artifact(alice_artifact)
        .unwrap();

    assert_eq!(
        guidance_decision(&wow_locked).unwrap().status,
        GuaranteeStatus::Supported
    );
    assert_eq!(
        guidance_decision(&xmr_locked).unwrap().status,
        GuaranteeStatus::Supported
    );
    assert_eq!(
        guarantee_decision(GuaranteeMode::CooperativeRefundCommands).status,
        GuaranteeStatus::UnsupportedForGuarantee
    );
}
