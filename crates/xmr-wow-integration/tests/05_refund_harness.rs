use std::path::Path;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;
use simnet_testbed::{
    cuprate_simnet::SimnetWallet, wownero_simnet::WowSimnetWallet, SimnetTestbed,
};
use tempfile::tempdir;
use xmr_wow_client::{
    build_observed_refund_timing, decrypt_secret, derive_key, encrypt_secret,
    restore_secret_into_state, SwapParams, SwapRole, SwapState, SwapStore,
};
use xmr_wow_crypto::{combine_public_keys, derive_view_key, DleqProof, Network};
use xmr_wow_wallet::{
    verify_lock, CryptoNoteWallet, RefundArtifact, RefundChain, WowWallet, XmrWallet,
};

const TEST_VTS_BITS: u32 = 512;
const TEST_SQUARINGS_PER_SECOND: u64 = 10;

fn scalar_from_bytes(secret: [u8; 32]) -> Scalar {
    Scalar::from_canonical_bytes(secret)
        .into_option()
        .expect("stored secret must remain canonical")
}

fn random_point() -> EdwardsPoint {
    Scalar::random(&mut OsRng) * G
}

fn random_xmr_destination() -> String {
    let spend = random_point();
    let view = random_point();
    xmr_wow_crypto::encode_address(&spend, &view, Network::MoneroStagenet)
}

fn random_wow_destination() -> String {
    let spend = random_point();
    let view = random_point();
    xmr_wow_crypto::encode_address(&spend, &view, Network::Wownero)
}

fn sample_params(xmr_height: u64, wow_height: u64) -> SwapParams {
    let (refund_timing, xmr_refund_delay_seconds, wow_refund_delay_seconds) =
        build_observed_refund_timing(xmr_height, wow_height, 80, 240).unwrap();

    SwapParams {
        amount_xmr: 500_000_000_000,
        amount_wow: 500_000_000_000,
        xmr_refund_delay_seconds,
        wow_refund_delay_seconds,
        refund_timing: Some(refund_timing),
        alice_refund_address: Some(random_xmr_destination()),
        bob_refund_address: Some(random_wow_destination()),
    }
}

fn build_test_refund_artifact(
    chain: RefundChain,
    swap_id: [u8; 32],
    destination: &str,
    refund_delay_seconds: u64,
    locked_secret: &Scalar,
) -> RefundArtifact {
    RefundArtifact::new_with_bits(
        chain,
        swap_id,
        destination,
        refund_delay_seconds,
        locked_secret.as_bytes(),
        TEST_SQUARINGS_PER_SECOND,
        TEST_VTS_BITS,
    )
    .expect("test refund artifact should build")
}

fn extract_pubkey_and_proof(state: &SwapState) -> ([u8; 32], DleqProof) {
    match state {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        other => panic!("expected key generation state, got {}", phase_name(other)),
    }
}

fn phase_name(state: &SwapState) -> &'static str {
    match state {
        SwapState::KeyGeneration { .. } => "KeyGeneration",
        SwapState::DleqExchange { .. } => "DleqExchange",
        SwapState::JointAddress { .. } => "JointAddress",
        SwapState::WowLocked { .. } => "WowLocked",
        SwapState::XmrLocked { .. } => "XmrLocked",
        SwapState::Complete { .. } => "Complete",
        SwapState::Refunded { .. } => "Refunded",
    }
}

fn derive_joint_keys(
    alice_secret: [u8; 32],
    bob_secret: [u8; 32],
    alice_pubkey: [u8; 32],
    bob_pubkey: [u8; 32],
) -> (Scalar, EdwardsPoint, Scalar) {
    let alice_point = CompressedEdwardsY::from_slice(&alice_pubkey)
        .unwrap()
        .decompress()
        .unwrap();
    let bob_point = CompressedEdwardsY::from_slice(&bob_pubkey)
        .unwrap()
        .decompress()
        .unwrap();
    let joint_spend_point = combine_public_keys(&alice_point, &bob_point);
    let joint_spend_secret = scalar_from_bytes(alice_secret) + scalar_from_bytes(bob_secret);
    let joint_view_scalar = derive_view_key(&Scalar::from_bytes_mod_order(
        joint_spend_point.compress().to_bytes(),
    ));

    (joint_spend_secret, joint_spend_point, joint_view_scalar)
}

fn persist_and_reload(db_path: &Path, state: &SwapState, secret_bytes: [u8; 32]) -> SwapState {
    let swap_id = state.swap_id().expect("locked states must have swap ids");
    let password = b"proof-harness";

    let store = SwapStore::open(db_path.to_str().unwrap()).unwrap();
    let salt = store.get_or_create_salt().unwrap();
    let enc_key = derive_key(password, &salt);
    let encrypted = encrypt_secret(&enc_key, &secret_bytes);
    let state_json = serde_json::to_string(state).unwrap();
    store
        .save_with_secret(&swap_id, &state_json, Some(&encrypted))
        .unwrap();
    drop(store);

    let reopened = SwapStore::open(db_path.to_str().unwrap()).unwrap();
    let (state_json, encrypted_secret) = reopened.load_with_secret(&swap_id).unwrap().unwrap();
    let encrypted_secret = encrypted_secret.expect("encrypted secret should persist");
    let decrypted = decrypt_secret(&enc_key, &encrypted_secret).unwrap();
    let reloaded: SwapState = serde_json::from_str(&state_json).unwrap();
    restore_secret_into_state(reloaded, *decrypted)
        .unwrap()
        .refresh_refund_readiness()
        .unwrap()
}

async fn fund_senders(
    testbed: &SimnetTestbed,
    xmr_sender: &SimnetWallet,
    wow_sender: &WowSimnetWallet,
) {
    {
        let mut node = testbed.xmr_node().lock().await;
        node.mine_to(&xmr_sender.spend_pub, &xmr_sender.view_scalar, 2)
            .await
            .unwrap();
        node.mine_blocks(66).await.unwrap();
    }

    {
        let mut node = testbed.wow_node().lock().await;
        node.mine_to(&wow_sender.spend_pub, &wow_sender.view_scalar, 2)
            .await
            .unwrap();
        node.mine_blocks(100).await.unwrap();
    }
}

#[tokio::test]
async fn happy_path_uses_real_wallets_and_swap_state_on_simnet() {
    let testbed = SimnetTestbed::new().await.unwrap();
    let params = sample_params(
        testbed.xmr_height().await.unwrap(),
        testbed.wow_height().await.unwrap(),
    );

    let xmr_sender = SimnetWallet::generate();
    let wow_sender = WowSimnetWallet::generate();
    fund_senders(&testbed, &xmr_sender, &wow_sender).await;

    let (alice, alice_secret) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, bob_secret) = SwapState::generate(SwapRole::Bob, params.clone(), &mut OsRng);
    let (alice_pubkey, alice_proof) = extract_pubkey_and_proof(&alice);
    let (bob_pubkey, bob_proof) = extract_pubkey_and_proof(&bob);

    let alice_joint = alice
        .receive_counterparty_key(bob_pubkey, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();
    let bob_joint = bob
        .receive_counterparty_key(alice_pubkey, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();
    let (_joint_spend_secret, joint_spend_point, joint_view_scalar) =
        derive_joint_keys(alice_secret, bob_secret, alice_pubkey, bob_pubkey);

    let wow_lock_wallet = WowWallet::with_sender_keys(
        testbed.wow_rpc_url(),
        *wow_sender.spend_scalar,
        *wow_sender.view_scalar,
    );
    let wow_lock_tx = wow_lock_wallet
        .lock(&joint_spend_point, &joint_view_scalar, params.amount_wow)
        .await
        .unwrap();
    testbed.mine_wow(1).await.unwrap();

    verify_lock(
        &WowWallet::new(testbed.wow_rpc_url()),
        &joint_spend_point,
        &joint_view_scalar,
        params.amount_wow,
        0,
    )
    .await
    .unwrap();

    let bob_wow_locked = bob_joint.record_wow_lock(wow_lock_tx).unwrap();
    let bob_wow_artifact = build_test_refund_artifact(
        RefundChain::Wow,
        bob_wow_locked.swap_id().unwrap(),
        params.bob_refund_address.as_deref().unwrap(),
        params.wow_refund_delay_seconds,
        &scalar_from_bytes(alice_secret),
    );
    let bob_wow_locked = bob_wow_locked
        .record_refund_artifact(bob_wow_artifact.into())
        .unwrap();
    bob_wow_locked.validate_refund_artifact().unwrap();

    let alice_wow_locked = alice_joint.record_wow_lock(wow_lock_tx).unwrap();

    let xmr_lock_wallet = XmrWallet::with_sender_keys(
        testbed.xmr_rpc_url(),
        *xmr_sender.spend_scalar,
        *xmr_sender.view_scalar,
    );
    let xmr_lock_tx = xmr_lock_wallet
        .lock(&joint_spend_point, &joint_view_scalar, params.amount_xmr)
        .await
        .unwrap();
    testbed.mine_xmr(1).await.unwrap();

    verify_lock(
        &XmrWallet::new(testbed.xmr_rpc_url()),
        &joint_spend_point,
        &joint_view_scalar,
        params.amount_xmr,
        0,
    )
    .await
    .unwrap();

    let alice_xmr_locked = alice_wow_locked.record_xmr_lock(xmr_lock_tx).unwrap();
    let alice_xmr_artifact = build_test_refund_artifact(
        RefundChain::Xmr,
        alice_xmr_locked.swap_id().unwrap(),
        params.alice_refund_address.as_deref().unwrap(),
        params.xmr_refund_delay_seconds,
        &scalar_from_bytes(bob_secret),
    );
    let alice_xmr_locked = alice_xmr_locked
        .record_refund_artifact(alice_xmr_artifact.into())
        .unwrap();
    alice_xmr_locked.validate_refund_artifact().unwrap();

    let bob_xmr_locked = bob_wow_locked.record_xmr_lock(xmr_lock_tx).unwrap();

    let bob_pre_sig = match &bob_xmr_locked {
        SwapState::XmrLocked {
            counterparty_pre_sig: None,
            my_adaptor_pre_sig,
            ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("Bob should have produced a pre-sig after both locks"),
    };
    let alice_pre_sig = match &alice_xmr_locked {
        SwapState::XmrLocked {
            counterparty_pre_sig: None,
            my_adaptor_pre_sig,
            ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("Alice should have produced a pre-sig after both locks"),
    };

    let alice_ready = alice_xmr_locked
        .receive_counterparty_pre_sig(bob_pre_sig.clone())
        .unwrap();
    let bob_ready = bob_xmr_locked
        .receive_counterparty_pre_sig(alice_pre_sig.clone())
        .unwrap();

    let bob_completed_sig = bob_pre_sig
        .complete(&scalar_from_bytes(bob_secret))
        .unwrap();
    let (alice_complete, extracted_bob) = alice_ready
        .complete_with_adaptor_claim(&bob_completed_sig)
        .unwrap();
    assert_eq!(extracted_bob.to_bytes(), bob_secret);

    let wow_claim_destination = random_wow_destination();
    let wow_claim_wallet = WowWallet::new(testbed.wow_rpc_url());
    let wow_claim_tx = wow_claim_wallet
        .sweep(
            &(scalar_from_bytes(alice_secret) + extracted_bob),
            &joint_view_scalar,
            &wow_claim_destination,
        )
        .await
        .unwrap();
    testbed.mine_wow(1).await.unwrap();
    assert!(
        wow_claim_wallet
            .poll_confirmation(&wow_claim_tx, 1)
            .await
            .unwrap()
            .confirmed
    );
    assert!(matches!(alice_complete, SwapState::Complete { .. }));

    let alice_completed_sig = alice_pre_sig
        .complete(&scalar_from_bytes(alice_secret))
        .unwrap();
    let (bob_complete, extracted_alice) = bob_ready
        .complete_with_adaptor_claim(&alice_completed_sig)
        .unwrap();
    assert_eq!(extracted_alice.to_bytes(), alice_secret);

    let xmr_claim_destination = random_xmr_destination();
    let xmr_claim_wallet = XmrWallet::new(testbed.xmr_rpc_url());
    let xmr_claim_tx = xmr_claim_wallet
        .sweep(
            &(extracted_alice + scalar_from_bytes(bob_secret)),
            &joint_view_scalar,
            &xmr_claim_destination,
        )
        .await
        .unwrap();
    testbed.mine_xmr(1).await.unwrap();
    assert!(
        xmr_claim_wallet
            .poll_confirmation(&xmr_claim_tx, 1)
            .await
            .unwrap()
            .confirmed
    );
    assert!(matches!(bob_complete, SwapState::Complete { .. }));
}

#[tokio::test]
async fn refund_artifact_survives_restart_and_solves_to_real_sweep() {
    let testbed = SimnetTestbed::new().await.unwrap();
    let params = sample_params(
        testbed.xmr_height().await.unwrap(),
        testbed.wow_height().await.unwrap(),
    );
    let wow_sender = WowSimnetWallet::generate();

    {
        let mut node = testbed.wow_node().lock().await;
        node.mine_to(&wow_sender.spend_pub, &wow_sender.view_scalar, 2)
            .await
            .unwrap();
        node.mine_blocks(100).await.unwrap();
    }

    let (alice, alice_secret) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, bob_secret) = SwapState::generate(SwapRole::Bob, params.clone(), &mut OsRng);
    let (alice_pubkey, alice_proof) = extract_pubkey_and_proof(&alice);
    let (bob_pubkey, bob_proof) = extract_pubkey_and_proof(&bob);
    let bob_joint = bob
        .receive_counterparty_key(alice_pubkey, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();
    let (_alice_joint, _, _) = (
        alice
            .receive_counterparty_key(bob_pubkey, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap(),
        alice_secret,
        bob_secret,
    );
    let (joint_spend_secret, joint_spend_point, joint_view_scalar) =
        derive_joint_keys(alice_secret, bob_secret, alice_pubkey, bob_pubkey);

    let wow_wallet = WowWallet::with_sender_keys(
        testbed.wow_rpc_url(),
        *wow_sender.spend_scalar,
        *wow_sender.view_scalar,
    );
    let wow_lock_tx = wow_wallet
        .lock(&joint_spend_point, &joint_view_scalar, params.amount_wow)
        .await
        .unwrap();
    testbed.mine_wow(1).await.unwrap();

    let bob_wow_locked = bob_joint.record_wow_lock(wow_lock_tx).unwrap();
    let artifact = build_test_refund_artifact(
        RefundChain::Wow,
        bob_wow_locked.swap_id().unwrap(),
        params.bob_refund_address.as_deref().unwrap(),
        params.wow_refund_delay_seconds,
        &scalar_from_bytes(alice_secret),
    );
    let bob_wow_locked = bob_wow_locked
        .record_refund_artifact(artifact.clone().into())
        .unwrap();
    let next_action_before_restart = bob_wow_locked.next_safe_action();

    let tempdir = tempdir().unwrap();
    let reloaded = persist_and_reload(
        &tempdir.path().join("refund.sqlite"),
        &bob_wow_locked,
        bob_secret,
    );
    assert!(reloaded.refund_artifact().is_some());
    reloaded.validate_refund_artifact().unwrap();
    assert_eq!(reloaded.next_safe_action(), next_action_before_restart);

    let before_xmr = reloaded.before_wow_lock_checkpoint().unwrap();
    assert!(before_xmr.artifact_present);
    assert!(before_xmr.artifact_validated);

    let sweep_wallet = WowWallet::new(testbed.wow_rpc_url());
    let solved_secret = artifact.solve().unwrap();
    artifact.validate_solved_secret(&solved_secret).unwrap();
    let solved_scalar = scalar_from_bytes(
        solved_secret
            .try_into()
            .expect("joint spend secret must stay 32 bytes"),
    );
    assert_eq!(solved_scalar, scalar_from_bytes(alice_secret));
    let refund_spend_secret = solved_scalar + scalar_from_bytes(bob_secret);
    assert_eq!(refund_spend_secret, joint_spend_secret);

    let refund_tx_hash = sweep_wallet
        .sweep(
            &refund_spend_secret,
            &joint_view_scalar,
            params.bob_refund_address.as_deref().unwrap(),
        )
        .await
        .unwrap();
    testbed.mine_wow(1).await.unwrap();
    assert!(
        sweep_wallet
            .poll_confirmation(&refund_tx_hash, 1)
            .await
            .unwrap()
            .confirmed
    );

    let refunded = reloaded.complete_with_refund(refund_tx_hash).unwrap();
    match refunded {
        SwapState::Refunded {
            refund_tx_hash: stored_hash,
            refund_evidence: Some(evidence),
            ..
        } => {
            assert_eq!(stored_hash, refund_tx_hash);
            assert_eq!(evidence.refund_tx_hash, refund_tx_hash);
            assert_eq!(evidence.chain, xmr_wow_wallet::RefundChain::Wow);
        }
        other => panic!("expected refunded state, got {}", phase_name(&other)),
    }
}
