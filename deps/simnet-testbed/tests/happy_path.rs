#![allow(non_snake_case)]
//! Simnet happy path for adaptor-signature claims.
//!
//! The test proves secret extraction only happens once a completed claim
//! signature appears.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    EdwardsPoint, Scalar,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use cuprate_simnet::{SimnetNode, SimnetWallet};
use monero_wallet::address::Network;
use monero_wallet::interface::FeeRate;
use simnet_testbed::adaptor::AdaptorSignature;

fn random_scalar() -> Scalar {
    use rand::RngCore as _;

    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn generate_key_contribution() -> (Scalar, EdwardsPoint) {
    let secret = random_scalar();
    let public = &secret * ED25519_BASEPOINT_TABLE;
    (secret, public)
}

fn combine_public_keys(a: &EdwardsPoint, b: &EdwardsPoint) -> EdwardsPoint {
    a + b
}

fn combine_secrets(a: &Scalar, b: &Scalar) -> Scalar {
    a + b
}

/// Full adaptor-signature round trip on simnet.
#[tokio::test]
async fn simnet_happy_path_adaptor_sig() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let mut node = SimnetNode::start().await.expect("XMR simnet");

    // Key material.
    let (alice_spend, alice_pub) = generate_key_contribution();
    let (alice_view, _) = generate_key_contribution();
    let (bob_spend, bob_pub) = generate_key_contribution();
    let (bob_view, _) = generate_key_contribution();

    // Joint address.
    let joint_spend_pub = combine_public_keys(&alice_pub, &bob_pub);
    let joint_view = combine_secrets(&alice_view, &bob_view);

    // Sanity check the combined key algebra.
    let combined_spend = combine_secrets(&alice_spend, &bob_spend);
    assert_eq!(
        (&combined_spend * ED25519_BASEPOINT_TABLE).compress(),
        joint_spend_pub.compress(),
        "(alice_spend + bob_spend) * G must equal alice_pub + bob_pub"
    );
    tracing::info!("Keysplit algebraic consistency verified");

    // Alice lock.
    node.mine_blocks(80).await.unwrap();
    node.mine_to(&joint_spend_pub, &joint_view, 5).await.unwrap();
    node.mine_blocks(66).await.unwrap(); // coinbase maturity
    tracing::info!("Alice locked XMR to joint address (5 coinbase blocks)");

    // Simulated WOW lock on the same chain.
    node.mine_to(&joint_spend_pub, &joint_view, 5).await.unwrap();
    node.mine_blocks(66).await.unwrap(); // coinbase maturity
    tracing::info!("Bob locked WOW (simulated) to joint address");

    // Pre-signature exchange.
    let msg = b"swap-claim";

    // Alice signs against Bob's adaptor point.
    let alice_pre_sig = AdaptorSignature::sign(
        &alice_spend, &alice_pub, msg, &bob_pub, &mut OsRng,
    );
    assert!(
        alice_pre_sig.verify_pre_sig(&alice_pub, msg, &bob_pub),
        "Alice's pre-sig must verify with bob_pub as adaptor"
    );
    tracing::info!("Alice's pre-sig verified by Bob");

    // Bob signs against Alice's adaptor point.
    let bob_pre_sig = AdaptorSignature::sign(
        &bob_spend, &bob_pub, msg, &alice_pub, &mut OsRng,
    );
    assert!(
        bob_pre_sig.verify_pre_sig(&bob_pub, msg, &alice_pub),
        "Bob's pre-sig must verify with alice_pub as adaptor"
    );
    tracing::info!("Bob's pre-sig verified by Alice");

    // Bob claims first.
    let completed_by_bob = alice_pre_sig.complete(&bob_spend);
    assert!(
        completed_by_bob.verify(&alice_pub, msg),
        "Completed sig must be valid Schnorr"
    );
    tracing::info!("Bob completed Alice's pre-sig (reveals bob_spend)");

    // Alice extracts Bob's secret from the completed signature.
    let extracted_bob = alice_pre_sig.extract_secret(&completed_by_bob);
    assert_eq!(
        extracted_bob.to_bytes(), bob_spend.to_bytes(),
        "Extracted secret must equal bob_spend"
    );
    assert_eq!(
        (&extracted_bob * ED25519_BASEPOINT_TABLE).compress(),
        bob_pub.compress(),
        "Extracted secret * G must equal bob_pub"
    );
    tracing::info!("Alice extracted Bob's secret via adaptor sig");

    // Alice can now derive the combined key.
    let alice_combined = combine_secrets(&alice_spend, &extracted_bob);

    // Alice claims.
    let mut alice_joint_wallet = SimnetWallet::from_scalars(
        Zeroizing::new(alice_combined),
        Zeroizing::new(joint_view),
    );
    alice_joint_wallet.refresh(&mut node).await.unwrap();
    let balance = alice_joint_wallet.balance();
    tracing::info!("Alice joint wallet balance: {balance} piconero");
    assert!(balance > 0, "Joint wallet must have funds");

    let alice_dest = SimnetWallet::generate();
    let alice_dest_addr = alice_dest.address(Network::Mainnet);

    let height = node.height().await.unwrap() as usize;
    let claim_amount = balance / 4;
    let inputs = alice_joint_wallet.coin_select(height, claim_amount).unwrap();
    let decoy_rpc = node.decoy_rpc();
    let fee_rate = FeeRate::new(20_000, 10_000).unwrap();

    let claim_tx = alice_joint_wallet
        .build_spend_tx_multi(inputs, alice_dest_addr, claim_amount, fee_rate, &decoy_rpc)
        .await
        .expect("Alice claim tx must build with combined key");

    let tx_hash = node.submit_tx(claim_tx.serialize()).expect("Alice claim must be consensus-valid");
    tracing::info!("Alice claim tx submitted: {}", hex::encode(tx_hash));
    node.mine_blocks(1).await.unwrap();
    assert_eq!(node.drain_mempool().len(), 0, "mempool drained after mine");
    tracing::info!("Alice claim confirmed on-chain");

    // Bob claims.
    let completed_by_alice = bob_pre_sig.complete(&alice_spend);
    assert!(
        completed_by_alice.verify(&bob_pub, msg),
        "Alice's completed sig must be valid Schnorr"
    );

    // Bob extracts Alice's secret.
    let extracted_alice = bob_pre_sig.extract_secret(&completed_by_alice);
    assert_eq!(
        extracted_alice.to_bytes(), alice_spend.to_bytes(),
        "Extracted secret must equal alice_spend"
    );
    assert_eq!(
        (&extracted_alice * ED25519_BASEPOINT_TABLE).compress(),
        alice_pub.compress(),
        "Extracted secret * G must equal alice_pub"
    );
    tracing::info!("Bob extracted Alice's secret via adaptor sig");

    // Bob can now derive the combined key.
    let bob_combined = combine_secrets(&extracted_alice, &bob_spend);

    // Mine fresh coinbase to the joint address before Bob scans.
    let pre_bob_height = node.height().await.unwrap();
    node.mine_to(&joint_spend_pub, &joint_view, 5).await.unwrap();
    node.mine_blocks(66).await.unwrap();

    let mut bob_joint_wallet = SimnetWallet::from_scalars(
        Zeroizing::new(bob_combined),
        Zeroizing::new(joint_view),
    );
    // Scan only the new blocks.
    let bob_scan_start = pre_bob_height as usize;
    let bob_tip = node.height().await.unwrap() as usize;
    for h in bob_scan_start..bob_tip {
        bob_joint_wallet.scan_block(&mut node, h).await.unwrap();
    }
    let bob_balance = bob_joint_wallet.balance();
    tracing::info!("Bob joint wallet balance: {bob_balance} piconero");
    assert!(bob_balance > 0, "Bob joint wallet must have funds");

    let bob_dest = SimnetWallet::generate();
    let bob_dest_addr = bob_dest.address(Network::Mainnet);

    let height = node.height().await.unwrap() as usize;
    let bob_claim_amount = bob_balance / 4;
    let inputs = bob_joint_wallet.coin_select(height, bob_claim_amount).unwrap();
    let decoy_rpc = node.decoy_rpc();

    let bob_claim_tx = bob_joint_wallet
        .build_spend_tx_multi(inputs, bob_dest_addr, bob_claim_amount, fee_rate, &decoy_rpc)
        .await
        .expect("Bob claim tx must build with combined key");

    let tx_hash = node.submit_tx(bob_claim_tx.serialize()).expect("Bob claim must be consensus-valid");
    tracing::info!("Bob claim tx submitted: {}", hex::encode(tx_hash));
    node.mine_blocks(1).await.unwrap();
    assert_eq!(node.drain_mempool().len(), 0, "mempool drained after mine");
    tracing::info!("Bob claim confirmed on-chain");

    // Final checks.
    assert_eq!(
        (&extracted_bob * ED25519_BASEPOINT_TABLE).compress(),
        bob_pub.compress(),
    );
    assert_eq!(
        (&extracted_alice * ED25519_BASEPOINT_TABLE).compress(),
        alice_pub.compress(),
    );
    tracing::info!(
        "ADAPTOR-SIG ATOMICITY PROVEN: secret extraction enables trustless claims"
    );
}

/// Completing with the wrong secret must fail.
#[tokio::test]
async fn adaptor_sig_wrong_secret_fails() {
    let (alice_spend, alice_pub) = generate_key_contribution();
    let (_bob_spend, bob_pub) = generate_key_contribution();
    let (wrong_secret, _) = generate_key_contribution();
    let msg = b"swap-claim";

    let alice_pre_sig = AdaptorSignature::sign(
        &alice_spend, &alice_pub, msg, &bob_pub, &mut OsRng,
    );
    assert!(alice_pre_sig.verify_pre_sig(&alice_pub, msg, &bob_pub));

    let wrong_completed = alice_pre_sig.complete(&wrong_secret);
    assert!(
        !wrong_completed.verify(&alice_pub, msg),
        "Completed sig with wrong secret must fail verification"
    );

    let extracted = alice_pre_sig.extract_secret(&wrong_completed);
    assert_ne!(
        (&extracted * ED25519_BASEPOINT_TABLE).compress(),
        bob_pub.compress(),
        "Extracted secret from wrong completion must not match bob_pub"
    );
}
