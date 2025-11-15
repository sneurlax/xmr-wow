//! End-to-end simnet wallet tests.
//!
//! These tests exercise the full loop a wallet would perform against a real
//! node (minus any network I/O):
//!
//! 1. Generate keys.
//! 2. Mine blocks with scannable coinbase outputs.
//! 3. Scan each block to detect received outputs.
//! 4. Verify the 60-block coinbase maturity lock.

use cuprate_simnet::{wallet::SimnetWallet, SimnetNode};
use monero_wallet::{address::Network, interface::FeeRate};

// ── Key generation ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_wallet_generate() {
    let w = SimnetWallet::generate();
    let addr = w.address(Network::Mainnet);
    let addr_str = addr.to_string();
    assert!(addr_str.starts_with('4'), "mainnet address should start with '4', got: {addr_str}");
}

#[tokio::test]
async fn test_wallet_scanner_builds() {
    let w = SimnetWallet::generate();
    let _scanner = w.scanner().unwrap();
}

// ── Mining to a wallet ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mine_to_wallet_single_block() {
    let mut node = SimnetNode::start().await.unwrap();
    let wallet = SimnetWallet::generate();
    let mut scanner = wallet.scanner().unwrap();

    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 2); // genesis + 1 mined

    let outputs = node.scan_block_at(1, &mut scanner).await.unwrap();
    assert_eq!(outputs.len(), 1, "should find exactly one coinbase output");
}

#[tokio::test]
async fn test_mine_to_wallet_multiple_blocks() {
    let mut node = SimnetNode::start().await.unwrap();
    let wallet = SimnetWallet::generate();
    let mut scanner = wallet.scanner().unwrap();

    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 5).await.unwrap();

    let mut total = 0usize;
    for h in 1..=5usize {
        let outputs = node.scan_block_at(h, &mut scanner).await.unwrap();
        total += outputs.len();
    }
    assert_eq!(total, 5, "each of the 5 blocks should yield one coinbase output");
}

#[tokio::test]
async fn test_random_blocks_not_scanned_by_wallet() {
    let mut node = SimnetNode::start().await.unwrap();
    let wallet = SimnetWallet::generate();
    let mut scanner = wallet.scanner().unwrap();

    node.mine_blocks(5).await.unwrap();

    for h in 1..=5usize {
        let outputs = node.scan_block_at(h, &mut scanner).await.unwrap();
        assert_eq!(outputs.len(), 0, "random-key coinbase must not scan to our wallet");
    }
}

// ── Coinbase maturity / 60-block lock ────────────────────────────────────────

#[tokio::test]
async fn test_coinbase_maturity_simulation() {
    // Canonical simnet use-case: mine coinbase to yourself, wait 60 blocks,
    // verify the output is now spendable.

    let mut node = SimnetNode::start().await.unwrap();
    let wallet = SimnetWallet::generate();
    let mut scanner = wallet.scanner().unwrap();

    // Mine one block with a coinbase to our wallet at height 1.
    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();

    // The coinbase at height 1 is locked until height 1 + 60 = 61.
    // Mine 60 more blocks (heights 2-61).
    node.mine_blocks(60).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 62);

    let scannable = node.scannable_block_at(1).await.unwrap();
    let timelocked = scanner.scan(scannable).unwrap();

    // additional_timelock is Block(61). With chain tip at height 62, the lock
    // is satisfied at height 61.
    let matured = timelocked.additional_timelock_satisfied_by(61, 0);
    assert_eq!(matured.len(), 1, "coinbase output should be mature at height 61");
}

#[tokio::test]
async fn test_coinbase_still_locked_before_maturity() {
    let mut node = SimnetNode::start().await.unwrap();
    let wallet = SimnetWallet::generate();
    let mut scanner = wallet.scanner().unwrap();

    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();

    // Mine only 59 more blocks — one short of maturity.
    node.mine_blocks(59).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 61);

    let scannable = node.scannable_block_at(1).await.unwrap();
    let timelocked = scanner.scan(scannable).unwrap();

    // At height 60 (one block before the lock expires at 61), still locked.
    let matured = timelocked.additional_timelock_satisfied_by(60, 0);
    assert_eq!(matured.len(), 0, "coinbase must still be locked one block before maturity");
}

// ── Mixed mining ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mixed_mining_only_ours_detected() {
    let mut node = SimnetNode::start().await.unwrap();
    let alice = SimnetWallet::generate();
    let bob = SimnetWallet::generate();
    let mut alice_scanner = alice.scanner().unwrap();

    // Heights 1-3: mine to alice; heights 4-6: mine to nobody.
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 3).await.unwrap();
    node.mine_blocks(3).await.unwrap();

    let mut alice_count = 0;
    for h in 1..=6usize {
        let outputs = node.scan_block_at(h, &mut alice_scanner).await.unwrap();
        alice_count += outputs.len();
    }
    assert_eq!(alice_count, 3);

    let mut bob_scanner = bob.scanner().unwrap();
    for h in 1..=6usize {
        let outputs = node.scan_block_at(h, &mut bob_scanner).await.unwrap();
        assert_eq!(outputs.len(), 0, "bob should not see alice's outputs");
    }
}

// ── ScannableBlock API ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_scannable_block_genesis_has_no_rct_index() {
    let mut node = SimnetNode::start().await.unwrap();
    let sb = node.scannable_block_at(0).await.unwrap();
    assert_eq!(
        sb.output_index_for_first_ringct_output, None,
        "genesis (v1 tx) has no RingCT outputs"
    );
}

#[tokio::test]
async fn test_scannable_block_height_1_rct_index_is_zero() {
    let mut node = SimnetNode::start().await.unwrap();
    node.mine_blocks(1).await.unwrap();
    let sb = node.scannable_block_at(1).await.unwrap();
    assert_eq!(
        sb.output_index_for_first_ringct_output,
        Some(0),
        "first mined block's coinbase is global RingCT output #0"
    );
}

// ── Stateful wallet ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_wallet_refresh_finds_coinbase() {
    let mut node = SimnetNode::start().await.unwrap();
    let mut wallet = SimnetWallet::generate();

    // Mine 5 blocks to this wallet.
    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 5).await.unwrap();

    wallet.refresh(&mut node).await.unwrap();

    assert_eq!(wallet.output_count(), 5, "should find one coinbase output per block");
    assert!(wallet.balance() > 0, "balance should be positive after mining");
}

#[tokio::test]
async fn test_wallet_refresh_is_idempotent() {
    let mut node = SimnetNode::start().await.unwrap();
    let mut wallet = SimnetWallet::generate();

    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 3).await.unwrap();

    wallet.refresh(&mut node).await.unwrap();
    let count_after_first = wallet.output_count();

    // Refresh again — should not double-count outputs.
    wallet.refresh(&mut node).await.unwrap();

    assert_eq!(
        wallet.output_count(),
        count_after_first,
        "second refresh must not accumulate duplicate outputs"
    );
    assert_eq!(wallet.output_count(), 3);
}

#[tokio::test]
async fn test_wallet_balance_after_mine_to() {
    let mut node = SimnetNode::start().await.unwrap();
    let mut wallet = SimnetWallet::generate();

    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();
    wallet.refresh(&mut node).await.unwrap();

    assert!(wallet.balance() > 0, "balance must be positive after mining one block");
    // Genesis (height 0) + mined block (height 1) → tip is 2, so we scanned
    // heights [0, 2), meaning last_scanned_height == 2.
    assert_eq!(
        wallet.last_scanned_height(),
        2,
        "last_scanned_height should be 2 after scanning genesis + one mined block"
    );
}

#[tokio::test]
async fn test_wallet_unlocked_balance_before_maturity() {
    // Coinbase outputs carry an additional_timelock of Block(height + 60).
    // At height 1 (just after mining), unlocked_balance should be 0.
    let mut node = SimnetNode::start().await.unwrap();
    let mut wallet = SimnetWallet::generate();

    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();
    wallet.refresh(&mut node).await.unwrap();

    // Chain tip is 2 (genesis + 1 mined block).  The coinbase at height 1
    // carries an additional lock of Block(61).  Height 1 < 61 → still locked.
    let unlocked = wallet.unlocked_balance(1);
    assert_eq!(unlocked, 0, "coinbase at height 1 must still be locked at height 1");
}

#[tokio::test]
async fn test_wallet_unlocked_balance_after_maturity() {
    let mut node = SimnetNode::start().await.unwrap();
    let mut wallet = SimnetWallet::generate();

    // Mine one block to the wallet (height 1), then 60 padding blocks.
    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();
    node.mine_blocks(60).await.unwrap();

    wallet.refresh(&mut node).await.unwrap();

    // The coinbase at height 1 has additional_timelock = Block(61).
    // At height 62 (tip) the lock expired at 61.
    let total = wallet.balance();
    let unlocked = wallet.unlocked_balance(62);
    assert_eq!(
        unlocked, total,
        "after 60 confirmation blocks the coinbase output should be fully unlocked"
    );
    assert!(unlocked > 0);
}

#[tokio::test]
async fn test_wallet_does_not_accumulate_others_outputs() {
    let mut node = SimnetNode::start().await.unwrap();
    let mut wallet_a = SimnetWallet::generate();
    let mut wallet_b = SimnetWallet::generate();

    // Mine 5 blocks to wallet A, then 3 blocks to wallet B.
    node.mine_to(&wallet_a.spend_pub, &wallet_a.view_scalar, 5).await.unwrap();
    node.mine_to(&wallet_b.spend_pub, &wallet_b.view_scalar, 3).await.unwrap();

    wallet_a.refresh(&mut node).await.unwrap();
    wallet_b.refresh(&mut node).await.unwrap();

    assert_eq!(wallet_a.output_count(), 5, "wallet A should see exactly its 5 outputs");
    assert_eq!(wallet_b.output_count(), 3, "wallet B should see exactly its 3 outputs");
    assert!(wallet_a.balance() > 0);
    assert!(wallet_b.balance() > 0);
}

// ── Key image computation ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_key_image_computation() {
    // Mine enough blocks so the wallet has at least one mature coinbase output.
    // 1 block to wallet + 60 padding blocks for coinbase maturity = 61 blocks mined.
    let mut node = SimnetNode::start().await.unwrap();
    let mut wallet = SimnetWallet::generate();

    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();
    node.mine_blocks(60).await.unwrap();

    wallet.refresh(&mut node).await.unwrap();

    assert_eq!(wallet.output_count(), 1, "wallet should have exactly one output");

    // Key image should be computable for output index 0.
    let ki = wallet.key_image_for_output(0);
    assert!(ki.is_some(), "key_image_for_output(0) must return Some");

    // Key image is a 32-byte compressed Edwards point; it must not be all-zero.
    let ki_bytes = ki.unwrap().0;
    assert_ne!(ki_bytes, [0u8; 32], "key image must not be the zero point");

    // Out-of-bounds index must return None.
    let ki_oob = wallet.key_image_for_output(1);
    assert!(ki_oob.is_none(), "key_image_for_output(1) must be None when only one output exists");
}

// ── Full spend cycle ──────────────────────────────────────────────────────────

/// Mine → scan → mature → spend → mine into block → verify tx landed.
///
/// Chain layout:
///   height  1     : coinbase to alice (our wallet)
///   heights 2-86  : padding blocks
///   height  87    : spend tx mined into this block
///
/// Minimum chain tip required by the decoy selection formula:
///   tip >= 86  (DEFAULT_LOCK_WINDOW=10, COINBASE_LOCK_WINDOW=60, ring_len=16:
///               tip - 10 - 60 >= 16  →  tip >= 86)
/// We mine 145 blocks after genesis (1 to alice + 144 padding) so that the
/// gamma-distribution decoy selector finds plenty of unlocked outputs in its
/// preferred "recent" range (heights 60-145 → unlocked heights 1-85).
#[tokio::test]
async fn test_full_spend_cycle() {
    let mut node = SimnetNode::start().await.unwrap();
    let mut alice = SimnetWallet::generate();
    let bob = SimnetWallet::generate();

    // Mine 1 block to alice, then 144 padding blocks.
    // After mining: tip = 146 (genesis + 1 + 144).
    // Unlocked outputs: heights 1..=86 (86 outputs), well above ring size 16.
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_blocks(144).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 146);

    // Scan all blocks so alice can see her mature coinbase output.
    alice.refresh(&mut node).await.unwrap();
    assert_eq!(alice.output_count(), 1);

    // The coinbase at height 1 has timelock Block(61).  At tip 146 it is mature.
    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0, "alice's coinbase must be unlocked at height 146");

    // Grab the output for spending and compute its key image.
    let output = alice.outputs()[0].clone();
    let ki = alice.key_image_for_output(0).expect("key image must be computable");
    assert_ne!(ki.0, [0u8; 32]);

    // Build a spend transaction sending half the balance to bob.
    // FeeRate::new(per_weight, mask): use a generous rate so fee arithmetic works.
    let fee_rate = FeeRate::new(20_000, 10_000).expect("valid fee rate");
    let send_amount = unlocked / 2;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(output, bob.address(Network::Mainnet), send_amount, fee_rate, &decoy_rpc)
        .await
        .expect("build_spend_tx must succeed");

    // Serialize and submit the transaction to the simnet mempool.
    let tx_blob = tx.serialize();
    let tx_hash = node.submit_tx(tx_blob).expect("submit_tx must succeed");
    assert_ne!(tx_hash, [0u8; 32]);

    // Mine one block to include the pending transaction.
    node.mine_blocks(1).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 147);

    // The mempool should now be empty (drained into the mined block).
    assert_eq!(node.drain_mempool().len(), 0, "mempool must be empty after mining");
}
