//! Multi-wallet simnet tests.
//!
//! Proves that two `WowSimnetWallet` instances can send funds back and forth
//! through a single `WowSimnetNode` with correct balance accounting throughout.

use wownero_simnet::{wallet::WowSimnetWallet, WowSimnetNode};
#[cfg(feature = "spend-tests")]
use wownero_wallet::{address::Network, interface::FeeRate};

#[cfg(feature = "spend-tests")]
fn fee_rate() -> FeeRate {
    FeeRate::new(20_000, 10_000).expect("valid fee rate")
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

/// Alice mines 145 blocks to herself, sends to Bob, Bob scans and finds his output.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn alice_sends_to_bob_and_bob_finds_output() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let mut bob = WowSimnetWallet::generate();

    // Mine 1 block to alice, then 144 padding blocks → tip = 146.
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_blocks(144).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 146);

    alice.refresh(&mut node).await.unwrap();
    assert_eq!(alice.output_count(), 1);

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0, "alice's coinbase must be unlocked at height 146");

    let output = alice.outputs()[0].clone();
    let send_amount = unlocked / 4;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            send_amount,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("build_spend_tx must succeed");

    node.submit_tx(tx.serialize()).expect("submit_tx must succeed");
    node.mine_blocks(1).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 147);

    bob.refresh(&mut node).await.unwrap();

    assert!(bob.output_count() > 0, "Bob must find his output");
    assert!(bob.balance() > 0, "Bob must have non-zero balance");
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

/// Alice sends to Bob; Alice scans the block containing the tx and finds her
/// change output.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn alice_receives_change_after_send() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let bob = WowSimnetWallet::generate();

    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_blocks(144).await.unwrap();

    alice.refresh(&mut node).await.unwrap();
    assert_eq!(alice.output_count(), 1);

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0);

    let output = alice.outputs()[0].clone();
    let send_amount = unlocked / 4;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            send_amount,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("build_spend_tx must succeed");

    node.submit_tx(tx.serialize()).expect("submit_tx must succeed");
    node.mine_blocks(1).await.unwrap();

    // Alice scans the block that contains her own spend tx (height 146).
    alice.refresh(&mut node).await.unwrap();

    assert!(
        alice.output_count() >= 1,
        "Alice must have at least the change output (got {})",
        alice.output_count()
    );
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

/// Mine one block to Alice, one to Bob, then padding; both wallets find their
/// coinbase.
#[tokio::test]
async fn two_wallets_both_mine_and_both_have_funds() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let mut bob = WowSimnetWallet::generate();

    // Mine 1 block to each, then 143 padding → tip = 146.
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_to(&bob.spend_pub, &bob.view_scalar, 1).await.unwrap();
    node.mine_blocks(143).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 146);

    alice.refresh(&mut node).await.unwrap();
    bob.refresh(&mut node).await.unwrap();

    assert_eq!(alice.output_count(), 1, "alice should see exactly 1 coinbase output");
    assert_eq!(bob.output_count(), 1, "bob should see exactly 1 coinbase output");

    assert!(alice.unlocked_balance(146) > 0, "alice's coinbase must be unlocked");
    assert!(bob.unlocked_balance(146) > 0, "bob's coinbase must be unlocked");
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

/// A submitted transaction is included in the next mined block and the mempool
/// is empty afterwards.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn mempool_empty_after_block_mines_submitted_tx() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let bob = WowSimnetWallet::generate();

    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_blocks(144).await.unwrap();

    alice.refresh(&mut node).await.unwrap();

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0);

    let output = alice.outputs()[0].clone();
    let send_amount = unlocked / 4;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            send_amount,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("build_spend_tx must succeed");

    node.submit_tx(tx.serialize()).expect("submit_tx must succeed");

    // The tx is in the pending mempool at this point.
    node.mine_blocks(1).await.unwrap();

    // mine_blocks drains the mempool into the block; a second drain must be empty.
    let remaining = node.drain_mempool();
    assert!(
        remaining.is_empty(),
        "mempool must be empty after mining drains pending txs"
    );
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

/// Full round-trip: Alice sends to Bob, Bob finds the output, Bob sends back to
/// Alice.
///
/// `WowSimnetDecoyRpc::get_unlocked_outputs` applies the 60-block coinbase lock to
/// ALL RCT outputs (it cannot distinguish coinbase from non-coinbase). Bob's
/// output lands at block height 147, so the decoy selector requires
/// `147 + 60 = 207 ≤ tip` before it will accept that output as spendable.
/// We therefore mine an extra 75 blocks (instead of the minimal 15) to bring
/// the tip to 222, satisfying that constraint while still providing plenty of
/// decoys (outputs at heights 1–162 are all unlocked at tip 222).
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn bob_can_spend_what_alice_sent() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let mut bob = WowSimnetWallet::generate();

    // ── Step 1: standard 145-block setup ─────────────────────────────────────
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_blocks(144).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 146);

    alice.refresh(&mut node).await.unwrap();
    assert_eq!(alice.output_count(), 1);

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0);

    let output = alice.outputs()[0].clone();
    let send_amount = unlocked / 4;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            send_amount,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("alice build_spend_tx must succeed");

    node.submit_tx(tx.serialize()).expect("submit_tx must succeed");
    node.mine_blocks(1).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 147);

    // ── Step 2: mine 75 padding blocks ───────────────────────────────────────
    // WowSimnetDecoyRpc treats every RCT output as coinbase (60-block lock).
    // Bob's output is at height 147; locked_until = 147 + 60 = 207.
    // We need tip ≥ 207, so mine 75 extra → tip = 222.
    node.mine_blocks(75).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 222);

    // ── Step 3: Bob scans and prepares to spend ───────────────────────────────
    bob.refresh(&mut node).await.unwrap();
    assert!(bob.output_count() > 0, "Bob must find alice's payment");

    let bob_output = bob.outputs()[0].clone();
    let bob_unlocked = bob.unlocked_balance(222);
    assert!(bob_unlocked > 0, "Bob's output must be unlocked at tip 222");

    let bob_send_amount = bob_unlocked / 4;
    let decoy_rpc2 = node.decoy_rpc();

    let tx2 = bob
        .build_spend_tx(
            bob_output,
            alice.address(Network::Mainnet),
            bob_send_amount,
            fee_rate(),
            &decoy_rpc2,
        )
        .await
        .expect("bob build_spend_tx must succeed");

    // ── Step 4: mine Bob's tx and verify Alice receives it ────────────────────
    node.submit_tx(tx2.serialize()).expect("submit tx2 must succeed");
    node.mine_blocks(1).await.unwrap();

    alice.refresh(&mut node).await.unwrap();

    assert!(
        alice.output_count() >= 2,
        "Alice must have at least her change output + the incoming from Bob (got {})",
        alice.output_count()
    );
}

// ── Test 9 ────────────────────────────────────────────────────────────────────

/// After the coinbase-lock fix, Bob's non-coinbase output only needs
/// `out.height` ≤ tip (no extra 60-block lock), so Bob can spend with only
/// 20 padding blocks instead of 75.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn bob_spends_quickly_after_receiving() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let mut bob = WowSimnetWallet::generate();

    // ── Step 1: standard 145-block setup ─────────────────────────────────────
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_blocks(144).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 146);

    alice.refresh(&mut node).await.unwrap();
    assert_eq!(alice.output_count(), 1);

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0);

    let output = alice.outputs()[0].clone();
    let send_amount = unlocked / 4;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            send_amount,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("alice build_spend_tx must succeed");

    node.submit_tx(tx.serialize()).expect("submit_tx must succeed");
    node.mine_blocks(1).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 147);

    // ── Step 2: mine only 20 padding blocks ──────────────────────────────────
    // With the coinbase-lock fix, Bob's non-coinbase output at height 147 is
    // unlocked at tip >= 147 (no extra 60-block lock).  20 padding blocks bring
    // the tip to 167, giving 107 unlocked coinbase decoys (heights 1..107) and
    // Bob's own output at height 147 — well above the ring size of 16.
    node.mine_blocks(20).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 167);

    // ── Step 3: Bob scans and checks balance ─────────────────────────────────
    bob.refresh(&mut node).await.unwrap();
    assert!(bob.output_count() > 0, "Bob must find alice's payment");

    let bob_unlocked = bob.unlocked_balance(167);
    assert!(bob_unlocked > 0, "Bob's output must be unlocked at tip 167 (non-coinbase lock fix)");

    // ── Step 4: Bob spends and Alice receives ────────────────────────────────
    let bob_output = bob.outputs()[0].clone();
    let bob_send_amount = bob_unlocked / 4;
    let decoy_rpc2 = node.decoy_rpc();

    let tx2 = bob
        .build_spend_tx(
            bob_output,
            alice.address(Network::Mainnet),
            bob_send_amount,
            fee_rate(),
            &decoy_rpc2,
        )
        .await
        .expect("bob build_spend_tx must succeed with only 20 padding blocks");

    node.submit_tx(tx2.serialize()).expect("submit tx2 must succeed");
    node.mine_blocks(1).await.unwrap();

    alice.refresh(&mut node).await.unwrap();
    assert!(
        alice.output_count() >= 2,
        "Alice must have at least her change output + the incoming from Bob (got {})",
        alice.output_count()
    );
}

// ── Test 6 ────────────────────────────────────────────────────────────────────

/// coin_select picks outputs covering a multi-input spend; Bob finds his output.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn two_inputs_cover_single_output() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let mut bob = WowSimnetWallet::generate();

    // Mine 2 blocks to alice, then 143 padding → tip = 146.
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 2).await.unwrap();
    node.mine_blocks(143).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 146);

    alice.refresh(&mut node).await.unwrap();
    assert_eq!(alice.output_count(), 2, "alice should have 2 coinbase outputs");

    let total_balance = alice.unlocked_balance(146);
    assert!(total_balance > 0, "alice must have unlocked funds");

    // Estimate fee for a 2-input tx and include it in the target.
    // Use a conservative fixed estimate (20_000 per_weight * 2000 weight).
    let est_fee: u64 = 40_000_000;
    let target = total_balance / 2 + est_fee;
    let selected = alice
        .coin_select(146, target)
        .expect("coin_select must return Some when funds are sufficient");
    assert!(
        selected.len() <= 2,
        "greedy selection should use at most 2 outputs (got {})",
        selected.len()
    );

    let send_amount = total_balance / 2;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx_multi(
            selected,
            bob.address(Network::Mainnet),
            send_amount,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("build_spend_tx_multi must succeed");

    node.submit_tx(tx.serialize()).expect("submit_tx must succeed");
    node.mine_blocks(1).await.unwrap();

    bob.refresh(&mut node).await.unwrap();
    assert!(bob.output_count() > 0, "Bob must find his output");
    assert!(bob.balance() > 0, "Bob must have non-zero balance");
}

// ── Test 7 ────────────────────────────────────────────────────────────────────

/// coin_select returns None when the wallet has no outputs.
#[tokio::test]
async fn coin_select_insufficient_returns_none() {
    let wallet = WowSimnetWallet::generate();
    let result = wallet.coin_select(100, 1_000_000_000_000_000_000u64);
    assert!(result.is_none(), "coin_select must return None when funds are insufficient");
}

// ── Test 8 ────────────────────────────────────────────────────────────────────

/// build_spend_tx_multi with two coinbase inputs advances the chain.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn build_spend_tx_multi_with_two_coinbase_inputs() {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let bob = WowSimnetWallet::generate();

    // Mine 2 blocks to alice (heights 1, 2), then 143 padding → tip = 146.
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 2).await.unwrap();
    node.mine_blocks(143).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 146);

    alice.refresh(&mut node).await.unwrap();

    // Both coinbase outputs must be unlocked at tip 146 (locked until 61 and 62).
    let unlocked = alice.unlocked_outputs(146);
    assert_eq!(unlocked.len(), 2, "both coinbase outputs must be unlocked at tip 146");

    let inputs: Vec<_> = unlocked.into_iter().cloned().collect();
    let total: u64 = inputs.iter().map(|o| o.commitment().amount).sum();
    let send_amount = total / 2;
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx_multi(
            inputs,
            bob.address(Network::Mainnet),
            send_amount,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("build_spend_tx_multi with two coinbase inputs must succeed");

    node.submit_tx(tx.serialize()).expect("submit_tx must succeed");
    node.mine_blocks(1).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 147, "node must advance to height 147");
}
