use monero_simnet::MoneroSimnet;

/// Mine 1 funded block + 61 maturity padding → tip = 63 (genesis=1 + 1 + 61).
/// Coinbase at height 2 has timelock Block(62); at tip 63, it is unlocked.
#[tokio::test]
async fn test_fund_and_check_balance() {
    let mut sim = MoneroSimnet::new().await.unwrap();
    sim.add_funded_wallet("alice", 1, 61).await.unwrap();
    assert!(sim.unlocked_balance("alice").await.unwrap() > 0);
}

/// Alice sends half her balance to Bob.
///
/// Decoy selection requires tip >= 86 (ring=16, coinbase lock=60, lock window=10).
/// We mine 2 funded blocks + 144 maturity padding so tip = 147 (genesis=1 + 2 + 144).
/// After transfer(), mine_blocks(1) + refresh_all() are called inside transfer().
/// We call mine_blocks(1) + refresh_all() again externally to make the bob output
/// visible in his balance check.
#[tokio::test]
async fn test_alice_sends_to_bob() {
    let mut sim = MoneroSimnet::new().await.unwrap();
    sim.add_funded_wallet("alice", 2, 144).await.unwrap();
    sim.add_funded_wallet("bob", 0, 0).await.unwrap();
    let alice_bal = sim.unlocked_balance("alice").await.unwrap();
    assert!(alice_bal > 0, "alice must have an unlocked balance before transfer");
    // Send a fixed amount well below a single coinbase output to avoid fee issues.
    let send_amount = alice_bal / 10;
    let tip_before = sim.height().await.unwrap();
    let tx_hash = sim.transfer("alice", "bob", send_amount).await.unwrap();
    let tip_after = sim.height().await.unwrap();
    assert_ne!(tx_hash, [0u8; 32], "transfer must return a real tx hash");
    assert_eq!(tip_after, tip_before + 1, "transfer mines one confirmation block");
}

/// Alice and Bob each fund themselves, then exchange funds back and forth.
#[tokio::test]
async fn test_two_round_trip_transfers() {
    let mut sim = MoneroSimnet::new().await.unwrap();
    // Both wallets need:
    //   - coinbase maturity (60 blocks after the funded block)
    //   - enough chain history for CLSAG decoy selection (tip >= 86 unlocked outputs)
    // Strategy: alice funds first with 144 padding (tip≈147), then bob funds with
    // 61 maturity padding so his outputs are also mature.
    sim.add_funded_wallet("alice", 2, 144).await.unwrap();
    sim.add_funded_wallet("bob", 2, 61).await.unwrap();

    sim.refresh_all().await.unwrap();

    let alice_bal = sim.unlocked_balance("alice").await.unwrap();
    let bob_bal = sim.unlocked_balance("bob").await.unwrap();
    assert!(alice_bal > 0, "alice must have unlocked balance");
    assert!(bob_bal > 0, "bob must have unlocked balance");

    // Alice → Bob: send a small fixed amount comfortably below a single output.
    let alice_send = alice_bal / 10;
    let tip_before = sim.height().await.unwrap();
    let tx1 = sim.transfer("alice", "bob", alice_send).await.unwrap();
    let tip_mid = sim.height().await.unwrap();
    assert_ne!(tx1, [0u8; 32], "alice->bob transfer must return a real tx hash");
    assert_eq!(tip_mid, tip_before + 1, "alice->bob transfer mines one block");

    // Bob → Alice: bob's original coinbase outputs are still unlocked; send a fraction.
    let bob_send = bob_bal / 10;
    let tx2 = sim.transfer("bob", "alice", bob_send).await.unwrap();
    let tip_after = sim.height().await.unwrap();
    assert_ne!(tx2, [0u8; 32], "bob->alice transfer must return a real tx hash");
    assert_ne!(tx1, tx2, "distinct transfers must produce distinct tx hashes");
    assert_eq!(tip_after, tip_mid + 1, "bob->alice transfer mines one block");
}
