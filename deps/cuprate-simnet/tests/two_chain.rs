#![cfg(feature = "merge-mining")]

use cuprate_simnet::{TwoChainSimnet, two_chain::AlwaysValidRandomX};

#[tokio::test]
async fn parent_blocks_without_child_advance_parent_only() {
    let mut sim = TwoChainSimnet::new().await.unwrap();
    for _ in 0..5 {
        sim.mine_parent_only().await.unwrap();
    }
    assert_eq!(sim.child_height(), 0, "no child blocks mined");
}

#[tokio::test]
async fn mine_with_child_commits_and_verifies() {
    let mut sim = TwoChainSimnet::new().await.unwrap();
    let (ph, ch) = sim.mine_with_child(b"block 1 payload".to_vec()).await.unwrap();
    assert_eq!(ch, 1);
    sim.verify_child_anchored(ph, ch).await.unwrap();

    let (ph2, ch2) = sim.mine_with_child(b"block 2 payload".to_vec()).await.unwrap();
    assert_eq!(ch2, 2);
    sim.verify_child_anchored(ph2, ch2).await.unwrap();
}

#[tokio::test]
async fn wrong_child_height_is_detected() {
    let mut sim = TwoChainSimnet::new().await.unwrap();
    let (ph, _ch) = sim.mine_with_child(b"payload".to_vec()).await.unwrap();
    let result = sim.verify_child_anchored(ph, 99).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn mixed_parent_and_child_blocks() {
    let mut sim = TwoChainSimnet::new().await.unwrap();
    for _ in 0..3 { sim.mine_parent_only().await.unwrap(); }
    let (ph1, ch1) = sim.mine_with_child(b"first".to_vec()).await.unwrap();
    let (ph2, ch2) = sim.mine_with_child(b"second".to_vec()).await.unwrap();
    for _ in 0..2 { sim.mine_parent_only().await.unwrap(); }
    let (ph3, ch3) = sim.mine_with_child(b"third".to_vec()).await.unwrap();

    sim.verify_child_anchored(ph1, ch1).await.unwrap();
    sim.verify_child_anchored(ph2, ch2).await.unwrap();
    sim.verify_child_anchored(ph3, ch3).await.unwrap();
    assert_eq!(sim.child_height(), 3);
}

#[tokio::test]
async fn verify_child_anchored_with_pow_enforcement() {
    let mut sim = TwoChainSimnet::new_with_pow_enforcement().await.unwrap();
    let (ph, ch) = sim.mine_with_child(b"pow enforcement test".to_vec()).await.unwrap();
    // AlwaysValidRandomX returns [0u8;32]; 0 * 1 < 2^256, so verify_pow passes.
    assert!(sim.verify_child_anchored(ph, ch).await.is_ok());
}

#[test]
fn always_valid_randomx_returns_zero_hash() {
    use monero_oxide_mm::merge_mining::RandomXVerifier;
    let hash = AlwaysValidRandomX.calculate_hash(b"anything").unwrap();
    assert_eq!(hash, [0u8; 32]);
}
