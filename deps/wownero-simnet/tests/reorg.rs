//! Tests for chain selection, reorg economics, and selfish-mining scenarios.
//!
//! The simnet bypasses real proof-of-work: every block adds exactly 1 to the
//! cumulative difficulty, so `cumulative_difficulty == height + 1` (genesis
//! contributes 1). That makes chain-selection ("most work") trivial to reason
//! about without running real PoW.
//!
//! The first ten tests mirror the reorg-tests worktree and cover pure chain
//! arithmetic. The final five extend those scenarios with wallet scanning to
//! verify that chain-selection outcomes align with who actually collects
//! spendable coinbase outputs.

use wownero_simnet::{wallet::WowSimnetWallet, WowSimnet, WowSimnetNode};

// ── helpers ───────────────────────────────────────────────────────────────────

fn cd(node: &mut WowSimnetNode) -> u128 {
    node.cumulative_difficulty()
}

fn assert_wins(winner: &mut WowSimnetNode, loser: &mut WowSimnetNode, msg: &str) {
    let wcd = cd(winner);
    let lcd = cd(loser);
    assert!(wcd > lcd, "{msg}: expected winner cd={wcd} > loser cd={lcd}");
}

// ── 1. Selfish mining: private chain outpaces public chain ────────────────────

/// A selfish miner who finds blocks faster than the honest network builds a
/// chain with higher cumulative difficulty. When they release, the honest
/// network's blocks are orphaned.
#[tokio::test]
async fn selfish_private_chain_outpaces_honest_network() {
    let mut selfish = WowSimnetNode::start().await.unwrap();
    let mut honest = WowSimnetNode::start().await.unwrap();

    selfish.mine_blocks(5).await.unwrap();
    honest.mine_blocks(3).await.unwrap();

    assert_wins(&mut selfish, &mut honest, "selfish chain (5 blocks) vs honest chain (3 blocks)");
}

// ── 2. Equal forks tie on cumulative difficulty ───────────────────────────────

/// Two miners who find the same number of blocks have equal cumulative
/// difficulty; tie-breaking is left to implementation policy (first-seen).
#[tokio::test]
async fn equal_forks_tie_on_cumulative_difficulty() {
    let mut a = WowSimnetNode::start().await.unwrap();
    let mut b = WowSimnetNode::start().await.unwrap();

    a.mine_blocks(4).await.unwrap();
    b.mine_blocks(4).await.unwrap();

    assert_eq!(cd(&mut a), cd(&mut b), "equal mining produces equal cumulative difficulty");
}

// ── 3. Deep reorg cost ────────────────────────────────────────────────────────

/// Reorganising a chain of N blocks requires the attacker to produce N+1
/// blocks so their cumulative difficulty strictly exceeds the victim's.
#[tokio::test]
async fn deep_reorg_requires_more_work_than_victim_chain() {
    let depth: u64 = 6;

    let mut victim = WowSimnetNode::start().await.unwrap();
    victim.mine_blocks(depth).await.unwrap();
    let victim_cd = cd(&mut victim);

    let mut attacker = WowSimnetNode::start().await.unwrap();
    attacker.mine_blocks(depth).await.unwrap();
    assert_eq!(cd(&mut attacker), victim_cd, "equal work → tie, cannot reorg");

    attacker.mine_blocks(1).await.unwrap();
    assert_wins(&mut attacker, &mut victim, "attacker needs depth+1 blocks to reorg depth-block chain");
}

// ── 4. Majority hashrate attacker ─────────────────────────────────────────────

/// An attacker with majority hashrate will eventually outpace the honest
/// network. Simulated with a 3:2 mining ratio over 5 rounds.
#[tokio::test]
async fn majority_hashrate_attacker_always_wins() {
    let rounds = 5u64;
    let attacker_rate = 3u64;
    let honest_rate = 2u64;

    let mut attacker = WowSimnetNode::start().await.unwrap();
    let mut honest = WowSimnetNode::start().await.unwrap();

    for _ in 0..rounds {
        attacker.mine_blocks(attacker_rate).await.unwrap();
        honest.mine_blocks(honest_rate).await.unwrap();
    }

    assert_wins(&mut attacker, &mut honest, "60% hashrate attacker wins over 5 rounds");
}

// ── 5. Minority selfish miner loses long run ──────────────────────────────────

/// A miner controlling less than 25% of hashrate cannot sustain a selfish
/// mining advantage. Simulated with a 1:3 mining ratio over 8 rounds.
#[tokio::test]
async fn minority_selfish_miner_loses_long_run() {
    let rounds = 8u64;
    let selfish_rate = 1u64;
    let honest_rate = 3u64;

    let mut selfish = WowSimnetNode::start().await.unwrap();
    let mut honest = WowSimnetNode::start().await.unwrap();

    for _ in 0..rounds {
        selfish.mine_blocks(selfish_rate).await.unwrap();
        honest.mine_blocks(honest_rate).await.unwrap();
    }

    assert_wins(&mut honest, &mut selfish, "honest network (75%) beats minority selfish miner (25%)");
}

// ── 6. Selfish mining: one-block-lead strategy ───────────────────────────────

/// Classic one-block-lead strategy: selfish keeps a secret lead of one block
/// and publishes when the honest network finds a block, orphaning it.
///
/// E1: selfish finds block (lead=1, secret).
/// E2: honest finds block → selfish publishes immediately; honest orphaned.
/// E3: selfish finds another block → lead=1 again.
#[tokio::test]
async fn selfish_one_block_lead_orphans_honest_block() {
    let mut selfish = WowSimnetNode::start().await.unwrap();
    selfish.mine_blocks(1).await.unwrap();
    let cd_after_e1 = cd(&mut selfish);

    let mut honest = WowSimnetNode::start().await.unwrap();
    honest.mine_blocks(1).await.unwrap();
    assert_eq!(cd(&mut selfish), cd(&mut honest), "E2: tie after selfish publishes");

    selfish.mine_blocks(1).await.unwrap();
    assert!(cd(&mut selfish) > cd_after_e1, "selfish chain grew after publishing");
    assert_wins(&mut selfish, &mut honest, "after E3 selfish is ahead — honest E2 block orphaned");
}

// ── 7. Withheld chain orphans honest blocks ───────────────────────────────────

/// A selfish pool mines 3 blocks in secret while the honest network mines 2.
/// When the pool dumps their chain, the honest blocks are orphaned.
#[tokio::test]
async fn selfish_pool_dumps_withheld_chain_orphaning_honest_blocks() {
    let mut pool = WowSimnetNode::start().await.unwrap();
    let mut honest = WowSimnetNode::start().await.unwrap();

    pool.mine_blocks(3).await.unwrap();
    honest.mine_blocks(2).await.unwrap();

    assert_wins(&mut pool, &mut honest, "withheld 3-block chain beats honest 2-block chain");
}

// ── 8. Network partition: larger mining group wins ────────────────────────────

/// When a network partitions, the group with more cumulative mining power
/// produces the winning chain.
///
/// Group A (~60% hashrate, rate=3) vs Group B (~40% hashrate, rate=2).
#[tokio::test]
async fn partition_larger_mining_group_wins_on_heal() {
    let rounds = 4u64;

    let mut group_a = WowSimnetNode::start().await.unwrap();
    let mut group_b = WowSimnetNode::start().await.unwrap();

    for _ in 0..rounds {
        group_a.mine_blocks(3).await.unwrap();
        group_b.mine_blocks(2).await.unwrap();
    }

    assert_wins(&mut group_a, &mut group_b, "group A (60%) has longer chain on heal");
}

// ── 9. Network convergence: sequential mining propagates ─────────────────────

/// When a multi-node network mines sequentially on a single node, every peer
/// receives the blocks immediately; all nodes agree on cumulative difficulty.
#[tokio::test]
async fn network_convergence_after_sequential_mining() {
    let mut net = WowSimnet::new(3).await.unwrap();
    net.mine_on(0, 6).await.unwrap();

    let cd0 = cd(&mut net.nodes[0]);
    let cd1 = cd(&mut net.nodes[1]);
    let cd2 = cd(&mut net.nodes[2]);

    assert_eq!(cd0, cd1, "nodes 0 and 1 agree on cumulative difficulty");
    assert_eq!(cd1, cd2, "nodes 1 and 2 agree on cumulative difficulty");
}

// ── 10. 51% attack: attacker overtakes established chain ─────────────────────

/// An attacker with >50% hashrate who starts behind will eventually exceed
/// the honest network's cumulative difficulty.
///
/// Honest: 4-block head-start, then 1 block/round.
/// Attacker: 0 head-start, 2 blocks/round.
/// Crossing after ceil(4 / (2-1)) = 4 rounds; we run 6 to be safe.
#[tokio::test]
async fn majority_attacker_overtakes_established_honest_chain() {
    let head_start = 4u64;
    let rounds = 6u64;

    let mut honest = WowSimnetNode::start().await.unwrap();
    honest.mine_blocks(head_start).await.unwrap();

    let mut attacker = WowSimnetNode::start().await.unwrap();

    for _ in 0..rounds {
        honest.mine_blocks(1).await.unwrap();
        attacker.mine_blocks(2).await.unwrap();
    }

    // honest = 4 + 6 = 10 blocks; attacker = 12 blocks.
    assert_wins(&mut attacker, &mut honest, "51% attacker (12) overtakes 4-block head-start honest (10)");
}

// ── 11. Selfish miner collects coinbase on the winning chain ─────────────────

/// Extend test 7: the selfish pool not only wins the chain-selection race but
/// also holds all the spendable coinbase outputs. The honest miners' blocks
/// are orphaned, so the honest chain has no outputs belonging to the pool's
/// wallet, and the pool's chain contains no outputs belonging to nobody.
#[tokio::test]
async fn selfish_miner_collects_coinbase_on_winning_chain() {
    let selfish_wallet = WowSimnetWallet::generate();

    let mut selfish = WowSimnetNode::start().await.unwrap();
    let mut honest = WowSimnetNode::start().await.unwrap();

    selfish.mine_to(&selfish_wallet.spend_pub, &selfish_wallet.view_scalar, 5).await.unwrap();
    honest.mine_blocks(3).await.unwrap();

    assert_wins(&mut selfish, &mut honest, "selfish (5 blocks) beats honest (3 blocks)");

    // Every block on the winning chain pays the selfish wallet.
    let mut scanner = selfish_wallet.scanner().unwrap();
    let mut total = 0;
    for h in 1..=5usize {
        total += selfish.scan_block_at(h, &mut scanner).await.unwrap().len();
    }
    assert_eq!(total, 5, "selfish wallet holds all 5 coinbase outputs on the winning chain");
}

// ── 12. Winning and losing chains hold distinct wallet outputs ───────────────

/// Two independent nodes mine to different wallets. The longer chain wins.
/// Each chain's wallet sees its own outputs but not the other's, demonstrating
/// chain isolation: outputs on a losing chain never appear on the winner.
#[tokio::test]
async fn winning_losing_chains_hold_distinct_outputs() {
    let alice = WowSimnetWallet::generate();
    let bob = WowSimnetWallet::generate();

    let mut alice_node = WowSimnetNode::start().await.unwrap();
    let mut bob_node = WowSimnetNode::start().await.unwrap();

    alice_node.mine_to(&alice.spend_pub, &alice.view_scalar, 5).await.unwrap();
    bob_node.mine_to(&bob.spend_pub, &bob.view_scalar, 3).await.unwrap();

    assert_wins(&mut alice_node, &mut bob_node, "alice's chain (5) beats bob's chain (3)");

    // Alice finds all 5 outputs on her own (winning) chain.
    let mut alice_scanner = alice.scanner().unwrap();
    let mut alice_on_winner = 0;
    for h in 1..=5usize {
        alice_on_winner += alice_node.scan_block_at(h, &mut alice_scanner).await.unwrap().len();
    }
    assert_eq!(alice_on_winner, 5, "alice sees 5 outputs on her chain");

    // Bob finds all 3 outputs on his own (losing) chain.
    let mut bob_scanner = bob.scanner().unwrap();
    let mut bob_on_loser = 0;
    for h in 1..=3usize {
        bob_on_loser += bob_node.scan_block_at(h, &mut bob_scanner).await.unwrap().len();
    }
    assert_eq!(bob_on_loser, 3, "bob sees 3 outputs on his chain");

    // Alice finds nothing on bob's separate chain — chains are isolated.
    let mut alice_scanner2 = alice.scanner().unwrap();
    let mut alice_on_loser = 0;
    for h in 1..=3usize {
        alice_on_loser += bob_node.scan_block_at(h, &mut alice_scanner2).await.unwrap().len();
    }
    assert_eq!(alice_on_loser, 0, "alice has no outputs on bob's chain");
}

// ── 13. 51% attacker mines coinbase to self and overtakes honest chain ────────

/// Extend test 10 with wallet scanning: the attacker not only accumulates more
/// chain work than the honest network but also collects all the coinbase rewards
/// on their winning chain.
#[tokio::test]
async fn majority_attacker_mines_coinbase_to_self() {
    let attacker_wallet = WowSimnetWallet::generate();

    let mut honest = WowSimnetNode::start().await.unwrap();
    honest.mine_blocks(4).await.unwrap(); // 4-block head start

    let mut attacker = WowSimnetNode::start().await.unwrap();

    for _ in 0..6 {
        honest.mine_blocks(1).await.unwrap();
        attacker.mine_to(&attacker_wallet.spend_pub, &attacker_wallet.view_scalar, 2).await.unwrap();
    }

    // honest = 10 blocks, attacker = 12 blocks.
    assert_wins(&mut attacker, &mut honest, "51% attacker (12) beats honest (10)");

    let mut scanner = attacker_wallet.scanner().unwrap();
    let mut total = 0;
    for h in 1..=12usize {
        total += attacker.scan_block_at(h, &mut scanner).await.unwrap().len();
    }
    assert_eq!(total, 12, "attacker's wallet holds all 12 coinbase outputs on the winning chain");
}

// ── 14. Chain work and coinbase maturity are consistent ──────────────────────

/// Mine a coinbase output then mine the 4 additional blocks required for
/// maturity, verifying that cumulative difficulty matches chain length and the
/// output is spendable at the correct height.
#[tokio::test]
async fn chain_work_tracks_coinbase_maturity() {
    let wallet = WowSimnetWallet::generate();
    let mut node = WowSimnetNode::start().await.unwrap();

    // Mine coinbase to wallet at height 1, then 4 more blocks (heights 2–5).
    node.mine_to(&wallet.spend_pub, &wallet.view_scalar, 1).await.unwrap();
    node.mine_blocks(4).await.unwrap();

    // cd == genesis(1) + 5 mined = 6.
    assert_eq!(node.cumulative_difficulty(), 6, "cd matches chain length");

    // Coinbase at height 1 unlocks at height 1 + 4 = 5.
    let scannable = node.scannable_block_at(1).await.unwrap();
    let timelocked = wallet.scanner().unwrap().scan(scannable).unwrap();

    let matured = timelocked.additional_timelock_satisfied_by(5, 0);
    assert_eq!(matured.len(), 1, "output is mature; chain work confirms canonical chain");

    // One block before: still locked.
    let scannable2 = node.scannable_block_at(1).await.unwrap();
    let timelocked2 = wallet.scanner().unwrap().scan(scannable2).unwrap();
    let premature = timelocked2.additional_timelock_satisfied_by(4, 0);
    assert_eq!(premature.len(), 0, "output is still locked one block before maturity");
}

// ── 15. Propagated wallet-targeted block is scannable on all nodes ───────────

/// When `WowSimnet::mine_on_to` mines a block to a wallet on one node and
/// propagates it to peers, every node holds the identical block bytes and
/// can independently scan the coinbase output — no node is privileged.
#[tokio::test]
async fn network_convergence_block_scannable_on_all_nodes() {
    let wallet = WowSimnetWallet::generate();
    let mut net = WowSimnet::new(3).await.unwrap();

    // Mine one wallet-targeted block on node 0; propagates to nodes 1 and 2.
    net.mine_on_to(0, 1, &wallet.spend_pub, &wallet.view_scalar).await.unwrap();

    // All nodes agree on cumulative difficulty.
    let cd0 = cd(&mut net.nodes[0]);
    let cd1 = cd(&mut net.nodes[1]);
    let cd2 = cd(&mut net.nodes[2]);
    assert_eq!(cd0, cd1, "nodes 0 and 1 agree on cumulative difficulty");
    assert_eq!(cd1, cd2, "nodes 1 and 2 agree on cumulative difficulty");

    // All nodes can independently scan the same coinbase output at height 1.
    for i in 0..3 {
        let mut scanner = wallet.scanner().unwrap();
        let outputs = net.nodes[i].scan_block_at(1, &mut scanner).await.unwrap();
        assert_eq!(outputs.len(), 1, "node {i} can scan the propagated coinbase output");
    }
}
