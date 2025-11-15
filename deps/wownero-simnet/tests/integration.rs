use wownero_simnet::{WowSimnet, WowSimnetConfig, WowSimnetNode};

#[cfg(feature = "merge-mining")]
use cuprate_types::blockchain::{BlockchainReadRequest, BlockchainResponse};
#[cfg(feature = "merge-mining")]
use tower::{Service, ServiceExt};
#[cfg(feature = "merge-mining")]
use wownero_oxide_mm::merge_mining::MergeMiningProof;
#[cfg(feature = "merge-mining")]
use wownero_simnet::TwoChainWowSimnet;
#[cfg(feature = "spend-tests")]
use wownero_simnet::{SimnetError, WowSimnetWallet};
#[cfg(feature = "spend-tests")]
use wownero_wallet::{address::Network, interface::FeeRate};

#[cfg(feature = "merge-mining")]
/// Re-parse a `wownero_oxide::block::Block` (from the DB) as a `wownero_oxide_mm::block::Block`
/// by going through the wire format. Both crates share the same serialization.
fn reparse_block(block: &wownero_oxide::block::Block) -> wownero_oxide_mm::block::Block {
    let bytes = block.serialize();
    wownero_oxide_mm::block::Block::read(&mut bytes.as_slice())
        .expect("block re-parse failed")
}

#[tokio::test]
async fn test_single_node_genesis() {
    let mut node = WowSimnetNode::start().await.unwrap();
    assert_eq!(node.height().await.unwrap(), 1);
}

#[tokio::test]
async fn test_mine_blocks() {
    let mut node = WowSimnetNode::start().await.unwrap();
    node.mine_blocks(10).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 11);
}

#[tokio::test]
async fn test_mine_past_coinbase_maturity() {
    let mut node = WowSimnetNode::start().await.unwrap();
    node.mine_blocks(60).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 61);
}

#[tokio::test]
async fn test_start_with_config() {
    let mut node = WowSimnetNode::start_with_config(WowSimnetConfig::mainnet()).await.unwrap();
    assert_eq!(node.height().await.unwrap(), 1);
}

#[tokio::test]
async fn test_two_node_sync() {
    let mut net = WowSimnet::new(2).await.unwrap();
    net.mine_on(0, 5).await.unwrap();
    assert_eq!(net.nodes[0].height().await.unwrap(), 6);
    assert_eq!(net.nodes[1].height().await.unwrap(), 6);
}

#[tokio::test]
async fn test_three_node_sync() {
    let mut net = WowSimnet::new(3).await.unwrap();
    net.mine_on(1, 3).await.unwrap();
    for node in net.nodes.iter_mut() {
        assert_eq!(node.height().await.unwrap(), 4);
    }
}

#[tokio::test]
async fn test_read_handle_cloneable() {
    let node = WowSimnetNode::start().await.unwrap();
    let _rh = node.read_handle();
}

#[tokio::test]
#[cfg(feature = "merge-mining")]
async fn e2e_merge_mining_proof_verified() {
    let mut sim = TwoChainWowSimnet::new().await.unwrap();
    let (ph, ch) = sim.mine_with_child(b"e2e test payload".to_vec()).await.unwrap();
    // verify_child_anchored now calls MergeMiningProof::verify internally
    sim.verify_child_anchored(ph, ch).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "merge-mining")]
async fn merge_mining_proof_round_trips() {
    let mut sim = TwoChainWowSimnet::new().await.unwrap();
    let (parent_height, child_height) =
        sim.mine_with_child(b"round-trip payload".to_vec()).await.unwrap();

    let BlockchainResponse::Block(block) = sim
        .parent
        .read_handle()
        .ready()
        .await
        .unwrap()
        .call(BlockchainReadRequest::Block { height: parent_height as usize })
        .await
        .unwrap()
    else { panic!("unexpected response") };

    let child_hash = sim.child_blocks[child_height as usize].hash();

    let mm_block = reparse_block(&block);
    let proof = MergeMiningProof {
        monero_header: mm_block.header.clone(),
        coinbase_tx: mm_block.miner_transaction().clone(),
        tx_count: 1 + mm_block.transactions.len(),
        coinbase_branch: vec![],
    };
    proof.verify(&child_hash).expect("original proof must verify");

    let bytes = proof.serialize();
    let recovered = MergeMiningProof::deserialize(&bytes).expect("deser must succeed");
    recovered.verify(&child_hash).expect("recovered proof must verify");
    assert_eq!(proof, recovered);
}

#[tokio::test]
#[cfg(feature = "merge-mining")]
async fn merge_mining_proof_rejects_wrong_child_hash() {
    let mut sim = TwoChainWowSimnet::new().await.unwrap();
    let (parent_height, _) = sim.mine_with_child(b"rejection test".to_vec()).await.unwrap();

    let BlockchainResponse::Block(block) = sim
        .parent
        .read_handle()
        .ready()
        .await
        .unwrap()
        .call(BlockchainReadRequest::Block { height: parent_height as usize })
        .await
        .unwrap()
    else { panic!("unexpected response") };

    let mm_block = reparse_block(&block);
    let proof = MergeMiningProof {
        monero_header: mm_block.header.clone(),
        coinbase_tx: mm_block.miner_transaction().clone(),
        tx_count: 1,
        coinbase_branch: vec![],
    };
    assert!(proof.verify(&[0xFFu8; 32]).is_err(), "wrong hash must be rejected");
}

#[tokio::test]
#[cfg(feature = "merge-mining")]
async fn five_block_child_chain_all_verify() {
    let mut sim = TwoChainWowSimnet::new().await.unwrap();
    let mut anchors = vec![];
    for i in 0u8..5 {
        let (ph, ch) = sim.mine_with_child(vec![i]).await.unwrap();
        anchors.push((ph, ch));
    }
    for (ph, ch) in anchors {
        sim.verify_child_anchored(ph, ch).await.unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "merge-mining")]
async fn relay_compat_blob_yields_verifiable_proof() {
    // Proves mm-relay's inject logic is compatible with MergeMiningProof::verify.
    use wownero_oxide_mm::block::{Block, BlockHeader};
    use wownero_oxide_mm::ed25519::CompressedPoint;
    use wownero_oxide_mm::transaction::{Input, Output, Timelock, Transaction, TransactionPrefix};
    use std::io::Cursor;

    let child_hash = [0xABu8; 32];

    // Build a minimal block (same structure as mm-relay's test helper).
    let extra = {
        let mut e = vec![0x01u8];
        e.extend_from_slice(&[2u8; 32]);
        e
    };
    let prefix = TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs: vec![Input::Gen(1)],
        outputs: vec![Output {
            amount: Some(600_000_000_000),
            key: CompressedPoint::from([1u8; 32]),
            view_tag: None,
        }],
        extra,
    };
    let miner_tx = Transaction::V1 { prefix, signatures: vec![] };
    let header = BlockHeader {
        hardfork_version: 1, hardfork_signal: 1,
        timestamp: 1_700_000_000, previous: [0u8; 32], nonce: 0,
    };
    let blob = Block::new(header, miner_tx, vec![]).unwrap().serialize();

    // Inject child hash using wownero_oxide_mm::extra (same logic as relay after dedup).
    let enhanced = {
        let block = Block::read(&mut Cursor::new(&blob)).unwrap();
        let mut tx = block.miner_transaction().clone();
        tx.prefix_mut().extra =
            wownero_oxide_mm::extra::set_merge_mining_hash(&tx.prefix().extra, child_hash);
        Block::new(block.header.clone(), tx, block.transactions.clone())
            .unwrap()
            .serialize()
    };

    let enhanced_block = Block::read(&mut Cursor::new(&enhanced)).unwrap();
    let proof = MergeMiningProof {
        monero_header: enhanced_block.header.clone(),
        coinbase_tx: enhanced_block.miner_transaction().clone(),
        tx_count: 1,
        coinbase_branch: vec![],
    };
    proof.verify(&child_hash).expect("relay-produced blob must verify");
}

// ─── Double-spend detection tests ────────────────────────────────────────────

#[cfg(feature = "spend-tests")]
fn fee_rate() -> FeeRate {
    FeeRate::new(20_000, 10_000).expect("valid fee rate")
}

#[cfg(feature = "spend-tests")]
/// Build a standard simnet node with Alice having an unlocked coinbase output.
/// Returns (node, alice, bob) after mining 145 blocks (tip = 146).
async fn setup_alice_funded() -> (WowSimnetNode, WowSimnetWallet, WowSimnetWallet) {
    let mut node = WowSimnetNode::start().await.unwrap();
    let mut alice = WowSimnetWallet::generate();
    let bob = WowSimnetWallet::generate();
    node.mine_to(&alice.spend_pub, &alice.view_scalar, 1).await.unwrap();
    node.mine_blocks(144).await.unwrap();
    alice.refresh(&mut node).await.unwrap();
    (node, alice, bob)
}

/// Submitting the exact same tx blob twice must be rejected with DoubleSpend.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn submit_same_tx_twice_is_rejected() {
    let (mut node, mut alice, bob) = setup_alice_funded().await;

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0);
    let output = alice.outputs()[0].clone();
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            unlocked / 4,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("build_spend_tx must succeed");

    let tx_blob = tx.serialize();
    node.submit_tx(tx_blob.clone()).expect("first submit must succeed");

    let result = node.submit_tx(tx_blob);
    assert!(
        matches!(result, Err(SimnetError::DoubleSpend(_))),
        "second submit of same tx must return DoubleSpend, got {:?}",
        result
    );
}

/// After a tx is mined, submitting the same tx again must be rejected.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn submit_after_confirmation_is_rejected() {
    let (mut node, mut alice, bob) = setup_alice_funded().await;

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0);
    let output = alice.outputs()[0].clone();
    let decoy_rpc = node.decoy_rpc();

    let tx = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            unlocked / 4,
            fee_rate(),
            &decoy_rpc,
        )
        .await
        .expect("build_spend_tx must succeed");

    let tx_blob = tx.serialize();
    node.submit_tx(tx_blob.clone()).expect("first submit must succeed");
    node.mine_blocks(1).await.unwrap();

    // The tx was confirmed; key images are in spent_key_images now.
    let result = node.submit_tx(tx_blob);
    assert!(
        matches!(result, Err(SimnetError::DoubleSpend(_))),
        "submit after confirmation must return DoubleSpend, got {:?}",
        result
    );
}

/// Two different transactions spending the same output (same key image) —
/// the second must be rejected as a mempool double-spend.
#[tokio::test]
#[cfg(feature = "spend-tests")]
async fn mempool_double_spend_is_rejected() {
    let (mut node, mut alice, bob) = setup_alice_funded().await;

    let unlocked = alice.unlocked_balance(146);
    assert!(unlocked > 0);
    let output = alice.outputs()[0].clone();

    // Build two independent txs that both spend the same alice output.
    let decoy_rpc1 = node.decoy_rpc();
    let tx1 = alice
        .build_spend_tx(
            output.clone(),
            bob.address(Network::Mainnet),
            unlocked / 4,
            fee_rate(),
            &decoy_rpc1,
        )
        .await
        .expect("tx1 build_spend_tx must succeed");

    let decoy_rpc2 = node.decoy_rpc();
    let tx2 = alice
        .build_spend_tx(
            output,
            bob.address(Network::Mainnet),
            unlocked / 5,
            fee_rate(),
            &decoy_rpc2,
        )
        .await
        .expect("tx2 build_spend_tx must succeed");

    node.submit_tx(tx1.serialize()).expect("tx1 must be accepted into mempool");

    let result = node.submit_tx(tx2.serialize());
    assert!(
        matches!(result, Err(SimnetError::DoubleSpend(_))),
        "tx2 with same key image must be rejected as mempool double-spend, got {:?}",
        result
    );
}
