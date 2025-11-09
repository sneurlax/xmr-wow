/// Integration tests: sharechain component tests.
use xmr_wow_sharechain::{
    SwapChain, SwapShare, EscrowOp, EscrowState, EscrowIndex, Difficulty, CONSENSUS_ID,
    EscrowCommitment,
};
use xmr_wow_integration::{genesis, next_share, build_chain};

fn make_commitment(id: u8) -> EscrowCommitment {
    EscrowCommitment {
        swap_id:         [id; 32],
        alice_sc_pubkey: [id + 1; 32],
        bob_sc_pubkey:   [id + 2; 32],
        k_b_expected:    [id + 3; 32],
        k_b_prime:       [id + 4; 32],
        claim_timelock:  1000,
        refund_timelock: 2000,
        amount:          1_000_000_000_000,
    }
}

#[test]
fn swap_chain_accepts_genesis_share() {
    let chain = SwapChain::new(Difficulty::from_u64(1));
    let g = genesis();
    chain.add_share(g.clone()).unwrap();
    assert_eq!(chain.share_count(), 1);
    assert_eq!(chain.tip_id(), Some(g.id()));
}

#[test]
fn escrow_open_claim_lifecycle() {
    let chain = SwapChain::new(Difficulty::from_u64(1));
    let c = make_commitment(1);
    let id = c.swap_id;

    // Open
    let diff = Difficulty::from_u64(1);
    let s1 = SwapShare {
        parent: [0u8; 32],
        uncles: vec![],
        height: 0,
        difficulty: diff,
        cumulative_difficulty: diff,
        timestamp: 0,
        nonce: 0,
        escrow_ops: vec![EscrowOp::Open(c)],
        escrow_merkle_root: [0u8; 32],
        pow_proof: None,
    };
    chain.add_share(s1.clone()).unwrap();
    {
        let idx = chain.escrow_index.read();
        assert!(matches!(idx.get(&id), Some(EscrowState::Open(_))));
    }

    // Claim ; k_b must match k_b_expected from the commitment
    let expected_k_b = [1 + 3; 32]; // make_commitment(1) sets k_b_expected = [id + 3; 32]
    let s2 = next_share(&chain, vec![EscrowOp::Claim { swap_id: id, k_b: expected_k_b }]);
    chain.add_share(s2).unwrap();

    let idx = chain.escrow_index.read();
    let state = idx.get(&id).unwrap();
    assert!(matches!(state, EscrowState::Claimed { .. }));
    match state {
        EscrowState::Claimed { k_b } => assert_eq!(k_b, &expected_k_b),
        _ => panic!("expected claimed"),
    }
}

#[test]
fn escrow_open_refund_lifecycle() {
    let chain = SwapChain::new(Difficulty::from_u64(1));
    let c = make_commitment(2);
    let id = c.swap_id;

    let diff = Difficulty::from_u64(1);
    let s1 = SwapShare {
        parent: [0u8; 32],
        uncles: vec![],
        height: 0,
        difficulty: diff,
        cumulative_difficulty: diff,
        timestamp: 0,
        nonce: 0,
        escrow_ops: vec![EscrowOp::Open(c)],
        escrow_merkle_root: [0u8; 32],
        pow_proof: None,
    };
    chain.add_share(s1).unwrap();

    let s2 = next_share(&chain, vec![EscrowOp::Refund { swap_id: id, sig: [0u8; 64] }]);
    chain.add_share(s2).unwrap();

    let idx = chain.escrow_index.read();
    assert!(matches!(idx.get(&id), Some(EscrowState::Refunded)));
}

#[test]
fn two_shares_tip_advances() {
    let chain = SwapChain::new(Difficulty::from_u64(1));
    let g = genesis();
    chain.add_share(g.clone()).unwrap();
    assert_eq!(chain.share_count(), 1);

    let s2 = next_share(&chain, vec![]);
    let s2_id = s2.id();
    chain.add_share(s2).unwrap();
    assert_eq!(chain.share_count(), 2);
    assert_eq!(chain.tip_id(), Some(s2_id));
}

#[test]
fn consensus_id_is_correct() {
    assert_eq!(CONSENSUS_ID, b"xmr-wow-swap-v1");
    assert_eq!(CONSENSUS_ID.len(), 15);
}

#[test]
fn escrow_index_standalone() {
    let mut idx = EscrowIndex::new();
    let c = make_commitment(10);
    let id = c.swap_id;

    idx.apply(&EscrowOp::Open(c.clone())).unwrap();
    assert!(matches!(idx.get(&id), Some(EscrowState::Open(_))));

    // k_b must match k_b_expected from the commitment: make_commitment(10) -> [10 + 3; 32]
    idx.apply(&EscrowOp::Claim { swap_id: id, k_b: [10 + 3; 32] }).unwrap();
    assert!(matches!(idx.get(&id), Some(EscrowState::Claimed { .. })));
}

#[test]
fn p2p_message_encodes_and_decodes() {
    use xmr_wow_sharechain::p2p::messages::{P2PMessage, MessageId};
    use bytes::Bytes;
    // Use ListenPort as a simple round-trip message (no Ping variant exists)
    let msg = P2PMessage::ListenPort(12345);
    let enc = msg.encode();
    let size = u32::from_le_bytes(enc[1..5].try_into().unwrap()) as usize;
    let payload = Bytes::copy_from_slice(&enc[5..5 + size]);
    let dec = P2PMessage::decode(MessageId::ListenPort, payload).unwrap();
    match dec {
        P2PMessage::ListenPort(port) => assert_eq!(port, 12345),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn build_chain_helper_produces_n_shares() {
    let chain = build_chain(5);
    assert_eq!(chain.share_count(), 5);
}

#[test]
fn wrong_parent_rejected() {
    let chain = SwapChain::new(Difficulty::from_u64(1));
    chain.add_share(genesis()).unwrap();
    let diff = Difficulty::from_u64(1);
    let bad = SwapShare {
        parent: [0xBE; 32],
        uncles: vec![],
        height: 1,
        difficulty: diff,
        cumulative_difficulty: diff.wrapping_add(diff),
        timestamp: 0,
        nonce: 0,
        escrow_ops: vec![],
        escrow_merkle_root: [0u8; 32],
        pow_proof: None,
    };
    assert!(chain.add_share(bad).is_err());
}

#[test]
fn duplicate_open_rejected() {
    let chain = SwapChain::new(Difficulty::from_u64(1));
    let c = make_commitment(3);
    let diff = Difficulty::from_u64(1);
    let s1 = SwapShare {
        parent: [0u8; 32],
        uncles: vec![],
        height: 0,
        difficulty: diff,
        cumulative_difficulty: diff,
        timestamp: 0,
        nonce: 0,
        escrow_ops: vec![EscrowOp::Open(c.clone())],
        escrow_merkle_root: [0u8; 32],
        pow_proof: None,
    };
    chain.add_share(s1).unwrap();

    // Try to open the same escrow again
    let s2 = next_share(&chain, vec![EscrowOp::Open(c)]);
    assert!(chain.add_share(s2).is_err());
}
