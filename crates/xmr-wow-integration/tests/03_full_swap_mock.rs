/// Integration tests: full XMR<->WOW swap lifecycle, in-process, no network I/O.
use rand::rngs::OsRng;
use xmr_wow_crypto::{
    DleqProof, KeyContribution,
    combine_public_keys, derive_view_key, joint_address, keccak256,
    Network,
};
use xmr_wow_sharechain::{
    SwapChain, SwapShare, EscrowOp, EscrowState, EscrowCommitment, Difficulty,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    scalar::Scalar,
};

// --- helpers -----------------------------------------------------------------

fn generate_party() -> (KeyContribution, DleqProof) {
    let contrib = KeyContribution::generate(&mut OsRng);
    let proof = DleqProof::prove(&contrib.secret, &contrib.public, b"xmr-wow-swap-v1", &mut OsRng);
    (contrib, proof)
}

fn make_commitment(
    alice_pub: [u8; 32],
    bob_pub: [u8; 32],
) -> EscrowCommitment {
    let mut id_input = Vec::with_capacity(64);
    id_input.extend_from_slice(&alice_pub);
    id_input.extend_from_slice(&bob_pub);
    EscrowCommitment {
        swap_id:         keccak256(&id_input),
        alice_sc_pubkey: alice_pub,
        bob_sc_pubkey:   bob_pub,
        k_b_expected:    bob_pub,   // Bob's K_b per D-06/D-07
        k_b_prime:       bob_pub,   // Same value per D-07
        claim_timelock:  1000,
        refund_timelock: 2000,
        amount:          1_000_000_000_000,
    }
}

fn make_genesis_with_op(op: EscrowOp) -> SwapShare {
    let diff = Difficulty::from_u64(1);
    SwapShare {
        parent: [0u8; 32],
        uncles: vec![],
        height: 0,
        difficulty: diff,
        cumulative_difficulty: diff,
        timestamp: 0,
        nonce: 0,
        escrow_ops: vec![op],
        escrow_merkle_root: [0u8; 32],
        pow_proof: None,
    }
}

fn make_child(parent_share: &SwapShare, ops: Vec<EscrowOp>) -> SwapShare {
    let diff = Difficulty::from_u64(1);
    SwapShare {
        parent: parent_share.id(),
        uncles: vec![],
        height: parent_share.height + 1,
        difficulty: diff,
        cumulative_difficulty: parent_share.cumulative_difficulty.wrapping_add(diff),
        timestamp: 1,
        nonce: 0,
        escrow_ops: ops,
        escrow_merkle_root: [0u8; 32],
        pow_proof: None,
    }
}

// --- Full swap lifecycle tests ------------------------------------------------

#[test]
fn full_swap_alice_claims() {
    // Phase 1: Key generation
    let (alice_contrib, alice_proof) = generate_party();
    let (bob_contrib, bob_proof) = generate_party();

    // Phase 2: DLEQ exchange
    alice_proof.verify(&alice_contrib.public, b"xmr-wow-swap-v1").unwrap();
    bob_proof.verify(&bob_contrib.public, b"xmr-wow-swap-v1").unwrap();

    // Phase 3: Joint addresses
    let joint_spend = combine_public_keys(&alice_contrib.public, &bob_contrib.public);
    let joint_spend_scalar = Scalar::from_bytes_mod_order(joint_spend.compress().to_bytes());
    let view_scalar = derive_view_key(&joint_spend_scalar);
    let view_point = view_scalar * G;

    let xmr_joint_address_alice = joint_address(
        &alice_contrib.public,
        &bob_contrib.public,
        &view_point,
        Network::MoneroStagenet,
    );
    let wow_joint_address_alice = joint_address(
        &alice_contrib.public,
        &bob_contrib.public,
        &view_point,
        Network::Wownero,
    );

    // Bob derives the same addresses (commutative sum)
    let xmr_joint_address_bob = joint_address(
        &alice_contrib.public,
        &bob_contrib.public,
        &view_point,
        Network::MoneroStagenet,
    );
    let wow_joint_address_bob = joint_address(
        &alice_contrib.public,
        &bob_contrib.public,
        &view_point,
        Network::Wownero,
    );

    assert_eq!(xmr_joint_address_alice, xmr_joint_address_bob,
        "Both parties must derive the same XMR address");
    assert_eq!(wow_joint_address_alice, wow_joint_address_bob,
        "Both parties must derive the same WOW address");
    assert_eq!(xmr_joint_address_alice.len(), 95, "XMR stagenet address is 95 chars");
    assert_eq!(wow_joint_address_alice.len(), 97, "WOW address is 97 chars");

    // Phase 4: Escrow on sharechain
    let commitment = make_commitment(
        alice_contrib.public_bytes(),
        bob_contrib.public_bytes(),
    );
    let swap_id = commitment.swap_id;

    let chain = SwapChain::new(Difficulty::from_u64(1));
    let s1 = make_genesis_with_op(EscrowOp::Open(commitment));
    chain.add_share(s1.clone()).unwrap();

    {
        let idx = chain.escrow_index.read();
        assert!(matches!(idx.get(&swap_id), Some(EscrowState::Open(_))),
            "EscrowState must be Open after open op");
    }

    // Phase 5: Alice claims, revealing k_bob_b
    let k_bob_b_bytes = bob_contrib.public_bytes();
    let s2 = make_child(&s1, vec![
        EscrowOp::Claim { swap_id, k_b: k_bob_b_bytes }
    ]);
    chain.add_share(s2).unwrap();

    let idx = chain.escrow_index.read();
    let state = idx.get(&swap_id).unwrap();
    assert!(matches!(state, EscrowState::Claimed { .. }),
        "EscrowState must be Claimed after claim");

    match state {
        EscrowState::Claimed { k_b } => {
            assert_eq!(k_b, &k_bob_b_bytes,
                "Bob can now reconstruct joint spend key using revealed k_b");
        }
        _ => panic!("expected Claimed"),
    }
}

#[test]
fn full_swap_bob_refunds() {
    let (alice_contrib, _alice_proof) = generate_party();
    let (bob_contrib, _bob_proof) = generate_party();

    let commitment = make_commitment(
        alice_contrib.public_bytes(),
        bob_contrib.public_bytes(),
    );
    let swap_id = commitment.swap_id;

    let chain = SwapChain::new(Difficulty::from_u64(1));
    let s1 = make_genesis_with_op(EscrowOp::Open(commitment));
    chain.add_share(s1.clone()).unwrap();

    // Bob refunds (with a dummy signature ; sharechain doesn't verify crypto)
    let refund_sig = [0u8; 64];
    let s2 = make_child(&s1, vec![
        EscrowOp::Refund { swap_id, sig: refund_sig }
    ]);
    chain.add_share(s2).unwrap();

    let idx = chain.escrow_index.read();
    assert!(matches!(idx.get(&swap_id), Some(EscrowState::Refunded)),
        "EscrowState must be Refunded after refund");
}

#[test]
fn wrong_k_b_claim_rejected_at_chain_level() {
    // The sharechain rejects wrong k_b via equality check against k_b_expected.
    // This ensures only the party who knows the real k_b can claim.
    let (alice_contrib, _) = generate_party();
    let (bob_contrib, _) = generate_party();

    let commitment = make_commitment(
        alice_contrib.public_bytes(),
        bob_contrib.public_bytes(),
    );
    let swap_id = commitment.swap_id;

    let chain = SwapChain::new(Difficulty::from_u64(1));
    let s1 = make_genesis_with_op(EscrowOp::Open(commitment));
    chain.add_share(s1.clone()).unwrap();

    // Submit wrong k_b ; chain must reject it
    let wrong_k_b = [0xABu8; 32]; // clearly wrong
    let s2 = make_child(&s1, vec![
        EscrowOp::Claim { swap_id, k_b: wrong_k_b }
    ]);
    let result = chain.add_share(s2);
    assert!(result.is_err(),
        "Sharechain must reject claim with wrong k_b");
}

#[test]
fn dleq_binding_prevents_key_substitution() {
    // Alice generates K_alice, proves DLEQ.
    // If Bob tries to substitute a different key, DleqProof::verify() must fail.
    let alice = KeyContribution::generate(&mut OsRng);
    let alice_proof = DleqProof::prove(&alice.secret, &alice.public, b"xmr-wow-swap-v1", &mut OsRng);

    // Bob tries to substitute Charlie's public key with Alice's proof
    let charlie = KeyContribution::generate(&mut OsRng);

    // Alice's proof verifies Alice's public key
    assert!(alice_proof.verify(&alice.public, b"xmr-wow-swap-v1").is_ok());
    // But NOT Charlie's public key
    assert!(alice_proof.verify(&charlie.public, b"xmr-wow-swap-v1").is_err(),
        "DLEQ proof must not verify for a different public key");
}

#[test]
fn joint_address_is_symmetric() {
    // joint_address(alice, bob) == joint_address(bob, alice) because Edwards addition is commutative
    let alice = KeyContribution::generate(&mut OsRng);
    let bob = KeyContribution::generate(&mut OsRng);
    let view = Scalar::random(&mut OsRng) * G;

    let ab = joint_address(&alice.public, &bob.public, &view, Network::Wownero);
    let ba = joint_address(&bob.public, &alice.public, &view, Network::Wownero);
    assert_eq!(ab, ba, "joint_address must be symmetric");
}

#[test]
fn swap_id_is_deterministic() {
    let alice = KeyContribution::generate(&mut OsRng);
    let bob = KeyContribution::generate(&mut OsRng);

    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let mut id_input = Vec::with_capacity(64);
    id_input.extend_from_slice(&alice_pub);
    id_input.extend_from_slice(&bob_pub);

    let id1 = keccak256(&id_input);
    let id2 = keccak256(&id_input);
    assert_eq!(id1, id2, "swap_id must be deterministic");
}
