use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use rand::rngs::OsRng;
/// Integration tests: full crypto primitive tests using real xmr-wow-crypto.
///
/// These complement the unit tests in xmr-wow-crypto, exercising the API
/// from the perspective of an external consumer.
use xmr_wow_crypto::{
    combine_public_keys, combine_secrets, derive_view_key, encode_address, joint_address,
    keccak256, verify_keypair, AdaptorSignature, DleqProof, KeyContribution, Network,
};

// --- Key split tests ---------------------------------------------------------

#[test]
fn keysplit_and_joint_address_xmr() {
    let alice = KeyContribution::generate(&mut OsRng);
    let bob = KeyContribution::generate(&mut OsRng);

    let joint_pub = combine_public_keys(&alice.public, &bob.public);
    let joint_sec = combine_secrets(&alice.secret, &bob.secret);

    // Algebraic check: (k_a + k_b)*G == K_a + K_b
    assert!(verify_keypair(&joint_sec, &joint_pub));

    // View key from joint spend
    let joint_spend_scalar = Scalar::from_bytes_mod_order(joint_pub.compress().to_bytes());
    let view = derive_view_key(&joint_spend_scalar);
    let view_point = view * G;

    let addr = encode_address(&joint_pub, &view_point, Network::MoneroStagenet);
    assert_eq!(addr.len(), 95, "XMR stagenet address must be 95 chars");
}

#[test]
fn keysplit_and_joint_address_wow() {
    let alice = KeyContribution::generate(&mut OsRng);
    let bob = KeyContribution::generate(&mut OsRng);

    let joint_pub = combine_public_keys(&alice.public, &bob.public);
    let joint_spend_scalar = Scalar::from_bytes_mod_order(joint_pub.compress().to_bytes());
    let view = derive_view_key(&joint_spend_scalar);
    let view_point = view * G;

    let addr = joint_address(&alice.public, &bob.public, &view_point, Network::Wownero);
    assert_eq!(addr.len(), 97, "WOW address must be 97 chars");
}

// --- DLEQ tests --------------------------------------------------------------

#[test]
fn dleq_prove_verify_roundtrip() {
    let contrib = KeyContribution::generate(&mut OsRng);
    let proof = DleqProof::prove(&contrib.secret, &contrib.public, b"xmr-wow-v1", &mut OsRng);
    assert!(proof.verify(&contrib.public, b"xmr-wow-v1").is_ok());
}

#[test]
fn dleq_wrong_key_rejected() {
    let alice = KeyContribution::generate(&mut OsRng);
    let bob = KeyContribution::generate(&mut OsRng);
    let proof = DleqProof::prove(&alice.secret, &alice.public, b"ctx", &mut OsRng);
    // Proof for alice's key should NOT verify against bob's public key
    assert!(proof.verify(&bob.public, b"ctx").is_err());
}

#[test]
fn dleq_wrong_context_rejected() {
    let contrib = KeyContribution::generate(&mut OsRng);
    let proof = DleqProof::prove(&contrib.secret, &contrib.public, b"context-a", &mut OsRng);
    assert!(proof.verify(&contrib.public, b"context-b").is_err());
}

#[test]
fn dleq_bytes_roundtrip() {
    let contrib = KeyContribution::generate(&mut OsRng);
    let proof = DleqProof::prove(&contrib.secret, &contrib.public, b"roundtrip", &mut OsRng);
    let bytes = proof.to_bytes();
    let recovered = DleqProof::from_bytes(&bytes).unwrap();
    assert!(recovered.verify(&contrib.public, b"roundtrip").is_ok());
}

// --- Adaptor signature tests -------------------------------------------------

#[test]
fn adaptor_sig_roundtrip() {
    let a = Scalar::random(&mut OsRng);
    let a_point = a * G;
    let t = Scalar::random(&mut OsRng);
    let adaptor_point = t * G;
    let msg = b"xmr-wow-swap-claim";

    let pre_sig = AdaptorSignature::sign(&a, &a_point, msg, &adaptor_point, &mut OsRng);
    assert!(pre_sig
        .verify_pre_sig(&a_point, msg, &adaptor_point)
        .is_ok());

    let completed = pre_sig.complete(&t).unwrap();
    assert!(completed.verify(&a_point, msg).is_ok());

    let recovered_t = pre_sig.extract_secret(&completed).unwrap();
    assert_eq!(recovered_t.to_bytes(), t.to_bytes());
}

#[test]
fn adaptor_wrong_t_fails_verify() {
    let a = Scalar::random(&mut OsRng);
    let a_point = a * G;
    let t = Scalar::random(&mut OsRng);
    let adaptor_point = t * G;
    let t2 = Scalar::random(&mut OsRng);
    let msg = b"message";

    let pre_sig = AdaptorSignature::sign(&a, &a_point, msg, &adaptor_point, &mut OsRng);
    let completed_wrong = pre_sig.complete(&t2).unwrap();
    assert!(completed_wrong.verify(&a_point, msg).is_err());
}

// --- Address tests -----------------------------------------------------------

#[test]
fn wow_address_is_97_chars() {
    let spend = Scalar::random(&mut OsRng) * G;
    let view = Scalar::random(&mut OsRng) * G;
    let addr = encode_address(&spend, &view, Network::Wownero);
    assert_eq!(
        addr.len(),
        97,
        "WOW address must be 97 chars, got {}",
        addr.len()
    );
}

#[test]
fn xmr_stagenet_address_is_95_chars() {
    let spend = Scalar::random(&mut OsRng) * G;
    let view = Scalar::random(&mut OsRng) * G;
    let addr = encode_address(&spend, &view, Network::MoneroStagenet);
    assert_eq!(addr.len(), 95);
}

// --- View key derivation -----------------------------------------------------

#[test]
fn view_key_derivation_is_deterministic() {
    let spend = Scalar::random(&mut OsRng);
    let v1 = derive_view_key(&spend);
    let v2 = derive_view_key(&spend);
    assert_eq!(v1.to_bytes(), v2.to_bytes());
}

#[test]
fn view_key_differs_for_different_spend_keys() {
    let s1 = Scalar::random(&mut OsRng);
    let s2 = Scalar::random(&mut OsRng);
    let v1 = derive_view_key(&s1);
    let v2 = derive_view_key(&s2);
    assert_ne!(v1.to_bytes(), v2.to_bytes());
}

// --- Keccak ------------------------------------------------------------------

#[test]
fn keccak256_is_deterministic() {
    let h1 = keccak256(b"xmr-wow-swap");
    let h2 = keccak256(b"xmr-wow-swap");
    assert_eq!(h1, h2);
}

#[test]
fn keccak256_differs_for_different_inputs() {
    let h1 = keccak256(b"alice");
    let h2 = keccak256(b"bob");
    assert_ne!(h1, h2);
}
