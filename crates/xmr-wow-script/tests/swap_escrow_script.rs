//! Integration tests for the canonical atomic swap escrow script.

mod helpers;
use helpers::{ctx, fail_engine, stub_engine};
use xmr_wow_script::{
    scripts::swap_escrow::{
        build_swap_escrow_script, claim_witness, refund_witness,
    },
    ScriptError,
};

// -- Test fixtures -------------------------------------------------------------

/// Standard test parameters for swap escrow scripts.
struct SwapFixture {
    k_b_point: [u8; 32],
    k_b_prime: [u8; 32],
    alice_sc_pubkey: [u8; 32],
    bob_sc_pubkey: [u8; 32],
    claim_deadline: u64,
    refund_height: u64,
    k_b_scalar: [u8; 32],   // scalar such that (stub) k_b_scalar*G == k_b_point
}

fn fixture() -> SwapFixture {
    SwapFixture {
        k_b_point:       [0x11u8; 32],
        k_b_prime:       [0x22u8; 32],
        alice_sc_pubkey: [0x33u8; 32],
        bob_sc_pubkey:   [0x44u8; 32],
        claim_deadline:  200,
        refund_height:   300,
        k_b_scalar:      [0x55u8; 32], // with StubBackend always valid
    }
}

// -- Claim path tests ----------------------------------------------------------

#[test]
fn alice_can_claim_with_valid_k_b_before_deadline() {
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    let witness = claim_witness(&f.k_b_scalar);
    // height < claim_deadline: claim window open
    let result = stub_engine().execute(&script, &witness, &ctx(100));
    assert!(result.valid, "expected valid claim: {:?}", result.error);

    // Verify RevealSecret was emitted with correct commitment and recipient
    assert_eq!(result.revealed_secrets.len(), 1, "expected one secret reveal");
    let reveal = &result.revealed_secrets[0];
    assert_eq!(reveal.commitment, f.k_b_prime, "wrong commitment revealed");
    assert_eq!(reveal.recipient, f.alice_sc_pubkey, "wrong recipient");
}

#[test]
fn alice_cannot_claim_after_deadline() {
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    let witness = claim_witness(&f.k_b_scalar);
    // height == claim_deadline: window closed (expiry is exclusive at deadline)
    let result = stub_engine().execute(&script, &witness, &ctx(f.claim_deadline));
    assert!(!result.valid, "expected failure after deadline");
    assert_eq!(
        result.error,
        Some(ScriptError::LockTimeExpired {
            current: f.claim_deadline,
            expiry: f.claim_deadline,
        })
    );
}

#[test]
fn alice_cannot_claim_with_wrong_k_b() {
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    // Use AlwaysFailBackend so check_keypair returns false -> CheckKeyPairVerify aborts
    let witness = claim_witness(&f.k_b_scalar);
    let result = fail_engine().execute(&script, &witness, &ctx(100));
    assert!(!result.valid, "expected failure with wrong k_b");
    assert_eq!(result.error, Some(ScriptError::KeyPairMismatch));
}

#[test]
fn alice_claim_at_height_zero_before_deadline() {
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    let witness = claim_witness(&f.k_b_scalar);
    let result = stub_engine().execute(&script, &witness, &ctx(0));
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.revealed_secrets.len(), 1);
}

// -- Refund path tests ---------------------------------------------------------

#[test]
fn bob_can_refund_after_refund_height() {
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    let sig = [0xAAu8; 64];
    let message = [0xBBu8; 32];
    let witness = refund_witness(&sig, &message);
    // height >= refund_height AND past claim_deadline
    let result = stub_engine().execute(&script, &witness, &ctx(f.refund_height));
    assert!(result.valid, "expected valid refund: {:?}", result.error);
    assert!(result.revealed_secrets.is_empty(), "refund should not emit reveal");
}

#[test]
fn bob_cannot_refund_before_refund_height() {
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    let sig = [0xAAu8; 64];
    let message = [0xBBu8; 32];
    let witness = refund_witness(&sig, &message);
    // height < refund_height
    let result = stub_engine().execute(&script, &witness, &ctx(f.refund_height - 1));
    assert!(!result.valid, "expected failure before refund height");
    assert!(matches!(
        result.error,
        Some(ScriptError::LockTimeNotReached { .. })
    ));
}

#[test]
fn bob_refund_with_invalid_sig_fails() {
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    let sig = [0xAAu8; 64];
    let message = [0xBBu8; 32];
    let witness = refund_witness(&sig, &message);
    let result = fail_engine().execute(&script, &witness, &ctx(f.refund_height));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::SignatureInvalid));
}

#[test]
fn bob_cannot_use_claim_path_with_garbage_k_b() {
    // Bob tries to use the claim path but provides a bad k_b.
    // AlwaysFailBackend: CheckKeyPairVerify will abort.
    let f = fixture();
    let script = build_swap_escrow_script(
        &f.k_b_point, &f.k_b_prime, &f.alice_sc_pubkey, &f.bob_sc_pubkey,
        f.claim_deadline, f.refund_height,
    );
    // Non-zero to trigger IF branch, but crypto will fail
    let garbage_k_b = [0x99u8; 32];
    let witness = claim_witness(&garbage_k_b);
    let result = fail_engine().execute(&script, &witness, &ctx(100));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::KeyPairMismatch));
}
