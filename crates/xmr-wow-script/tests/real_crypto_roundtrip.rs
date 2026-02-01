//! Ed25519Backend integration tests (requires `real-crypto` feature).
//!
//! Verifies OP_CHECKKEYPAIR with real curve25519-dalek scalar multiplication
//! rather than the stub backend used by the unit tests.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use xmr_wow_script::{Ed25519Backend, Engine, Opcode, ScriptContext, ScriptError};

/// Build a test script context (height 0, dummy tx/output hashes).
fn ctx(height: u64) -> ScriptContext {
    ScriptContext {
        current_height: height,
        tx_hash: [0xABu8; 32],
        output_id: [0xCDu8; 32],
    }
}

/// Build an engine with the real Ed25519 backend.
fn real_engine() -> Engine<Ed25519Backend> {
    Engine::new(Ed25519Backend)
}

// ---------------------------------------------------------------------------
// Keypair generation helpers
//
// We generate deterministic keypairs from fixed scalars to avoid depending
// on a random number generator in tests (tests must be reproducible).
// ---------------------------------------------------------------------------

/// Compute the Ed25519 public key (compressed point) for a given scalar byte array.
///
/// Uses `curve25519-dalek` directly: point = scalar_mod_order * ED25519_BASEPOINT_POINT.
fn pubkey_for(scalar_bytes: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*scalar_bytes);
    let point = scalar * ED25519_BASEPOINT_POINT;
    point.compress().to_bytes()
}

/// Scalar A: 0x01 repeated: a non-zero, non-trivial scalar.
const SCALAR_A: [u8; 32] = [0x01u8; 32];

/// Scalar B: 0x02 repeated: a different scalar from A.
const SCALAR_B: [u8; 32] = [0x02u8; 32];

// ---------------------------------------------------------------------------
// Test 1: Valid keypair passes OP_CHECKKEYPAIRVERIFY
//
// Script: PUSH scalar_a | PUSH pubkey_a | CheckKeyPairVerify | PUSH 0x01
// With Ed25519Backend, scalar_a * G == pubkey_a, so the verify succeeds.
// ---------------------------------------------------------------------------

#[test]
fn test_real_keypair_valid_passes_checkkeypairverify() {
    let pubkey = pubkey_for(&SCALAR_A);

    // Cross-verify our test helper: the backend's check_keypair should agree
    // that (SCALAR_A, pubkey_for(SCALAR_A)) is a valid keypair.
    use xmr_wow_script::backend::CryptoBackend;
    let backend = Ed25519Backend;
    assert!(
        backend.check_keypair(&SCALAR_A, &pubkey).unwrap_or(false),
        "Ed25519Backend must confirm valid keypair before script test"
    );

    let script = vec![
        Opcode::Push(SCALAR_A.to_vec()),
        Opcode::Push(pubkey.to_vec()),
        Opcode::CheckKeyPairVerify,
        Opcode::Push(vec![0x01]), // leave truthy result on stack
    ];

    let result = real_engine().execute(&script, &[], &ctx(0));
    assert!(
        result.valid,
        "valid real keypair must pass CheckKeyPairVerify; error: {:?}",
        result.error
    );
}

// ---------------------------------------------------------------------------
// Test 2: Mismatched keypair fails OP_CHECKKEYPAIRVERIFY
//
// Script: PUSH scalar_a | PUSH pubkey_b | CheckKeyPairVerify
// scalar_a * G != pubkey_b, so the verify must fail with KeyPairMismatch.
// ---------------------------------------------------------------------------

#[test]
fn test_real_keypair_mismatch_fails_checkkeypairverify() {
    let wrong_pubkey = pubkey_for(&SCALAR_B); // pubkey for scalar_b, not scalar_a

    // Cross-verify: the backend must reject SCALAR_A paired with pubkey_for(SCALAR_B).
    use xmr_wow_script::backend::CryptoBackend;
    let backend = Ed25519Backend;
    let check = backend
        .check_keypair(&SCALAR_A, &wrong_pubkey)
        .unwrap_or(true);
    assert!(
        !check,
        "Ed25519Backend must reject mismatched keypair before script test"
    );

    let script = vec![
        Opcode::Push(SCALAR_A.to_vec()),
        Opcode::Push(wrong_pubkey.to_vec()),
        Opcode::CheckKeyPairVerify, // must abort with KeyPairMismatch
    ];

    let result = real_engine().execute(&script, &[], &ctx(0));
    assert!(
        !result.valid,
        "mismatched real keypair must fail CheckKeyPairVerify"
    );
    assert_eq!(
        result.error,
        Some(ScriptError::KeyPairMismatch),
        "expected KeyPairMismatch error for mismatched keypair"
    );
}

// ---------------------------------------------------------------------------
// Test 3: CheckKeyPair (non-verify) pushes truthy result for valid keypair
//
// Script: PUSH scalar | PUSH pubkey | CheckKeyPair
// On success, CheckKeyPair leaves [0x01] on the stack. The engine's final
// truthy-top check validates the result. No explicit Verify needed.
// ---------------------------------------------------------------------------

#[test]
fn test_real_checkkeypair_pushes_true_for_valid() {
    let pubkey = pubkey_for(&SCALAR_A);

    let script = vec![
        Opcode::Push(SCALAR_A.to_vec()),
        Opcode::Push(pubkey.to_vec()),
        Opcode::CheckKeyPair, // pushes [0x01] on success; engine checks truthy final stack
    ];

    let result = real_engine().execute(&script, &[], &ctx(0));
    assert!(
        result.valid,
        "CheckKeyPair with valid real keypair should push truthy; error: {:?}",
        result.error
    );
}

// ---------------------------------------------------------------------------
// Test 4: CheckKeyPair (non-verify) pushes 0x00 for invalid keypair
// ---------------------------------------------------------------------------

#[test]
fn test_real_checkkeypair_pushes_false_for_invalid() {
    let wrong_pubkey = pubkey_for(&SCALAR_B);

    let script = vec![
        Opcode::Push(SCALAR_A.to_vec()),
        Opcode::Push(wrong_pubkey.to_vec()),
        Opcode::CheckKeyPair,     // pushes [0x00] on mismatch
        Opcode::Push(vec![0x00]), // expected: false
        Opcode::EqualVerify,      // verifies stack top == 0x00
        Opcode::Push(vec![0x01]), // leave truthy result
    ];

    let result = real_engine().execute(&script, &[], &ctx(0));
    assert!(
        result.valid,
        "CheckKeyPair with mismatched keypair should push [0x00]; error: {:?}",
        result.error
    );
}

// ---------------------------------------------------------------------------
// Test 5: Non-canonical scalar rejected
//
// A scalar with the high bit set that is >= group order l is non-canonical.
// The Ed25519Backend must reject it via from_canonical_bytes.
// ---------------------------------------------------------------------------

#[test]
fn test_real_noncanonical_scalar_rejected() {
    // 0xFF...FF is larger than the Ed25519 group order and not canonical.
    // from_canonical_bytes will return None, triggering InvalidScalar.
    let noncanonical_scalar = [0xFFu8; 32];
    let pubkey = pubkey_for(&SCALAR_A);

    let script = vec![
        Opcode::Push(noncanonical_scalar.to_vec()),
        Opcode::Push(pubkey.to_vec()),
        Opcode::CheckKeyPairVerify,
    ];

    let result = real_engine().execute(&script, &[], &ctx(0));
    assert!(
        !result.valid,
        "non-canonical scalar must be rejected by Ed25519Backend"
    );
    // Either InvalidScalar (canonical check failed) is acceptable.
    assert!(
        matches!(result.error, Some(ScriptError::InvalidScalar) | Some(ScriptError::KeyPairMismatch)),
        "expected InvalidScalar or KeyPairMismatch for non-canonical scalar, got: {:?}",
        result.error
    );
}
