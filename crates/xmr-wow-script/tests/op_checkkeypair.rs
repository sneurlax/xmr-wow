//! Tests for OP_CHECKKEYPAIR and OP_CHECKKEYPAIRVERIFY.
//!
//! With stub-crypto, check_keypair always returns Ok(true), so "valid" tests
//! always pass. For "invalid" tests we use AlwaysFailBackend or arrange
//! for the engine to error on malformed input before crypto is called.

mod helpers;
use helpers::{bytes32, ctx, fail_engine, stub_engine};
use xmr_wow_script::{Opcode, ScriptError};

// -- CheckKeyPair (non-verify: pushes result) ----------------------------------

#[test]
fn valid_keypair_executes_successfully() {
    // Script: PUSH scalar | PUSH point | CheckKeyPairVerify | PUSH 1
    // With StubBackend, keypair always valid.
    let scalar = bytes32(0x11);
    let point = bytes32(0x22);
    let script = vec![
        Opcode::Push(scalar),
        Opcode::Push(point),
        Opcode::CheckKeyPairVerify,
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(result.valid, "expected valid, got error: {:?}", result.error);
}

#[test]
fn checkkeypair_returns_false_not_abort_without_verify_suffix() {
    // CheckKeyPair (not Verify) should push 0x00 when crypto fails,
    // then execution continues (the Verify at end catches it).
    // Use AlwaysFailBackend so check_keypair returns false.
    let scalar = bytes32(0x11);
    let point = bytes32(0x22);
    let script = vec![
        Opcode::Push(scalar),
        Opcode::Push(point),
        Opcode::CheckKeyPair, // pushes [0x00] ; does NOT abort
        Opcode::Verify,       // pops [0x00] ; THIS aborts because falsy
    ];
    let result = fail_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::VerifyFailed));
}

#[test]
fn checkkeypair_result_can_be_tested_with_equal() {
    // CheckKeyPair pushes [0x00] on failure, script can branch on it.
    let scalar = bytes32(0x11);
    let point = bytes32(0x22);
    let script = vec![
        Opcode::Push(scalar),
        Opcode::Push(point),
        Opcode::CheckKeyPair,       // pushes [0x00] (fail backend)
        Opcode::Push(vec![0x00]),   // expected false
        Opcode::EqualVerify,        // verifies they match
        Opcode::Push(vec![0x01]),   // leave truthy result
    ];
    let result = fail_engine().execute(&script, &[], &ctx(0));
    assert!(result.valid, "expected valid: {:?}", result.error);
}

// -- CheckKeyPairVerify (aborts on failure) ------------------------------------

#[test]
fn invalid_keypair_aborts() {
    // AlwaysFailBackend returns Ok(false) -> CheckKeyPairVerify -> KeyPairMismatch
    let scalar = bytes32(0x11);
    let point = bytes32(0x22);
    let script = vec![
        Opcode::Push(scalar),
        Opcode::Push(point),
        Opcode::CheckKeyPairVerify,
    ];
    let result = fail_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::KeyPairMismatch));
}

// -- Malformed input errors ----------------------------------------------------

#[test]
fn wrong_scalar_size_aborts() {
    // 31-byte scalar -> engine tries to interpret top as point (32 req) -> error
    // Stack layout for CheckKeyPair: [..., scalar, point] with point on top.
    // Push 31-byte item as point -> InvalidPointLength
    let bad_scalar = vec![0x11u8; 31]; // 31 bytes ; wrong size for point
    let point = bytes32(0x22);
    let script = vec![
        Opcode::Push(bad_scalar), // this will be consumed as "scalar" (below point)
        Opcode::Push(point),
        Opcode::CheckKeyPair,
        Opcode::Push(vec![0x01]),
    ];
    // StubBackend is used but won't be called ; the size check happens first.
    // Actually: items[0]=top=point(32 ok), items[1]=below=scalar(31 bytes)
    // to_32(&items[1]) will fail with InvalidPointLength (we reuse that error for scalar).
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    // The error is InvalidPointLength because to_32 is used for both
    // (both must be 32 bytes)
    assert!(matches!(
        result.error,
        Some(ScriptError::InvalidPointLength { got: 31 })
    ));
}

#[test]
fn wrong_point_size_aborts() {
    let scalar = bytes32(0x11);
    let bad_point = vec![0x22u8; 31]; // 31 bytes
    let script = vec![
        Opcode::Push(scalar),
        Opcode::Push(bad_point), // top item ; consumed as point
        Opcode::CheckKeyPair,
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert!(matches!(
        result.error,
        Some(ScriptError::InvalidPointLength { got: 31 })
    ));
}

#[test]
fn stack_underflow_on_checkkeypair_with_empty_stack() {
    let script = vec![Opcode::CheckKeyPair];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert!(matches!(
        result.error,
        Some(ScriptError::StackUnderflow { .. })
    ));
}

#[test]
fn stack_underflow_on_checkkeypair_with_one_item() {
    let script = vec![
        Opcode::Push(bytes32(0x11)),
        Opcode::CheckKeyPair,
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert!(matches!(
        result.error,
        Some(ScriptError::StackUnderflow { needed: 2, have: 1 })
    ));
}
