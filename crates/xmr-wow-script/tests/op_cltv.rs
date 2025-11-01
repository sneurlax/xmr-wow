//! Tests for CheckLockTimeVerify and CheckLockTimeExpiry.

mod helpers;
use helpers::{ctx, stub_engine};
use xmr_wow_script::{Opcode, ScriptError};

// -- CheckLockTimeVerify -------------------------------------------------------

#[test]
fn cltv_passes_when_height_reached() {
    let script = vec![
        Opcode::CheckLockTimeVerify(100),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(100));
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn cltv_passes_well_above_required() {
    let script = vec![
        Opcode::CheckLockTimeVerify(100),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(99999));
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn cltv_aborts_when_height_not_reached() {
    let script = vec![
        Opcode::CheckLockTimeVerify(100),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(99));
    assert!(!result.valid);
    assert_eq!(
        result.error,
        Some(ScriptError::LockTimeNotReached { current: 99, required: 100 })
    );
}

#[test]
fn cltv_aborts_at_zero_height_for_nonzero_lock() {
    let script = vec![
        Opcode::CheckLockTimeVerify(1),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert!(matches!(result.error, Some(ScriptError::LockTimeNotReached { .. })));
}

// -- CheckLockTimeExpiry -------------------------------------------------------

#[test]
fn cltv_expiry_passes_before_deadline() {
    let script = vec![
        Opcode::CheckLockTimeExpiry(100),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(99));
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn cltv_expiry_passes_at_zero() {
    let script = vec![
        Opcode::CheckLockTimeExpiry(100),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn cltv_expiry_aborts_at_deadline() {
    // CheckLockTimeExpiry requires current_height < expiry; at == expiry it fails
    let script = vec![
        Opcode::CheckLockTimeExpiry(100),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(100));
    assert!(!result.valid);
    assert_eq!(
        result.error,
        Some(ScriptError::LockTimeExpired { current: 100, expiry: 100 })
    );
}

#[test]
fn cltv_expiry_aborts_after_deadline() {
    let script = vec![
        Opcode::CheckLockTimeExpiry(100),
        Opcode::Push(vec![0x01]),
    ];
    let result = stub_engine().execute(&script, &[], &ctx(150));
    assert!(!result.valid);
    assert_eq!(
        result.error,
        Some(ScriptError::LockTimeExpired { current: 150, expiry: 100 })
    );
}
