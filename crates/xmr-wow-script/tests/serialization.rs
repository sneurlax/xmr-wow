//! Tests for script binary serialization and deserialization.

mod helpers;
use helpers::{bytes32, ctx, stub_engine};
use xmr_wow_script::{
    deserialize_script, serialize_script, Opcode, ScriptError,
    scripts::swap_escrow::build_swap_escrow_script,
};

// -- Round-trip tests ----------------------------------------------------------

#[test]
fn simple_script_serialization_roundtrip() {
    let script = vec![
        Opcode::Push(vec![0x01, 0x02, 0x03]),
        Opcode::Dup,
        Opcode::EqualVerify,
        Opcode::Push(vec![0x01]),
    ];
    let bytes = serialize_script(&script);
    let recovered = deserialize_script(&bytes).expect("deserialize failed");
    assert_eq!(script, recovered);
}

#[test]
fn canonical_swap_script_serialization_roundtrip() {
    let k_b_point = [0x11u8; 32];
    let k_b_prime = [0x22u8; 32];
    let alice_sc_pubkey = [0x33u8; 32];
    let bob_sc_pubkey = [0x44u8; 32];
    let script = build_swap_escrow_script(
        &k_b_point, &k_b_prime, &alice_sc_pubkey, &bob_sc_pubkey, 200, 300,
    );
    let bytes = serialize_script(&script);
    let recovered = deserialize_script(&bytes).expect("deserialize failed");
    assert_eq!(script, recovered, "roundtrip mismatch");
}

#[test]
fn all_opcodes_roundtrip() {
    let script = vec![
        Opcode::Push(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        Opcode::Dup,
        Opcode::Drop,
        Opcode::Swap,
        Opcode::Pick(2),
        Opcode::Equal,
        Opcode::EqualVerify,
        Opcode::Verify,
        Opcode::CheckKeyPair,
        Opcode::CheckKeyPairVerify,
        Opcode::CheckSig,
        Opcode::CheckSigVerify,
        Opcode::Hash256,
        Opcode::HashLockVerify,
        Opcode::CheckLockTimeVerify(0x0102030405060708),
        Opcode::CheckLockTimeExpiry(0xFFFFFFFFFFFFFFFF),
        Opcode::RevealSecret,
    ];
    // Wrap in a valid If/Else/EndIf structure for completeness
    let mut full = vec![Opcode::Push(vec![0x01]), Opcode::If];
    full.extend(script);
    full.push(Opcode::Else);
    full.push(Opcode::Push(vec![0x01]));
    full.push(Opcode::EndIf);

    let bytes = serialize_script(&full);
    let recovered = deserialize_script(&bytes).expect("deserialize failed");
    assert_eq!(full, recovered);
}

#[test]
fn cltv_height_preserved_exactly() {
    // Verify little-endian u64 serialization is correct.
    let h = 0x0102030405060708u64;
    let script = vec![
        Opcode::CheckLockTimeVerify(h),
        Opcode::Push(vec![0x01]),
    ];
    let bytes = serialize_script(&script);
    // version(1) + count(4) + tag(1) + height(8) + push_tag(1) + len(1) + data(1) = 17
    assert_eq!(bytes.len(), 17);
    // The height bytes start at offset 6 (after version + count + tag)
    let height_bytes = &bytes[6..14];
    assert_eq!(height_bytes, &h.to_le_bytes());
    let recovered = deserialize_script(&bytes).unwrap();
    assert_eq!(recovered[0], Opcode::CheckLockTimeVerify(h));
}

// -- Error cases ---------------------------------------------------------------

#[test]
fn serialization_rejects_unknown_opcode_tag() {
    // Manually craft a script with an unknown tag (0xFF)
    let mut bytes = Vec::new();
    bytes.push(0x01); // version
    bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 opcode declared
    bytes.push(0xFF); // unknown tag

    let result = deserialize_script(&bytes);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ScriptError::UnknownOpcodeTag { tag: 0xFF, .. }
    ));
}

#[test]
fn serialization_rejects_wrong_version() {
    let mut bytes = Vec::new();
    bytes.push(0x02); // wrong version
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let result = deserialize_script(&bytes);
    assert_eq!(result.unwrap_err(), ScriptError::UnsupportedVersion { got: 0x02 });
}

#[test]
fn serialization_rejects_truncated_push_data() {
    let mut bytes = Vec::new();
    bytes.push(0x01); // version
    bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 opcode
    bytes.push(0x01); // Push tag
    bytes.push(10);   // length = 10
    bytes.extend_from_slice(&[0xAA; 5]); // only 5 bytes of data (should be 10)

    let result = deserialize_script(&bytes);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ScriptError::PushLengthOverflow { .. }
    ));
}

#[test]
fn serialization_rejects_truncated_cltv_height() {
    let mut bytes = Vec::new();
    bytes.push(0x01); // version
    bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 opcode
    bytes.push(0x50); // CheckLockTimeVerify tag
    bytes.extend_from_slice(&[0x00; 4]); // only 4 bytes instead of 8

    let result = deserialize_script(&bytes);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ScriptError::UnexpectedEof { .. }
    ));
}

#[test]
fn serialization_rejects_opcode_count_mismatch() {
    // Declare 3 opcodes but only encode 1
    let mut bytes = Vec::new();
    bytes.push(0x01); // version
    bytes.extend_from_slice(&3u32.to_le_bytes()); // declares 3
    bytes.push(0x10); // only Dup (1 opcode)

    let result = deserialize_script(&bytes);
    assert!(matches!(
        result.unwrap_err(),
        ScriptError::OpcodecountMismatch { count: 1, declared: 3 }
    ));
}

#[test]
fn serialization_rejects_oversized_script() {
    // Create a byte buffer that exceeds MAX_SCRIPT_BYTES (10 KiB)
    let big = vec![0u8; 10 * 1024 + 1];
    let result = deserialize_script(&big);
    assert!(matches!(
        result.unwrap_err(),
        ScriptError::ScriptTooLarge { .. }
    ));
}

// -- Execution after deserialization ------------------------------------------

#[test]
fn deserialized_script_executes_correctly() {
    let original = vec![
        Opcode::Push(vec![0x01, 0x02]),
        Opcode::Push(vec![0x01, 0x02]),
        Opcode::EqualVerify,
        Opcode::Push(vec![0x01]),
    ];
    let bytes = serialize_script(&original);
    let script = deserialize_script(&bytes).unwrap();
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(result.valid, "{:?}", result.error);
}
