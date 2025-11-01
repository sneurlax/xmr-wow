use thiserror::Error;

/// All ways script execution can fail.
///
/// The VM never panics ; every failure path returns ScriptError.
/// This is enforced by the engine's op-count and stack-depth guards
/// which intercept every opcode before dispatch.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ScriptError {
    // -- Stack errors ----------------------------------------------------
    #[error("stack underflow: opcode requires {needed} items but stack has {have}")]
    StackUnderflow { needed: usize, have: usize },

    #[error("stack depth limit exceeded (max {max})")]
    StackDepthExceeded { max: usize },

    #[error("Pick index {index} out of range (stack depth {depth})")]
    PickOutOfRange { index: usize, depth: usize },

    // -- Type/size errors -------------------------------------------------
    #[error("expected 32-byte scalar, got {got} bytes")]
    InvalidScalarLength { got: usize },

    #[error("expected 32-byte Ed25519 point, got {got} bytes")]
    InvalidPointLength { got: usize },

    #[error("expected 64-byte Ed25519 signature, got {got} bytes")]
    InvalidSignatureLength { got: usize },

    #[error("bytes are not a valid Ed25519 point (not on curve or non-canonical)")]
    PointNotOnCurve,

    #[error("bytes are not a valid Ed25519 scalar (non-canonical encoding)")]
    InvalidScalar,

    // -- Crypto failures --------------------------------------------------
    #[error("CheckKeyPairVerify failed: scalar*G != point")]
    KeyPairMismatch,

    #[error("CheckSigVerify failed: signature invalid")]
    SignatureInvalid,

    #[error("HashLockVerify failed: SHA-256(preimage) != hash")]
    HashLockMismatch,

    // -- Control flow / script logic --------------------------------------
    #[error("Verify failed: top of stack is falsy")]
    VerifyFailed,

    #[error("EqualVerify failed: top two stack items are not equal")]
    EqualVerifyFailed,

    #[error("unmatched If/Else/EndIf in script")]
    UnmatchedControlFlow,

    // -- Timelock failures ------------------------------------------------
    #[error("CheckLockTimeVerify: current height {current} < required {required}")]
    LockTimeNotReached { current: u64, required: u64 },

    #[error("CheckLockTimeExpiry: current height {current} >= expiry {expiry}")]
    LockTimeExpired { current: u64, expiry: u64 },

    // -- Resource limits --------------------------------------------------
    #[error("script operation count limit exceeded (max {max})")]
    OpCountExceeded { max: usize },

    #[error("script byte length limit exceeded (max {max} bytes)")]
    ScriptTooLarge { max: usize },

    // -- Serialization ----------------------------------------------------
    #[error("unknown opcode tag 0x{tag:02x} at byte offset {offset}")]
    UnknownOpcodeTag { tag: u8, offset: usize },

    #[error("unexpected end of script bytes while parsing opcode at offset {offset}")]
    UnexpectedEof { offset: usize },

    #[error("Push length {len} exceeds remaining script bytes at offset {offset}")]
    PushLengthOverflow { len: usize, offset: usize },

    #[error("invalid script version: expected 0x01, got 0x{got:02x}")]
    UnsupportedVersion { got: u8 },

    #[error("script contains {count} opcodes but header declared {declared}")]
    OpcodecountMismatch { count: usize, declared: usize },
}
