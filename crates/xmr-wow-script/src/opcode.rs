//! Opcode definitions and wire format.
//!
//! Scripts encode as `[version: u8][opcode_count: u32 LE][opcodes...]`.
//! `Push` carries `[len: u8][data...]`; fixed-width opcodes store only the
//! tag or a fixed payload. Limits: 10 KiB per script, 1,000 ops, 100 stack
//! slots.

use crate::error::ScriptError;
use serde::{Deserialize, Serialize};

pub const SCRIPT_VERSION: u8 = 0x01;
pub const MAX_SCRIPT_BYTES: usize = 10 * 1024; // 10 KiB
pub const MAX_PUSH_LEN: usize = 255;            // 1-byte length prefix

/// Opcode set for the XMR<->WOW swap VM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Opcode {
    // -- Stack manipulation ----------------------------------------------
    /// Push raw bytes onto the stack. Max 255 bytes.
    Push(Vec<u8>),
    /// Duplicate top of stack. Costs 1 stack slot.
    Dup,
    /// Discard top of stack.
    Drop,
    /// Swap top two stack elements.
    Swap,
    /// Copy item at depth `index` to top. index=0 is equivalent to Dup.
    Pick(u8),

    // -- Comparison ------------------------------------------------------
    /// Pop two items; push `[1]` if byte-equal, `[0]` if not.
    Equal,
    /// Pop two items; abort with EqualVerifyFailed if not byte-equal.
    EqualVerify,

    // -- Control flow ----------------------------------------------------
    /// Pop top; if truthy execute if-branch, else execute else-branch.
    If,
    /// Delimiter between if-branch and else-branch.
    Else,
    /// End of if/else block.
    EndIf,
    /// Pop top; abort with VerifyFailed if falsy (zero bytes or empty).
    Verify,

    // -- Cryptographic ---------------------------------------------------
    /// Check whether `scalar * G == point`.
    CheckKeyPair,

    /// Abort on key mismatch instead of pushing `[0]`.
    CheckKeyPairVerify,

    /// Verify an Ed25519 signature.
    CheckSig,

    /// Like CheckSig but aborts with SignatureInvalid on failure.
    CheckSigVerify,

    /// Replace top of stack with its SHA-256 digest (32 bytes).
    Hash256,

    /// Abort unless `SHA-256(preimage) == expected_hash`.
    HashLockVerify,

    // -- Timelocks --------------------------------------------------------
    /// Abort unless context.current_height >= lock_height.
    /// Equivalent to Bitcoin's CLTV. Does not pop the stack.
    CheckLockTimeVerify(u64),

    /// Abort unless context.current_height < expiry_height.
    /// Used for "must claim before height T". Does not pop the stack.
    CheckLockTimeExpiry(u64),

    // -- Secret revelation ------------------------------------------------
    /// Emit a secret-reveal event for chain watchers.
    RevealSecret,
}

// -- Serialization -------------------------------------------------------------

const TAG_PUSH: u8 = 0x01;
const TAG_DUP: u8 = 0x10;
const TAG_DROP: u8 = 0x11;
const TAG_SWAP: u8 = 0x12;
const TAG_PICK: u8 = 0x13;
const TAG_EQUAL: u8 = 0x20;
const TAG_EQUAL_VERIFY: u8 = 0x21;
const TAG_IF: u8 = 0x30;
const TAG_ELSE: u8 = 0x31;
const TAG_ENDIF: u8 = 0x32;
const TAG_VERIFY: u8 = 0x33;
const TAG_CHECK_KEY_PAIR: u8 = 0x40;
const TAG_CHECK_KEY_PAIR_VERIFY: u8 = 0x41;
const TAG_CHECK_SIG: u8 = 0x42;
const TAG_CHECK_SIG_VERIFY: u8 = 0x43;
const TAG_HASH256: u8 = 0x44;
const TAG_HASH_LOCK_VERIFY: u8 = 0x45;
const TAG_CLTV: u8 = 0x50;
const TAG_CLTE: u8 = 0x51;
const TAG_REVEAL_SECRET: u8 = 0x60;

impl Opcode {
    pub fn serialize_into(&self, buf: &mut Vec<u8>) {
        match self {
            Opcode::Push(data) => {
                buf.push(TAG_PUSH);
                buf.push(data.len() as u8);
                buf.extend_from_slice(data);
            }
            Opcode::Dup => buf.push(TAG_DUP),
            Opcode::Drop => buf.push(TAG_DROP),
            Opcode::Swap => buf.push(TAG_SWAP),
            Opcode::Pick(n) => {
                buf.push(TAG_PICK);
                buf.push(*n);
            }
            Opcode::Equal => buf.push(TAG_EQUAL),
            Opcode::EqualVerify => buf.push(TAG_EQUAL_VERIFY),
            Opcode::If => buf.push(TAG_IF),
            Opcode::Else => buf.push(TAG_ELSE),
            Opcode::EndIf => buf.push(TAG_ENDIF),
            Opcode::Verify => buf.push(TAG_VERIFY),
            Opcode::CheckKeyPair => buf.push(TAG_CHECK_KEY_PAIR),
            Opcode::CheckKeyPairVerify => buf.push(TAG_CHECK_KEY_PAIR_VERIFY),
            Opcode::CheckSig => buf.push(TAG_CHECK_SIG),
            Opcode::CheckSigVerify => buf.push(TAG_CHECK_SIG_VERIFY),
            Opcode::Hash256 => buf.push(TAG_HASH256),
            Opcode::HashLockVerify => buf.push(TAG_HASH_LOCK_VERIFY),
            Opcode::CheckLockTimeVerify(h) => {
                buf.push(TAG_CLTV);
                buf.extend_from_slice(&h.to_le_bytes());
            }
            Opcode::CheckLockTimeExpiry(h) => {
                buf.push(TAG_CLTE);
                buf.extend_from_slice(&h.to_le_bytes());
            }
            Opcode::RevealSecret => buf.push(TAG_REVEAL_SECRET),
        }
    }

    /// Parse one opcode from `bytes` starting at `*offset`.
    /// Advances `*offset` past the consumed bytes.
    pub fn parse_one(bytes: &[u8], offset: &mut usize) -> Result<Opcode, ScriptError> {
        let tag = bytes
            .get(*offset)
            .copied()
            .ok_or(ScriptError::UnexpectedEof { offset: *offset })?;
        *offset += 1;

        let op = match tag {
            TAG_PUSH => {
                let len = bytes
                    .get(*offset)
                    .copied()
                    .ok_or(ScriptError::UnexpectedEof { offset: *offset })?
                    as usize;
                *offset += 1;
                let end = offset.checked_add(len).ok_or(ScriptError::PushLengthOverflow {
                    len,
                    offset: *offset - 1,
                })?;
                if end > bytes.len() {
                    return Err(ScriptError::PushLengthOverflow {
                        len,
                        offset: *offset - 1,
                    });
                }
                let data = bytes[*offset..end].to_vec();
                *offset = end;
                Opcode::Push(data)
            }
            TAG_DUP => Opcode::Dup,
            TAG_DROP => Opcode::Drop,
            TAG_SWAP => Opcode::Swap,
            TAG_PICK => {
                let n = bytes
                    .get(*offset)
                    .copied()
                    .ok_or(ScriptError::UnexpectedEof { offset: *offset })?;
                *offset += 1;
                Opcode::Pick(n)
            }
            TAG_EQUAL => Opcode::Equal,
            TAG_EQUAL_VERIFY => Opcode::EqualVerify,
            TAG_IF => Opcode::If,
            TAG_ELSE => Opcode::Else,
            TAG_ENDIF => Opcode::EndIf,
            TAG_VERIFY => Opcode::Verify,
            TAG_CHECK_KEY_PAIR => Opcode::CheckKeyPair,
            TAG_CHECK_KEY_PAIR_VERIFY => Opcode::CheckKeyPairVerify,
            TAG_CHECK_SIG => Opcode::CheckSig,
            TAG_CHECK_SIG_VERIFY => Opcode::CheckSigVerify,
            TAG_HASH256 => Opcode::Hash256,
            TAG_HASH_LOCK_VERIFY => Opcode::HashLockVerify,
            TAG_CLTV => {
                let h = parse_u64_le(bytes, offset)?;
                Opcode::CheckLockTimeVerify(h)
            }
            TAG_CLTE => {
                let h = parse_u64_le(bytes, offset)?;
                Opcode::CheckLockTimeExpiry(h)
            }
            TAG_REVEAL_SECRET => Opcode::RevealSecret,
            other => {
                return Err(ScriptError::UnknownOpcodeTag {
                    tag: other,
                    offset: *offset - 1,
                })
            }
        };
        Ok(op)
    }
}

fn parse_u64_le(bytes: &[u8], offset: &mut usize) -> Result<u64, ScriptError> {
    let end = offset
        .checked_add(8)
        .ok_or(ScriptError::UnexpectedEof { offset: *offset })?;
    if end > bytes.len() {
        return Err(ScriptError::UnexpectedEof { offset: *offset });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    Ok(u64::from_le_bytes(buf))
}

/// Serialize a complete script to bytes.
///
/// Format: [0x01][opcode_count: 4 LE bytes][opcodes...]
pub fn serialize_script(script: &[Opcode]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(SCRIPT_VERSION);
    let count = script.len() as u32;
    buf.extend_from_slice(&count.to_le_bytes());
    for op in script {
        op.serialize_into(&mut buf);
    }
    buf
}

/// Deserialize a script from bytes.
///
/// Returns ScriptError on any malformed input.
pub fn deserialize_script(bytes: &[u8]) -> Result<Vec<Opcode>, ScriptError> {
    if bytes.len() > MAX_SCRIPT_BYTES {
        return Err(ScriptError::ScriptTooLarge { max: MAX_SCRIPT_BYTES });
    }
    let mut offset = 0;
    // version
    let version = bytes
        .get(offset)
        .copied()
        .ok_or(ScriptError::UnexpectedEof { offset })?;
    offset += 1;
    if version != SCRIPT_VERSION {
        return Err(ScriptError::UnsupportedVersion { got: version });
    }
    // opcode count
    if offset + 4 > bytes.len() {
        return Err(ScriptError::UnexpectedEof { offset });
    }
    let mut cnt_buf = [0u8; 4];
    cnt_buf.copy_from_slice(&bytes[offset..offset + 4]);
    let declared = u32::from_le_bytes(cnt_buf) as usize;
    offset += 4;

    let mut opcodes = Vec::with_capacity(declared.min(1024));
    while offset < bytes.len() {
        opcodes.push(Opcode::parse_one(bytes, &mut offset)?);
    }
    if opcodes.len() != declared {
        return Err(ScriptError::OpcodecountMismatch {
            count: opcodes.len(),
            declared,
        });
    }
    Ok(opcodes)
}
