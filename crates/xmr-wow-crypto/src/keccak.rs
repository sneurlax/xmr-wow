//! Keccak-256 hash function helpers.

use tiny_keccak::{Hasher, Keccak};

/// Compute Keccak-256 of a single byte slice.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Compute Keccak-256 over multiple parts concatenated together.
pub fn keccak256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak::v256();
    for part in parts {
        h.update(part);
    }
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}
