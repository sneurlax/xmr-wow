// P2Pool for Monero - Keccak-256 (not SHA3-256!)
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// Monero uses the original Keccak submission (before NIST standardized SHA-3
// with different padding). The `tiny-keccak` crate exposes both variants;
// we use `Keccak` (not `Sha3`) to match Monero's hash function.

use crate::Hash;
use tiny_keccak::{Hasher, Keccak};

/// Compute the Monero Keccak-256 hash of `data`.
pub fn keccak256(data: &[u8]) -> Hash {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    Hash(out)
}

/// Compute the Monero Keccak-256 hash from multiple slices without allocation.
pub fn keccak256_parts(parts: &[&[u8]]) -> Hash {
    let mut keccak = Keccak::v256();
    for part in parts {
        keccak.update(part);
    }
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    Hash(out)
}

/// Streaming Keccak-256 hasher for incremental hashing.
pub struct KeccakHasher(Keccak);

impl KeccakHasher {
    pub fn new() -> Self {
        Self(Keccak::v256())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> Hash {
        let mut out = [0u8; 32];
        self.0.finalize(&mut out);
        Hash(out)
    }
}

impl Default for KeccakHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_empty() {
        // Monero Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let h = keccak256(b"");
        assert_eq!(
            format!("{}", h),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn keccak256_parts_matches_single() {
        let data = b"hello world";
        let single = keccak256(data);
        let parts = keccak256_parts(&[b"hello ", b"world"]);
        assert_eq!(single, parts);
    }
}
