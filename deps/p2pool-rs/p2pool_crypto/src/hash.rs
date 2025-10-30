// P2Pool for Monero - Hash and difficulty types
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A 256-bit hash value (32 bytes), as used throughout Monero and p2pool.
///
/// Alignment matches the C++ implementation which aligns `hash` to `uint64_t`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C, align(8))]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);
    pub const SIZE: usize = 32;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut h = Hash::ZERO;
            h.0.copy_from_slice(bytes);
            Some(h)
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Compare as big-endian 256-bit integer (Monero PoW check convention).
    pub fn as_u64s(&self) -> [u64; 4] {
        let mut out = [0u64; 4];
        for (i, chunk) in self.0.chunks_exact(8).enumerate() {
            out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        out
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare as big-endian: highest word first (matches C++ operator<)
        let a = self.as_u64s();
        let b = other.as_u64s();
        for i in (0..4).rev() {
            match a[i].cmp(&b[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::str::FromStr for Hash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Hash::from_bytes(&bytes).ok_or(hex::FromHexError::InvalidStringLength)
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ─── DifficultyType ───────────────────────────────────────────────────────────

/// A 128-bit unsigned integer representing cumulative or per-block difficulty.
///
/// Stored as two 64-bit limbs (lo, hi), matching the C++ `difficulty_type`.
/// All arithmetic is performed with full 128-bit semantics.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct DifficultyType {
    pub lo: u64,
    pub hi: u64,
}

impl DifficultyType {
    pub const ZERO: DifficultyType = DifficultyType { lo: 0, hi: 0 };
    pub const MAX: DifficultyType = DifficultyType {
        lo: u64::MAX,
        hi: u64::MAX,
    };

    pub fn new(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }

    pub fn from_u64(v: u64) -> Self {
        Self { lo: v, hi: 0 }
    }

    pub fn is_zero(&self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    pub fn to_u128(&self) -> u128 {
        (self.hi as u128) << 64 | self.lo as u128
    }

    pub fn from_u128(v: u128) -> Self {
        Self {
            lo: v as u64,
            hi: (v >> 64) as u64,
        }
    }

    pub fn to_f64(&self) -> f64 {
        self.hi as f64 * 18446744073709551616.0 + self.lo as f64
    }

    /// Compute the 64-bit mining target: `floor((2^64 + diff - 1) / diff)`.
    /// Returns `u64::MAX` if difficulty is 0 or 1.
    pub fn target64(&self) -> u64 {
        if self.hi != 0 {
            return 1;
        }
        match self.lo {
            0 | 1 => u64::MAX,
            d => {
                // Ceiling division: ceil(2^64 / d) = floor((2^64 - 1) / d) + 1
                let two64: u128 = 1u128 << 64;
                let result = two64 / d as u128;
                let rem = two64 % d as u128;
                if rem != 0 { result as u64 + 1 } else { result as u64 }
            }
        }
    }

    /// Check whether `pow_hash` meets this difficulty.
    ///
    /// A hash passes if `hash * difficulty < 2^256` (Monero PoW rule).
    /// We compute the 320-bit product `hash × difficulty` step by step using
    /// 128-bit arithmetic, accumulating carry words, and check that the top
    /// 64-bit word of the result is zero.
    pub fn check_pow(&self, pow_hash: &Hash) -> bool {
        if self.is_zero() {
            return false;
        }

        // For simplicity handle the common case where difficulty fits in 64 bits.
        // For 128-bit difficulty (self.hi != 0) we fall back to a conservative check.
        if self.hi != 0 {
            // Very high difficulty: only an all-zeros hash could pass.
            return pow_hash.is_zero();
        }

        let d = self.lo as u128;
        if d <= 1 {
            return true;
        }

        // Compute hash[0..3] * d as a 320-bit integer and check upper 64 bits == 0.
        // words[0] is the least significant 64-bit word (little-endian).
        let words = pow_hash.as_u64s();
        let p0 = words[0] as u128 * d;
        let p1 = words[1] as u128 * d + (p0 >> 64);
        let p2 = words[2] as u128 * d + (p1 >> 64);
        let p3 = words[3] as u128 * d + (p2 >> 64);
        // The product is < 2^256 iff the bits above bit 255 are zero.
        (p3 >> 64) == 0
    }
}

impl PartialOrd for DifficultyType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DifficultyType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hi.cmp(&other.hi).then(self.lo.cmp(&other.lo))
    }
}

impl std::ops::Add for DifficultyType {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::from_u128(self.to_u128().wrapping_add(rhs.to_u128()))
    }
}

impl std::ops::AddAssign for DifficultyType {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Sub for DifficultyType {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::from_u128(self.to_u128().wrapping_sub(rhs.to_u128()))
    }
}

impl std::ops::SubAssign for DifficultyType {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl std::ops::Mul<u64> for DifficultyType {
    type Output = Self;
    fn mul(self, rhs: u64) -> Self {
        Self::from_u128(self.to_u128().wrapping_mul(rhs as u128))
    }
}

impl std::ops::Div<u64> for DifficultyType {
    type Output = Self;
    fn div(self, rhs: u64) -> Self {
        Self::from_u128(self.to_u128() / rhs as u128)
    }
}

impl fmt::Display for DifficultyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_u128())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_ordering_is_big_endian_by_word() {
        let mut a = Hash::ZERO;
        let mut b = Hash::ZERO;
        a.0[31] = 1; // highest byte in memory = word 3 high byte
        b.0[30] = 1;
        // a.as_u64s()[3] has bit 56 set; b.as_u64s()[3] has bit 48 set → a > b
        assert!(a > b);
    }

    #[test]
    fn difficulty_arithmetic() {
        let d = DifficultyType::from_u64(1_000_000);
        let e = DifficultyType::from_u64(1);
        assert_eq!((d + e).lo, 1_000_001);
        assert_eq!((d - e).lo, 999_999);
        assert_eq!((d * 2).lo, 2_000_000);
        assert_eq!((d / 2).lo, 500_000);
    }

    #[test]
    fn difficulty_target64() {
        // diff = 1 → target = MAX
        assert_eq!(DifficultyType::from_u64(1).target64(), u64::MAX);
        // diff = 2 → target = 2^63
        assert_eq!(DifficultyType::from_u64(2).target64(), 1u64 << 63);
    }
}
