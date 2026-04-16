//! Time-lock puzzle generation and solving.
//!
//! Implements the Rivest–Shamir–Wagner time-lock puzzle scheme:
//!
//! - **Generator** (knows factorization): computes `a^(2^t) mod n` efficiently
//!   using the trapdoor `λ(n)`, locks secret as `c_k = secret + a^(2^t) mod n`.
//! - **Solver** (doesn't know factorization): must perform `t` sequential
//!   squarings `a -> a^2 -> a^4 -> ... -> a^(2^t) mod n` to recover the secret.
//!
//! The time-lock property: generation is O(log t) but solving is O(t).

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::VtsError;
use crate::rsa::RsaModulus;

/// A time-lock puzzle that locks a secret behind sequential computation.
///
/// The puzzle can only be solved by performing `t` sequential squarings
/// of `a` modulo `n`. The generator creates the puzzle efficiently using
/// the RSA trapdoor (knowledge of the factorization of `n`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockPuzzle {
    /// RSA modulus (public). Product of two safe primes.
    #[serde(with = "biguint_serde")]
    pub n: BigUint,

    /// Base value, random element in Z_n*.
    #[serde(with = "biguint_serde")]
    pub a: BigUint,

    /// Number of sequential squarings required to solve.
    pub t: u64,

    /// Encrypted secret: `secret_int + a^(2^t) mod n`.
    #[serde(with = "biguint_serde")]
    pub c_k: BigUint,

    /// Original difficulty parameter in seconds.
    pub difficulty_seconds: u64,

    /// Length of the original secret in bytes (for padding after solve).
    pub secret_len: usize,
}

impl TimeLockPuzzle {
    /// Generate a new time-lock puzzle locking the given secret.
    ///
    /// The secret is locked behind `difficulty_seconds * squarings_per_second`
    /// sequential squarings. The generator uses the RSA trapdoor to compute
    /// the puzzle efficiently.
    ///
    /// Returns `(puzzle, modulus)`; the modulus contains the secret factorization
    /// that the generator should discard after creating the puzzle.
    ///
    /// # Arguments
    ///
    /// * `secret`; The bytes to lock behind the time-lock.
    /// * `difficulty_seconds`; How many seconds the solver should take.
    /// * `squarings_per_second`; Estimated squarings/sec on solver hardware.
    ///
    /// # Errors
    ///
    /// Returns `VtsError::PuzzleGeneration` if parameters are invalid.
    pub fn generate(
        secret: &[u8],
        difficulty_seconds: u64,
        squarings_per_second: u64,
    ) -> Result<(Self, RsaModulus), VtsError> {
        Self::generate_with_rng(secret, difficulty_seconds, squarings_per_second, &mut rand::thread_rng())
    }

    /// Generate a puzzle with a provided RNG (for deterministic testing).
    pub fn generate_with_rng(
        secret: &[u8],
        difficulty_seconds: u64,
        squarings_per_second: u64,
        rng: &mut impl Rng,
    ) -> Result<(Self, RsaModulus), VtsError> {
        if difficulty_seconds == 0 {
            return Err(VtsError::PuzzleGeneration(
                "difficulty_seconds must be > 0".to_string(),
            ));
        }
        if squarings_per_second == 0 {
            return Err(VtsError::PuzzleGeneration(
                "squarings_per_second must be > 0".to_string(),
            ));
        }
        if secret.is_empty() {
            return Err(VtsError::PuzzleGeneration(
                "secret must not be empty".to_string(),
            ));
        }

        let t = difficulty_seconds.saturating_mul(squarings_per_second);
        if t == 0 {
            return Err(VtsError::PuzzleGeneration(
                "computed squarings count is 0".to_string(),
            ));
        }

        // Use the configured bit length (smaller in tests for speed).
        let bit_length = if cfg!(test) { 512 } else { 2048 };

        let modulus = RsaModulus::generate(bit_length, rng)?;

        // Pick random base in [2, n-1]
        let a = loop {
            let candidate = rng.gen_biguint(modulus.n.bits());
            if candidate >= BigUint::from(2u32) && candidate < modulus.n {
                break candidate;
            }
        };

        // Compute a^(2^t) mod n using the trapdoor:
        // e = 2^t mod λ(n)
        // b = a^e mod n
        let lambda = modulus.lambda();
        let two = BigUint::from(2u32);
        let t_big = BigUint::from(t);
        let e = two.modpow(&t_big, &lambda);
        let b = a.modpow(&e, &modulus.n);

        // Encode secret and compute c_k = secret_int + b mod n
        let secret_int = BigUint::from_bytes_be(secret);
        if secret_int >= modulus.n {
            return Err(VtsError::PuzzleGeneration(
                "secret is too large for the modulus".to_string(),
            ));
        }
        let c_k = (&secret_int + &b) % &modulus.n;

        let puzzle = TimeLockPuzzle {
            n: modulus.n.clone(),
            a,
            t,
            c_k,
            difficulty_seconds,
            secret_len: secret.len(),
        };

        Ok((puzzle, modulus))
    }

    /// Solve the puzzle by sequential squaring to recover the locked secret.
    ///
    /// This is the slow path: `t` sequential squarings of `a mod n`.
    /// Time complexity is O(t) modular squarings; intentionally slow.
    ///
    /// Returns the recovered secret as bytes.
    pub fn solve(&self) -> Result<Vec<u8>, VtsError> {
        if self.n <= BigUint::one() {
            return Err(VtsError::PuzzleSolving("invalid modulus".to_string()));
        }

        // Sequential squaring: b = a^(2^t) mod n
        let mut b = self.a.clone();
        for _ in 0..self.t {
            b = (&b * &b) % &self.n;
        }

        // Recover secret: secret_int = (c_k - b) mod n
        // Use modular subtraction to handle wraparound
        let secret_int = if self.c_k >= b {
            &self.c_k - &b
        } else {
            // c_k < b means we wrapped: secret_int = n - (b - c_k)
            &self.n - (&b - &self.c_k)
        };

        // Pad or trim to match original secret length
        let raw = secret_int.to_bytes_be();
        if raw.len() >= self.secret_len {
            Ok(raw[raw.len() - self.secret_len..].to_vec())
        } else {
            // Pad with leading zeros
            let mut padded = vec![0u8; self.secret_len - raw.len()];
            padded.extend_from_slice(&raw);
            Ok(padded)
        }
    }

    /// Validate basic structural properties of the puzzle.
    pub fn validate(&self) -> Result<(), VtsError> {
        if self.n <= BigUint::one() {
            return Err(VtsError::InvalidPuzzle("modulus must be > 1".to_string()));
        }
        if self.a < BigUint::from(2u32) || self.a >= self.n {
            return Err(VtsError::InvalidPuzzle(
                "base must be in [2, n-1]".to_string(),
            ));
        }
        if self.c_k >= self.n {
            return Err(VtsError::InvalidPuzzle(
                "encrypted secret must be < n".to_string(),
            ));
        }
        if self.t == 0 {
            return Err(VtsError::InvalidPuzzle(
                "squaring count must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Serde helper for BigUint serialization as hex strings.
pub(crate) mod biguint_serde {
    use num_bigint::BigUint;
    use num_traits::Num;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_str_radix(16))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BigUint::from_str_radix(&s, 16).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_solve_round_trip() {
        let secret = b"my_refund_secret_key_32_bytes!!!";
        // Use very small difficulty for test speed
        let (puzzle, _modulus) = TimeLockPuzzle::generate(secret, 1, 10).unwrap();

        let recovered = puzzle.solve().unwrap();
        assert_eq!(recovered, secret.to_vec());
    }

    #[test]
    fn test_solve_recovers_exact_secret_bytes_1_byte() {
        let secret = &[0x42u8];
        let (puzzle, _) = TimeLockPuzzle::generate(secret, 1, 5).unwrap();
        let recovered = puzzle.solve().unwrap();
        assert_eq!(recovered, secret.to_vec());
    }

    #[test]
    fn test_solve_recovers_exact_secret_bytes_32_bytes() {
        let secret: Vec<u8> = (0..32).collect();
        let (puzzle, _) = TimeLockPuzzle::generate(&secret, 1, 5).unwrap();
        let recovered = puzzle.solve().unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_generate_with_zero_difficulty_fails() {
        let secret = b"test";
        let result = TimeLockPuzzle::generate(secret, 0, 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("difficulty_seconds"));
    }

    #[test]
    fn test_generate_with_zero_squarings_per_second_fails() {
        let secret = b"test";
        let result = TimeLockPuzzle::generate(secret, 10, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_with_empty_secret_fails() {
        let result = TimeLockPuzzle::generate(b"", 1, 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_puzzle_serialization_round_trip() {
        let secret = b"serde_test_secret";
        let (puzzle, _) = TimeLockPuzzle::generate(secret, 1, 5).unwrap();

        let json = serde_json::to_string(&puzzle).unwrap();
        let deserialized: TimeLockPuzzle = serde_json::from_str(&json).unwrap();

        assert_eq!(puzzle.n, deserialized.n);
        assert_eq!(puzzle.a, deserialized.a);
        assert_eq!(puzzle.t, deserialized.t);
        assert_eq!(puzzle.c_k, deserialized.c_k);
        assert_eq!(puzzle.difficulty_seconds, deserialized.difficulty_seconds);

        // Deserialized puzzle should still solve correctly
        let recovered = deserialized.solve().unwrap();
        assert_eq!(recovered, secret.to_vec());
    }

    #[test]
    fn test_puzzle_validate_accepts_valid() {
        let secret = b"valid";
        let (puzzle, _) = TimeLockPuzzle::generate(secret, 1, 5).unwrap();
        assert!(puzzle.validate().is_ok());
    }
}
