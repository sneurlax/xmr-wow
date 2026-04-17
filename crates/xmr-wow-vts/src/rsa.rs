//! RSA safe-prime modulus generation for time-lock puzzles.
//!
//! The security of RSA time-lock puzzles relies on the hardness of factoring
//! the modulus `n = p * q`. Safe primes (where `(p-1)/2` is also prime) provide
//! stronger guarantees against certain factoring algorithms.

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::Rng;

use crate::error::VtsError;

/// Minimum allowed RSA modulus bit length for production use.
pub const MIN_BIT_LENGTH: u32 = 2048;

/// Minimum bit length allowed in test mode (for fast unit tests).
#[cfg(test)]
pub const TEST_MIN_BIT_LENGTH: u32 = 256;

/// RSA modulus with its factorization (the trapdoor secret).
///
/// The factorization (`p`, `q`) is the trapdoor that allows the puzzle
/// generator to compute `a^(2^t) mod n` efficiently. Once the puzzle
/// is published, only `n` is revealed: the solver must perform
/// sequential squaring.
pub struct RsaModulus {
    /// The RSA modulus `n = p * q`.
    pub n: BigUint,
    /// First safe prime factor.
    p: BigUint,
    /// Second safe prime factor.
    q: BigUint,
}

impl std::fmt::Debug for RsaModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaModulus")
            .field(
                "n",
                &format!(
                    "{}...",
                    &self.n.to_str_radix(16)[..8.min(self.n.to_str_radix(16).len())]
                ),
            )
            .field("bits", &self.n.bits())
            .finish()
    }
}

impl RsaModulus {
    /// Generate a new RSA modulus from two safe primes.
    ///
    /// Each prime is `bit_length / 2` bits, so the modulus is approximately
    /// `bit_length` bits. Both primes are safe primes: `p` is prime and
    /// `(p-1)/2` is also prime.
    ///
    /// # Errors
    ///
    /// Returns `VtsError::ModulusGeneration` if:
    /// - `bit_length < 2048` (production) or `< 256` (test)
    /// - Prime generation fails
    pub fn generate(bit_length: u32, rng: &mut impl Rng) -> Result<Self, VtsError> {
        let min = if cfg!(test) {
            #[cfg(test)]
            {
                TEST_MIN_BIT_LENGTH
            }
            #[cfg(not(test))]
            {
                MIN_BIT_LENGTH
            }
        } else {
            MIN_BIT_LENGTH
        };

        if bit_length < min {
            return Err(VtsError::ModulusGeneration(format!(
                "bit length {} is below minimum {}",
                bit_length, min
            )));
        }

        Self::generate_inner(bit_length, rng)
    }

    /// Generate an RSA modulus with relaxed minimum bit length (256).
    ///
    /// **For testing only.** This bypasses the production 2048-bit minimum,
    /// allowing 256-bit moduli for fast integration tests in debug mode.
    ///
    /// # Safety
    ///
    /// Moduli < 2048 bits are trivially factorable. Never use in production.
    pub fn generate_for_test(bit_length: u32, rng: &mut impl Rng) -> Result<Self, VtsError> {
        if bit_length < 256 {
            return Err(VtsError::ModulusGeneration(format!(
                "bit length {} is below test minimum 256",
                bit_length
            )));
        }
        Self::generate_inner(bit_length, rng)
    }

    fn generate_inner(bit_length: u32, rng: &mut impl Rng) -> Result<Self, VtsError> {
        let prime_bits = bit_length / 2;
        let p = generate_safe_prime(prime_bits, rng)?;
        let q = generate_safe_prime(prime_bits, rng)?;

        // Ensure p != q (astronomically unlikely but verify)
        if p == q {
            return Err(VtsError::ModulusGeneration(
                "generated identical primes (extremely unlikely: retry)".to_string(),
            ));
        }

        let n = &p * &q;

        Ok(RsaModulus { n, p, q })
    }

    /// Create an RsaModulus from known factors (for testing only).
    #[cfg(test)]
    pub fn from_factors(p: BigUint, q: BigUint) -> Self {
        let n = &p * &q;
        RsaModulus { n, p, q }
    }

    /// Euler's totient function: `φ(n) = (p-1)(q-1)`.
    pub fn phi(&self) -> BigUint {
        let one = BigUint::one();
        (&self.p - &one) * (&self.q - &one)
    }

    /// Carmichael's function: `λ(n) = lcm(p-1, q-1)`.
    ///
    /// Used instead of `φ(n)` for modular exponentiation because
    /// `a^λ(n) ≡ 1 (mod n)` for all `a` coprime to `n`, and `λ(n) | φ(n)`.
    pub fn lambda(&self) -> BigUint {
        let one = BigUint::one();
        let p_minus_1 = &self.p - &one;
        let q_minus_1 = &self.q - &one;
        let gcd = p_minus_1.gcd(&q_minus_1);
        &p_minus_1 / &gcd * &q_minus_1
    }
}

impl Drop for RsaModulus {
    fn drop(&mut self) {
        // Zeroize the secret factorization.
        // BigUint doesn't implement Zeroize, so we overwrite with zero.
        self.p = BigUint::zero();
        self.q = BigUint::zero();
    }
}

/// Generate a safe prime of `bit_length` bits.
///
/// A safe prime `p` satisfies: `p` is prime AND `(p-1)/2` is prime.
/// These are also known as primes where `p = 2q + 1` for prime `q`
/// (where `q` is a Sophie Germain prime).
fn generate_safe_prime(bit_length: u32, rng: &mut impl Rng) -> Result<BigUint, VtsError> {
    let two = BigUint::from(2u32);

    loop {
        // Generate a random candidate of the right bit length.
        // Set the top bit to ensure it's the right size.
        let mut candidate: BigUint = rng.gen_biguint(bit_length as u64);

        // Set the top bit for correct size
        candidate |= BigUint::one() << (bit_length as u64 - 1);
        // Set the bottom bit to make it odd
        candidate |= BigUint::one();

        // Check if (candidate - 1) / 2 is prime first (Sophie Germain check)
        let q = (&candidate - BigUint::one()) / &two;
        if !is_probably_prime(&q, 20) {
            continue;
        }

        // Then check if candidate itself is prime
        if is_probably_prime(&candidate, 20) {
            return Ok(candidate);
        }
    }
}

/// Miller-Rabin probabilistic primality test.
///
/// Returns `true` if `n` is probably prime with error probability at most
/// `4^(-rounds)`. For 20 rounds, error probability < 2^(-40).
fn is_probably_prime(n: &BigUint, rounds: u32) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    if *n < two {
        return false;
    }
    if *n == two || *n == three {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 as 2^r * d where d is odd
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r: u32 = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = rand::thread_rng();

    'witness: for _ in 0..rounds {
        // Pick random a in [2, n-2]
        let a = loop {
            let candidate = rng.gen_biguint(n.bits());
            if candidate >= two && candidate < n_minus_1 {
                break candidate;
            }
        };

        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..r - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }

        return false; // composite
    }

    true // probably prime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulus_generation_produces_valid_modulus() {
        let mut rng = rand::thread_rng();
        // Use small bit length for test speed
        let modulus = RsaModulus::generate(512, &mut rng).unwrap();

        // Verify n = p * q
        assert_eq!(modulus.n, &modulus.p * &modulus.q);

        // Verify p and q are prime
        assert!(is_probably_prime(&modulus.p, 20));
        assert!(is_probably_prime(&modulus.q, 20));

        // Verify safe prime property: (p-1)/2 and (q-1)/2 are prime
        let two = BigUint::from(2u32);
        let p_sophie = (&modulus.p - BigUint::one()) / &two;
        let q_sophie = (&modulus.q - BigUint::one()) / &two;
        assert!(is_probably_prime(&p_sophie, 20));
        assert!(is_probably_prime(&q_sophie, 20));
    }

    #[test]
    fn test_minimum_bit_length_enforced() {
        let mut rng = rand::thread_rng();
        // Should fail for bit lengths below test minimum (256)
        let result = RsaModulus::generate(128, &mut rng);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("below minimum"));
    }

    #[test]
    fn test_phi_and_lambda_consistency() {
        let mut rng = rand::thread_rng();
        let modulus = RsaModulus::generate(512, &mut rng).unwrap();

        let phi = modulus.phi();
        let lambda = modulus.lambda();

        // λ(n) divides φ(n)
        assert!((&phi % &lambda).is_zero());

        // λ(n) > 0
        assert!(!lambda.is_zero());

        // φ(n) = (p-1)(q-1) should be close to n in magnitude
        assert!(phi < modulus.n);
    }

    #[test]
    fn test_distinct_primes() {
        let mut rng = rand::thread_rng();
        let modulus = RsaModulus::generate(512, &mut rng).unwrap();
        assert_ne!(modulus.p, modulus.q);
    }
}
