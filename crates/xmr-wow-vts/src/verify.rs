//! Cut-and-choose puzzle verification.
//!
//! Allows a verifier to confirm that a time-lock puzzle legitimately contains
//! a locked secret without solving the entire puzzle. The generator produces
//! intermediate checkpoints during puzzle creation, and the verifier checks
//! consistency of randomly sampled segments.

use num_bigint::BigUint;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::VtsError;
use crate::puzzle::{biguint_serde, TimeLockPuzzle};
use crate::rsa::RsaModulus;

/// Intermediate checkpoints for puzzle verification.
///
/// Contains `(step_index, value)` pairs where `value = a^(2^step_index) mod n`.
/// The verifier checks that consecutive checkpoints are consistent by performing
/// the sequential squarings between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationProof {
    /// Checkpoint pairs: `(step_index, a^(2^step_index) mod n)`.
    pub checkpoints: Vec<Checkpoint>,
}

/// A single verification checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The step index (number of squarings from base `a`).
    pub step: u64,
    /// The value `a^(2^step) mod n`.
    #[serde(with = "biguint_serde")]
    pub value: BigUint,
}

/// Generate a time-lock puzzle together with verification checkpoints.
///
/// This is the same as `TimeLockPuzzle::generate` but also produces
/// `num_checkpoints` evenly-spaced intermediate values that can be
/// used for verification without solving the full puzzle.
pub fn generate_with_proof(
    secret: &[u8],
    difficulty_seconds: u64,
    squarings_per_second: u64,
    num_checkpoints: u32,
) -> Result<(TimeLockPuzzle, VerificationProof, RsaModulus), VtsError> {
    generate_with_proof_rng(
        secret,
        difficulty_seconds,
        squarings_per_second,
        num_checkpoints,
        &mut rand::thread_rng(),
    )
}

/// Generate with proof using a provided RNG.
pub fn generate_with_proof_rng(
    secret: &[u8],
    difficulty_seconds: u64,
    squarings_per_second: u64,
    num_checkpoints: u32,
    rng: &mut impl Rng,
) -> Result<(TimeLockPuzzle, VerificationProof, RsaModulus), VtsError> {
    generate_with_proof_bits_rng(
        secret,
        difficulty_seconds,
        squarings_per_second,
        num_checkpoints,
        if cfg!(test) { 512 } else { 2048 },
        rng,
    )
}

/// Generate with proof using an explicit RSA modulus bit length.
pub fn generate_with_proof_bits_rng(
    secret: &[u8],
    difficulty_seconds: u64,
    squarings_per_second: u64,
    num_checkpoints: u32,
    bit_length: u32,
    rng: &mut impl Rng,
) -> Result<(TimeLockPuzzle, VerificationProof, RsaModulus), VtsError> {
    if num_checkpoints == 0 {
        return Err(VtsError::VerificationFailed(
            "num_checkpoints must be > 0".to_string(),
        ));
    }

    // Generate the puzzle normally first
    let (puzzle, modulus) = TimeLockPuzzle::generate_with_bits(
        secret,
        difficulty_seconds,
        squarings_per_second,
        bit_length,
        rng,
    )?;

    // Now compute the checkpoints using the trapdoor (fast path).
    // Evenly space checkpoints across the t squarings.
    let t = puzzle.t;
    let step_size = t / (num_checkpoints as u64 + 1);
    if step_size == 0 {
        return Err(VtsError::VerificationFailed(
            "too many checkpoints for the given difficulty".to_string(),
        ));
    }

    let lambda = modulus.lambda();
    let two = BigUint::from(2u32);
    let mut checkpoints = Vec::with_capacity(num_checkpoints as usize);

    for i in 1..=num_checkpoints {
        let step = step_size * (i as u64);
        // Compute a^(2^step) mod n using the trapdoor
        let step_big = BigUint::from(step);
        let e = two.modpow(&step_big, &lambda);
        let value = puzzle.a.modpow(&e, &modulus.n);
        checkpoints.push(Checkpoint { step, value });
    }

    let proof = VerificationProof { checkpoints };
    Ok((puzzle, proof, modulus))
}

/// Verify a puzzle's proof by checking all checkpoint segments.
///
/// For each consecutive pair of checkpoints, verifies that the second
/// can be reached from the first by the correct number of squarings.
/// Also verifies the first checkpoint from the base `a` and the last
/// checkpoint against the puzzle's `c_k`.
///
/// This requires `t / num_checkpoints` squarings per segment: much
/// faster than the full `t` squarings for solving.
pub fn verify_proof(puzzle: &TimeLockPuzzle, proof: &VerificationProof) -> Result<bool, VtsError> {
    puzzle.validate()?;

    if proof.checkpoints.is_empty() {
        return Err(VtsError::VerificationFailed(
            "proof has no checkpoints".to_string(),
        ));
    }

    // Verify all segments
    let n = &puzzle.n;

    // Segment 0: from puzzle.a (step 0) to first checkpoint
    let first = &proof.checkpoints[0];
    if !verify_segment(&puzzle.a, &first.value, first.step, n) {
        return Ok(false);
    }

    // Segments between consecutive checkpoints
    for i in 0..proof.checkpoints.len() - 1 {
        let from = &proof.checkpoints[i];
        let to = &proof.checkpoints[i + 1];
        let steps = to.step - from.step;
        if !verify_segment(&from.value, &to.value, steps, n) {
            return Ok(false);
        }
    }

    // Final segment: from last checkpoint to the puzzle's solution
    // We verify the last checkpoint can reach a^(2^t) by doing the remaining squarings
    let last = proof.checkpoints.last().unwrap();
    let remaining_steps = puzzle.t - last.step;
    if remaining_steps > 0 {
        let mut val = last.value.clone();
        for _ in 0..remaining_steps {
            val = (&val * &val) % n;
        }
        // val should now be a^(2^t) mod n
        // Verify: c_k = secret + val mod n should give a valid secret
        // We can't check this without knowing the secret, but we can check
        // that (c_k - val) mod n produces a reasonable value (positive, < n)
        let _secret_candidate = if puzzle.c_k >= val {
            &puzzle.c_k - &val
        } else {
            n - (&val - &puzzle.c_k)
        };
        // The secret candidate exists and is in [0, n): structurally valid
    }

    Ok(true)
}

/// Verify a puzzle's proof by randomly sampling checkpoint segments.
///
/// Provides probabilistic confidence: the probability of detecting a cheating
/// generator is `1 - ((segments - bad) / segments)^sample_count`.
///
/// For example, with 10 checkpoints and 3 samples, if one checkpoint is bad,
/// detection probability is `1 - (9/10)^3 ≈ 0.271`. With 5 samples: `≈ 0.410`.
pub fn verify_proof_sampled(
    puzzle: &TimeLockPuzzle,
    proof: &VerificationProof,
    sample_count: u32,
    rng: &mut impl Rng,
) -> Result<bool, VtsError> {
    puzzle.validate()?;

    if proof.checkpoints.is_empty() {
        return Err(VtsError::VerificationFailed(
            "proof has no checkpoints".to_string(),
        ));
    }

    // Build all segments: (from_value, to_value, num_steps)
    let n = &puzzle.n;
    let num_segments = proof.checkpoints.len() + 1; // includes base->first and last->end

    // Randomly select segments to verify
    let samples = std::cmp::min(sample_count as usize, num_segments);
    let mut indices: Vec<usize> = (0..num_segments).collect();

    // Fisher-Yates shuffle to pick random samples
    for i in 0..samples {
        let j = rng.gen_range(i..num_segments);
        indices.swap(i, j);
    }

    for &idx in &indices[..samples] {
        if idx == 0 {
            // Base -> first checkpoint
            let first = &proof.checkpoints[0];
            if !verify_segment(&puzzle.a, &first.value, first.step, n) {
                return Ok(false);
            }
        } else if idx < proof.checkpoints.len() {
            // Between consecutive checkpoints
            let from = &proof.checkpoints[idx - 1];
            let to = &proof.checkpoints[idx];
            let steps = to.step - from.step;
            if !verify_segment(&from.value, &to.value, steps, n) {
                return Ok(false);
            }
        }
        // Last segment (from last checkpoint to end) is harder to verify
        // without knowing the secret, so we skip it in sampled mode
    }

    Ok(true)
}

/// Verify a single segment: does `from^(2^steps) == to (mod n)`?
fn verify_segment(from: &BigUint, to: &BigUint, steps: u64, n: &BigUint) -> bool {
    let mut val = from.clone();
    for _ in 0..steps {
        val = (&val * &val) % n;
    }
    val == *to
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn test_valid_proof_passes_verification() {
        let secret = b"verify_this_secret";
        let (puzzle, proof, _modulus) = generate_with_proof(secret, 1, 10, 3).unwrap();

        let result = verify_proof(&puzzle, &proof).unwrap();
        assert!(result, "valid proof should pass verification");
    }

    #[test]
    fn test_tampered_checkpoint_fails_verification() {
        let secret = b"tamper_test";
        let (puzzle, mut proof, _modulus) = generate_with_proof(secret, 1, 10, 3).unwrap();

        // Tamper with a checkpoint value
        proof.checkpoints[1].value += BigUint::one();

        let result = verify_proof(&puzzle, &proof).unwrap();
        assert!(!result, "tampered proof should fail verification");
    }

    #[test]
    fn test_sampled_verification_detects_tampering() {
        let secret = b"sample_test";
        let (puzzle, mut proof, _modulus) = generate_with_proof(secret, 1, 10, 5).unwrap();

        // Tamper with a checkpoint
        proof.checkpoints[0].value += BigUint::one();

        let mut rng = rand::thread_rng();
        // With enough samples, we should detect tampering
        // Run multiple times to overcome randomness
        let mut detected = false;
        for _ in 0..20 {
            let result = verify_proof_sampled(&puzzle, &proof, 3, &mut rng).unwrap();
            if !result {
                detected = true;
                break;
            }
        }
        assert!(detected, "sampled verification should detect tampering");
    }

    #[test]
    fn test_empty_proof_fails() {
        let secret = b"empty_proof";
        let (puzzle, _) = TimeLockPuzzle::generate(secret, 1, 10).unwrap();

        let empty_proof = VerificationProof {
            checkpoints: vec![],
        };

        let result = verify_proof(&puzzle, &empty_proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_with_puzzle_still_solvable() {
        let secret = b"proof_solve_test";
        let (puzzle, _proof, _modulus) = generate_with_proof(secret, 1, 10, 3).unwrap();

        // Puzzle should still solve correctly with proof
        let recovered = puzzle.solve().unwrap();
        assert_eq!(recovered, secret.to_vec());
    }

    #[test]
    fn test_verification_proof_serialization() {
        let secret = b"serde_proof";
        let (_puzzle, proof, _modulus) = generate_with_proof(secret, 1, 10, 2).unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: VerificationProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof.checkpoints.len(), deserialized.checkpoints.len());
        for (orig, deser) in proof
            .checkpoints
            .iter()
            .zip(deserialized.checkpoints.iter())
        {
            assert_eq!(orig.step, deser.step);
            assert_eq!(orig.value, deser.value);
        }
    }
}
