//! Difficulty calibration for time-lock puzzles.
//!
//! Benchmarks the local hardware to determine how many sequential squarings
//! can be performed per second, which is needed to convert human-readable
//! time durations into puzzle difficulty parameters.

use num_bigint::{BigUint, RandBigInt};
use std::time::Instant;

use crate::error::VtsError;
use crate::rsa::RsaModulus;

/// Conservative default for typical modern hardware with 2048-bit modulus.
///
/// This is a deliberately conservative estimate. Running `calibrate_squarings_per_second`
/// on the target hardware will produce a more accurate value.
pub const DEFAULT_SQUARINGS_PER_SECOND: u64 = 100_000;

/// Number of squarings to perform during calibration benchmark.
const CALIBRATION_SQUARINGS: u64 = 10_000;

/// Benchmark local hardware to determine squarings per second.
///
/// Generates a temporary RSA modulus and performs `CALIBRATION_SQUARINGS`
/// sequential squarings, measuring wall-clock time. Returns the calibrated
/// rate suitable for use with `TimeLockPuzzle::generate`.
///
/// # Arguments
///
/// * `bit_length`; RSA modulus bit length (should match production use, e.g. 2048).
///
/// # Errors
///
/// Returns `VtsError::CalibrationError` if modulus generation fails or
/// the benchmark produces implausible results.
pub fn calibrate_squarings_per_second(bit_length: u32) -> Result<u64, VtsError> {
    let mut rng = rand::thread_rng();

    // Generate a temporary modulus for benchmarking
    let modulus = RsaModulus::generate(bit_length, &mut rng)
        .map_err(|e| VtsError::CalibrationError(format!("modulus generation: {}", e)))?;

    // Pick a random base
    let mut val: BigUint = loop {
        let candidate = rng.gen_biguint(modulus.n.bits());
        if candidate >= BigUint::from(2u32) && candidate < modulus.n {
            break candidate;
        }
    };

    // Benchmark sequential squaring
    let start = Instant::now();
    for _ in 0..CALIBRATION_SQUARINGS {
        val = (&val * &val) % &modulus.n;
    }
    let elapsed = start.elapsed();

    // Prevent compiler from optimizing away the computation
    let _ = val;

    let elapsed_secs = elapsed.as_secs_f64();
    if elapsed_secs <= 0.0 {
        return Err(VtsError::CalibrationError(
            "benchmark completed in zero time; results unreliable".to_string(),
        ));
    }

    let rate = (CALIBRATION_SQUARINGS as f64 / elapsed_secs) as u64;
    if rate == 0 {
        return Err(VtsError::CalibrationError(
            "computed rate is 0; hardware too slow or benchmark too short".to_string(),
        ));
    }

    Ok(rate)
}

/// Convert a time duration (seconds) to a number of sequential squarings.
///
/// Simple multiplication: the solver will need `difficulty_seconds * squarings_per_second`
/// sequential squarings to recover the secret.
pub fn difficulty_to_squarings(difficulty_seconds: u64, squarings_per_second: u64) -> u64 {
    difficulty_seconds.saturating_mul(squarings_per_second)
}

/// Convert a number of squarings back to estimated solve time (seconds).
///
/// Inverse of `difficulty_to_squarings`. Useful for displaying estimated
/// solve time to users.
pub fn squarings_to_difficulty(squarings: u64, squarings_per_second: u64) -> u64 {
    if squarings_per_second == 0 {
        return u64::MAX; // Infinite time if no squarings possible
    }
    squarings / squarings_per_second
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibrate_returns_nonzero() {
        // Use small bit length for test speed
        let rate = calibrate_squarings_per_second(512).unwrap();
        assert!(rate > 0, "calibration should return a positive rate");
        // Sanity: should be at least 1000 squarings/sec even on slow hardware
        assert!(rate > 1000, "calibrated rate {} is implausibly low", rate);
    }

    #[test]
    fn test_difficulty_squarings_round_trip() {
        let difficulty = 60; // 60 seconds
        let rate = 100_000;
        let squarings = difficulty_to_squarings(difficulty, rate);
        assert_eq!(squarings, 6_000_000);

        let recovered_difficulty = squarings_to_difficulty(squarings, rate);
        assert_eq!(recovered_difficulty, difficulty);
    }

    #[test]
    fn test_difficulty_to_squarings_overflow_saturates() {
        let result = difficulty_to_squarings(u64::MAX, u64::MAX);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn test_squarings_to_difficulty_zero_rate() {
        let result = squarings_to_difficulty(1000, 0);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn test_default_squarings_per_second_is_reasonable() {
        // Should be in a plausible range
        assert!(DEFAULT_SQUARINGS_PER_SECOND >= 10_000);
        assert!(DEFAULT_SQUARINGS_PER_SECOND <= 10_000_000);
    }
}
