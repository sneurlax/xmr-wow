//! Error types for the VTS crate.

use thiserror::Error;

/// Errors produced by VTS time-lock puzzle operations.
#[derive(Debug, Error)]
pub enum VtsError {
    /// RSA modulus generation failed (e.g. bad bit length, prime search exhausted).
    #[error("RSA modulus generation failed: {0}")]
    ModulusGeneration(String),

    /// Puzzle generation failed (e.g. invalid parameters).
    #[error("puzzle generation failed: {0}")]
    PuzzleGeneration(String),

    /// Puzzle solving failed (e.g. inconsistent state).
    #[error("puzzle solving failed: {0}")]
    PuzzleSolving(String),

    /// Puzzle verification failed (e.g. tampered checkpoint).
    #[error("puzzle verification failed: {0}")]
    VerificationFailed(String),

    /// Puzzle structure is invalid (e.g. missing fields, bad modulus).
    #[error("invalid puzzle: {0}")]
    InvalidPuzzle(String),

    /// Calibration benchmark failed.
    #[error("calibration error: {0}")]
    CalibrationError(String),
}
