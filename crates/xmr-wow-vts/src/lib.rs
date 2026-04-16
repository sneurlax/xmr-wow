//! Verifiable Timed Signatures (VTS): RSA time-lock puzzles for refund guarantee timelocks.
//!
//! This crate implements homomorphic time-lock puzzles based on the
//! Rivest–Shamir–Wagner scheme using RSA sequential squaring.
//!
//! # Overview
//!
//! A time-lock puzzle locks a secret behind a computational barrier that can only
//! be overcome by performing a known number of sequential operations (modular
//! squarings). The key insight: the puzzle *generator* can create the puzzle
//! efficiently using RSA's trapdoor (knowledge of the factorization), while the
//! *solver* must perform the full sequential computation.
//!
//! # Usage
//!
//! ```rust,no_run
//! use xmr_wow_vts::{TimeLockPuzzle, calibration};
//!
//! // Generate a puzzle locking a secret for ~60 seconds
//! let secret = b"refund_spend_key";
//! let rate = calibration::DEFAULT_SQUARINGS_PER_SECOND;
//! let (puzzle, _modulus) = TimeLockPuzzle::generate(secret, 60, rate).unwrap();
//!
//! // Solve the puzzle (takes ~60 seconds of sequential computation)
//! let recovered = puzzle.solve().unwrap();
//! assert_eq!(recovered, secret.to_vec());
//! ```
//!
//! # Modules
//!
//! - [`puzzle`]; Time-lock puzzle generation and solving
//! - [`verify`]; Cut-and-choose puzzle verification
//! - [`rsa`]; RSA safe-prime modulus generation
//! - [`calibration`]; Hardware-specific difficulty calibration
//! - [`error`]; Error types

pub mod calibration;
pub mod error;
pub mod puzzle;
pub mod rsa;
pub mod verify;

pub use error::VtsError;
pub use puzzle::TimeLockPuzzle;
