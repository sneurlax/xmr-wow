#![allow(non_snake_case)]
//! Schnorr adaptor signatures on Ed25519.
//!
//! ## Construction
//!
//! Standard Schnorr on Ed25519:
//! - Nonce: r random, R = r*G
//! - Challenge: c = H(R || A || msg)
//! - Signature: (R, s) where s = r + c*a
//! - Verify: s*G == R + c*A
//!
//! Adaptor (pre-)signature with adaptor point T = t*G:
//! - Nonce: r random, R = r*G
//! - Encrypted nonce: R_T = R + T
//! - Challenge: c = H(R_T || A || msg)   <- same structure but commits to R_T
//! - Pre-signature: (R_T, s') where s' = r + c*a
//! - Pre-sig verify: s'*G + T == R_T + c*A
//!   (because s'*G = R + c*A = R_T - T + c*A)
//!
//! Completion (knowing t where T = t*G):
//! - s = s' + t
//! - Completed sig: (R_T, s)
//! - Verify as standard Schnorr: s*G == R_T + c*A 
//!   (because s*G = s'*G + t*G = R_T - T + c*A + T = R_T + c*A)
//!
//! Adaptor secret extraction:
//! - Given pre-sig s' and completed sig s: t = s - s'
//!
//! ## Hash function
//!
//! We use Keccak-256 with domain separation for the challenge hash, matching
//! Monero's cryptographic conventions. This does NOT produce standard Ed25519
//! signatures compatible with RFC 8032 / FIPS 186-5.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::keccak::keccak256;

#[inline(always)]
fn parse_scalar(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}

/// Schnorr challenge: c = Keccak256("xmr-adaptor-v1" || R_T || A || msg)
fn challenge(R_T: &EdwardsPoint, A: &EdwardsPoint, msg: &[u8]) -> Scalar {
    let mut buf = Vec::with_capacity(15 + 64 + msg.len());
    buf.extend_from_slice(b"xmr-adaptor-v1:");
    buf.extend_from_slice(R_T.compress().as_bytes());
    buf.extend_from_slice(A.compress().as_bytes());
    buf.extend_from_slice(msg);
    Scalar::from_bytes_mod_order(keccak256(&buf))
}

// --- AdaptorSignature --------------------------------------------------------

/// A Schnorr adaptor pre-signature.
///
/// This is NOT a valid Schnorr signature by itself. It becomes a valid
/// signature when the adaptor secret t is supplied via `complete()`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AdaptorSignature {
    /// The encrypted nonce point R_T = R + T (R = r*G, T = t*G).
    pub r_plus_t: [u8; 32],
    /// The partial scalar s' = r + c*a (where c = H(R_T || A || msg)).
    pub s_prime: [u8; 32],
}

/// A completed (valid) Schnorr signature, produced from an adaptor pre-sig.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CompletedSignature {
    /// The nonce point R_T used during signing (same as in the pre-signature).
    pub r_t: [u8; 32],
    /// The full scalar s = s' + t.
    pub s: [u8; 32],
}

impl AdaptorSignature {
    /// Create a Schnorr adaptor pre-signature.
    ///
    /// - `a`: signer's private scalar (never share)
    /// - `A`: signer's public key (A = a*G)
    /// - `msg`: the message being signed
    /// - `T`: the adaptor point (counterparty's public key contribution T = t*G)
    pub fn sign<R: RngCore + CryptoRng>(
        a: &Scalar,
        A: &EdwardsPoint,
        msg: &[u8],
        T: &EdwardsPoint,
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let R = r * G;
        let R_T = R + T;
        let c = challenge(&R_T, A, msg);
        let s_prime = r + c * a;
        AdaptorSignature {
            r_plus_t: R_T.compress().to_bytes(),
            s_prime: s_prime.to_bytes(),
        }
    }

    /// Verify a pre-signature given the adaptor point T and signer's public key A.
    ///
    /// Check: s'*G + T == R_T + c*A
    /// (equivalently: s'*G == R_T - T + c*A)
    pub fn verify_pre_sig(
        &self,
        A: &EdwardsPoint,
        msg: &[u8],
        T: &EdwardsPoint,
    ) -> Result<(), CryptoError> {
        let R_T = CompressedEdwardsY::from_slice(&self.r_plus_t)
            .map_err(|_| CryptoError::AdaptorVerificationFailed)?
            .decompress()
            .ok_or(CryptoError::AdaptorVerificationFailed)?;

        let s_prime: Scalar = parse_scalar(self.s_prime)
            .ok_or(CryptoError::AdaptorVerificationFailed)?;

        let c = challenge(&R_T, A, msg);

        // s'*G + T == R_T + c*A
        let lhs: EdwardsPoint = s_prime * G + T;
        let rhs: EdwardsPoint = R_T + c * A;

        if lhs.compress() == rhs.compress() {
            Ok(())
        } else {
            Err(CryptoError::AdaptorVerificationFailed)
        }
    }

    /// Complete the signature by providing the adaptor secret t (where T = t*G).
    ///
    /// The resulting `CompletedSignature` is a valid Schnorr signature
    /// verifiable with the signer's public key A.
    pub fn complete(&self, t: &Scalar) -> Result<CompletedSignature, CryptoError> {
        let s_prime: Scalar = parse_scalar(self.s_prime)
            .ok_or(CryptoError::AdaptorVerificationFailed)?;
        let s: Scalar = s_prime + t;
        Ok(CompletedSignature {
            r_t: self.r_plus_t,
            s: s.to_bytes(),
        })
    }

    /// Extract the adaptor secret t from a pre-signature and its completion.
    ///
    /// t = s - s'
    ///
    /// This is how the atomic swap protocol allows one party to learn the other's
    /// secret once a completed signature appears on-chain.
    pub fn extract_secret(
        &self,
        completed: &CompletedSignature,
    ) -> Result<Scalar, CryptoError> {
        let s_prime: Scalar = parse_scalar(self.s_prime)
            .ok_or(CryptoError::SecretExtractionFailed)?;
        let s: Scalar = parse_scalar(completed.s)
            .ok_or(CryptoError::SecretExtractionFailed)?;
        Ok(s - s_prime)
    }
}

impl CompletedSignature {
    /// Verify a completed signature against the signer's public key.
    ///
    /// Check: s*G == R_T + c*A  where c = H(R_T || A || msg)
    pub fn verify(&self, A: &EdwardsPoint, msg: &[u8]) -> Result<(), CryptoError> {
        let R_T = CompressedEdwardsY::from_slice(&self.r_t)
            .map_err(|_| CryptoError::AdaptorVerificationFailed)?
            .decompress()
            .ok_or(CryptoError::AdaptorVerificationFailed)?;

        let s: Scalar = parse_scalar(self.s)
            .ok_or(CryptoError::AdaptorVerificationFailed)?;

        let c = challenge(&R_T, A, msg);

        let lhs: EdwardsPoint = s * G;
        let rhs: EdwardsPoint = R_T + c * A;

        if lhs.compress() == rhs.compress() {
            Ok(())
        } else {
            Err(CryptoError::AdaptorVerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
    use rand::rngs::OsRng;

    fn make_party() -> (Scalar, EdwardsPoint) {
        let s = Scalar::random(&mut OsRng);
        let p = s * G;
        (s, p)
    }

    #[test]
    fn test_adaptor_pre_sig_verifies() {
        let (a, A) = make_party();
        let (t, T) = make_party();
        let msg = b"swap-tx-hash-goes-here";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        assert!(pre_sig.verify_pre_sig(&A, msg, &T).is_ok());
    }

    #[test]
    fn test_pre_sig_not_valid_standard_schnorr() {
        // A pre-sig (R_T, s') should NOT satisfy s'*G == R_T + c*A
        // (it fails the completed-sig check, which requires s*G == R_T + c*A)
        let (a, A) = make_party();
        let (t, T) = make_party();
        let msg = b"message";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);

        // Treat pre_sig as if it were a completed sig ; it should fail
        let fake_completed = CompletedSignature {
            r_t: pre_sig.r_plus_t,
            s: pre_sig.s_prime,
        };
        // This should fail because s'*G == R_T - T + c*A != R_T + c*A (unless T=0)
        assert!(fake_completed.verify(&A, msg).is_err());
    }

    #[test]
    fn test_complete_produces_valid_sig() {
        let (a, A) = make_party();
        let (t, T) = make_party();
        let msg = b"tx-commitment";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        let completed = pre_sig.complete(&t).unwrap();
        assert!(completed.verify(&A, msg).is_ok());
    }

    #[test]
    fn test_extract_secret_recovers_t() {
        let (a, A) = make_party();
        let (t, T) = make_party();
        let msg = b"atomic-swap";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        let completed = pre_sig.complete(&t).unwrap();

        let recovered_t = pre_sig.extract_secret(&completed).unwrap();
        assert_eq!(recovered_t.to_bytes(), t.to_bytes());
    }

    #[test]
    fn test_wrong_t_complete_fails_verify() {
        let (a, A) = make_party();
        let (_t, T) = make_party();
        let (wrong_t, _) = make_party();
        let msg = b"message";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        let completed_wrong = pre_sig.complete(&wrong_t).unwrap();
        assert!(completed_wrong.verify(&A, msg).is_err());
    }

    #[test]
    fn test_presig_wrong_key_fails() {
        let (a, A) = make_party();
        let (_a2, A2) = make_party();
        let (_t, T) = make_party();
        let msg = b"message";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        assert!(pre_sig.verify_pre_sig(&A2, msg, &T).is_err());
    }

    #[test]
    fn test_presig_wrong_adaptor_fails() {
        let (a, A) = make_party();
        let (_t, T) = make_party();
        let (_t2, T2) = make_party();
        let msg = b"message";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        assert!(pre_sig.verify_pre_sig(&A, msg, &T2).is_err());
    }

    #[test]
    fn test_full_atomic_swap_cycle() {
        // Simulate the full atomic swap crypto flow:
        // 1. Alice has key (a, A), Bob has adaptor secret t (T = t*G)
        // 2. Alice creates pre-sig
        // 3. Bob verifies pre-sig
        // 4. Bob completes sig (publishing t implicitly)
        // 5. Alice recovers t from the completed sig
        let (a, A) = make_party();
        let (t, T) = make_party();
        let msg = b"sidechain-redeem-tx";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        pre_sig.verify_pre_sig(&A, msg, &T).expect("pre-sig must verify");

        let completed = pre_sig.complete(&t).unwrap();
        completed.verify(&A, msg).expect("completed sig must verify");

        let recovered = pre_sig.extract_secret(&completed).unwrap();
        assert_eq!(recovered.to_bytes(), t.to_bytes(), "must recover Bob's secret");

        // Confirm recovered t gives the right adaptor point
        assert_eq!((recovered * G).compress(), T.compress());
    }
}
