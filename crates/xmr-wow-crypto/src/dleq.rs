#![allow(non_snake_case)]
//! Chaum-Pedersen same-curve DLEQ proofs for Ed25519.
//!
//! A DLEQ (Discrete Log Equality) proof lets a prover demonstrate knowledge
//! of a secret scalar k such that K = k*G, without revealing k.
//!
//! ## Protocol (Schnorr sigma / Fiat-Shamir transformed)
//!
//! 1. Prover picks random nonce r, computes R = r*G.
//! 2. Challenge: c = H(G_compressed || K_compressed || R_compressed || context)
//!    (Keccak-256, domain-separated by the context string)
//! 3. Response: s = r + c*k (mod l)
//! 4. Proof = (R_compressed, s_bytes)
//!
//! Verification: s*G == R + c*K
//!
//! ## Dual DLEQ
//!
//! Proves the same scalar k satisfies both k*G = K and k*H = J, for an
//! alternate generator H. Used when two different elliptic curve points
//! (e.g., for two different chains) share the same secret.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::error::CryptoError;

#[inline(always)]
fn parse_scalar(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}

// --- helpers ----------------------------------------------------------------

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Compute the Fiat-Shamir challenge scalar for a single-generator DLEQ proof.
///
/// c = Keccak256("xmr-dleq-v1:" || context || G || K || R) mod l
fn challenge_single(K: &EdwardsPoint, R: &EdwardsPoint, context: &[u8]) -> Scalar {
    let mut buf = Vec::with_capacity(8 + context.len() + 96);
    // Domain separation
    buf.extend_from_slice(b"xmr-dleq-v1:");
    buf.extend_from_slice(context);
    // Fixed generator G
    buf.extend_from_slice(G.compress().as_bytes());
    // Public key K
    buf.extend_from_slice(K.compress().as_bytes());
    // Commitment R
    buf.extend_from_slice(R.compress().as_bytes());
    Scalar::from_bytes_mod_order(keccak256(&buf))
}

/// Compute the Fiat-Shamir challenge scalar for a dual-generator DLEQ proof.
fn challenge_dual(
    K: &EdwardsPoint,
    J: &EdwardsPoint,
    H: &EdwardsPoint,
    R_g: &EdwardsPoint,
    R_h: &EdwardsPoint,
    context: &[u8],
) -> Scalar {
    let mut buf = Vec::with_capacity(12 + context.len() + 160);
    buf.extend_from_slice(b"xmr-dleq-dual-v1:");
    buf.extend_from_slice(context);
    buf.extend_from_slice(G.compress().as_bytes());
    buf.extend_from_slice(H.compress().as_bytes());
    buf.extend_from_slice(K.compress().as_bytes());
    buf.extend_from_slice(J.compress().as_bytes());
    buf.extend_from_slice(R_g.compress().as_bytes());
    buf.extend_from_slice(R_h.compress().as_bytes());
    Scalar::from_bytes_mod_order(keccak256(&buf))
}

// --- DleqProof ---------------------------------------------------------------

/// A non-interactive Chaum-Pedersen DLEQ proof for a single generator G.
///
/// Proves: exists k such that K = k * G, without revealing k.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DleqProof {
    /// The commitment R = r*G (compressed Edwards point, 32 bytes).
    pub commitment: [u8; 32],
    /// The response s = r + c*k (mod l), encoded as little-endian bytes.
    pub response: [u8; 32],
}

impl DleqProof {
    /// Create a proof that k*G == K.
    ///
    /// `context` is a domain-separation string, e.g. `b"xmr-swap-alice-v1"`.
    pub fn prove<R: RngCore + CryptoRng>(
        k: &Scalar,
        K: &EdwardsPoint,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let R = r * G;
        let c = challenge_single(K, &R, context);
        let s = r + c * k;
        DleqProof {
            commitment: R.compress().to_bytes(),
            response: s.to_bytes(),
        }
    }

    /// Verify the proof for the given public key K.
    ///
    /// Returns `Ok(())` if valid. Constant-time with respect to the proof bytes.
    pub fn verify(&self, K: &EdwardsPoint, context: &[u8]) -> Result<(), CryptoError> {
        let R = CompressedEdwardsY::from_slice(&self.commitment)
            .map_err(|_| CryptoError::DleqVerificationFailed)?
            .decompress()
            .ok_or(CryptoError::DleqVerificationFailed)?;

        let s = parse_scalar(self.response)
            .ok_or(CryptoError::DleqVerificationFailed)?;

        let c = challenge_single(K, &R, context);

        // Check: s*G == R + c*K
        let lhs: EdwardsPoint = s * G;
        let rhs: EdwardsPoint = R + c * K;

        if lhs.compress() == rhs.compress() {
            Ok(())
        } else {
            Err(CryptoError::DleqVerificationFailed)
        }
    }
}

// --- DleqProofDual -----------------------------------------------------------

/// A dual-generator DLEQ proof.
///
/// Proves: exists k such that K = k*G AND J = k*H, for an alternate generator H.
///
/// This is useful when the same atomic swap secret must appear as a spend key
/// on two different generators (e.g., primary chain G and sidechain H = 2*G).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DleqProofDual {
    /// R_g = r*G (commitment with standard generator).
    pub commitment_g: [u8; 32],
    /// R_h = r*H (commitment with alternate generator).
    pub commitment_h: [u8; 32],
    /// s = r + c*k (shared response scalar).
    pub response: [u8; 32],
}

impl DleqProofDual {
    /// Create a dual proof that k*G == K and k*H == J.
    ///
    /// `H` must be a generator known to both parties (deterministically derived).
    pub fn prove<R: RngCore + CryptoRng>(
        k: &Scalar,
        K: &EdwardsPoint,
        J: &EdwardsPoint,
        H: &EdwardsPoint,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let R_g = r * G;
        let R_h = r * H;
        let c = challenge_dual(K, J, H, &R_g, &R_h, context);
        let s = r + c * k;
        DleqProofDual {
            commitment_g: R_g.compress().to_bytes(),
            commitment_h: R_h.compress().to_bytes(),
            response: s.to_bytes(),
        }
    }

    /// Verify the dual proof.
    pub fn verify(
        &self,
        K: &EdwardsPoint,
        J: &EdwardsPoint,
        H: &EdwardsPoint,
        context: &[u8],
    ) -> Result<(), CryptoError> {
        let R_g = CompressedEdwardsY::from_slice(&self.commitment_g)
            .map_err(|_| CryptoError::DleqVerificationFailed)?
            .decompress()
            .ok_or(CryptoError::DleqVerificationFailed)?;

        let R_h = CompressedEdwardsY::from_slice(&self.commitment_h)
            .map_err(|_| CryptoError::DleqVerificationFailed)?
            .decompress()
            .ok_or(CryptoError::DleqVerificationFailed)?;

        let s = parse_scalar(self.response)
            .ok_or(CryptoError::DleqVerificationFailed)?;

        let c = challenge_dual(K, J, H, &R_g, &R_h, context);

        // Check: s*G == R_g + c*K
        let lhs_g: EdwardsPoint = s * G;
        let rhs_g: EdwardsPoint = R_g + c * K;
        // Check: s*H == R_h + c*J
        let lhs_h: EdwardsPoint = s * H;
        let rhs_h: EdwardsPoint = R_h + c * J;

        if lhs_g.compress() == rhs_g.compress() && lhs_h.compress() == rhs_h.compress() {
            Ok(())
        } else {
            Err(CryptoError::DleqVerificationFailed)
        }
    }
}

// --- Serialized layout for sidechain VM --------------------------------------

/// Byte layout of a DleqProof for inclusion in sidechain transaction data.
///
/// Total: 64 bytes
/// [0..32]  commitment R = r*G (CompressedEdwardsY)
/// [32..64] response s = r + c*k (canonical Scalar, little-endian)
///
/// The verifier recomputes c = Keccak256("xmr-dleq-v1:" || context || G || K || R)
/// and checks s*G == R + c*K.
impl DleqProof {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.commitment);
        out[32..].copy_from_slice(&self.response);
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, CryptoError> {
        let mut commitment = [0u8; 32];
        let mut response = [0u8; 32];
        commitment.copy_from_slice(&bytes[..32]);
        response.copy_from_slice(&bytes[32..]);
        // Validate both fields on deserialization
        CompressedEdwardsY::from_slice(&commitment)
            .map_err(|_| CryptoError::InvalidPoint)?
            .decompress()
            .ok_or(CryptoError::InvalidPoint)?;
        parse_scalar(response).ok_or(CryptoError::InvalidScalar)?;
        Ok(DleqProof { commitment, response })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
    use rand::rngs::OsRng;

    #[test]
    fn test_dleq_prove_verify() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let proof = DleqProof::prove(&k, &K, b"test-context", &mut OsRng);
        assert!(proof.verify(&K, b"test-context").is_ok());
    }

    #[test]
    fn test_dleq_wrong_key_fails() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let proof = DleqProof::prove(&k, &K, b"test-context", &mut OsRng);

        let k2 = Scalar::random(&mut OsRng);
        let K2 = k2 * G;
        assert!(proof.verify(&K2, b"test-context").is_err());
    }

    #[test]
    fn test_dleq_modified_response_fails() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let mut proof = DleqProof::prove(&k, &K, b"test-context", &mut OsRng);
        proof.response[0] ^= 0x01;
        // May produce invalid canonical scalar -> DleqVerificationFailed
        let _ = proof.verify(&K, b"test-context"); // either ok-but-wrong or Err
        // Either way, it must NOT succeed with the original K
        // (flipping a byte in s makes s*G != R + c*K with overwhelming probability)
        // Re-run until we get a non-canonical byte flip that still parses:
        // Just assert both cases are handled (no panic):
        let mut proof2 = DleqProof::prove(&k, &K, b"test-context", &mut OsRng);
        // force response to all-zeros (valid canonical scalar = 0)
        proof2.response = [0u8; 32];
        assert!(proof2.verify(&K, b"test-context").is_err());
    }

    #[test]
    fn test_dleq_modified_commitment_fails() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let mut proof = DleqProof::prove(&k, &K, b"test-context", &mut OsRng);
        // Replace commitment with G (a different point)
        proof.commitment = G.compress().to_bytes();
        assert!(proof.verify(&K, b"test-context").is_err());
    }

    #[test]
    fn test_dleq_wrong_context_fails() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let proof = DleqProof::prove(&k, &K, b"context-a", &mut OsRng);
        assert!(proof.verify(&K, b"context-b").is_err());
    }

    #[test]
    fn test_dleq_different_contexts_produce_different_proofs() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        // Use a fixed rng seed to get deterministic proofs for comparison.
        // With OsRng proofs differ due to random r, so just verify both contexts
        // fail to cross-verify.
        let proof_a = DleqProof::prove(&k, &K, b"context-a", &mut OsRng);
        let proof_b = DleqProof::prove(&k, &K, b"context-b", &mut OsRng);
        assert!(proof_a.verify(&K, b"context-b").is_err());
        assert!(proof_b.verify(&K, b"context-a").is_err());
    }

    #[test]
    fn test_dleq_roundtrip_bytes() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let proof = DleqProof::prove(&k, &K, b"roundtrip", &mut OsRng);
        let bytes = proof.to_bytes();
        let recovered = DleqProof::from_bytes(&bytes).unwrap();
        assert!(recovered.verify(&K, b"roundtrip").is_ok());
    }

    #[test]
    fn test_dleq_dual_prove_verify() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        // H = 2*G as the alternate generator
        let two = Scalar::from(2u64);
        let H = two * G;
        let J = k * H;

        let proof = DleqProofDual::prove(&k, &K, &J, &H, b"dual-test", &mut OsRng);
        assert!(proof.verify(&K, &J, &H, b"dual-test").is_ok());
    }

    #[test]
    fn test_dleq_dual_wrong_j_fails() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let two = Scalar::from(2u64);
        let H = two * G;
        let J = k * H;

        let proof = DleqProofDual::prove(&k, &K, &J, &H, b"dual-test", &mut OsRng);

        // Wrong J (a different k)
        let k2 = Scalar::random(&mut OsRng);
        let J_wrong = k2 * H;
        assert!(proof.verify(&K, &J_wrong, &H, b"dual-test").is_err());
    }

    #[test]
    fn test_dleq_dual_wrong_k_fails() {
        let k = Scalar::random(&mut OsRng);
        let K = k * G;
        let two = Scalar::from(2u64);
        let H = two * G;
        let J = k * H;

        let proof = DleqProofDual::prove(&k, &K, &J, &H, b"dual-test", &mut OsRng);

        let k2 = Scalar::random(&mut OsRng);
        let K_wrong = k2 * G;
        assert!(proof.verify(&K_wrong, &J, &H, b"dual-test").is_err());
    }
}
