#![allow(non_snake_case)]
//! Standalone adaptor signatures for simnet tests.
//!
//! This mirrors `xmr-wow-crypto::adaptor` because the simnet workspace cannot
//! depend on the main workspace.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use tiny_keccak::{Hasher, Keccak};

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// `Keccak256("xmr-adaptor-v1:" || R_T || A || msg)`.
fn challenge(R_T: &EdwardsPoint, A: &EdwardsPoint, msg: &[u8]) -> Scalar {
    let mut buf = Vec::with_capacity(15 + 64 + msg.len());
    buf.extend_from_slice(b"xmr-adaptor-v1:");
    buf.extend_from_slice(R_T.compress().as_bytes());
    buf.extend_from_slice(A.compress().as_bytes());
    buf.extend_from_slice(msg);
    Scalar::from_bytes_mod_order(keccak256(&buf))
}

fn parse_scalar(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}

fn random_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Schnorr adaptor pre-signature.
#[derive(Clone, Debug)]
pub struct AdaptorSignature {
    /// Encrypted nonce point `R + T`.
    pub r_plus_t: [u8; 32],
    /// Partial scalar `s'`.
    pub s_prime: [u8; 32],
}

/// Completed Schnorr signature.
#[derive(Clone, Debug)]
pub struct CompletedSignature {
    /// Nonce point used during signing.
    pub r_t: [u8; 32],
    /// Full scalar `s`.
    pub s: [u8; 32],
}

impl AdaptorSignature {
    /// Create a pre-signature.
    pub fn sign<R: RngCore + CryptoRng>(
        a: &Scalar, A: &EdwardsPoint, msg: &[u8], T: &EdwardsPoint, rng: &mut R,
    ) -> Self {
        let r = random_scalar(rng);
        let R = r * G;
        let R_T = R + T;
        let c = challenge(&R_T, A, msg);
        let s_prime = r + c * a;
        AdaptorSignature {
            r_plus_t: R_T.compress().to_bytes(),
            s_prime: s_prime.to_bytes(),
        }
    }

    /// Verify a pre-signature.
    pub fn verify_pre_sig(&self, A: &EdwardsPoint, msg: &[u8], T: &EdwardsPoint) -> bool {
        let R_T = match CompressedEdwardsY::from_slice(&self.r_plus_t)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => return false,
        };
        let s_prime = match parse_scalar(self.s_prime) {
            Some(s) => s,
            None => return false,
        };
        let c = challenge(&R_T, A, msg);
        let lhs: EdwardsPoint = s_prime * G + T;
        let rhs: EdwardsPoint = R_T + c * A;
        lhs.compress() == rhs.compress()
    }

    /// Complete a pre-signature with the adaptor secret.
    pub fn complete(&self, t: &Scalar) -> CompletedSignature {
        let s_prime = parse_scalar(self.s_prime).expect("valid s_prime");
        let s = s_prime + t;
        CompletedSignature {
            r_t: self.r_plus_t,
            s: s.to_bytes(),
        }
    }

    /// Recover the adaptor secret from a pre-signature and completion.
    pub fn extract_secret(&self, completed: &CompletedSignature) -> Scalar {
        let s_prime = parse_scalar(self.s_prime).expect("valid s_prime");
        let s = parse_scalar(completed.s).expect("valid s");
        s - s_prime
    }
}

impl CompletedSignature {
    /// Verify a completed signature.
    pub fn verify(&self, A: &EdwardsPoint, msg: &[u8]) -> bool {
        let R_T = match CompressedEdwardsY::from_slice(&self.r_t)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => return false,
        };
        let s = match parse_scalar(self.s) {
            Some(s) => s,
            None => return false,
        };
        let c = challenge(&R_T, A, msg);
        let lhs: EdwardsPoint = s * G;
        let rhs: EdwardsPoint = R_T + c * A;
        lhs.compress() == rhs.compress()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
    use rand::rngs::OsRng;

    fn make_party() -> (Scalar, EdwardsPoint) {
        let s = random_scalar(&mut OsRng);
        let p = s * G;
        (s, p)
    }

    #[test]
    fn test_sign_verify_complete_extract() {
        let (a, A) = make_party();
        let (t, T) = make_party();
        let msg = b"simnet-swap-test";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        assert!(pre_sig.verify_pre_sig(&A, msg, &T));

        let completed = pre_sig.complete(&t);
        assert!(completed.verify(&A, msg));

        let recovered = pre_sig.extract_secret(&completed);
        assert_eq!(recovered.to_bytes(), t.to_bytes());
        assert_eq!((recovered * G).compress(), T.compress());
    }

    #[test]
    fn test_wrong_adaptor_fails() {
        let (a, A) = make_party();
        let (_t, T) = make_party();
        let (_t2, T2) = make_party();
        let msg = b"message";

        let pre_sig = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
        assert!(!pre_sig.verify_pre_sig(&A, msg, &T2));
    }
}
