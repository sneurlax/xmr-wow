//! Ed25519 key-split primitives for atomic swap joint spend keys.
//!
//! The joint spend key construction:
//! - Alice generates (k_a, K_a) where K_a = k_a * G
//! - Bob generates (k_b, K_b) where K_b = k_b * G
//! - Joint public key: K_joint = K_a + K_b
//! - Joint private key: k_joint = k_a + k_b (mod l)
//! - Algebraic consistency: k_joint * G = (k_a + k_b) * G = K_a + K_b = K_joint 
//!
//! This is the key structure used for the atomic swap escrow address on
//! Monero-family chains (XMR, WOW, SAL, AEON, ZANO).

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

#[inline(always)]
fn parse_scalar(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}

/// One party's contribution to a joint spend key.
///
/// The joint key is alice.public + bob.public on the Edwards curve.
/// The joint scalar is alice.secret + bob.secret mod l.
///
/// SECURITY: `secret` must NEVER be revealed to the counterparty directly.
/// Use a DLEQ proof to show that `public == secret * G` without revealing `secret`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyContribution {
    /// The secret scalar k_x. Never share this.
    pub secret: Scalar,
    /// The public point K_x = k_x * G. Safe to share.
    #[zeroize(skip)]
    pub public: EdwardsPoint,
}

impl KeyContribution {
    /// Generate a fresh random contribution.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = Scalar::random(rng);
        let public = secret * G;
        KeyContribution { secret, public }
    }

    /// Serialize the public key to 32 compressed bytes.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }

    /// Deserialize a counterparty's public contribution from compressed bytes.
    ///
    /// Validates that the point is on the curve and in the prime-order subgroup.
    pub fn from_public_bytes(bytes: &[u8; 32]) -> Result<EdwardsPoint, CryptoError> {
        let compressed = CompressedEdwardsY::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidPoint)?;
        let point = compressed.decompress().ok_or(CryptoError::InvalidPoint)?;
        // Reject points with a torsion component (8-torsion).
        // For Monero's prime-order subgroup l*P must be the identity.
        if !point.is_torsion_free() {
            return Err(CryptoError::NonPrimeOrderPoint);
        }
        Ok(point)
    }
}

/// Combine two public key contributions into the joint spend public key.
///
/// This is simple Edwards point addition.
#[inline]
pub fn combine_public_keys(a: &EdwardsPoint, b: &EdwardsPoint) -> EdwardsPoint {
    a + b
}

/// Combine two secret scalars into the joint spend secret (mod l).
///
/// SECURITY: Only call this after the swap protocol has completed and you
/// hold both parties' secrets legitimately.
#[inline]
pub fn combine_secrets(a: &Scalar, b: &Scalar) -> Scalar {
    a + b
}

/// Verify that a scalar and point form a valid keypair: k * G == K.
///
/// This is the core check performed by OP_CHECKKEYPAIR on the sidechain.
/// Constant-time with respect to the scalar value.
pub fn verify_keypair(scalar: &Scalar, point: &EdwardsPoint) -> bool {
    let expected = scalar * G;
    // Use compressed representation for comparison (constant-time via CtOption).
    expected.compress() == point.compress()
}

/// Verify a keypair from raw serialized bytes.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if the math doesn't check out,
/// or `Err` if the bytes are not valid encodings.
pub fn verify_keypair_bytes(
    scalar_bytes: &[u8; 32],
    point_bytes: &[u8; 32],
) -> Result<bool, CryptoError> {
    let scalar: Scalar = parse_scalar(*scalar_bytes)
        .ok_or(CryptoError::InvalidScalar)?;
    let point = KeyContribution::from_public_bytes(point_bytes)?;
    Ok(verify_keypair(&scalar, &point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_verify_keypair_valid() {
        let contrib = KeyContribution::generate(&mut OsRng);
        assert!(verify_keypair(&contrib.secret, &contrib.public));
    }

    #[test]
    fn test_verify_keypair_wrong_scalar() {
        let a = KeyContribution::generate(&mut OsRng);
        let b = KeyContribution::generate(&mut OsRng);
        // a's scalar vs b's point ; should be false
        assert!(!verify_keypair(&a.secret, &b.public));
    }

    #[test]
    fn test_combine_public_keys_algebraic_consistency() {
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);

        let k_joint = alice.secret + bob.secret;
        let k_joint_point = k_joint * G;
        let combined_public = combine_public_keys(&alice.public, &bob.public);

        // (k_a + k_b)*G == K_a + K_b
        assert_eq!(k_joint_point.compress(), combined_public.compress());
    }

    #[test]
    fn test_combine_secrets_and_verify() {
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);

        let joint_secret = combine_secrets(&alice.secret, &bob.secret);
        let joint_public = combine_public_keys(&alice.public, &bob.public);

        assert!(verify_keypair(&joint_secret, &joint_public));
    }

    #[test]
    fn test_verify_keypair_bytes_roundtrip() {
        let contrib = KeyContribution::generate(&mut OsRng);
        let scalar_bytes = contrib.secret.to_bytes();
        let point_bytes = contrib.public_bytes();

        let result = verify_keypair_bytes(&scalar_bytes, &point_bytes).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_keypair_bytes_mismatched() {
        let a = KeyContribution::generate(&mut OsRng);
        let b = KeyContribution::generate(&mut OsRng);

        let result = verify_keypair_bytes(&a.secret.to_bytes(), &b.public_bytes()).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_invalid_point_bytes_rejected() {
        let bad_bytes = [0xffu8; 32];
        assert!(KeyContribution::from_public_bytes(&bad_bytes).is_err());
    }

    #[test]
    fn test_invalid_scalar_bytes_rejected() {
        // The group order l in little-endian bytes is NOT a valid canonical scalar.
        // Canonical means strictly less than l; l itself is non-canonical.
        // l = 2^252 + 27742317777372353535851937790883648493
        // l LE bytes: [0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,
        //              0xde,0xf9,0xde,0x14,0x00,...,0x00,0x10]
        let l_bytes: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        let point_bytes = (Scalar::random(&mut OsRng) * G).compress().to_bytes();
        let result = verify_keypair_bytes(&l_bytes, &point_bytes);
        assert!(result.is_err(), "group order l must be rejected as non-canonical scalar");
    }

    #[test]
    fn test_public_bytes_roundtrip() {
        let contrib = KeyContribution::generate(&mut OsRng);
        let bytes = contrib.public_bytes();
        let recovered = KeyContribution::from_public_bytes(&bytes).unwrap();
        assert_eq!(contrib.public.compress(), recovered.compress());
    }
}
