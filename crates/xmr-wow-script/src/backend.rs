//! Pluggable cryptographic backend trait.
//!
//! The VM is generic over `CryptoBackend` so that:
//! - Tests can use `StubBackend` (always-pass) to test VM logic in isolation
//! - Production uses `Ed25519Backend` backed by curve25519-dalek
//! - The xmr-wow-crypto crate can provide its own backend
//!
//! Using a generic parameter (not dyn trait) means zero-cost dispatch and
//! allows the backend to be monomorphized at compile time.

/// Cryptographic operations required by the script VM.
pub trait CryptoBackend: Send + Sync {
    /// Verify that `scalar_bytes * G == point_bytes` on edwards25519.
    ///
    /// Returns:
    /// - `Ok(true)`  if the keypair is valid
    /// - `Ok(false)` if the scalar is well-formed but scalar*G != point
    /// - `Err(_)`    if either input is malformed (wrong size, not on curve, etc.)
    ///
    /// Both inputs must be 32 bytes. The point must be a canonically-encoded
    /// compressed Ed25519 point. The scalar must be a canonical 32-byte
    /// little-endian scalar (< group order).
    fn check_keypair(
        &self,
        scalar_bytes: &[u8; 32],
        point_bytes: &[u8; 32],
    ) -> Result<bool, crate::error::ScriptError>;

    /// Verify an Ed25519 signature.
    ///
    /// Returns true if sig is a valid Ed25519 signature over `message`
    /// by the key at `pubkey`.
    fn check_sig(
        &self,
        sig: &[u8; 64],
        pubkey: &[u8; 32],
        message: &[u8],
    ) -> Result<bool, crate::error::ScriptError>;

    /// Compute SHA-256 of `data`. Always succeeds.
    fn hash256(&self, data: &[u8]) -> [u8; 32];
}

// -- Stub backend --------------------------------------------------------------

/// Test stub: check_keypair and check_sig always return true.
/// hash256 uses real SHA-256.
///
/// Use with `--features stub-crypto` to test VM control-flow, stack
/// manipulation, timelocks, and serialization without real crypto deps.
#[cfg(feature = "stub-crypto")]
pub struct StubBackend;

#[cfg(feature = "stub-crypto")]
impl CryptoBackend for StubBackend {
    fn check_keypair(
        &self,
        _scalar: &[u8; 32],
        _point: &[u8; 32],
    ) -> Result<bool, crate::error::ScriptError> {
        Ok(true)
    }

    fn check_sig(
        &self,
        _sig: &[u8; 64],
        _pubkey: &[u8; 32],
        _message: &[u8],
    ) -> Result<bool, crate::error::ScriptError> {
        Ok(true)
    }

    fn hash256(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}

// -- Stub backend that always returns FALSE for crypto -------------------------

/// Test stub where crypto always FAILS (returns false/mismatch).
/// Useful for testing that invalid witnesses correctly fail scripts.
#[cfg(feature = "stub-crypto")]
pub struct AlwaysFailBackend;

#[cfg(feature = "stub-crypto")]
impl CryptoBackend for AlwaysFailBackend {
    fn check_keypair(
        &self,
        _scalar: &[u8; 32],
        _point: &[u8; 32],
    ) -> Result<bool, crate::error::ScriptError> {
        Ok(false)
    }

    fn check_sig(
        &self,
        _sig: &[u8; 64],
        _pubkey: &[u8; 32],
        _message: &[u8],
    ) -> Result<bool, crate::error::ScriptError> {
        Ok(false)
    }

    fn hash256(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}

// -- Real Ed25519 backend ------------------------------------------------------

/// Production backend using curve25519-dalek + ed25519-dalek.
///
/// OP_CHECKKEYPAIR implementation:
///   1. Deserialize scalar using CompressedEdwardsY from point_bytes
///      and Scalar::from_canonical_bytes for scalar_bytes
///   2. Compute candidate = scalar * ED25519_BASEPOINT_POINT
///   3. Compare candidate.compress().as_bytes() == point_bytes
///
/// This is the implementation that the atomic swap security rests on.
/// Every other opcode is standard; this one is unique to our protocol.
#[cfg(feature = "real-crypto")]
pub struct Ed25519Backend;

#[cfg(feature = "real-crypto")]
impl CryptoBackend for Ed25519Backend {
    fn check_keypair(
        &self,
        scalar_bytes: &[u8; 32],
        point_bytes: &[u8; 32],
    ) -> Result<bool, crate::error::ScriptError> {
        use curve25519_dalek::{
            edwards::CompressedEdwardsY,
            scalar::Scalar,
            constants::ED25519_BASEPOINT_POINT,
        };
        use crate::error::ScriptError;

        // 1. Deserialize the expected point. Reject if not on curve.
        let compressed = CompressedEdwardsY(*point_bytes);
        let point = compressed
            .decompress()
            .ok_or(ScriptError::PointNotOnCurve)?;

        // 2. Deserialize the scalar. Reject non-canonical encodings.
        //    from_canonical_bytes returns None for values >= group order.
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*scalar_bytes))
            .ok_or(ScriptError::InvalidScalar)?;

        // 3. Compute scalar*G and compare compressed representations.
        let candidate = scalar * ED25519_BASEPOINT_POINT;
        Ok(candidate == point)
    }

    fn check_sig(
        &self,
        sig_bytes: &[u8; 64],
        pubkey_bytes: &[u8; 32],
        message: &[u8],
    ) -> Result<bool, crate::error::ScriptError> {
        use ed25519_dalek::{Signature, VerifyingKey};
        use crate::error::ScriptError;

        let vk = VerifyingKey::from_bytes(pubkey_bytes)
            .map_err(|_| ScriptError::PointNotOnCurve)?;

        let sig = Signature::from_bytes(sig_bytes);

        use ed25519_dalek::Verifier;
        Ok(vk.verify(message, &sig).is_ok())
    }

    fn hash256(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}
