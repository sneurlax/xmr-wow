//! Encrypted secret persistence for atomic swap key material.
//!
//! Secret scalars (private key contributions) must survive process restarts
//! but MUST NOT be stored in plaintext. This module provides argon2id key
//! derivation and AES-256-GCM authenticated encryption for 32-byte secrets.
//!
//! ## Encryption scheme
//!
//! 1. Password -> 32-byte key via Argon2id (65536 KiB memory, 3 iterations, 1 lane)
//! 2. Random 12-byte nonce
//! 3. AES-256-GCM encrypt the 32-byte secret
//! 4. Output: nonce (12) || ciphertext+tag (48) = 60 bytes total
//!
//! ## CRITICAL: encrypt before broadcast
//!
//! the encrypted secret MUST be persisted to SQLite BEFORE
//! any lock transaction is broadcast. If the process crashes after broadcast
//! but before persistence, funds are permanently lost.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::swap_state::SwapError;

/// Derive a 32-byte key from password + salt via Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    // hardcoded params always satisfy argon2 constraints
    let params = Params::new(65536, 3, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .expect("argon2 hash should not fail with valid params");
    key
}

/// AES-256-GCM encrypt a 32-byte secret. Returns nonce || ciphertext || tag (60 bytes).
pub fn encrypt_secret(key: &[u8; 32], secret: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_ref())
        .expect("AES-256-GCM encryption should not fail");
    // nonce (12) + ciphertext (32) + tag (16) = 60 bytes
    let mut result = Vec::with_capacity(60);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

/// AES-256-GCM decrypt a 60-byte blob back to the 32-byte secret.
pub fn decrypt_secret(key: &[u8; 32], encrypted: &[u8]) -> Result<Zeroizing<[u8; 32]>, SwapError> {
    if encrypted.len() < 60 {
        return Err(SwapError::DecryptionFailed(format!(
            "encrypted blob too short: {} bytes (expected 60)",
            encrypted.len()
        )));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let nonce_arr: [u8; 12] = nonce_bytes.try_into().expect("nonce is exactly 12 bytes");
    let nonce = Nonce::from(nonce_arr);

    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        SwapError::DecryptionFailed(
            "AES-256-GCM decryption failed (wrong password or corrupted data)".into(),
        )
    })?;

    if plaintext.len() != 32 {
        return Err(SwapError::DecryptionFailed(format!(
            "decrypted secret has wrong length: {} bytes (expected 32)",
            plaintext.len()
        )));
    }

    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let password = b"test-password-123";
        let salt: [u8; 16] = rand::random();
        let key = derive_key(password, &salt);
        let secret: [u8; 32] = rand::random();

        let encrypted = encrypt_secret(&key, &secret);
        let decrypted = decrypt_secret(&key, &encrypted).unwrap();
        assert_eq!(*decrypted, secret);
    }

    #[test]
    fn wrong_password_fails() {
        let salt: [u8; 16] = rand::random();
        let key1 = derive_key(b"correct-password", &salt);
        let key2 = derive_key(b"wrong-password", &salt);
        let secret: [u8; 32] = rand::random();

        let encrypted = encrypt_secret(&key1, &secret);
        let result = decrypt_secret(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_blob_is_60_bytes() {
        let key = derive_key(b"password", b"saltsaltsaltsalt");
        let secret = [0x42u8; 32];
        let encrypted = encrypt_secret(&key, &secret);
        assert_eq!(
            encrypted.len(),
            60,
            "nonce(12) + ciphertext(32) + tag(16) = 60"
        );
    }

    #[test]
    fn decrypt_too_short_fails() {
        let key = [0u8; 32];
        let result = decrypt_secret(&key, &[0u8; 30]);
        assert!(result.is_err());
    }

    #[test]
    fn derive_key_deterministic() {
        let key1 = derive_key(b"password", b"saltsaltsaltsalt");
        let key2 = derive_key(b"password", b"saltsaltsaltsalt");
        assert_eq!(key1, key2, "same password+salt must produce same key");
    }

    #[test]
    fn derive_key_different_salt() {
        let key1 = derive_key(b"password", b"saltsaltsaltsalt");
        let key2 = derive_key(b"password", b"othersaltothers!");
        assert_ne!(key1, key2, "different salt must produce different key");
    }
}
