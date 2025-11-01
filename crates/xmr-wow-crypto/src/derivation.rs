//! Deterministic HD key derivation for atomic swap ephemeral keys.
//!
//! Uses HMAC-SHA512 with domain separation to derive swap-specific
//! key contributions from a master seed. This ensures each swap and
//! each chain gets a unique ephemeral key, preventing key reuse.
//!
//! ## Derivation path
//!
//! `k = HMAC-SHA512(key=master_seed, data="xmr-swap-v1:" || role || ":" || chain || ":" || swap_id)`
//!
//! The 64-byte HMAC output is split into two 32-byte halves.
//! The first 32 bytes become the scalar via `from_bytes_mod_order`.
//!
//! ## Security
//!
//! - The master seed MUST be 32 bytes of cryptographically random data.
//! - Never reuse a master seed across multiple swaps.
//! - The derivation is deterministic: same inputs -> same output.
//!   Store the master seed, not the derived keys.
//! - Derived scalars are not guaranteed to be canonical; we use
//!   `from_bytes_mod_order` which reduces mod l.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    scalar::Scalar,
};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::keysplit::KeyContribution;

type HmacSha512 = Hmac<Sha512>;

/// The role of this party in the swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapRole {
    Alice,
    Bob,
}

impl SwapRole {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            SwapRole::Alice => b"alice",
            SwapRole::Bob   => b"bob",
        }
    }
}

/// Derive an ephemeral swap key contribution.
///
/// All parameters must be identical across calls to reproduce the same key.
/// Different chains, swap IDs, or roles produce independent keys.
///
/// # Parameters
/// - `master_seed`: 32-byte secret seed (unique per swap participant, per swap).
/// - `chain`: chain identifier, e.g. `"XMR"`, `"WOW"`, `"SAL"`, `"SC"`.
/// - `swap_id`: 32-byte unique identifier for this specific swap.
/// - `role`: `Alice` or `Bob` (produces different keys for each party).
pub fn derive_swap_key(
    master_seed: &[u8; 32],
    chain: &str,
    swap_id: &[u8; 32],
    role: SwapRole,
) -> KeyContribution {
    let mut mac = HmacSha512::new_from_slice(master_seed)
        .expect("HMAC-SHA512 accepts any key length");

    // Domain: "xmr-swap-v1:" || role || ":" || chain || ":" || swap_id
    mac.update(b"xmr-swap-v1:");
    mac.update(role.as_bytes());
    mac.update(b":");
    mac.update(chain.as_bytes());
    mac.update(b":");
    mac.update(swap_id);

    let result = mac.finalize().into_bytes();

    // Use the first 32 bytes as the scalar seed.
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&result[..32]);

    let secret = Scalar::from_bytes_mod_order(scalar_bytes);
    scalar_bytes.zeroize();

    let public = secret * G;
    KeyContribution { secret, public }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand_core::RngCore;

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    }

    fn random_swap_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_deterministic_same_inputs() {
        let seed = random_seed();
        let swap_id = random_swap_id();

        let k1 = derive_swap_key(&seed, "XMR", &swap_id, SwapRole::Alice);
        let k2 = derive_swap_key(&seed, "XMR", &swap_id, SwapRole::Alice);

        assert_eq!(k1.secret.to_bytes(), k2.secret.to_bytes());
        assert_eq!(k1.public.compress(), k2.public.compress());
    }

    #[test]
    fn test_different_chains_produce_different_keys() {
        let seed = random_seed();
        let swap_id = random_swap_id();

        let k_xmr = derive_swap_key(&seed, "XMR", &swap_id, SwapRole::Alice);
        let k_wow = derive_swap_key(&seed, "WOW", &swap_id, SwapRole::Alice);
        let k_sal = derive_swap_key(&seed, "SAL", &swap_id, SwapRole::Alice);
        let k_sc  = derive_swap_key(&seed, "SC",  &swap_id, SwapRole::Alice);

        assert_ne!(k_xmr.secret.to_bytes(), k_wow.secret.to_bytes());
        assert_ne!(k_xmr.secret.to_bytes(), k_sal.secret.to_bytes());
        assert_ne!(k_xmr.secret.to_bytes(), k_sc.secret.to_bytes());
        assert_ne!(k_wow.secret.to_bytes(), k_sal.secret.to_bytes());
    }

    #[test]
    fn test_different_swap_ids_produce_different_keys() {
        let seed = random_seed();
        let id1 = random_swap_id();
        let id2 = random_swap_id();

        let k1 = derive_swap_key(&seed, "XMR", &id1, SwapRole::Alice);
        let k2 = derive_swap_key(&seed, "XMR", &id2, SwapRole::Alice);

        assert_ne!(k1.secret.to_bytes(), k2.secret.to_bytes());
    }

    #[test]
    fn test_alice_and_bob_produce_different_keys() {
        let seed = random_seed();
        let swap_id = random_swap_id();

        let k_alice = derive_swap_key(&seed, "XMR", &swap_id, SwapRole::Alice);
        let k_bob   = derive_swap_key(&seed, "XMR", &swap_id, SwapRole::Bob);

        assert_ne!(k_alice.secret.to_bytes(), k_bob.secret.to_bytes());
    }

    #[test]
    fn test_derived_key_satisfies_keypair_equation() {
        let seed = random_seed();
        let swap_id = random_swap_id();
        let k = derive_swap_key(&seed, "XMR", &swap_id, SwapRole::Alice);

        // K = k*G must hold
        use crate::keysplit::verify_keypair;
        assert!(verify_keypair(&k.secret, &k.public));
    }

    #[test]
    fn test_different_seeds_produce_different_keys() {
        let s1 = random_seed();
        let s2 = random_seed();
        let swap_id = random_swap_id();

        let k1 = derive_swap_key(&s1, "XMR", &swap_id, SwapRole::Alice);
        let k2 = derive_swap_key(&s2, "XMR", &swap_id, SwapRole::Alice);

        assert_ne!(k1.secret.to_bytes(), k2.secret.to_bytes());
    }
}
