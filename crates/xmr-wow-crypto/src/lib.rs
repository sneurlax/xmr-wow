// xmr-wow-crypto: cryptographic primitives for XMR<->WOW atomic swaps
// Ported and extended from xmr-swap-crypto; adds Wownero address support.

pub mod adaptor;
pub mod address;
pub mod derivation;
pub mod dleq;
pub mod error;
pub mod keccak;
pub mod keysplit;
pub mod mnemonic;

// Re-export the most-used types at the crate root.
pub use adaptor::{AdaptorSignature, CompletedSignature};
pub use address::{
    decode_address, derive_view_key, encode_address, encode_address_from_bytes, joint_address,
    Network,
};
pub use derivation::{derive_swap_key, SwapRole};
pub use dleq::{DleqProof, DleqProofDual};
pub use error::CryptoError;
pub use keccak::{keccak256, keccak256_parts};
pub use keysplit::{
    combine_public_keys, combine_secrets, verify_keypair, verify_keypair_bytes, KeyContribution,
};
pub use mnemonic::{mnemonic_to_scalar, scalar_to_mnemonic, SeedCoin};
