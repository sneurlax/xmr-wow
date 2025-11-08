#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use sha3::{Digest, Keccak256};

mod bounds;
pub use bounds::*;

/// The Keccak-256 hash function.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
  Keccak256::digest(data.as_ref()).into()
}

/// Legacy helper retained for downstream users still expecting the old primitives API.
pub fn keccak256_to_scalar(data: impl AsRef<[u8]>) -> curve25519_dalek::Scalar {
  curve25519_dalek::Scalar::from_bytes_mod_order(keccak256(data))
}
