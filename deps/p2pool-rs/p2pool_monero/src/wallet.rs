// P2Pool for Monero - Monero wallet address type
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// A Monero standard address is: prefix (varint) | spend_pub_key (32B) |
//   view_pub_key (32B) | checksum (4B), encoded in Monero base58.
// Subaddresses use different prefixes.
//
// Address prefixes per network (standard / integrated / subaddress):
//   Mainnet:  18 / 19 / 42
//   Testnet:  53 / 54 / 63
//   Stagenet: 24 / 25 / 36

use p2pool_crypto::Hash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("base58 decode error")]
    Base58,
    #[error("invalid address length: expected 69 bytes, got {0}")]
    Length(usize),
    #[error("invalid checksum")]
    Checksum,
    #[error("unknown network prefix: {0}")]
    UnknownPrefix(u64),
    #[error("torsion subgroup check failed")]
    TorsionCheck,
}

/// Monero network type, derived from the address prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Stagenet,
}

/// A decoded Monero wallet address.
///
/// Corresponds to the C++ `Wallet` class. Stores the raw 32-byte spend and
/// view public keys so they can be used for ephemeral key derivation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
    pub spend_public_key: Hash,
    pub view_public_key: Hash,
    pub network: NetworkType,
    pub is_subaddress: bool,
    prefix: u64,
    checksum: [u8; 4],
}

impl Wallet {
    /// The standard address length in base58 characters.
    /// Monero base58 encodes 69 raw bytes (1 prefix + 32 + 32 + 4) into 95 characters.
    pub const ADDRESS_LENGTH: usize = 95;

    /// Decode and validate a Monero address string.
    pub fn decode(address: &str) -> Result<Self, WalletError> {
        if address.len() != Self::ADDRESS_LENGTH {
            return Err(WalletError::Length(address.len()));
        }

        let raw = base58_monero::decode(address).map_err(|_| WalletError::Base58)?;

        // raw should be 69 bytes: prefix_varint + 32 + 32 + 4
        // The Monero prefix is always a single byte for all current network types.
        if raw.len() != 69 {
            return Err(WalletError::Length(raw.len()));
        }

        let prefix = raw[0] as u64;
        let spend = Hash::from_bytes(&raw[1..33]).ok_or(WalletError::Length(raw.len()))?;
        let view = Hash::from_bytes(&raw[33..65]).ok_or(WalletError::Length(raw.len()))?;
        let checksum_bytes: [u8; 4] = raw[65..69].try_into().unwrap();

        // Verify checksum: keccak256(prefix || spend || view)[0..4]
        let expected = Self::compute_checksum(&raw[..65]);
        if checksum_bytes != expected {
            return Err(WalletError::Checksum);
        }

        let (network, is_subaddress) = Self::decode_prefix(prefix)?;

        Ok(Self {
            spend_public_key: spend,
            view_public_key: view,
            network,
            is_subaddress,
            prefix,
            checksum: checksum_bytes,
        })
    }

    /// Encode this wallet address as a 95-character Monero base58 string.
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(69);
        raw.push(self.prefix as u8);
        raw.extend_from_slice(self.spend_public_key.as_bytes());
        raw.extend_from_slice(self.view_public_key.as_bytes());
        raw.extend_from_slice(&self.checksum);
        base58_monero::encode(&raw).expect("encode cannot fail for valid 69-byte input")
    }

    /// Build a wallet from raw public keys (mainnet standard address).
    pub fn from_keys(
        spend: Hash,
        view: Hash,
        network: NetworkType,
        subaddress: bool,
    ) -> Self {
        let prefix = Self::encode_prefix(network, subaddress);
        let mut payload = Vec::with_capacity(65);
        payload.push(prefix as u8);
        payload.extend_from_slice(spend.as_bytes());
        payload.extend_from_slice(view.as_bytes());
        let checksum = Self::compute_checksum(&payload);
        Self {
            spend_public_key: spend,
            view_public_key: view,
            network,
            is_subaddress: subaddress,
            prefix,
            checksum,
        }
    }

    /// Derive the one-time ephemeral public key for output `index` in a
    /// transaction with secret key `tx_key_sec`.
    ///
    /// Implements the Monero stealth address derivation (standard addresses):
    ///
    ///   derivation = mul8(tx_key_sec · view_public_key)     -- shared secret
    ///   view_tag   = keccak256("view_tag" || derivation || varint(index))[0]
    ///   scalar_hs  = keccak256(derivation || varint(index)) mod l
    ///   P          = scalar_hs · G + spend_public_key
    ///
    /// Mirrors the C++ `Wallet::get_eph_public_key` → `generate_key_derivation`
    /// + `derive_public_key` call chain.
    ///
    /// Returns `false` if either public key is not a valid Edwards point.
    pub fn get_eph_public_key(
        &self,
        tx_key_sec: &Hash,
        output_index: u64,
        eph_public_key: &mut Hash,
        view_tag: &mut u8,
    ) -> bool {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use p2pool_crypto::keccak256_parts;

        // --- Step 1: compute derivation = mul8(tx_key_sec · view_public_key) ---
        let view_point = match CompressedEdwardsY::from_slice(self.view_public_key.as_bytes())
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => return false,
        };

        // tx_key_sec is a Monero scalar (little-endian, may not be fully reduced).
        let tx_scalar = Scalar::from_bytes_mod_order(*tx_key_sec.as_bytes());

        // shared = scalar * point, then ×8 (cofactor clearing)
        let shared = (tx_scalar * view_point).mul_by_cofactor();
        let derivation_bytes = shared.compress().to_bytes();

        // --- Step 2: view tag ---
        // view_tag = keccak256("view_tag" || derivation || varint(index))[0]
        {
            let index_varint = crate::varint::encode_to_vec(output_index);
            let tag_hash = keccak256_parts(&[b"view_tag", &derivation_bytes, &index_varint]);
            *view_tag = tag_hash.0[0];
        }

        // --- Step 3: scalar Hs = keccak256(derivation || varint(index)) mod l ---
        let index_varint = crate::varint::encode_to_vec(output_index);
        let hs_bytes = keccak256_parts(&[&derivation_bytes, &index_varint]);
        let hs_scalar = Scalar::from_bytes_mod_order(*hs_bytes.as_bytes());

        // --- Step 4: P = Hs·G + spend_public_key ---
        let spend_point = match CompressedEdwardsY::from_slice(self.spend_public_key.as_bytes())
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => return false,
        };

        let eph_point = curve25519_dalek::EdwardsPoint::mul_base(&hs_scalar) + spend_point;
        let eph_bytes = eph_point.compress().to_bytes();

        *eph_public_key = Hash(eph_bytes);
        true
    }

    fn decode_prefix(prefix: u64) -> Result<(NetworkType, bool), WalletError> {
        match prefix {
            18 => Ok((NetworkType::Mainnet, false)),
            42 => Ok((NetworkType::Mainnet, true)),
            53 => Ok((NetworkType::Testnet, false)),
            63 => Ok((NetworkType::Testnet, true)),
            24 => Ok((NetworkType::Stagenet, false)),
            36 => Ok((NetworkType::Stagenet, true)),
            other => Err(WalletError::UnknownPrefix(other)),
        }
    }

    fn encode_prefix(network: NetworkType, subaddress: bool) -> u64 {
        match (network, subaddress) {
            (NetworkType::Mainnet, false) => 18,
            (NetworkType::Mainnet, true) => 42,
            (NetworkType::Testnet, false) => 53,
            (NetworkType::Testnet, true) => 63,
            (NetworkType::Stagenet, false) => 24,
            (NetworkType::Stagenet, true) => 36,
        }
    }

    fn compute_checksum(payload: &[u8]) -> [u8; 4] {
        let h = p2pool_crypto::keccak256(payload);
        [h.0[0], h.0[1], h.0[2], h.0[3]]
    }
}

impl std::fmt::Display for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl std::str::FromStr for Wallet {
    type Err = WalletError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

impl PartialOrd for Wallet {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Wallet {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.spend_public_key
            .cmp(&other.spend_public_key)
            .then(self.view_public_key.cmp(&other.view_public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-good mainnet address from p2pool-cpp wallet_tests.cpp
    const ADDR1: &str = "49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6";
    const SPEND1: &str = "d2e232e441546a695b27187692d035ef7be5c54692700c9f470dcd706753a833";
    const VIEW1: &str = "06f68970da46f709e2b4d0ffabd0d1f78ea6717786b5766c25c259111f212490";

    #[test]
    fn decode_mainnet_address() {
        let w = Wallet::decode(ADDR1).expect("valid address must decode");
        assert_eq!(w.network, NetworkType::Mainnet);
        assert!(!w.is_subaddress);
        assert_eq!(hex::encode(w.spend_public_key.0), SPEND1);
        assert_eq!(hex::encode(w.view_public_key.0), VIEW1);
    }

    #[test]
    fn encode_roundtrip() {
        let w = Wallet::decode(ADDR1).unwrap();
        assert_eq!(w.encode(), ADDR1);
    }

    #[test]
    fn decode_subaddress() {
        // Mainnet subaddress (prefix 42) from wallet_tests.cpp
        let addr = "86eQxzSW4AZfvsWRSop755WZUsog6L3x32NRZukeeShnS4mBGVpcqQhS6pCNxj44usPKNwesZ45ooHyjDku6nVZdT3Q9qrz";
        let w = Wallet::decode(addr).expect("subaddress must decode");
        assert_eq!(w.network, NetworkType::Mainnet);
        assert!(w.is_subaddress);
    }

    #[test]
    fn decode_testnet_address() {
        let addr = "9x6aEN1yd2WhPMPw89LV5LLK1ZFe6N8xiAm18Ay4q1U4LKMde7MpDdPRN6GiiGCJMVTHuptGGmfj2Qfp2vcKSRSG79HJrQn";
        let w = Wallet::decode(addr).expect("testnet address must decode");
        assert_eq!(w.network, NetworkType::Testnet);
    }

    #[test]
    fn decode_stagenet_address() {
        let addr = "55AJ4jJBhV6JsoqrEsAazTLrJjg9SA1SFReLUoXDudrsA9tdL9i2VkJefEbx3zrFRt6swuibPVySPGNzsNvyshrRNZbSDnD";
        let w = Wallet::decode(addr).expect("stagenet address must decode");
        assert_eq!(w.network, NetworkType::Stagenet);
    }

    #[test]
    fn bad_checksum_rejected() {
        // Flip the last character (different checksum)
        let bad = "49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS7";
        assert!(Wallet::decode(bad).is_err());
    }

    #[test]
    fn eph_key_derivation_deterministic() {
        let w = Wallet::decode(ADDR1).unwrap();
        // Use a non-zero tx secret key (all-zeros would be the neutral element)
        let mut tx_sec = p2pool_crypto::Hash::ZERO;
        tx_sec.0[0] = 1;

        let mut eph1 = p2pool_crypto::Hash::ZERO;
        let mut eph2 = p2pool_crypto::Hash::ZERO;
        let mut vt1 = 0u8;
        let mut vt2 = 0u8;

        assert!(w.get_eph_public_key(&tx_sec, 0, &mut eph1, &mut vt1));
        assert!(w.get_eph_public_key(&tx_sec, 0, &mut eph2, &mut vt2));

        assert_eq!(eph1, eph2, "derivation must be deterministic");
        assert_eq!(vt1, vt2, "view tag must be deterministic");
        assert!(!eph1.is_zero(), "ephemeral key must not be zero");
    }

    #[test]
    fn eph_key_varies_with_index() {
        let w = Wallet::decode(ADDR1).unwrap();
        let mut tx_sec = p2pool_crypto::Hash::ZERO;
        tx_sec.0[0] = 1;

        let mut eph0 = p2pool_crypto::Hash::ZERO;
        let mut eph1 = p2pool_crypto::Hash::ZERO;
        let mut vt0 = 0u8;
        let mut vt1 = 0u8;

        w.get_eph_public_key(&tx_sec, 0, &mut eph0, &mut vt0);
        w.get_eph_public_key(&tx_sec, 1, &mut eph1, &mut vt1);

        assert_ne!(eph0, eph1, "different output indices must give different keys");
    }
}
