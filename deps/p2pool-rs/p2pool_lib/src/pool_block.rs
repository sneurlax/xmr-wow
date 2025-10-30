// P2Pool for Monero - PoolBlock (p2pool share block)
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// The PoolBlock is the fundamental unit of p2pool. It embeds a Monero block
// template (header + miner tx) in its first section and appends side-chain
// metadata (parent, uncles, sidechain height, difficulty, etc.) in its second
// section.
//
// Layout (from the C++ comment in pool_block.h):
//
//   ┌────────────────────────────────────────────────────────────────────────┐
//   │                          POOL BLOCK                                    │
//   │──────────────────────────────────┬────────────────────────────────────│
//   │      Monero block template       │          Side-chain data            │
//   │──────────────────────────────────┼────────────────────────────────────│
//   │  …NONCE…EXTRA_NONCE…HASH…        │  parent, uncles, height, diff, …   │
//   └──────────────────────────────────┴────────────────────────────────────┘
//
// HASH (the sidechain_id / merge-mining root) comes in TX_EXTRA_MERGE_MINING_TAG
// directly after the extra nonce. It is computed as:
//   keccak256(main_chain_bytes || side_chain_bytes)
// with NONCE, EXTRA_NONCE, and the HASH field itself zeroed out during hashing.
//
// The PoW hash is computed over just the Monero block template portion using
// Monero's RandomX consensus rules.

use p2pool_crypto::{DifficultyType, Hash};
use p2pool_monero::wallet::Wallet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unexpected end of input at offset {0}")]
    UnexpectedEof(usize),
    #[error("invalid varint at offset {0}")]
    InvalidVarint(usize),
    #[error("expected byte 0x{expected:02x}, got 0x{got:02x} at offset {offset}")]
    UnexpectedByte { expected: u8, got: u8, offset: usize },
    #[error("block exceeds maximum size {MAX_BLOCK_SIZE}")]
    TooLarge,
    #[error("invalid wallet public keys in sidechain data")]
    InvalidWallet,
}

/// A cursor-based reader for binary p2pool wire data.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.pos >= self.data.len() {
            return Err(ParseError::UnexpectedEof(self.pos));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        if self.pos + N > self.data.len() {
            return Err(ParseError::UnexpectedEof(self.pos));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(arr)
    }

    fn read_slice(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + n > self.data.len() {
            return Err(ParseError::UnexpectedEof(self.pos));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_hash(&mut self) -> Result<Hash, ParseError> {
        let arr = self.read_bytes::<32>()?;
        Ok(Hash(arr))
    }

    fn read_u32_le(&mut self) -> Result<u32, ParseError> {
        let arr = self.read_bytes::<4>()?;
        Ok(u32::from_le_bytes(arr))
    }

    fn read_varint(&mut self) -> Result<u64, ParseError> {
        let start = self.pos;
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.read_u8()?;
            if shift >= 63 && (b & 0x7F) > 1 {
                return Err(ParseError::InvalidVarint(start));
            }
            result |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err(ParseError::InvalidVarint(start));
            }
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), ParseError> {
        let got = self.read_u8()?;
        if got != expected {
            return Err(ParseError::UnexpectedByte {
                expected,
                got,
                offset: self.pos - 1,
            });
        }
        Ok(())
    }
}

/// Maximum pool block size (128 KiB minus 5-byte P2P header).
pub const MAX_BLOCK_SIZE: usize = 128 * 1024 - 5;

/// Minimum block reward in atomic units (0.6 XMR).
pub const BASE_BLOCK_REWARD: u64 = 600_000_000_000;

/// Maximum sidechain height (1000 years at 1 block/second).
pub const MAX_SIDECHAIN_HEIGHT: u64 = 31_556_952_000;

/// Maximum cumulative difficulty (1000 years at 1 TH/s).
pub const MAX_CUMULATIVE_DIFFICULTY: DifficultyType = DifficultyType {
    lo: 13_019_633_956_666_736_640,
    hi: 1710,
};

/// Monero tx_extra constants (from common.h).
pub const TX_EXTRA_TAG_PUBKEY: u8 = 1;
pub const TX_EXTRA_NONCE: u8 = 2;
pub const TX_EXTRA_MERGE_MINING_TAG: u8 = 3;
pub const TXOUT_TO_TAGGED_KEY: u8 = 3;
pub const TXIN_GEN: u8 = 0xFF;
pub const TX_VERSION: u8 = 2;
pub const MINER_REWARD_UNLOCK_TIME: u64 = 60;
pub const HARDFORK_SUPPORTED_VERSION: u8 = 16;

/// A single miner's share in a PPLNS window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerShare {
    /// The miner's total work weight (in sidechain difficulty units).
    pub weight: DifficultyType,
    /// The miner's payout address.
    pub wallet: Wallet,
}

/// Cumulative-difficulty data point used for difficulty adjustment.
#[derive(Clone, Debug)]
pub struct DifficultyData {
    pub timestamp: u64,
    pub cumulative_difficulty: DifficultyType,
}

/// Extra data for a merge-mined auxiliary chain.
///
/// The map key is the chain's unique ID hash.
/// The value is the raw bytes committed for that chain (starts with the
/// merge-mining hash and difficulty as two varints, then chain-specific data).
pub type MergeMiningExtra = BTreeMap<Hash, Vec<u8>>;

/// A p2pool share block (pool block), which combines a Monero block template
/// with p2pool side-chain metadata.
///
/// This is the core data structure of p2pool. Every miner that submits a
/// valid share broadcasts a PoolBlock to the p2p network.
#[derive(Clone, Debug)]
pub struct PoolBlock {
    // ── Monero block header ──────────────────────────────────────────────────
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    /// Hash of the previous Monero main-chain block.
    pub prev_id: Hash,
    pub nonce: u32,

    // ── Coinbase (miner) transaction ─────────────────────────────────────────
    /// The Monero block height this coinbase pays out at.
    pub txin_gen_height: u64,
    /// One-time public keys for each output (pays to each miner in PPLNS window).
    pub eph_public_keys: Vec<Hash>,
    /// Amount (piconero) and view tag for each output.
    pub output_amounts: Vec<TxOutput>,
    /// Transaction public key committed in tx_extra.
    pub txkey_pub: Hash,
    /// Secret seed for deriving `txkey_pub` (never sent over the network, local only).
    pub txkey_sec_seed: Hash,
    /// Derived transaction secret key.
    pub txkey_sec: Hash,
    /// Size (in bytes) of the extra nonce field in the serialized tx_extra.
    pub extra_nonce_size: u64,
    /// The extra nonce value (4 bytes). Miners vary this to find shares.
    pub extra_nonce: u32,
    /// Encoded Merkle tree parameters: #aux_chains and nonce for merge mining.
    pub merkle_tree_data: u64,
    pub merkle_tree_data_size: u32,
    /// The merge-mining root hash committed in TX_EXTRA_MERGE_MINING_TAG.
    pub merkle_root: Hash,
    /// All transaction hashes in the block (index 0 = miner tx hash).
    pub transactions: Vec<Hash>,

    // ── Side-chain metadata ──────────────────────────────────────────────────
    /// The miner's Monero wallet address (encoded in sidechain data).
    pub miner_wallet: Option<Wallet>,
    /// Hash of the parent p2pool share block.
    pub parent: Hash,
    /// Hashes of uncle blocks included in this block.
    pub uncles: Vec<Hash>,
    /// Height of this block in the p2pool sidechain.
    pub sidechain_height: u64,
    /// Per-block sidechain difficulty (set by the difficulty algorithm).
    pub difficulty: DifficultyType,
    /// Cumulative sidechain difficulty at this block.
    pub cumulative_difficulty: DifficultyType,
    /// Merkle proof path for merge mining.
    pub merkle_proof: Vec<Hash>,
    pub merkle_proof_path: u32,
    /// Per-chain merge-mining extra data.
    pub merge_mining_extra: MergeMiningExtra,
    /// 4-byte padding buffer for arbitrary extra data in the sidechain section.
    pub sidechain_extra_buf: [u32; 4],

    // ── Identity ────────────────────────────────────────────────────────────
    /// The sidechain block ID = keccak256(main_data || sidechain_data),
    /// with NONCE / EXTRA_NONCE / HASH zeroed.
    pub sidechain_id: Hash,

    // ── Off-chain / transient state ──────────────────────────────────────────
    pub depth: u64,
    pub verified: bool,
    pub invalid: bool,
    pub broadcasted: bool,
    pub want_broadcast: bool,
    pub precalculated: bool,
    pub precalculated_shares: Vec<MinerShare>,
    pub local_timestamp: u64,
    pub received_timestamp: u64,
    /// Cached hashing blob for RandomX (not serialized).
    pub hashing_blob: Vec<u8>,
    /// Cached PoW hash (not serialized).
    pub pow_hash: Hash,
    /// Cached RandomX seed hash (not serialized).
    pub seed: Hash,
}

/// An output in the coinbase transaction paying a miner.
#[derive(Clone, Debug)]
pub struct TxOutput {
    /// Amount in piconero (atomic units). Top 56 bits used (8-bit view tag packed in).
    pub amount: u64,
    /// View tag: first byte of the derivation scalar, used for fast scanning.
    pub view_tag: u8,
}

impl PoolBlock {
    /// The `full_id` uniquely identifies a block by (sidechain_id, nonce, extra_nonce).
    /// Used to de-duplicate incoming block broadcasts (from the C++ `full_id` type).
    pub fn full_id(&self) -> [u8; Hash::SIZE + 4 + 4] {
        let mut key = [0u8; Hash::SIZE + 4 + 4];
        key[..Hash::SIZE].copy_from_slice(self.sidechain_id.as_bytes());
        key[Hash::SIZE..Hash::SIZE + 4].copy_from_slice(&self.nonce.to_le_bytes());
        key[Hash::SIZE + 4..].copy_from_slice(&self.extra_nonce.to_le_bytes());
        key
    }

    /// Encode the Merkle tree data field from (#aux_chains, nonce).
    ///
    /// Mirrors the C++ `encode_merkle_tree_data` in pool_block.h:
    ///   n_bits = ceil_log2(n_aux_chains), clamped to [1,8]
    ///   result  = (n_bits-1) | ((n_aux_chains-1) << 3) | (nonce << (3+n_bits))
    pub fn encode_merkle_tree_data(n_aux_chains: u32, nonce: u32) -> u64 {
        let mut n_bits = 1u32;
        while (1u32 << n_bits) < n_aux_chains && n_bits < 8 {
            n_bits += 1;
        }
        // Encode: bottom 3 bits = (n_bits - 1), next n_bits bits = (n_aux_chains - 1),
        // remaining upper bits = nonce.  Nonce shift uses full n_bits (not n_bits-1).
        ((n_bits - 1) | ((n_aux_chains - 1) << 3) | (nonce << (3 + n_bits))) as u64
    }

    /// Decode the Merkle tree data field back into (#aux_chains, nonce).
    pub fn decode_merkle_tree_data(&self) -> (u32, u32) {
        let k = self.merkle_tree_data as u32;
        let n = 1 + (k & 7);
        let n_aux_chains = 1 + ((k >> 3) & ((1 << n) - 1));
        let nonce = self.merkle_tree_data as u32 >> (3 + n);
        (n_aux_chains, nonce)
    }

    /// Serialize the main-chain portion (Monero block template) into bytes.
    ///
    /// Optionally override nonce and extra_nonce (used to zero them for hashing).
    pub fn serialize_mainchain_data(
        &self,
        nonce_override: Option<u32>,
        extra_nonce_override: Option<u32>,
    ) -> Vec<u8> {
        use p2pool_monero::varint;

        let mut out = Vec::new();
        varint::encode(self.major_version as u64, &mut out);
        varint::encode(self.minor_version as u64, &mut out);
        varint::encode(self.timestamp, &mut out);
        out.extend_from_slice(self.prev_id.as_bytes());
        let nonce = nonce_override.unwrap_or(self.nonce);
        out.extend_from_slice(&nonce.to_le_bytes());

        // miner tx
        varint::encode(TX_VERSION as u64, &mut out);
        varint::encode(self.txin_gen_height + MINER_REWARD_UNLOCK_TIME, &mut out);
        varint::encode(1, &mut out); // 1 input
        out.push(TXIN_GEN);
        varint::encode(self.txin_gen_height, &mut out);
        // outputs
        varint::encode(self.output_amounts.len() as u64, &mut out);
        for (i, output) in self.output_amounts.iter().enumerate() {
            varint::encode(output.amount, &mut out);
            out.push(TXOUT_TO_TAGGED_KEY);
            if let Some(key) = self.eph_public_keys.get(i) {
                out.extend_from_slice(key.as_bytes());
            } else {
                out.extend_from_slice(&[0u8; 32]);
            }
            out.push(output.view_tag);
        }
        // tx_extra
        let mut extra = Vec::new();
        extra.push(TX_EXTRA_TAG_PUBKEY);
        extra.extend_from_slice(self.txkey_pub.as_bytes());
        extra.push(TX_EXTRA_NONCE);
        let en = extra_nonce_override.unwrap_or(self.extra_nonce);
        varint::encode(self.extra_nonce_size, &mut extra);
        extra.extend_from_slice(&en.to_le_bytes());
        // pad remaining extra_nonce_size bytes
        let written = 4usize;
        let pad = (self.extra_nonce_size as usize).saturating_sub(written);
        extra.extend(std::iter::repeat(0u8).take(pad));
        extra.push(TX_EXTRA_MERGE_MINING_TAG);
        // merkle tree data size (varint)
        varint::encode(self.merkle_tree_data_size as u64, &mut extra);
        extra.extend_from_slice(self.merkle_root.as_bytes());

        varint::encode(extra.len() as u64, &mut out);
        out.extend_from_slice(&extra);
        // RCT type = 0 (coinbase)
        varint::encode(0, &mut out);

        // transaction hashes (after miner tx)
        let tx_count = self.transactions.len().saturating_sub(1);
        varint::encode(tx_count as u64, &mut out);
        for h in self.transactions.iter().skip(1) {
            out.extend_from_slice(h.as_bytes());
        }

        out
    }

    /// Serialize the side-chain portion into bytes.
    pub fn serialize_sidechain_data(&self) -> Vec<u8> {
        use p2pool_monero::varint;

        let mut out = Vec::new();

        // miner wallet spend + view keys
        if let Some(wallet) = &self.miner_wallet {
            out.extend_from_slice(wallet.spend_public_key.as_bytes());
            out.extend_from_slice(wallet.view_public_key.as_bytes());
        } else {
            out.extend_from_slice(&[0u8; 64]);
        }

        // tx secret key seed
        out.extend_from_slice(self.txkey_sec_seed.as_bytes());

        // parent
        out.extend_from_slice(self.parent.as_bytes());

        // uncles
        varint::encode(self.uncles.len() as u64, &mut out);
        for uncle in &self.uncles {
            out.extend_from_slice(uncle.as_bytes());
        }

        // sidechain height
        varint::encode(self.sidechain_height, &mut out);

        // difficulty
        varint::encode(self.difficulty.lo, &mut out);
        varint::encode(self.difficulty.hi, &mut out);

        // cumulative difficulty
        varint::encode(self.cumulative_difficulty.lo, &mut out);
        varint::encode(self.cumulative_difficulty.hi, &mut out);

        // merkle proof
        varint::encode(self.merkle_proof.len() as u64, &mut out);
        for h in &self.merkle_proof {
            out.extend_from_slice(h.as_bytes());
        }
        out.extend_from_slice(&self.merkle_proof_path.to_le_bytes());

        // merge mining extra (sorted by key)
        varint::encode(self.merge_mining_extra.len() as u64, &mut out);
        for (chain_id, data) in &self.merge_mining_extra {
            out.extend_from_slice(chain_id.as_bytes());
            varint::encode(data.len() as u64, &mut out);
            out.extend_from_slice(data);
        }

        // sidechain extra buf
        for word in &self.sidechain_extra_buf {
            out.extend_from_slice(&word.to_le_bytes());
        }

        out
    }

    /// Deserialize a PoolBlock from its wire representation.
    ///
    /// The bytes must be a concatenation of
    ///   `serialize_mainchain_data()` || `serialize_sidechain_data()`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ParseError> {
        use p2pool_monero::wallet::NetworkType;

        if bytes.len() > MAX_BLOCK_SIZE {
            return Err(ParseError::TooLarge);
        }

        let mut r = Reader::new(bytes);
        let mut block = PoolBlock::default();

        // ── main-chain header ──────────────────────────────────────────────────
        block.major_version = r.read_varint()? as u8;
        block.minor_version = r.read_varint()? as u8;
        block.timestamp = r.read_varint()?;
        block.prev_id = r.read_hash()?;
        block.nonce = r.read_u32_le()?;

        // ── miner tx ──────────────────────────────────────────────────────────
        let _tx_version = r.read_varint()?; // should be TX_VERSION (2)
        let unlock_time = r.read_varint()?;
        let _input_count = r.read_varint()?; // should be 1
        r.expect_byte(TXIN_GEN)?;
        block.txin_gen_height = r.read_varint()?;
        // Sanity check: unlock_time == txin_gen_height + MINER_REWARD_UNLOCK_TIME
        let _ = unlock_time;

        // outputs
        let n_outputs = r.read_varint()? as usize;
        for _ in 0..n_outputs {
            let amount = r.read_varint()?;
            r.expect_byte(TXOUT_TO_TAGGED_KEY)?;
            let eph_key = r.read_hash()?;
            let view_tag = r.read_u8()?;
            block.eph_public_keys.push(eph_key);
            block.output_amounts.push(TxOutput { amount, view_tag });
        }

        // tx_extra
        let extra_len = r.read_varint()? as usize;
        let extra_end = r.pos + extra_len;
        {
            let mut er = Reader::new(r.read_slice(extra_len)?);

            // TX_EXTRA_TAG_PUBKEY
            er.expect_byte(TX_EXTRA_TAG_PUBKEY)?;
            block.txkey_pub = er.read_hash()?;

            // TX_EXTRA_NONCE
            er.expect_byte(TX_EXTRA_NONCE)?;
            block.extra_nonce_size = er.read_varint()?;
            let nonce_bytes = er.read_slice(block.extra_nonce_size as usize)?;
            if nonce_bytes.len() >= 4 {
                block.extra_nonce =
                    u32::from_le_bytes(nonce_bytes[..4].try_into().unwrap());
            }

            // TX_EXTRA_MERGE_MINING_TAG
            er.expect_byte(TX_EXTRA_MERGE_MINING_TAG)?;
            block.merkle_tree_data_size = er.read_varint()? as u32;
            block.merkle_root = er.read_hash()?;
        }
        let _ = extra_end; // already consumed via read_slice

        // rct_type (0 for coinbase)
        let _rct_type = r.read_varint()?;

        // transaction hashes (non-coinbase)
        let n_txs = r.read_varint()? as usize;
        block.transactions.push(Hash::ZERO); // placeholder for miner tx hash (index 0)
        for _ in 0..n_txs {
            block.transactions.push(r.read_hash()?);
        }

        // ── sidechain data ─────────────────────────────────────────────────────
        let spend_pub = r.read_hash()?;
        let view_pub = r.read_hash()?;

        // Try to build a Wallet from the raw keys. The C++ requires valid Edwards
        // points but doesn't reject an all-zeros wallet (genesis block has none).
        if !spend_pub.is_zero() || !view_pub.is_zero() {
            match Wallet::from_keys(spend_pub, view_pub, NetworkType::Mainnet, false)
                .spend_public_key
                .is_zero()
            {
                // from_keys always succeeds; we just store it.
                _ => {
                    block.miner_wallet =
                        Some(Wallet::from_keys(spend_pub, view_pub, NetworkType::Mainnet, false));
                }
            }
        }

        block.txkey_sec_seed = r.read_hash()?;
        block.parent = r.read_hash()?;

        let n_uncles = r.read_varint()? as usize;
        for _ in 0..n_uncles {
            block.uncles.push(r.read_hash()?);
        }

        block.sidechain_height = r.read_varint()?;
        block.difficulty.lo = r.read_varint()?;
        block.difficulty.hi = r.read_varint()?;
        block.cumulative_difficulty.lo = r.read_varint()?;
        block.cumulative_difficulty.hi = r.read_varint()?;

        let n_proof = r.read_varint()? as usize;
        for _ in 0..n_proof {
            block.merkle_proof.push(r.read_hash()?);
        }
        block.merkle_proof_path = r.read_u32_le()?;

        let n_mm = r.read_varint()? as usize;
        for _ in 0..n_mm {
            let chain_id = r.read_hash()?;
            let data_len = r.read_varint()? as usize;
            let data = r.read_slice(data_len)?.to_vec();
            block.merge_mining_extra.insert(chain_id, data);
        }

        for i in 0..4 {
            block.sidechain_extra_buf[i] = r.read_u32_le()?;
        }

        // Compute and cache the sidechain ID.
        block.sidechain_id = block.calculate_sidechain_id();

        Ok(block)
    }

    /// Serialize a PoolBlock into its complete wire representation.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.serialize_mainchain_data(None, None);
        out.extend_from_slice(&self.serialize_sidechain_data());
        out
    }

    /// Compute the sidechain block ID.
    ///
    /// ID = keccak256(main_data(nonce=0, extra_nonce=0) || sidechain_data)
    /// with the HASH (merkle_root) field also zeroed out.
    pub fn calculate_sidechain_id(&self) -> Hash {
        // Serialize with zeroed nonce, extra_nonce, and merkle_root
        let mut zeroed = self.clone();
        zeroed.merkle_root = Hash::ZERO;
        let main = zeroed.serialize_mainchain_data(Some(0), Some(0));
        let side = zeroed.serialize_sidechain_data();
        let mut input = main;
        input.extend_from_slice(&side);
        p2pool_crypto::keccak256(&input)
    }
}

impl Default for PoolBlock {
    fn default() -> Self {
        Self {
            major_version: HARDFORK_SUPPORTED_VERSION,
            minor_version: HARDFORK_SUPPORTED_VERSION,
            timestamp: 0,
            prev_id: Hash::ZERO,
            nonce: 0,
            txin_gen_height: 0,
            eph_public_keys: Vec::new(),
            output_amounts: Vec::new(),
            txkey_pub: Hash::ZERO,
            txkey_sec_seed: Hash::ZERO,
            txkey_sec: Hash::ZERO,
            extra_nonce_size: 4,
            extra_nonce: 0,
            merkle_tree_data: 0,
            merkle_tree_data_size: 0,
            merkle_root: Hash::ZERO,
            transactions: Vec::new(),
            miner_wallet: None,
            parent: Hash::ZERO,
            uncles: Vec::new(),
            sidechain_height: 0,
            difficulty: DifficultyType::ZERO,
            cumulative_difficulty: DifficultyType::ZERO,
            merkle_proof: Vec::new(),
            merkle_proof_path: 0,
            merge_mining_extra: BTreeMap::new(),
            sidechain_extra_buf: [0u32; 4],
            sidechain_id: Hash::ZERO,
            depth: 0,
            verified: false,
            invalid: false,
            broadcasted: false,
            want_broadcast: false,
            precalculated: false,
            precalculated_shares: Vec::new(),
            local_timestamp: 0,
            received_timestamp: 0,
            hashing_blob: Vec::new(),
            pow_hash: Hash::ZERO,
            seed: Hash::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_data_roundtrip() {
        let block = PoolBlock::default();
        for n in 1u32..=256 {
            for nonce in [0u32, 1, 0xDEAD] {
                let encoded = PoolBlock::encode_merkle_tree_data(n, nonce);
                let mut b = block.clone();
                b.merkle_tree_data = encoded;
                let (n2, nonce2) = b.decode_merkle_tree_data();
                assert_eq!(n, n2, "n={n} nonce={nonce}");
                assert_eq!(nonce, nonce2, "n={n} nonce={nonce}");
            }
        }
    }

    #[test]
    fn full_id_unique() {
        let mut b = PoolBlock::default();
        b.sidechain_id.0[0] = 1;
        b.nonce = 42;
        b.extra_nonce = 99;
        let id = b.full_id();
        assert_eq!(id[0], 1);
        assert_eq!(&id[32..36], &42u32.to_le_bytes());
        assert_eq!(&id[36..40], &99u32.to_le_bytes());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut b = PoolBlock::default();
        b.timestamp = 1_700_000_000;
        b.prev_id.0[0] = 0xAB;
        b.nonce = 0xDEADBEEF;
        b.txin_gen_height = 3_140_000;
        b.txkey_pub.0[1] = 0x42;
        b.extra_nonce_size = 4;
        b.extra_nonce = 0x12345678;
        b.merkle_tree_data = PoolBlock::encode_merkle_tree_data(3, 7);
        b.merkle_tree_data_size = 1;
        b.sidechain_height = 1_234_567;
        b.difficulty = DifficultyType::from_u64(1_000_000);
        b.cumulative_difficulty = DifficultyType::from_u64(5_000_000_000);
        b.parent.0[0] = 0x01;
        b.sidechain_extra_buf = [1, 2, 3, 4];

        let bytes = b.serialize();
        let b2 = PoolBlock::deserialize(&bytes).expect("deserialization must succeed");

        assert_eq!(b2.timestamp, b.timestamp);
        assert_eq!(b2.prev_id, b.prev_id);
        assert_eq!(b2.nonce, b.nonce);
        assert_eq!(b2.txin_gen_height, b.txin_gen_height);
        assert_eq!(b2.txkey_pub, b.txkey_pub);
        assert_eq!(b2.extra_nonce, b.extra_nonce);
        assert_eq!(b2.extra_nonce_size, b.extra_nonce_size);
        assert_eq!(b2.merkle_root, b.merkle_root);
        assert_eq!(b2.parent, b.parent);
        assert_eq!(b2.sidechain_height, b.sidechain_height);
        assert_eq!(b2.difficulty, b.difficulty);
        assert_eq!(b2.cumulative_difficulty, b.cumulative_difficulty);
        assert_eq!(b2.sidechain_extra_buf, b.sidechain_extra_buf);

        // Sidechain ID must match (both computed from same fields).
        assert_eq!(b.calculate_sidechain_id(), b2.sidechain_id);
    }

    #[test]
    fn deserialize_with_outputs_and_uncles() {
        let mut b = PoolBlock::default();
        b.txin_gen_height = 100;
        b.eph_public_keys = vec![Hash::ZERO; 2];
        b.output_amounts = vec![
            TxOutput { amount: 1_000_000_000, view_tag: 0xAB },
            TxOutput { amount: 2_000_000_000, view_tag: 0xCD },
        ];
        b.transactions = vec![Hash::ZERO, {
            let mut h = Hash::ZERO;
            h.0[0] = 0xFF;
            h
        }];
        b.uncles = vec![{
            let mut h = Hash::ZERO;
            h.0[0] = 0x55;
            h
        }];
        b.merkle_proof = vec![Hash::ZERO];
        b.difficulty = DifficultyType::from_u64(500_000);
        b.cumulative_difficulty = DifficultyType::new(12345, 0);

        let bytes = b.serialize();
        let b2 = PoolBlock::deserialize(&bytes).expect("deserialization must succeed");

        assert_eq!(b2.output_amounts.len(), 2);
        assert_eq!(b2.output_amounts[0].amount, 1_000_000_000);
        assert_eq!(b2.output_amounts[0].view_tag, 0xAB);
        assert_eq!(b2.eph_public_keys.len(), 2);
        assert_eq!(b2.uncles.len(), 1);
        assert_eq!(b2.uncles[0].0[0], 0x55);
        assert_eq!(b2.merkle_proof.len(), 1);
        // transactions: index 0 = placeholder coinbase, index 1 = our extra tx
        assert_eq!(b2.transactions.len(), 2);
        assert_eq!(b2.transactions[1].0[0], 0xFF);
    }
}
