// P2Pool for Monero - Monero block serialization
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// Monero block format (version 2+):
//   [major_version: varint] [minor_version: varint] [timestamp: varint]
//   [prev_id: 32B] [nonce: 4B LE]
//   miner_tx:
//     [version: varint=2] [unlock_time: varint=height+60]
//     [vin_count: varint=1] [TXIN_GEN=0xFF] [height: varint]
//     [vout_count: varint] ([amount: varint] [TXOUT_TO_TAGGED_KEY=3] [key: 32B] [view_tag: 1B])+
//     [tx_extra_len: varint] [TX_EXTRA_TAG_PUBKEY=1] [txkey_pub: 32B]
//       [TX_EXTRA_NONCE=2] [extra_nonce_size: varint] [extra_nonce: 4B]
//       [TX_EXTRA_MERGE_MINING_TAG=3] [mm_depth: varint] [mm_root: 32B]
//     [rct_type: varint=0]
//   [tx_count: varint] [tx_hash: 32B]+

use p2pool_crypto::Hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::varint;

#[derive(Debug, Error)]
pub enum BlockError {
    #[error("buffer too short at offset {offset}")]
    TooShort { offset: usize },
    #[error("varint decode error: {0}")]
    VarInt(#[from] crate::varint::VarIntError),
    #[error("invalid field: {0}")]
    Invalid(String),
}

/// A single transaction output in the miner (coinbase) transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    /// Output amount in atomic units (piconero).
    pub amount: u64,
    /// One-time public key for the output.
    pub ephemeral_public_key: Hash,
    /// View tag (first byte of the derivation scalar).
    pub view_tag: u8,
}

/// The coinbase (miner) transaction embedded in a Monero block.
#[derive(Clone, Debug, Default)]
pub struct MinerTx {
    /// Block height that is paid out (= txin_gen height).
    pub height: u64,
    /// Transaction public key r·G committed in tx_extra.
    pub tx_key_pub: Hash,
    /// Extra nonce committed by p2pool (4 bytes, written as TX_EXTRA_NONCE).
    pub extra_nonce: u32,
    /// Size of the extra nonce field in the serialized tx_extra (normally 4, may be padded).
    pub extra_nonce_size: u64,
    /// Merge mining root hash committed in TX_EXTRA_MERGE_MINING_TAG.
    pub merge_mining_root: Hash,
    /// Merkle tree data encoding number of aux chains and nonce.
    pub merkle_tree_data: u64,
    /// Outputs paying to each miner.
    pub outputs: Vec<TxOutput>,
}

/// A Monero block header (excluding the miner tx and transaction list).
#[derive(Clone, Debug, Default)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_id: Hash,
    pub nonce: u32,
}

impl BlockHeader {
    /// Serialize the block header prefix into `out` (for hashing/PoW).
    pub fn serialize(&self, out: &mut Vec<u8>) {
        varint::encode(self.major_version as u64, out);
        varint::encode(self.minor_version as u64, out);
        varint::encode(self.timestamp, out);
        out.extend_from_slice(self.prev_id.as_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
    }
}

/// A complete Monero block (header + miner tx + transaction hashes).
#[derive(Clone, Debug, Default)]
pub struct MoneroBlock {
    pub header: BlockHeader,
    pub miner_tx: MinerTx,
    /// Hashes of all non-coinbase transactions in the block.
    pub tx_hashes: Vec<Hash>,
}

impl MoneroBlock {
    /// Serialize the entire block for submission to monerod.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        self.header.serialize(out);
        self.serialize_miner_tx(out);
        varint::encode(self.tx_hashes.len() as u64, out);
        for h in &self.tx_hashes {
            out.extend_from_slice(h.as_bytes());
        }
    }

    fn serialize_miner_tx(&self, out: &mut Vec<u8>) {
        let tx = &self.miner_tx;
        // version = 2
        varint::encode(2, out);
        // unlock_time = height + MINER_REWARD_UNLOCK_TIME (60)
        varint::encode(tx.height + 60, out);
        // vin: 1x TXIN_GEN
        varint::encode(1, out);
        out.push(0xFF); // TXIN_GEN
        varint::encode(tx.height, out);
        // vout
        varint::encode(tx.outputs.len() as u64, out);
        for output in &tx.outputs {
            varint::encode(output.amount, out);
            out.push(3); // TXOUT_TO_TAGGED_KEY
            out.extend_from_slice(output.ephemeral_public_key.as_bytes());
            out.push(output.view_tag);
        }
        // tx_extra
        let mut extra = Vec::new();
        // TX_EXTRA_TAG_PUBKEY = 1
        extra.push(1);
        extra.extend_from_slice(tx.tx_key_pub.as_bytes());
        // TX_EXTRA_NONCE = 2
        extra.push(2);
        let nonce_bytes = tx.extra_nonce.to_le_bytes();
        varint::encode(tx.extra_nonce_size, &mut extra);
        extra.extend_from_slice(&nonce_bytes);
        // pad to extra_nonce_size if needed
        let written = 4usize;
        let pad = tx.extra_nonce_size as usize - written;
        for _ in 0..pad {
            extra.push(0);
        }
        // TX_EXTRA_MERGE_MINING_TAG = 3
        extra.push(3);
        let mm_depth = 0u64; // depth encoded in merkle_tree_data
        varint::encode(mm_depth, &mut extra);
        extra.extend_from_slice(tx.merge_mining_root.as_bytes());

        varint::encode(extra.len() as u64, out);
        out.extend_from_slice(&extra);
        // RCT type = 0 (no RingCT for coinbase)
        varint::encode(0, out);
    }
}
