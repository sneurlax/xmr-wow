//! Canonical wallet output type representing a received, owned output.
//!
//! This is the single source of truth for output data across the library.
//! Scanner results, wallet state, and transaction building all use this type.

use serde::{Deserialize, Serialize};

use crate::tx_builder::native::StoredOutputData;

/// Canonical wallet output type representing a received, owned output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOutput {
    pub tx_hash: String,
    pub output_index: u8,
    pub amount: u64,
    pub amount_xmr: String,
    pub key: String,
    pub key_offset: String,
    pub commitment_mask: String,
    pub subaddress_index: Option<(u32, u32)>,
    pub payment_id: Option<String>,
    pub received_output_bytes: String,
    pub block_height: u64,
    pub spent: bool,
    /// Height at which this output was spent. None if unspent or unknown.
    #[serde(default)]
    pub spent_height: Option<u64>,
    pub key_image: String,
    pub is_coinbase: bool,
    /// Whether this output is frozen (excluded from coin selection).
    #[serde(default)]
    pub frozen: bool,
}

impl WalletOutput {
    /// Returns a canonical output key string: "tx_hash:output_index".
    pub fn output_key(&self) -> String {
        format!("{}:{}", self.tx_hash, self.output_index)
    }
}

impl From<&WalletOutput> for StoredOutputData {
    fn from(o: &WalletOutput) -> Self {
        StoredOutputData {
            tx_hash: o.tx_hash.clone(),
            output_index: o.output_index,
            amount: o.amount,
            key: o.key.clone(),
            key_offset: o.key_offset.clone(),
            commitment_mask: o.commitment_mask.clone(),
            subaddress: o.subaddress_index,
            payment_id: o.payment_id.clone(),
            received_output_bytes: o.received_output_bytes.clone(),
        }
    }
}

impl From<WalletOutput> for StoredOutputData {
    fn from(o: WalletOutput) -> Self {
        StoredOutputData {
            tx_hash: o.tx_hash,
            output_index: o.output_index,
            amount: o.amount,
            key: o.key,
            key_offset: o.key_offset,
            commitment_mask: o.commitment_mask,
            subaddress: o.subaddress_index,
            payment_id: o.payment_id,
            received_output_bytes: o.received_output_bytes,
        }
    }
}
