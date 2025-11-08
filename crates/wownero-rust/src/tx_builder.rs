//! Transaction building for Wownero.
//!
//! Forked from monero-rust, using wownero-oxide (dalek v4) as the crypto backend.
//! wownero-oxide automatically handles WOW-specific transaction parameters:
//! RctType 8 (WowneroClsagBulletproofPlus), ring size 22, INV_EIGHT scaling.
//!
//! Data structures are preserved. Functions that relied on monero-serai's
//! `SignableTransactionBuilder`, `Decoys`, `ReceivedOutput`, `SpendableOutput`,
//! `Fee`, and `Transaction` types are stubbed with `todo!()`.
//!
//! These will be implemented using wownero-oxide's wallet::send module
//! when the WowWallet adapter is fully wired.

pub mod native {
    use serde::{Deserialize, Serialize};

    use crate::scanner::Lookahead;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ChangeOutputInfo {
        pub tx_hash: String,
        pub output_index: u8,
        pub amount: u64,
        pub amount_xmr: String,
        pub key: String,
        pub key_offset: String,
        pub commitment_mask: String,
        pub subaddress_index: Option<(u32, u32)>,
        pub received_output_bytes: String,
        pub key_image: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TransactionResult {
        pub tx_id: String,
        pub fee: u64,
        pub tx_blob: String,
        /// The private transaction key (r scalar), hex-encoded.
        /// This key is required to prove payments to recipients.
        pub tx_key: String,
        /// Additional private keys for subaddress outputs, hex-encoded.
        pub tx_key_additional: Vec<String>,
        pub change_outputs: Vec<ChangeOutputInfo>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StoredOutputData {
        pub tx_hash: String,
        pub output_index: u8,
        pub amount: u64,
        pub key: String,
        pub key_offset: String,
        pub commitment_mask: String,
        pub subaddress: Option<(u32, u32)>,
        pub payment_id: Option<String>,
        pub received_output_bytes: String,
    }

    /// Ring member data (key + commitment as hex).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RingMember {
        pub key: String,
        pub commitment: String,
    }

    /// Decoy selection result for a single input.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DecoySelection {
        pub real_index: u8,
        pub offsets: Vec<u64>,
        pub ring: Vec<RingMember>,
    }

    /// Result of decoy fetching operation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DecoyResult {
        pub height: usize,
        pub decoys: Vec<DecoySelection>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FeeEstimate {
        pub fee: u64,
        pub weight: usize,
        pub per_weight: u64,
        pub mask: u64,
        pub inputs: usize,
        pub outputs: usize,
    }

    /// Prepared transaction state, ready for signing.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PreparedTransaction {
        pub node_url: String,
        pub network: String,
        pub recipients: Vec<(String, u64)>,
        pub fee: u64,
        pub total_input: u64,
        pub change: u64,
        pub stored_outputs: Vec<StoredOutputData>,
    }

    fn extra_weight(outputs: usize, has_payment_id: bool, data_sizes: &[usize]) -> usize {
        // tx public key: tag (1) + key (32)
        let base = 1 + 32;
        // assume additional keys needed (worst case for subaddresses)
        let additional = 1 + 1 + (outputs * 32);
        // payment id: nonce tag (1) + length (1) + encrypted tag (1) + id (8)
        let payment_id = if has_payment_id { 11 } else { 0 };
        // arbitrary data
        let data: usize = data_sizes
            .iter()
            .map(|len| {
                // nonce tag (1) + varint length + marker (1) + data
                1 + varint_len(1 + len) + 1 + len
            })
            .sum();
        base + additional + payment_id + data
    }

    fn varint_len(val: usize) -> usize {
        if val < 0x80 {
            1
        } else if val < 0x4000 {
            2
        } else if val < 0x200000 {
            3
        } else if val < 0x10000000 {
            4
        } else {
            5
        }
    }

    /// Estimate the transaction weight for fee calculation.
    ///
    /// Calculates the expected serialized size of a transaction based on
    /// input/output counts and extra field contents.
    pub fn estimate_tx_weight(
        num_inputs: usize,
        num_outputs: usize,
        has_payment_id: bool,
        data_sizes: &[usize],
    ) -> usize {
        // Version (1) + timelock (1) = 2 bytes header
        let header = 2;

        // Each input: type (1) + amount (1) + ring_len offsets (16 * ~3) + key_image (32)
        // + CLSAG: s values (16 * 32) + c1 (32) + D (32) + pseudo_out (32) = 576 + 32
        let per_input = 1 + 1 + (16 * 3) + 32 + 576 + 32; // ~690 bytes
        let inputs_weight = num_inputs * per_input;

        // Each output: key (32) + view tag (1) + encrypted amount (8) + commitment (32)
        let per_output = 32 + 1 + 8 + 32;
        let outputs_weight = num_outputs * per_output;

        // Bulletproofs+ proof: ~672 + 64*ceil(log2(num_outputs)) bytes
        let bp_size = if num_outputs <= 2 {
            672
        } else {
            let padded = (num_outputs as u32).next_power_of_two();
            672 + 64 * padded.trailing_zeros() as usize
        };

        let extra = extra_weight(num_outputs, has_payment_id, data_sizes);

        header + inputs_weight + outputs_weight + bp_size + extra
    }

    // -----------------------------------------------------------------------
    // Stubbed transaction building functions
    //
    // These functions previously depended on monero-serai's
    // SignableTransactionBuilder, Decoys, ReceivedOutput, SpendableOutput,
    // Fee, Scanner, ViewPair, and Transaction types.
    // -----------------------------------------------------------------------

    /// Create and sign a transaction.
    ///
    /// TODO: Implement using wownero-oxide's SignableTransaction.
    pub async fn create_transaction(
        _node_url: &str,
        _network: &str,
        _spend_key_hex: &str,
        _view_key_hex: &str,
        _stored_outputs: &[StoredOutputData],
        _recipients: &[(String, u64)],
        _lookahead: Lookahead,
    ) -> Result<TransactionResult, String> {
        todo!("create_transaction: port to wownero-oxide SignableTransaction")
    }

    /// Create and sign a transaction with pre-fetched decoys.
    ///
    /// TODO: Implement using wownero-oxide's SignableTransaction.
    pub async fn create_transaction_with_decoys(
        _node_url: &str,
        _network: &str,
        _spend_key_hex: &str,
        _view_key_hex: &str,
        _stored_outputs: &[StoredOutputData],
        _recipients: &[(String, u64)],
        _decoy_result: &DecoyResult,
        _lookahead: Lookahead,
    ) -> Result<TransactionResult, String> {
        todo!("create_transaction_with_decoys: port to wownero-oxide SignableTransaction")
    }

    /// Fetch decoys for a set of inputs.
    ///
    /// TODO: Implement using wownero-oxide's decoy selection.
    pub async fn fetch_decoys(
        _node_url: &str,
        _stored_outputs: &[StoredOutputData],
    ) -> Result<DecoyResult, String> {
        todo!("fetch_decoys: port to wownero-oxide decoy selection")
    }

    /// Estimate the fee for a transaction.
    pub fn estimate_fee_for_tx(
        num_inputs: usize,
        num_outputs: usize,
        per_weight: u64,
        mask: u64,
    ) -> FeeEstimate {
        let weight = estimate_tx_weight(num_inputs, num_outputs, false, &[]);
        let raw_fee = weight as u64 * per_weight;
        let fee = if mask > 0 {
            ((raw_fee + mask - 1) / mask) * mask
        } else {
            raw_fee
        };
        FeeEstimate {
            fee,
            weight,
            per_weight,
            mask,
            inputs: num_inputs,
            outputs: num_outputs,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_estimate_tx_weight() {
            let weight = estimate_tx_weight(1, 2, false, &[]);
            assert!(weight > 0);
            // Should be roughly 1400-1800 bytes for a 1-in/2-out tx
            assert!(weight > 1000);
            assert!(weight < 3000);
        }

        #[test]
        fn test_estimate_fee_for_tx() {
            let estimate = estimate_fee_for_tx(1, 2, 20000, 10000);
            assert!(estimate.fee > 0);
            assert_eq!(estimate.inputs, 1);
            assert_eq!(estimate.outputs, 2);
            // Fee should be aligned to mask
            assert_eq!(estimate.fee % 10000, 0);
        }

        #[test]
        fn test_varint_len() {
            assert_eq!(varint_len(0), 1);
            assert_eq!(varint_len(127), 1);
            assert_eq!(varint_len(128), 2);
            assert_eq!(varint_len(16383), 2);
            assert_eq!(varint_len(16384), 3);
        }

        #[test]
        fn test_extra_weight() {
            let w1 = extra_weight(2, false, &[]);
            let w2 = extra_weight(2, true, &[]);
            assert!(w2 > w1); // payment ID adds weight
        }
    }
}
