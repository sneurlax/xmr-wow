use std::collections::HashSet;

use crate::coin_selection::{estimate_fee, select_inputs, CoinSelectionResult};
use crate::tx_builder::native::StoredOutputData;
use crate::wallet_output::WalletOutput;
use crate::wallet_state::is_spendable;

/// Prepared inputs ready for transaction building.
#[derive(Debug, Clone)]
pub struct PreparedInputs {
    pub stored_outputs: Vec<StoredOutputData>,
    pub spent_output_keys: Vec<String>,
    pub total_input: u64,
    pub estimated_fee: u64,
}

/// Prepare inputs for a regular send transaction.
///
/// Filters wallet outputs to spendable ones, runs coin selection for the
/// requested amount, and converts to `StoredOutputData` ready for
/// `create_transaction()`.
pub fn prepare_send_inputs(
    wallet_outputs: &[WalletOutput],
    daemon_height: u64,
    total_amount: u64,
    num_recipients: usize,
    manual_selection: Option<&[String]>,
    excluded_key_images: Option<&HashSet<String>>,
) -> Result<PreparedInputs, String> {
    let spendable: Vec<WalletOutput> = wallet_outputs
        .iter()
        .filter(|o| {
            !o.spent
                && !o.frozen
                && is_spendable(o, daemon_height)
                && !excluded_key_images.is_some_and(|exc| exc.contains(&o.key_image))
        })
        .cloned()
        .collect();

    let CoinSelectionResult {
        selected,
        total,
        estimated_fee,
    } = select_inputs(&spendable, total_amount, num_recipients, manual_selection)?;

    let spent_output_keys: Vec<String> = selected.iter().map(|o| o.output_key()).collect();
    let stored_outputs: Vec<StoredOutputData> = selected.into_iter().map(Into::into).collect();

    Ok(PreparedInputs {
        stored_outputs,
        spent_output_keys,
        total_input: total,
        estimated_fee,
    })
}

/// Prepare inputs for a sweep-all transaction.
///
/// Takes all spendable outputs (optionally filtered by output keys for
/// account-level sweeps) and converts to `StoredOutputData` ready for
/// `sweep_all()`.
pub fn prepare_sweep_inputs(
    wallet_outputs: &[WalletOutput],
    daemon_height: u64,
    selected_output_keys: Option<&[String]>,
    excluded_key_images: Option<&HashSet<String>>,
) -> Result<PreparedInputs, String> {
    let mut spendable: Vec<WalletOutput> = wallet_outputs
        .iter()
        .filter(|o| {
            !o.spent
                && !o.frozen
                && is_spendable(o, daemon_height)
                && !excluded_key_images.is_some_and(|exc| exc.contains(&o.key_image))
        })
        .cloned()
        .collect();

    if let Some(keys) = selected_output_keys {
        spendable.retain(|o| keys.contains(&o.output_key()));
    }

    if spendable.is_empty() {
        return Err("No spendable outputs available for sweep".to_string());
    }

    let total_input: u64 = spendable.iter().map(|o| o.amount).sum();
    // Sweep has 1 output (destination, no change); padded to 2 by BP+ = base case
    let estimated_fee = estimate_fee(spendable.len(), 1);
    let spent_output_keys: Vec<String> = spendable.iter().map(|o| o.output_key()).collect();
    let stored_outputs: Vec<StoredOutputData> = spendable.into_iter().map(Into::into).collect();

    Ok(PreparedInputs {
        stored_outputs,
        spent_output_keys,
        total_input,
        estimated_fee,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_output(amount: u64, height: u64, tx_hash: &str) -> WalletOutput {
        WalletOutput {
            tx_hash: tx_hash.to_string(),
            output_index: 0,
            amount,
            amount_xmr: format!("{:.12}", amount as f64 / 1_000_000_000_000.0),
            key: "k".into(),
            key_offset: "ko".into(),
            commitment_mask: "cm".into(),
            subaddress_index: Some((0, 0)),
            payment_id: None,
            received_output_bytes: "".into(),
            block_height: height,
            spent: false,
            spent_height: None,
            key_image: format!("ki_{}", tx_hash),
            is_coinbase: false,
            frozen: false,
        }
    }

    fn make_spent(amount: u64, height: u64, tx_hash: &str) -> WalletOutput {
        let mut o = make_output(amount, height, tx_hash);
        o.spent = true;
        o
    }

    fn make_coinbase(amount: u64, height: u64, tx_hash: &str) -> WalletOutput {
        let mut o = make_output(amount, height, tx_hash);
        o.is_coinbase = true;
        o
    }

    fn make_frozen(amount: u64, height: u64, tx_hash: &str) -> WalletOutput {
        let mut o = make_output(amount, height, tx_hash);
        o.frozen = true;
        o
    }

    // ---- prepare_send_inputs ----

    #[test]
    fn send_filters_out_spent_outputs() {
        let outputs = vec![
            make_output(5_000_000_000_000, 100, "tx1"),
            make_spent(3_000_000_000_000, 100, "tx2"),
        ];
        let result = prepare_send_inputs(&outputs, 200, 1_000_000_000_000, 1, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    #[test]
    fn send_filters_frozen_outputs() {
        let outputs = vec![
            make_output(5_000_000_000_000, 100, "tx1"),
            make_frozen(3_000_000_000_000, 100, "tx2"),
        ];
        let result = prepare_send_inputs(&outputs, 200, 1_000_000_000_000, 1, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    #[test]
    fn send_error_when_only_frozen() {
        let outputs = vec![make_frozen(5_000_000_000_000, 100, "tx1")];
        let result = prepare_send_inputs(&outputs, 200, 1_000_000_000_000, 1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn send_filters_out_unconfirmed() {
        // height 105: output at 100 has only 5 confirmations (needs 10)
        let outputs = vec![make_output(5_000_000_000_000, 100, "tx1")];
        let result = prepare_send_inputs(&outputs, 105, 1_000_000_000_000, 1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn send_includes_confirmed_outputs() {
        // height 110: output at 100 has 10 confirmations
        let outputs = vec![make_output(5_000_000_000_000, 100, "tx1")];
        let result = prepare_send_inputs(&outputs, 110, 1_000_000_000_000, 1, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
    }

    #[test]
    fn send_filters_immature_coinbase() {
        // height 150: coinbase at 100 has 50 confirmations (needs 60)
        let outputs = vec![
            make_coinbase(5_000_000_000_000, 100, "cb1"),
            make_output(2_000_000_000_000, 100, "tx1"),
        ];
        let result = prepare_send_inputs(&outputs, 150, 1_000_000_000_000, 1, None, None).unwrap();
        // Only the regular output should be selected (coinbase not spendable yet)
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    #[test]
    fn send_includes_mature_coinbase() {
        // height 160: coinbase at 100 has 60 confirmations
        let outputs = vec![make_coinbase(2_000_000_000_000, 100, "cb1")];
        let result = prepare_send_inputs(&outputs, 160, 1_000_000_000_000, 1, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
    }

    #[test]
    fn send_runs_coin_selection() {
        let outputs = vec![
            make_output(5_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 100, "tx2"),
            make_output(500_000_000_000, 100, "tx3"),
        ];
        // For 1 XMR, should pick the 2 XMR output (smallest sufficient)
        let result = prepare_send_inputs(&outputs, 200, 1_000_000_000_000, 1, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].amount, 2_000_000_000_000);
    }

    #[test]
    fn send_returns_correct_spent_keys() {
        let mut o1 = make_output(2_000_000_000_000, 100, "tx_abc");
        o1.output_index = 1;
        let outputs = vec![o1];
        let result = prepare_send_inputs(&outputs, 200, 1_000_000_000_000, 1, None, None).unwrap();
        assert_eq!(result.spent_output_keys, vec!["tx_abc:1".to_string()]);
    }

    #[test]
    fn send_converts_subaddress_field() {
        let mut o = make_output(5_000_000_000_000, 100, "tx1");
        o.subaddress_index = Some((1, 3));
        let result = prepare_send_inputs(&[o], 200, 1_000_000_000_000, 1, None, None).unwrap();
        // StoredOutputData uses `subaddress`, not `subaddress_index`
        assert_eq!(result.stored_outputs[0].subaddress, Some((1, 3)));
    }

    #[test]
    fn send_manual_selection() {
        let outputs = vec![
            make_output(1_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 100, "tx2"),
            make_output(3_000_000_000_000, 100, "tx3"),
        ];
        let keys = vec!["tx1:0".to_string(), "tx3:0".to_string()];
        let result =
            prepare_send_inputs(&outputs, 200, 500_000_000_000, 1, Some(&keys), None).unwrap();
        assert_eq!(result.stored_outputs.len(), 2);
        assert_eq!(result.total_input, 4_000_000_000_000);
    }

    #[test]
    fn send_error_when_no_spendable() {
        let outputs = vec![make_spent(5_000_000_000_000, 100, "tx1")];
        let result = prepare_send_inputs(&outputs, 200, 1_000_000_000_000, 1, None, None);
        assert!(result.is_err());
    }

    // ---- prepare_sweep_inputs ----

    #[test]
    fn sweep_returns_all_spendable() {
        let outputs = vec![
            make_output(1_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 100, "tx2"),
            make_output(3_000_000_000_000, 100, "tx3"),
        ];
        let result = prepare_sweep_inputs(&outputs, 200, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 3);
        assert_eq!(result.total_input, 6_000_000_000_000);
    }

    #[test]
    fn sweep_filters_frozen() {
        let outputs = vec![
            make_output(1_000_000_000_000, 100, "tx1"),
            make_frozen(2_000_000_000_000, 100, "tx2"),
        ];
        let result = prepare_sweep_inputs(&outputs, 200, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    #[test]
    fn sweep_error_when_only_frozen() {
        let outputs = vec![make_frozen(1_000_000_000_000, 100, "tx1")];
        let result = prepare_sweep_inputs(&outputs, 200, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn sweep_filters_spent() {
        let outputs = vec![
            make_output(1_000_000_000_000, 100, "tx1"),
            make_spent(2_000_000_000_000, 100, "tx2"),
        ];
        let result = prepare_sweep_inputs(&outputs, 200, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    #[test]
    fn sweep_filters_unconfirmed() {
        let outputs = vec![
            make_output(1_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 108, "tx2"), // only 2 confirmations at height 110
        ];
        let result = prepare_sweep_inputs(&outputs, 110, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    #[test]
    fn sweep_filters_by_output_keys() {
        let outputs = vec![
            make_output(1_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 100, "tx2"),
            make_output(3_000_000_000_000, 100, "tx3"),
        ];
        let keys = vec!["tx1:0".to_string(), "tx3:0".to_string()];
        let result = prepare_sweep_inputs(&outputs, 200, Some(&keys), None).unwrap();
        assert_eq!(result.stored_outputs.len(), 2);
        assert_eq!(result.total_input, 4_000_000_000_000);
    }

    #[test]
    fn sweep_error_when_empty() {
        let outputs = vec![make_spent(1_000_000_000_000, 100, "tx1")];
        let result = prepare_sweep_inputs(&outputs, 200, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No spendable outputs"));
    }

    #[test]
    fn sweep_returns_correct_spent_keys() {
        let mut o1 = make_output(1_000_000_000_000, 100, "tx_a");
        o1.output_index = 0;
        let mut o2 = make_output(2_000_000_000_000, 100, "tx_b");
        o2.output_index = 2;
        let result = prepare_sweep_inputs(&[o1, o2], 200, None, None).unwrap();
        assert_eq!(
            result.spent_output_keys,
            vec!["tx_a:0".to_string(), "tx_b:2".to_string()]
        );
    }

    #[test]
    fn sweep_fee_scales_with_output_count() {
        let outputs = vec![
            make_output(1_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 100, "tx2"),
        ];
        let result = prepare_sweep_inputs(&outputs, 200, None, None).unwrap();
        // Sweep has 1 output (destination), estimate_fee(2, 1) since 1 output pads to 2
        assert_eq!(result.estimated_fee, estimate_fee(2, 1));
    }

    #[test]
    fn sweep_immature_coinbase_excluded() {
        let outputs = vec![
            make_coinbase(5_000_000_000_000, 100, "cb1"),
            make_output(1_000_000_000_000, 100, "tx1"),
        ];
        // Only 50 confirmations for coinbase (needs 60)
        let result = prepare_sweep_inputs(&outputs, 150, None, None).unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    // ---- excluded_key_images tests ----

    #[test]
    fn send_excludes_pending_key_images() {
        let outputs = vec![
            make_output(5_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 100, "tx2"),
        ];
        let excluded: HashSet<String> = ["ki_tx2".to_string()].into();
        let result =
            prepare_send_inputs(&outputs, 200, 1_000_000_000_000, 1, None, Some(&excluded))
                .unwrap();
        assert_eq!(result.stored_outputs.len(), 1);
        assert_eq!(result.stored_outputs[0].tx_hash, "tx1");
    }

    #[test]
    fn sweep_excludes_pending_key_images() {
        let outputs = vec![
            make_output(5_000_000_000_000, 100, "tx1"),
            make_output(2_000_000_000_000, 100, "tx2"),
            make_output(1_000_000_000_000, 100, "tx3"),
        ];
        let excluded: HashSet<String> = ["ki_tx2".to_string()].into();
        let result = prepare_sweep_inputs(&outputs, 200, None, Some(&excluded)).unwrap();
        assert_eq!(result.stored_outputs.len(), 2);
        assert_eq!(result.total_input, 6_000_000_000_000); // tx1 + tx3
    }
}
