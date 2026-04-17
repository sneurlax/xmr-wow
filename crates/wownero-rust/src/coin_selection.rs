use crate::wallet_output::WalletOutput;

/// Fee estimation constants (conservative estimates).
/// Derived from Protocol::v16 (ring_len=16, bp_plus=true) at min fee rate
/// (per_weight=20000, mask=10000). Actual per-input marginal weight is 771 bytes
/// (Input 163 + CLSAG 576 + pseudo_out 32) = 15,420,000 piconero. Base overhead
/// for a 2-output tx is ~915 bytes = 18,300,000 piconero. Constants include ~4%
/// margin for fee rate fluctuations.
pub const FEE_PER_INPUT_ESTIMATE: u64 = 16_000_000;
pub const BASE_FEE_ESTIMATE: u64 = 19_000_000;

/// Extra fee per Bulletproofs+ output-count doubling beyond the base 2 outputs.
/// When outputs exceed 2, BP+ pads to next power of 2. Each doubling adds ~640
/// bytes of proof weight = ~12,800,000 piconero. We use 13M for margin.
const BP_DOUBLING_FEE_ESTIMATE: u64 = 13_000_000;

/// Per-output field overhead (commitment + encrypted amount ~ 40 bytes = 800,000 piconero).
const PER_OUTPUT_FIELD_FEE_ESTIMATE: u64 = 1_000_000;

/// Minimum useful output amount (piconero). Outputs below this cost more
/// in fees to spend than they're worth. Approximately equal to the marginal
/// fee for one input at minimum fee rate.
pub const DUST_THRESHOLD: u64 = 20_000_000; // 0.00002 XMR

/// Estimate the transaction fee given input and output counts.
///
/// Accounts for Bulletproofs+ output padding (outputs are padded to the next
/// power of 2, and each doubling beyond 2 adds ~640 bytes of proof weight).
pub fn estimate_fee(num_inputs: usize, num_outputs: usize) -> u64 {
    let base = BASE_FEE_ESTIMATE + (num_inputs as u64 * FEE_PER_INPUT_ESTIMATE);

    if num_outputs <= 2 {
        return base;
    }

    // Extra output fields beyond the 2 included in BASE_FEE_ESTIMATE
    let extra_output_fields = (num_outputs - 2) as u64 * PER_OUTPUT_FIELD_FEE_ESTIMATE;

    // BP+ pads to next power of 2; each doubling beyond 2 adds ~640 bytes
    let padded = (num_outputs as u32).next_power_of_two();
    let bp_doublings = padded.trailing_zeros().saturating_sub(1); // base is 2 = 2^1
    let bp_extra = bp_doublings as u64 * BP_DOUBLING_FEE_ESTIMATE;

    base + extra_output_fields + bp_extra
}

/// Result of coin selection.
#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    pub selected: Vec<WalletOutput>,
    pub total: u64,
    pub estimated_fee: u64,
}

/// Select inputs for a transaction.
///
/// Strategy:
/// 1. Try to find the smallest single output covering amount + fee
/// 2. If no single output works, find the combination with minimum inputs
///    that minimizes excess (locked change)
///
/// `num_recipients` is the number of destination addresses (used to estimate
/// fee weight from output count: recipients + 1 change output).
///
/// If `manual_selection` is Some, only those outputs (by "txHash:outputIndex" key) are used.
pub fn select_inputs(
    spendable: &[WalletOutput],
    amount: u64,
    num_recipients: usize,
    manual_selection: Option<&[String]>,
) -> Result<CoinSelectionResult, String> {
    let mut candidates: Vec<WalletOutput> = if let Some(selected_keys) = manual_selection {
        spendable
            .iter()
            .filter(|o| selected_keys.contains(&o.output_key()))
            .cloned()
            .collect()
    } else {
        spendable.to_vec()
    };

    if candidates.is_empty() {
        return Err(if manual_selection.is_some() {
            "No selected outputs available to spend".to_string()
        } else {
            "No confirmed outputs available to spend (outputs need 10 confirmations)".to_string()
        });
    }

    let num_outputs = num_recipients + 1; // recipients + change

    // If manual selection, use all selected outputs
    if manual_selection.is_some() {
        let total: u64 = candidates.iter().map(|o| o.amount).sum();
        let estimated_fee = estimate_fee(candidates.len(), num_outputs);
        return Ok(CoinSelectionResult {
            selected: candidates,
            total,
            estimated_fee,
        });
    }

    // Auto-selection: try single output first
    let single_input_fee = estimate_fee(1, num_outputs);
    let needed_for_single = amount + single_input_fee;

    candidates.sort_by_key(|o| o.amount);

    if let Some(output) = candidates.iter().find(|o| o.amount >= needed_for_single) {
        let output = output.clone();
        return Ok(CoinSelectionResult {
            total: output.amount,
            estimated_fee: single_input_fee,
            selected: vec![output],
        });
    }

    // No single output works: find optimal multi-input combination
    candidates.sort_by_key(|o| std::cmp::Reverse(o.amount));

    let mut best: Option<CoinSelectionResult> = None;

    for target_count in 2..=candidates.len() {
        let estimated_fee = estimate_fee(target_count, num_outputs);
        let needed_total = amount + estimated_fee;

        if let Some((selection, total)) =
            find_best_combination(&candidates, needed_total, target_count)
        {
            if best.is_none() {
                best = Some(CoinSelectionResult {
                    selected: selection,
                    total,
                    estimated_fee,
                });
                break; // Minimum input count found
            }
        }
    }

    match best {
        Some(result) => Ok(result),
        None => {
            // Fall back to using all outputs
            let total: u64 = candidates.iter().map(|o| o.amount).sum();
            let estimated_fee = estimate_fee(candidates.len(), num_outputs);
            Ok(CoinSelectionResult {
                selected: candidates,
                total,
                estimated_fee,
            })
        }
    }
}

/// Maximum number of combinations to evaluate before giving up on exact search.
const MAX_COMBINATIONS: u64 = 100_000;

/// Find the best combination of exactly `target_count` outputs summing to >= `needed_total`.
/// Among valid combinations, picks the one with smallest excess (minimizes locked change).
/// Falls back to a greedy selection if the search space exceeds MAX_COMBINATIONS.
pub fn find_best_combination(
    outputs: &[WalletOutput],
    needed_total: u64,
    target_count: usize,
) -> Option<(Vec<WalletOutput>, u64)> {
    if target_count == 0 || target_count > outputs.len() {
        return None;
    }

    // Check if search space is tractable: C(n, k) <= MAX_COMBINATIONS
    if combinations_exceed(outputs.len(), target_count, MAX_COMBINATIONS) {
        // Greedy: pick the largest `target_count` outputs (already sorted descending)
        let selected: Vec<WalletOutput> = outputs.iter().take(target_count).cloned().collect();
        let total: u64 = selected.iter().map(|o| o.amount).sum();
        return if total >= needed_total {
            Some((selected, total))
        } else {
            None
        };
    }

    fn search(
        outputs: &[WalletOutput],
        needed: u64,
        target_count: usize,
        start_idx: usize,
        current: &mut Vec<WalletOutput>,
        current_sum: u64,
        best: &mut Option<(Vec<WalletOutput>, u64)>,
    ) {
        if current.len() == target_count {
            if current_sum >= needed {
                let current_excess = current_sum - needed;
                let is_better = match best {
                    None => true,
                    Some((_, best_sum)) => {
                        let best_excess = *best_sum - needed;
                        current_excess < best_excess
                    }
                };
                if is_better {
                    *best = Some((current.clone(), current_sum));
                }
            }
            return;
        }

        let remaining_needed = target_count - current.len();
        for i in start_idx..outputs.len() {
            if outputs.len() - i < remaining_needed {
                break;
            }

            current.push(outputs[i].clone());
            search(
                outputs,
                needed,
                target_count,
                i + 1,
                current,
                current_sum + outputs[i].amount,
                best,
            );
            current.pop();
        }
    }

    let mut best: Option<(Vec<WalletOutput>, u64)> = None;
    let mut current = Vec::new();
    search(
        outputs,
        needed_total,
        target_count,
        0,
        &mut current,
        0,
        &mut best,
    );
    best
}

/// Check if C(n, k) exceeds `limit` without overflowing.
fn combinations_exceed(n: usize, k: usize, limit: u64) -> bool {
    let k = k.min(n - k);
    let mut c: u64 = 1;
    for i in 0..k {
        c = match c.checked_mul((n - i) as u64) {
            Some(v) => v / (i as u64 + 1),
            None => return true,
        };
        if c > limit {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_output(amount: u64, tx_hash: &str) -> WalletOutput {
        WalletOutput {
            tx_hash: tx_hash.to_string(),
            output_index: 0,
            amount,
            amount_xmr: format!("{:.12}", amount as f64 / 1_000_000_000_000.0),
            key: "k".into(),
            key_offset: "ko".into(),
            commitment_mask: "cm".into(),
            subaddress_index: None,
            payment_id: None,
            received_output_bytes: "".into(),
            block_height: 100,
            spent: false,
            spent_height: None,
            key_image: format!("ki_{}", tx_hash),
            is_coinbase: false,
            frozen: false,
        }
    }

    #[test]
    fn test_single_output_sufficient() {
        let outputs = vec![
            make_output(5_000_000_000_000, "tx1"),
            make_output(2_000_000_000_000, "tx2"),
            make_output(500_000_000_000, "tx3"),
        ];
        let result = select_inputs(&outputs, 1_000_000_000_000, 1, None).unwrap();
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].amount, 2_000_000_000_000); // smallest sufficient
    }

    #[test]
    fn test_multiple_outputs_needed() {
        let outputs = vec![
            make_output(2_000_000_000_000, "tx1"),
            make_output(1_500_000_000_000, "tx2"),
            make_output(800_000_000_000, "tx3"),
        ];
        let result = select_inputs(&outputs, 3_000_000_000_000, 1, None).unwrap();
        assert_eq!(result.selected.len(), 2);
        let total: u64 = result.selected.iter().map(|o| o.amount).sum();
        assert!(total >= 3_000_000_000_000 + result.estimated_fee);
    }

    #[test]
    fn test_manual_selection() {
        let outputs = vec![
            make_output(1_000_000_000_000, "tx1"),
            make_output(2_000_000_000_000, "tx2"),
            make_output(3_000_000_000_000, "tx3"),
        ];
        let selected_keys = vec!["tx1:0".to_string(), "tx3:0".to_string()];
        let result = select_inputs(&outputs, 500_000_000_000, 1, Some(&selected_keys)).unwrap();
        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.total, 4_000_000_000_000);
    }

    #[test]
    fn test_empty_spendable_returns_error() {
        let result = select_inputs(&[], 1_000_000_000_000, 1, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_prefers_single_over_multi() {
        let outputs = vec![
            make_output(3_000_000_000_000, "tx_large"),
            make_output(100_000_000_000, "tx1"),
            make_output(100_000_000_000, "tx2"),
            make_output(100_000_000_000, "tx3"),
            make_output(100_000_000_000, "tx4"),
            make_output(100_000_000_000, "tx5"),
        ];
        let result = select_inputs(&outputs, 400_000_000_000, 1, None).unwrap();
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].tx_hash, "tx_large");
    }

    #[test]
    fn test_minimize_change() {
        // 3 XMR needed, outputs [0.75, 1, 1.5, 2.5]
        // Best: 2.5 + 0.75 = 3.25 (least change)
        let outputs = vec![
            make_output(750_000_000_000, "tx1"),
            make_output(1_000_000_000_000, "tx2"),
            make_output(1_500_000_000_000, "tx3"),
            make_output(2_500_000_000_000, "tx4"),
        ];
        let result = select_inputs(&outputs, 3_000_000_000_000, 1, None).unwrap();
        assert_eq!(result.selected.len(), 2);
        let total: u64 = result.selected.iter().map(|o| o.amount).sum();
        assert_eq!(total, 3_250_000_000_000);
    }

    #[test]
    fn test_find_best_combination_basic() {
        let outputs = vec![
            make_output(500_000_000_000, "tx1"),
            make_output(600_000_000_000, "tx2"),
            make_output(700_000_000_000, "tx3"),
            make_output(800_000_000_000, "tx4"),
        ];
        let result = find_best_combination(&outputs, 1_250_000_000_000, 2);
        assert!(result.is_some());
        let (selected, total) = result.unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(total, 1_300_000_000_000); // 800 + 500 = smallest >= 1250
    }

    #[test]
    fn test_find_best_combination_impossible() {
        let outputs = vec![
            make_output(100_000_000_000, "tx1"),
            make_output(200_000_000_000, "tx2"),
        ];
        let result = find_best_combination(&outputs, 1_000_000_000_000, 2);
        assert!(result.is_none());
    }

    #[test]
    fn test_estimate_fee_2_outputs() {
        // 2 outputs = base case, no extra BP+ cost
        assert_eq!(
            estimate_fee(1, 2),
            BASE_FEE_ESTIMATE + FEE_PER_INPUT_ESTIMATE
        );
        assert_eq!(
            estimate_fee(2, 2),
            BASE_FEE_ESTIMATE + 2 * FEE_PER_INPUT_ESTIMATE
        );
    }

    #[test]
    fn test_estimate_fee_3_outputs() {
        // 3 outputs pads to 4 = 1 BP+ doubling beyond base
        let fee_1in_3out = estimate_fee(1, 3);
        let fee_1in_2out = estimate_fee(1, 2);
        // Should be noticeably more than 2-output case
        assert!(fee_1in_3out > fee_1in_2out + 10_000_000);
    }

    #[test]
    fn test_estimate_fee_increases_with_outputs() {
        // More outputs = higher fee
        let fee_2out = estimate_fee(1, 2);
        let fee_3out = estimate_fee(1, 3);
        let fee_5out = estimate_fee(1, 5);
        assert!(fee_3out > fee_2out);
        assert!(fee_5out > fee_3out);
    }

    #[test]
    fn test_select_inputs_multi_recipient() {
        // With 3 recipients (4 outputs), fee estimate should be higher
        let outputs = vec![
            make_output(5_000_000_000_000, "tx1"),
            make_output(2_000_000_000_000, "tx2"),
        ];
        let result_1r = select_inputs(&outputs, 1_000_000_000_000, 1, None).unwrap();
        let result_3r = select_inputs(&outputs, 1_000_000_000_000, 3, None).unwrap();
        assert!(result_3r.estimated_fee > result_1r.estimated_fee);
    }
}
