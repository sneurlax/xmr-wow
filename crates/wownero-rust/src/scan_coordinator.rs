use std::collections::HashSet;

use crate::scanner::{BlockScanResult, Lookahead, DEFAULT_LOOKAHEAD};
use crate::wallet_output::WalletOutput;
use crate::wallet_state::{WalletState, MAX_REORG_DEPTH};

/// Sync progress information.
#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub current_height: u64,
    pub target_height: u64,
    pub is_synced: bool,
    pub is_scanning: bool,
}

/// Compute sync progress from heights.
pub fn sync_progress(current_height: u64, target_height: u64) -> SyncProgress {
    let is_synced = current_height >= target_height;
    SyncProgress {
        current_height,
        target_height,
        is_synced,
        is_scanning: !is_synced,
    }
}

/// Per-block output summary from batch processing.
#[derive(Debug, Clone)]
pub struct BlockOutputSummary {
    pub block_height: u64,
    pub block_hash: String,
    pub block_timestamp: u64,
    pub tx_count: usize,
    pub outputs: Vec<WalletOutput>,
    pub daemon_height: u64,
    pub spent_key_images: Vec<String>,
    pub spent_key_image_tx_hashes: Vec<String>,
}

/// Processed result from a single-wallet batch scan.
#[derive(Debug, Clone)]
pub struct ProcessedBatch {
    pub batch_end_height: u64,
    pub outputs_to_store: Vec<WalletOutput>,
    pub spent_key_images: Vec<String>,
    pub spent_key_image_tx_hashes: Vec<String>,
    pub should_continue: bool,
    pub blocks_with_outputs: Vec<BlockOutputSummary>,
    pub daemon_height: u64,
    pub block_hashes: Vec<(u64, String)>,
}

/// Compute the lookahead needed for a scan.
///
/// If specific accounts are requested, the lookahead account is the max.
/// Otherwise, use the provided account_lookahead.
pub fn compute_lookahead(
    account_lookahead: u32,
    subaddress_lookahead: u32,
    accounts_to_scan: Option<&[u32]>,
) -> Lookahead {
    let account = if let Some(accounts) = accounts_to_scan {
        accounts.iter().max().copied().unwrap_or(0)
    } else {
        account_lookahead
    };
    let subaddress = if subaddress_lookahead > 0 {
        subaddress_lookahead
    } else {
        DEFAULT_LOOKAHEAD.subaddress
    };
    Lookahead {
        account,
        subaddress,
    }
}

/// Filter outputs by account set.
///
/// If `accounts` is None, all outputs pass. If Some, only outputs whose
/// account (first element of subaddress_index, defaulting to 0) is in
/// the set pass.
pub fn filter_outputs_by_accounts<'a>(
    outputs: impl Iterator<Item = &'a WalletOutput>,
    accounts: Option<&HashSet<u32>>,
) -> Vec<WalletOutput> {
    outputs
        .filter(|o| match accounts {
            None => true,
            Some(set) => {
                let account = o.subaddress_index.map(|(a, _)| a).unwrap_or(0);
                set.contains(&account)
            }
        })
        .cloned()
        .collect()
}

/// Process a batch of single-wallet scan results.
///
/// Aggregates outputs and spent key images across the batch, filters
/// outputs by account, and determines whether scanning should continue.
pub fn process_single_wallet_batch(
    batch_results: &[BlockScanResult],
    accounts_to_scan: Option<&[u32]>,
    target_height: u64,
    batch_start_height: u64,
) -> ProcessedBatch {
    if batch_results.is_empty() {
        return ProcessedBatch {
            batch_end_height: batch_start_height,
            outputs_to_store: Vec::new(),
            spent_key_images: Vec::new(),
            spent_key_image_tx_hashes: Vec::new(),
            should_continue: false,
            blocks_with_outputs: Vec::new(),
            daemon_height: 0,
            block_hashes: Vec::new(),
        };
    }

    let batch_end_height = batch_results
        .last()
        .map(|r| r.block_height + 1)
        .unwrap_or(batch_start_height);

    let accounts_set: Option<HashSet<u32>> =
        accounts_to_scan.map(|a| a.iter().copied().collect());

    let mut all_outputs = Vec::new();
    let mut all_spent_key_images = Vec::new();
    let mut all_spent_key_image_tx_hashes = Vec::new();
    let mut blocks_with_outputs = Vec::new();
    let mut all_block_hashes = Vec::new();
    let mut last_daemon_height = 0u64;

    for result in batch_results {
        last_daemon_height = result.daemon_height;
        all_block_hashes.push((result.block_height, result.block_hash.clone()));

        all_spent_key_images.extend(result.spent_key_images.iter().cloned());
        all_spent_key_image_tx_hashes.extend(result.spent_key_image_tx_hashes.iter().cloned());

        let filtered = filter_outputs_by_accounts(
            result.outputs.iter(),
            accounts_set.as_ref(),
        );

        if !filtered.is_empty() {
            all_outputs.extend(filtered.iter().cloned());

            blocks_with_outputs.push(BlockOutputSummary {
                block_height: result.block_height,
                block_hash: result.block_hash.clone(),
                block_timestamp: result.block_timestamp,
                tx_count: result.tx_count,
                outputs: filtered,
                daemon_height: result.daemon_height,
                spent_key_images: result.spent_key_images.clone(),
                spent_key_image_tx_hashes: result.spent_key_image_tx_hashes.clone(),
            });
        }
    }

    ProcessedBatch {
        batch_end_height,
        outputs_to_store: all_outputs,
        spent_key_images: all_spent_key_images,
        spent_key_image_tx_hashes: all_spent_key_image_tx_hashes,
        should_continue: batch_end_height < target_height,
        blocks_with_outputs,
        daemon_height: last_daemon_height,
        block_hashes: all_block_hashes,
    }
}

/// Outcome of a batch scan with reorg detection.
#[derive(Debug, Clone)]
pub enum ScanBatchOutcome {
    Normal(ProcessedBatch),
    Reorg(ReorgInfo),
}

/// Information about a detected blockchain reorganization.
#[derive(Debug, Clone)]
pub struct ReorgInfo {
    pub split_height: u64,
    pub blocks_detached: u64,
    pub outputs_removed: usize,
    pub outputs_unspent: usize,
    pub removed_key_images: Vec<String>,
    pub unspent_key_images: Vec<String>,
}

/// Process a batch with reorg detection.
///
/// Compares block hashes in the batch against known hashes in wallet state.
/// If a mismatch is found, rolls back the wallet state and returns `Reorg`.
/// Otherwise delegates to `process_single_wallet_batch` and returns `Normal`.
pub fn process_batch_with_reorg_detection(
    batch_results: &[BlockScanResult],
    wallet_state: &mut WalletState,
    accounts_to_scan: Option<&[u32]>,
    target_height: u64,
    batch_start_height: u64,
) -> Result<ScanBatchOutcome, String> {
    // Check for reorg: compare batch block hashes against known hashes
    for result in batch_results {
        if let Some(known_hash) = wallet_state.block_hashes.get_hash(result.block_height) {
            if known_hash != result.block_hash {
                let split_height = result.block_height;
                let current = wallet_state.current_height;
                if current >= split_height && current - split_height > MAX_REORG_DEPTH {
                    return Err(format!(
                        "Reorg depth {} exceeds maximum {}",
                        current - split_height,
                        MAX_REORG_DEPTH
                    ));
                }
                let rollback = wallet_state.rollback_to_height(split_height);
                return Ok(ScanBatchOutcome::Reorg(ReorgInfo {
                    split_height,
                    blocks_detached: current.saturating_sub(split_height) + 1,
                    outputs_removed: rollback.removed_outputs.len(),
                    outputs_unspent: rollback.outputs_unspent,
                    removed_key_images: rollback.removed_key_images,
                    unspent_key_images: rollback.unspent_key_images,
                }));
            }
        }
    }

    let batch = process_single_wallet_batch(
        batch_results,
        accounts_to_scan,
        target_height,
        batch_start_height,
    );
    Ok(ScanBatchOutcome::Normal(batch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_output(amount: u64, height: u64, tx_hash: &str, account: u32) -> WalletOutput {
        WalletOutput {
            tx_hash: tx_hash.to_string(),
            output_index: 0,
            amount,
            amount_xmr: String::new(),
            key: "k".into(),
            key_offset: "ko".into(),
            commitment_mask: "cm".into(),
            subaddress_index: Some((account, 0)),
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

    fn make_block_result(
        height: u64,
        outputs: Vec<WalletOutput>,
        spent_key_images: Vec<String>,
    ) -> BlockScanResult {
        let tx_hashes_len = spent_key_images.len();
        BlockScanResult {
            block_height: height,
            block_hash: format!("hash_{}", height),
            block_timestamp: height * 120,
            tx_count: outputs.len() + spent_key_images.len(),
            outputs,
            daemon_height: 1000,
            spent_key_images,
            spent_key_image_tx_hashes: vec![String::new(); tx_hashes_len],
        }
    }

    // ---- sync_progress ----

    #[test]
    fn progress_synced_when_current_ge_target() {
        let p = sync_progress(100, 100);
        assert!(p.is_synced);
        assert!(!p.is_scanning);

        let p = sync_progress(101, 100);
        assert!(p.is_synced);
        assert!(!p.is_scanning);
    }

    #[test]
    fn progress_scanning_when_behind() {
        let p = sync_progress(50, 100);
        assert!(!p.is_synced);
        assert!(p.is_scanning);
    }

    // ---- compute_lookahead ----

    #[test]
    fn lookahead_uses_account_lookahead_when_no_accounts() {
        let l = compute_lookahead(5, 0, None);
        assert_eq!(l.account, 5);
        assert_eq!(l.subaddress, DEFAULT_LOOKAHEAD.subaddress);
    }

    #[test]
    fn lookahead_uses_max_account_from_list() {
        let l = compute_lookahead(5, 0, Some(&[0, 3, 1]));
        assert_eq!(l.account, 3);
    }

    #[test]
    fn lookahead_handles_empty_accounts_list() {
        let l = compute_lookahead(5, 0, Some(&[]));
        assert_eq!(l.account, 0);
    }

    #[test]
    fn lookahead_uses_subaddress_when_provided() {
        let l = compute_lookahead(5, 200, None);
        assert_eq!(l.account, 5);
        assert_eq!(l.subaddress, 200);
    }

    #[test]
    fn lookahead_falls_back_to_default_subaddress_when_zero() {
        let l = compute_lookahead(5, 0, None);
        assert_eq!(l.subaddress, DEFAULT_LOOKAHEAD.subaddress);
    }

    // ---- filter_outputs_by_accounts ----

    #[test]
    fn filter_none_passes_all() {
        let outputs = vec![
            make_output(1000, 100, "tx1", 0),
            make_output(2000, 100, "tx2", 1),
            make_output(3000, 100, "tx3", 2),
        ];
        let filtered = filter_outputs_by_accounts(outputs.iter(), None);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_specific_accounts() {
        let outputs = vec![
            make_output(1000, 100, "tx1", 0),
            make_output(2000, 100, "tx2", 1),
            make_output(3000, 100, "tx3", 2),
        ];
        let accounts: HashSet<u32> = [0, 2].into();
        let filtered = filter_outputs_by_accounts(outputs.iter(), Some(&accounts));
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].tx_hash, "tx1");
        assert_eq!(filtered[1].tx_hash, "tx3");
    }

    #[test]
    fn filter_defaults_none_subaddress_to_account_0() {
        let mut o = make_output(1000, 100, "tx1", 0);
        o.subaddress_index = None;
        let outputs = vec![o];
        let accounts: HashSet<u32> = [0].into();
        let filtered = filter_outputs_by_accounts(outputs.iter(), Some(&accounts));
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn filter_excludes_none_subaddress_if_account_0_not_in_set() {
        let mut o = make_output(1000, 100, "tx1", 0);
        o.subaddress_index = None;
        let outputs = vec![o];
        let accounts: HashSet<u32> = [1].into();
        let filtered = filter_outputs_by_accounts(outputs.iter(), Some(&accounts));
        assert_eq!(filtered.len(), 0);
    }

    // ---- process_single_wallet_batch ----

    #[test]
    fn empty_batch_returns_no_continue() {
        let batch = process_single_wallet_batch(&[], None, 1000, 500);
        assert!(!batch.should_continue);
        assert_eq!(batch.batch_end_height, 500);
        assert!(batch.outputs_to_store.is_empty());
        assert!(batch.spent_key_images.is_empty());
    }

    #[test]
    fn batch_aggregates_outputs_across_blocks() {
        let results = vec![
            make_block_result(100, vec![make_output(1000, 100, "tx1", 0)], vec![]),
            make_block_result(101, vec![], vec![]),
            make_block_result(102, vec![make_output(2000, 102, "tx2", 0)], vec![]),
        ];
        let batch = process_single_wallet_batch(&results, None, 1000, 100);
        assert_eq!(batch.outputs_to_store.len(), 2);
        assert_eq!(batch.batch_end_height, 103); // last height + 1
    }

    #[test]
    fn batch_aggregates_key_images_across_blocks() {
        let results = vec![
            make_block_result(100, vec![], vec!["ki_a".into()]),
            make_block_result(101, vec![], vec!["ki_b".into(), "ki_c".into()]),
        ];
        let batch = process_single_wallet_batch(&results, None, 1000, 100);
        assert_eq!(batch.spent_key_images.len(), 3);
        assert!(batch.spent_key_images.contains(&"ki_a".to_string()));
        assert!(batch.spent_key_images.contains(&"ki_b".to_string()));
        assert!(batch.spent_key_images.contains(&"ki_c".to_string()));
    }

    #[test]
    fn batch_filters_outputs_by_account() {
        let results = vec![
            make_block_result(
                100,
                vec![
                    make_output(1000, 100, "tx1", 0),
                    make_output(2000, 100, "tx2", 1),
                    make_output(3000, 100, "tx3", 2),
                ],
                vec![],
            ),
        ];
        let batch = process_single_wallet_batch(&results, Some(&[0, 2]), 1000, 100);
        assert_eq!(batch.outputs_to_store.len(), 2);
        assert_eq!(batch.outputs_to_store[0].tx_hash, "tx1");
        assert_eq!(batch.outputs_to_store[1].tx_hash, "tx3");
    }

    #[test]
    fn batch_only_includes_blocks_with_filtered_outputs() {
        let results = vec![
            make_block_result(100, vec![make_output(1000, 100, "tx1", 0)], vec![]),
            make_block_result(101, vec![make_output(2000, 101, "tx2", 1)], vec![]),
            make_block_result(102, vec![make_output(3000, 102, "tx3", 0)], vec![]),
        ];
        // Only account 0
        let batch = process_single_wallet_batch(&results, Some(&[0]), 1000, 100);
        assert_eq!(batch.blocks_with_outputs.len(), 2); // blocks 100 and 102
        assert_eq!(batch.blocks_with_outputs[0].block_height, 100);
        assert_eq!(batch.blocks_with_outputs[1].block_height, 102);
    }

    #[test]
    fn batch_should_continue_when_below_target() {
        let results = vec![
            make_block_result(100, vec![], vec![]),
        ];
        let batch = process_single_wallet_batch(&results, None, 1000, 100);
        assert!(batch.should_continue);
        assert_eq!(batch.batch_end_height, 101);
    }

    #[test]
    fn batch_should_not_continue_at_target() {
        let results = vec![
            make_block_result(999, vec![], vec![]),
        ];
        let batch = process_single_wallet_batch(&results, None, 1000, 999);
        assert!(!batch.should_continue);
        assert_eq!(batch.batch_end_height, 1000);
    }

    #[test]
    fn batch_preserves_daemon_height() {
        let results = vec![
            make_block_result(100, vec![], vec![]),
        ];
        let batch = process_single_wallet_batch(&results, None, 1000, 100);
        assert_eq!(batch.daemon_height, 1000);
    }

    #[test]
    fn batch_key_images_not_filtered_by_account() {
        // Key images from all transactions should be collected regardless of account filter
        let results = vec![
            make_block_result(
                100,
                vec![make_output(1000, 100, "tx1", 1)], // account 1 output
                vec!["ki_from_any_tx".into()],
            ),
        ];
        // Filter to account 0 only
        let batch = process_single_wallet_batch(&results, Some(&[0]), 1000, 100);
        // Outputs filtered out, but key images preserved
        assert_eq!(batch.outputs_to_store.len(), 0);
        assert_eq!(batch.spent_key_images.len(), 1);
        assert_eq!(batch.spent_key_images[0], "ki_from_any_tx");
    }

    // ---- process_single_wallet_batch block_hashes ----

    #[test]
    fn batch_includes_block_hashes() {
        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
            make_block_result(102, vec![], vec![]),
        ];
        let batch = process_single_wallet_batch(&results, None, 1000, 100);
        assert_eq!(batch.block_hashes.len(), 3);
        assert_eq!(batch.block_hashes[0], (100, "hash_100".to_string()));
        assert_eq!(batch.block_hashes[1], (101, "hash_101".to_string()));
        assert_eq!(batch.block_hashes[2], (102, "hash_102".to_string()));
    }

    // ---- process_batch_with_reorg_detection ----

    #[test]
    fn reorg_detection_normal_all_beyond_tip() {
        let mut state = WalletState::new();
        state.current_height = 99;
        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, None, 1000, 100,
        ).unwrap();
        assert!(matches!(outcome, ScanBatchOutcome::Normal(_)));
    }

    #[test]
    fn reorg_detection_normal_matching_hashes() {
        let mut state = WalletState::new();
        state.current_height = 101;
        state.record_block_hash(100, "hash_100".to_string());
        state.record_block_hash(101, "hash_101".to_string());
        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
            make_block_result(102, vec![], vec![]),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, None, 1000, 100,
        ).unwrap();
        assert!(matches!(outcome, ScanBatchOutcome::Normal(_)));
    }

    #[test]
    fn reorg_detection_detects_different_hash() {
        let mut state = WalletState::new();
        state.current_height = 102;
        state.record_block_hash(100, "hash_100".to_string());
        state.record_block_hash(101, "old_hash_101".to_string()); // differs from "hash_101"
        state.record_block_hash(102, "hash_102".to_string());
        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
            make_block_result(102, vec![], vec![]),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, None, 1000, 100,
        ).unwrap();
        match outcome {
            ScanBatchOutcome::Reorg(info) => {
                assert_eq!(info.split_height, 101);
            }
            _ => panic!("Expected Reorg"),
        }
    }

    #[test]
    fn reorg_detection_too_deep() {
        let mut state = WalletState::new();
        state.current_height = 2000;
        state.record_block_hash(100, "old_hash".to_string());
        let results = vec![
            make_block_result(100, vec![], vec![]),
        ];
        let result = process_batch_with_reorg_detection(
            &results, &mut state, None, 3000, 100,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn reorg_detection_no_known_hash_for_height() {
        let mut state = WalletState::new();
        state.current_height = 102;
        // No hashes recorded ; no reorg can be detected
        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, None, 1000, 100,
        ).unwrap();
        assert!(matches!(outcome, ScanBatchOutcome::Normal(_)));
    }

    #[test]
    fn reorg_removes_outputs_and_unspends() {
        let mut state = WalletState::new();
        // Output below fork survives, output at fork removed
        state.add_outputs(vec![
            make_output(1000, 50, "tx_keep", 0),
            make_output(2000, 101, "tx_remove", 0),
        ]);
        state.mark_spent_by_key_images_at_height(
            &["ki_tx_keep".to_string()], 105,
        );
        state.current_height = 105;
        state.record_block_hash(100, "hash_100".to_string());
        state.record_block_hash(101, "old_hash_101".to_string());

        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, None, 1000, 100,
        ).unwrap();

        match outcome {
            ScanBatchOutcome::Reorg(info) => {
                assert_eq!(info.split_height, 101);
                assert_eq!(info.outputs_removed, 1); // tx_remove
                assert_eq!(info.outputs_unspent, 1); // tx_keep unspent
                assert_eq!(info.blocks_detached, 5); // 105 - 101 + 1
                assert_eq!(info.unspent_key_images, vec!["ki_tx_keep".to_string()]);
            }
            _ => panic!("Expected Reorg"),
        }

        // State rolled back
        assert_eq!(state.outputs().len(), 1);
        assert_eq!(state.outputs()[0].tx_hash, "tx_keep");
        assert!(!state.outputs()[0].spent);
        assert_eq!(state.current_height, 100);
    }

    #[test]
    fn reorg_detection_with_account_filter() {
        let mut state = WalletState::new();
        state.current_height = 99;
        // No known hashes = normal path, but test account filtering is preserved
        let results = vec![
            make_block_result(
                100,
                vec![
                    make_output(1000, 100, "tx1", 0),
                    make_output(2000, 100, "tx2", 1),
                ],
                vec![],
            ),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, Some(&[0]), 1000, 100,
        ).unwrap();
        match outcome {
            ScanBatchOutcome::Normal(batch) => {
                assert_eq!(batch.outputs_to_store.len(), 1);
                assert_eq!(batch.outputs_to_store[0].tx_hash, "tx1");
            }
            _ => panic!("Expected Normal"),
        }
    }

    #[test]
    fn reorg_at_max_depth_boundary() {
        let mut state = WalletState::new();
        let results = vec![make_block_result(100, vec![], vec![])];

        // Depth = MAX_REORG_DEPTH + 1: should fail
        state.current_height = 100 + MAX_REORG_DEPTH + 1;
        state.record_block_hash(100, "old_hash".to_string());
        let result = process_batch_with_reorg_detection(
            &results, &mut state, None, 3000, 100,
        );
        assert!(result.is_err());

        // Depth = MAX_REORG_DEPTH exactly: should succeed (> not >=)
        state.current_height = 100 + MAX_REORG_DEPTH;
        state.record_block_hash(100, "old_hash".to_string());
        let result = process_batch_with_reorg_detection(
            &results, &mut state, None, 3000, 100,
        );
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ScanBatchOutcome::Reorg(_)));
    }

    #[test]
    fn normal_batch_populates_block_hashes_for_recording() {
        let mut state = WalletState::new();
        state.current_height = 99;
        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, None, 1000, 100,
        ).unwrap();
        match outcome {
            ScanBatchOutcome::Normal(batch) => {
                assert_eq!(batch.block_hashes.len(), 2);
                // Caller can record these into state
                for (h, hash) in &batch.block_hashes {
                    state.record_block_hash(*h, hash.clone());
                }
                assert_eq!(state.block_hashes.get_hash(100), Some("hash_100"));
                assert_eq!(state.block_hashes.get_hash(101), Some("hash_101"));
            }
            _ => panic!("Expected Normal"),
        }
    }

    #[test]
    fn reorg_first_block_in_batch() {
        // Reorg at the very first block of the batch
        let mut state = WalletState::new();
        state.current_height = 100;
        state.record_block_hash(100, "old_hash_100".to_string());

        let results = vec![
            make_block_result(100, vec![], vec![]),
            make_block_result(101, vec![], vec![]),
        ];
        let outcome = process_batch_with_reorg_detection(
            &results, &mut state, None, 1000, 100,
        ).unwrap();
        match outcome {
            ScanBatchOutcome::Reorg(info) => {
                assert_eq!(info.split_height, 100);
            }
            _ => panic!("Expected Reorg"),
        }
    }
}
