use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::wallet_output::WalletOutput;

const CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE: u64 = 10;
const CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW: u64 = 60;

/// Pending spends expire after 2 hours if not confirmed.
pub const PENDING_SPEND_TTL_SECS: u64 = 7200;

/// Number of recent block hashes kept densely (every height).
const DENSE_HASH_WINDOW: u64 = 100;

/// Maximum reorg depth we'll handle. Deeper reorgs are treated as errors.
pub const MAX_REORG_DEPTH: u64 = 1000;

/// Balance breakdown for a wallet or account.
#[derive(Debug, Clone, Default)]
pub struct Balance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    /// Total amount of outputs that are pending-spent (broadcast but not yet confirmed).
    pub pending_spend: u64,
}

/// Transaction lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    Created,
    Broadcast,
    Confirmed { height: u64 },
}

/// Reference to a change output expected from a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeOutputRef {
    pub tx_hash: String,
    pub output_index: u8,
    pub amount: u64,
}

/// A pending spend: an output used in a broadcast-but-unconfirmed transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSpend {
    pub tx_id: String,
    pub key_image: String,
    pub output_key: String,
    pub amount: u64,
    pub created_at_secs: u64,
}

/// A tracked transaction through its lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedTransaction {
    pub tx_id: String,
    pub status: TxStatus,
    pub spent_key_images: Vec<String>,
    pub spent_output_keys: Vec<String>,
    pub change_outputs: Vec<ChangeOutputRef>,
    pub fee: u64,
    pub created_at_secs: u64,
}

/// Sparse chain of block hashes for fork-point detection.
///
/// Stores a compact set of block hashes: dense for recent blocks, exponentially
/// spaced for older ones. Mirrors wallet2's `get_short_chain_history()`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockHashChain {
    hashes: BTreeMap<u64, String>,
    genesis_hash: Option<String>,
}

impl BlockHashChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_block(&mut self, height: u64, hash: String) {
        if height == 0 {
            self.genesis_hash = Some(hash.clone());
        }
        self.hashes.insert(height, hash);
    }

    pub fn get_hash(&self, height: u64) -> Option<&str> {
        self.hashes.get(&height).map(|s| s.as_str())
    }

    pub fn tip_height(&self) -> Option<u64> {
        self.hashes.keys().next_back().copied()
    }

    /// Remove all hashes at heights >= split_height.
    pub fn rollback_to(&mut self, split_height: u64) {
        // BTreeMap::split_off returns everything >= key
        let removed = self.hashes.split_off(&split_height);
        // If genesis was in the removed range, keep it
        if let Some(genesis) = &self.genesis_hash {
            if removed.get(&0).map(|h| h == genesis).unwrap_or(false) {
                self.hashes.insert(0, genesis.clone());
            }
        }
    }

    /// Prune to keep last DENSE_HASH_WINDOW dense + exponential anchors + genesis.
    pub fn compact(&mut self) {
        let tip = match self.tip_height() {
            Some(t) => t,
            None => return,
        };

        let dense_start = tip.saturating_sub(DENSE_HASH_WINDOW - 1);
        let mut keep = HashSet::new();

        // Keep dense window
        for h in dense_start..=tip {
            keep.insert(h);
        }

        // Keep exponential anchors below dense window
        if dense_start > 0 {
            let mut step = 1u64;
            let mut h = dense_start - 1;
            loop {
                keep.insert(h);
                step *= 2;
                if h < step {
                    break;
                }
                h -= step;
            }
        }

        // Always keep genesis
        keep.insert(0);

        self.hashes.retain(|h, _| keep.contains(h));
    }

    /// Build block_ids list for `/getblocks.bin`, matching wallet2's algorithm.
    ///
    /// Returns (height, hash_hex) pairs ordered from highest to lowest.
    pub fn get_short_chain_history(&self) -> Vec<(u64, String)> {
        let tip = match self.tip_height() {
            Some(t) => t,
            None => {
                // Only genesis available
                if let Some(g) = &self.genesis_hash {
                    return vec![(0, g.clone())];
                }
                return vec![];
            }
        };

        let mut result = Vec::new();
        let mut current = tip;
        let mut step = 1u64;
        let mut count = 0u64;

        loop {
            if let Some(hash) = self.hashes.get(&current) {
                result.push((current, hash.clone()));
            }

            if current == 0 {
                break;
            }

            // First 10 are dense (step=1), then exponential
            count += 1;
            if count >= 10 {
                step *= 2;
            }

            if current < step {
                // Jump to genesis
                if current != 0 {
                    if let Some(hash) = self.hashes.get(&0).or(self.genesis_hash.as_ref()) {
                        result.push((0, hash.clone()));
                    }
                }
                break;
            }
            current -= step;
        }

        result
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

/// A conflict detected when a key image is spent at two different heights.
#[derive(Debug, Clone, PartialEq)]
pub struct SpentConflict {
    pub key_image: String,
    pub previous_spent_height: Option<u64>,
    pub new_height: u64,
}

/// Result of rolling back wallet state after a reorg.
#[derive(Debug, Clone)]
pub struct RollbackResult {
    pub removed_outputs: Vec<WalletOutput>,
    pub removed_key_images: Vec<String>,
    pub unspent_key_images: Vec<String>,
    pub outputs_unspent: usize,
}

/// Core wallet state manager.
///
/// Holds outputs, tracks heights, and provides balance/spendability queries.
/// This is the logic that was previously scattered across hub WalletActor
/// and Dart-side utils.
pub struct WalletState {
    outputs: Vec<WalletOutput>,
    /// Maps key_image -> index in outputs vec for O(1) lookups
    key_image_index: HashMap<String, usize>,
    pub current_height: u64,
    pub daemon_height: u64,
    pub block_hashes: BlockHashChain,
    /// Outputs used in broadcast-but-unconfirmed transactions (key_image -> PendingSpend).
    pending_spends: HashMap<String, PendingSpend>,
    /// Transaction lifecycle tracking (tx_id -> TrackedTransaction).
    tracked_transactions: HashMap<String, TrackedTransaction>,
    /// Maps key_image -> tx_hash of the transaction that spent it, for conflict dedup.
    spent_by_tx: HashMap<String, String>,
}

impl WalletState {
    pub fn new() -> Self {
        WalletState {
            outputs: Vec::new(),
            key_image_index: HashMap::new(),
            current_height: 0,
            daemon_height: 0,
            block_hashes: BlockHashChain::new(),
            pending_spends: HashMap::new(),
            tracked_transactions: HashMap::new(),
            spent_by_tx: HashMap::new(),
        }
    }

    /// Extend outputs (used when scanning finds new outputs).
    ///
    /// Deduplicates by key_image: if an output with the same key_image already
    /// exists, the new one is skipped ; unless the existing entry is unconfirmed
    /// (block_height == 0) and the new one is confirmed, in which case the
    /// existing entry is replaced (mempool-to-confirmed upgrade).
    pub fn add_outputs(&mut self, new_outputs: Vec<WalletOutput>) {
        for output in new_outputs {
            if output.block_height > self.current_height {
                self.current_height = output.block_height;
            }
            if let Some(&existing_idx) = self.key_image_index.get(&output.key_image) {
                // Replace unconfirmed with confirmed version
                if self.outputs[existing_idx].block_height == 0 && output.block_height > 0 {
                    self.outputs[existing_idx] = output;
                }
                // Otherwise skip duplicate
            } else {
                let idx = self.outputs.len();
                self.key_image_index.insert(output.key_image.clone(), idx);
                self.outputs.push(output);
            }
        }
    }

    /// Replace all outputs (used when restoring from persistence).
    pub fn replace_outputs(&mut self, outputs: Vec<WalletOutput>) {
        self.outputs = outputs;
        self.rebuild_key_image_index();
        self.spent_by_tx.clear();
    }

    /// Mark outputs as spent by matching key images.
    /// Returns the number of outputs newly marked as spent.
    pub fn mark_spent_by_key_images(&mut self, key_images: &[String]) -> usize {
        let mut count = 0;
        for ki in key_images {
            if let Some(&idx) = self.key_image_index.get(ki) {
                if !self.outputs[idx].spent {
                    self.outputs[idx].spent = true;
                    count += 1;
                }
            }
        }
        count
    }

    /// Mark outputs as spent by output keys ("txHash:outputIndex" format).
    /// Returns the number of outputs newly marked as spent.
    pub fn mark_spent_by_output_keys(&mut self, output_keys: &[String]) -> usize {
        let key_set: HashSet<&str> = output_keys.iter().map(|s| s.as_str()).collect();
        let mut count = 0;
        for output in &mut self.outputs {
            if !output.spent {
                let key = output.output_key();
                if key_set.contains(key.as_str()) {
                    output.spent = true;
                    count += 1;
                }
            }
        }
        count
    }

    /// Calculate balance using current_height for confirmation depth.
    pub fn balance(&self) -> Balance {
        self.balance_at_height(self.current_height)
    }

    /// Calculate balance at a specific height.
    pub fn balance_at_height(&self, height: u64) -> Balance {
        let mut bal = Balance::default();
        for output in &self.outputs {
            if output.spent {
                continue;
            }
            if self.pending_spends.contains_key(&output.key_image) {
                bal.pending_spend += output.amount;
                continue;
            }
            let confirmations = height.saturating_sub(output.block_height);
            let required = if output.is_coinbase {
                CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
            } else {
                CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
            };
            if confirmations >= required {
                bal.confirmed += output.amount;
            } else {
                bal.unconfirmed += output.amount;
            }
        }
        bal
    }

    /// Get all spendable (confirmed, unspent) outputs.
    pub fn spendable_outputs(&self) -> Vec<&WalletOutput> {
        self.spendable_outputs_at_height(self.daemon_height)
    }

    /// Get spendable outputs at a specific height.
    pub fn spendable_outputs_at_height(&self, height: u64) -> Vec<&WalletOutput> {
        self.outputs
            .iter()
            .filter(|o| {
                !o.spent
                    && !o.frozen
                    && !self.pending_spends.contains_key(&o.key_image)
                    && is_spendable(o, height)
            })
            .collect()
    }

    /// Get spendable outputs filtered to specific accounts.
    pub fn spendable_outputs_for_accounts(&self, accounts: &[u32]) -> Vec<&WalletOutput> {
        self.spendable_outputs()
            .into_iter()
            .filter(|o| {
                let account = o.subaddress_index.map(|(a, _)| a).unwrap_or(0);
                accounts.contains(&account)
            })
            .collect()
    }

    /// Get all outputs (including spent).
    pub fn outputs(&self) -> &[WalletOutput] {
        &self.outputs
    }

    /// Get mutable access to outputs.
    pub fn outputs_mut(&mut self) -> &mut Vec<WalletOutput> {
        &mut self.outputs
    }

    /// Mark outputs as spent, recording the height at which the spend occurred.
    /// Returns the number of outputs newly marked as spent.
    pub fn mark_spent_by_key_images_at_height(&mut self, key_images: &[String], height: u64) -> usize {
        let mut count = 0;
        for ki in key_images {
            if let Some(&idx) = self.key_image_index.get(ki) {
                if !self.outputs[idx].spent {
                    self.outputs[idx].spent = true;
                    self.outputs[idx].spent_height = Some(height);
                    count += 1;
                }
            }
        }
        count
    }

    /// Like `mark_spent_by_key_images_at_height` but also detects conflicts:
    /// an output spent by a *different transaction*.
    ///
    /// `tx_hashes` is parallel to `key_images` ; the tx that contains each key
    /// image.  When a tx hash is known and matches the previously recorded
    /// spending tx, the spend is treated as identical (rescan) regardless of
    /// height.  A conflict is only raised when the spending tx differs.
    ///
    /// Not a conflict: broadcast-marked (`spent_height: None`) confirmed at any
    /// height, or same spending transaction (idempotent rescan).
    ///
    /// Returns (newly_spent_count, conflicts).
    pub fn mark_spent_detecting_conflicts(
        &mut self,
        key_images: &[String],
        tx_hashes: &[String],
        height: u64,
    ) -> (usize, Vec<SpentConflict>) {
        let mut count = 0;
        let mut conflicts = Vec::new();
        for (i, ki) in key_images.iter().enumerate() {
            let tx_hash = tx_hashes.get(i).map(|s| s.as_str()).unwrap_or("");
            if let Some(&idx) = self.key_image_index.get(ki) {
                let output = &mut self.outputs[idx];
                if !output.spent {
                    output.spent = true;
                    output.spent_height = Some(height);
                    if !tx_hash.is_empty() {
                        self.spent_by_tx.insert(ki.clone(), tx_hash.to_string());
                    }
                    count += 1;
                } else if let Some(prev_h) = output.spent_height {
                    // Check if same spending transaction (rescan)
                    let same_tx = !tx_hash.is_empty()
                        && self.spent_by_tx.get(ki).map_or(false, |prev| prev == tx_hash);
                    if same_tx {
                        // Idempotent rescan ; update height to latest observation
                        output.spent_height = Some(height);
                    } else if prev_h != height {
                        // Different tx or unknown tx at different height -> conflict
                        conflicts.push(SpentConflict {
                            key_image: ki.clone(),
                            previous_spent_height: Some(prev_h),
                            new_height: height,
                        });
                        // Update the recorded spending tx if we now know it
                        if !tx_hash.is_empty() {
                            self.spent_by_tx.insert(ki.clone(), tx_hash.to_string());
                        }
                    }
                    // Same height, unknown tx = idempotent, no conflict
                } else {
                    // spent_height: None = broadcast-marked, now confirmed on-chain
                    output.spent_height = Some(height);
                    if !tx_hash.is_empty() {
                        self.spent_by_tx.insert(ki.clone(), tx_hash.to_string());
                    }
                }
            }
        }
        (count, conflicts)
    }

    /// Read-only check: find conflicts where mempool key images match
    /// outputs already confirmed-spent at some height.
    pub fn check_spent_conflicts(&self, key_images: &[String]) -> Vec<SpentConflict> {
        let mut conflicts = Vec::new();
        for ki in key_images {
            if let Some(&idx) = self.key_image_index.get(ki) {
                let output = &self.outputs[idx];
                if output.spent {
                    if let Some(prev_h) = output.spent_height {
                        conflicts.push(SpentConflict {
                            key_image: ki.clone(),
                            previous_spent_height: Some(prev_h),
                            new_height: 0, // 0 = mempool sentinel
                        });
                    }
                }
            }
        }
        conflicts
    }

    /// Roll back wallet state to just before `split_height`.
    ///
    /// 1. Un-spend outputs with spent_height >= split_height
    /// 2. Remove outputs with block_height >= split_height
    /// 3. Rebuild key_image_index
    /// 4. Roll back block_hashes
    /// 5. Update current_height
    pub fn rollback_to_height(&mut self, split_height: u64) -> RollbackResult {
        let mut unspent_key_images = Vec::new();
        let mut outputs_unspent = 0usize;

        // Un-spend outputs whose spend was in the reorged range
        for output in &mut self.outputs {
            if output.spent {
                if let Some(sh) = output.spent_height {
                    if sh >= split_height {
                        output.spent = false;
                        output.spent_height = None;
                        unspent_key_images.push(output.key_image.clone());
                        outputs_unspent += 1;
                    }
                }
                // Outputs with spent_height: None are NOT reverted (conservative)
            }
        }

        // Remove outputs received in the reorged range
        let mut removed_outputs = Vec::new();
        let mut removed_key_images = Vec::new();
        let mut kept = Vec::new();
        for output in self.outputs.drain(..) {
            if output.block_height >= split_height {
                removed_key_images.push(output.key_image.clone());
                removed_outputs.push(output);
            } else {
                kept.push(output);
            }
        }
        self.outputs = kept;

        self.rebuild_key_image_index();
        self.block_hashes.rollback_to(split_height);

        // Clear pending spends and spending-tx records for removed/unspent key images
        for ki in removed_key_images.iter().chain(unspent_key_images.iter()) {
            self.pending_spends.remove(ki);
            self.spent_by_tx.remove(ki);
        }

        if split_height > 0 {
            self.current_height = split_height - 1;
        } else {
            self.current_height = 0;
        }

        RollbackResult {
            removed_outputs,
            removed_key_images,
            unspent_key_images,
            outputs_unspent,
        }
    }

    pub fn record_block_hash(&mut self, height: u64, hash: String) {
        self.block_hashes.record_block(height, hash);
    }

    pub fn get_short_chain_history(&self) -> Vec<(u64, String)> {
        self.block_hashes.get_short_chain_history()
    }

    /// Freeze an output by key image, preventing it from being selected for spending.
    /// Returns true if the output was found and frozen.
    pub fn freeze_output(&mut self, key_image: &str) -> bool {
        if let Some(&idx) = self.key_image_index.get(key_image) {
            self.outputs[idx].frozen = true;
            true
        } else {
            false
        }
    }

    /// Thaw (unfreeze) an output by key image, allowing it to be selected for spending.
    /// Returns true if the output was found and thawed.
    pub fn thaw_output(&mut self, key_image: &str) -> bool {
        if let Some(&idx) = self.key_image_index.get(key_image) {
            self.outputs[idx].frozen = false;
            true
        } else {
            false
        }
    }

    // ---- Pending spend management ----

    /// Add pending spends for a broadcast transaction.
    pub fn add_pending_spends(&mut self, tx_id: &str, spends: Vec<PendingSpend>) {
        for spend in spends {
            self.pending_spends.insert(spend.key_image.clone(), spend);
        }
        // Advance tracked tx to Broadcast if it exists
        if let Some(tx) = self.tracked_transactions.get_mut(tx_id) {
            if tx.status == TxStatus::Created {
                tx.status = TxStatus::Broadcast;
            }
        }
    }

    /// Confirm a pending spend: remove it from pending and mark the output as spent.
    /// Returns true if the key image was pending.
    pub fn confirm_pending_spend(&mut self, key_image: &str, height: u64) -> bool {
        if self.pending_spends.remove(key_image).is_some() {
            if let Some(&idx) = self.key_image_index.get(key_image) {
                if !self.outputs[idx].spent {
                    self.outputs[idx].spent = true;
                    self.outputs[idx].spent_height = Some(height);
                }
            }
            true
        } else {
            false
        }
    }

    /// Remove expired pending spends (older than PENDING_SPEND_TTL_SECS).
    /// Returns the tx_ids of transactions whose pending spends were all cleaned up.
    pub fn cleanup_expired_pending_spends(&mut self, now_secs: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .pending_spends
            .iter()
            .filter(|(_, ps)| now_secs.saturating_sub(ps.created_at_secs) >= PENDING_SPEND_TTL_SECS)
            .map(|(ki, _)| ki.clone())
            .collect();

        let mut affected_txs: HashSet<String> = HashSet::new();
        for ki in &expired {
            if let Some(ps) = self.pending_spends.remove(ki) {
                affected_txs.insert(ps.tx_id.clone());
            }
        }

        // Return tx_ids where ALL pending spends are now gone
        affected_txs
            .into_iter()
            .filter(|tx_id| !self.pending_spends.values().any(|ps| &ps.tx_id == tx_id))
            .collect()
    }

    /// Check if an output is pending-spent.
    pub fn is_pending_spent(&self, key_image: &str) -> bool {
        self.pending_spends.contains_key(key_image)
    }

    /// Get all pending spends.
    pub fn pending_spends(&self) -> &HashMap<String, PendingSpend> {
        &self.pending_spends
    }

    /// Get pending spends for a specific transaction.
    pub fn pending_spends_for_tx(&self, tx_id: &str) -> Vec<&PendingSpend> {
        self.pending_spends
            .values()
            .filter(|ps| ps.tx_id == tx_id)
            .collect()
    }

    /// Collect all pending key images into a HashSet (for passing to coin selection).
    pub fn pending_key_images(&self) -> HashSet<String> {
        self.pending_spends.keys().cloned().collect()
    }

    // ---- Tracked transaction management ----

    /// Track a new transaction.
    pub fn track_transaction(&mut self, tx: TrackedTransaction) {
        self.tracked_transactions.insert(tx.tx_id.clone(), tx);
    }

    /// Advance a tracked transaction's status.
    /// Returns the new status if the transaction exists.
    pub fn advance_tx_status(&mut self, tx_id: &str, new_status: TxStatus) -> Option<&TxStatus> {
        if let Some(tx) = self.tracked_transactions.get_mut(tx_id) {
            tx.status = new_status;
            Some(&tx.status)
        } else {
            None
        }
    }

    /// Get a tracked transaction by ID.
    pub fn get_tracked_tx(&self, tx_id: &str) -> Option<&TrackedTransaction> {
        self.tracked_transactions.get(tx_id)
    }

    /// Get all tracked transactions.
    pub fn tracked_transactions(&self) -> &HashMap<String, TrackedTransaction> {
        &self.tracked_transactions
    }

    /// Find a tracked transaction by one of its spent key images.
    pub fn find_tx_by_key_image(&self, key_image: &str) -> Option<&TrackedTransaction> {
        self.tracked_transactions
            .values()
            .find(|tx| tx.spent_key_images.iter().any(|ki| ki == key_image))
    }

    /// Restore pending spends from persistence, filtering out expired entries.
    pub fn restore_pending_spends(&mut self, spends: HashMap<String, PendingSpend>, now_secs: u64) {
        for (ki, ps) in spends {
            if now_secs.saturating_sub(ps.created_at_secs) < PENDING_SPEND_TTL_SECS {
                self.pending_spends.insert(ki, ps);
            }
        }
    }

    /// Restore tracked transactions from persistence.
    ///
    /// Also rebuilds `spent_by_tx` from confirmed transactions so that
    /// subsequent rescans can identify idempotent key-image observations.
    pub fn restore_tracked_transactions(&mut self, txs: HashMap<String, TrackedTransaction>) {
        for (id, tx) in txs {
            if matches!(tx.status, TxStatus::Confirmed { .. } | TxStatus::Broadcast) {
                for ki in &tx.spent_key_images {
                    self.spent_by_tx.insert(ki.clone(), tx.tx_id.clone());
                }
            }
            self.tracked_transactions.insert(id, tx);
        }
    }

    /// Remove tracked transactions older than `max_age_secs` that are already confirmed.
    pub fn cleanup_old_tracked_txs(&mut self, now_secs: u64, max_age_secs: u64) -> usize {
        let before = self.tracked_transactions.len();
        self.tracked_transactions.retain(|_, tx| {
            if matches!(tx.status, TxStatus::Confirmed { .. }) {
                now_secs.saturating_sub(tx.created_at_secs) < max_age_secs
            } else {
                true
            }
        });
        before - self.tracked_transactions.len()
    }

    fn rebuild_key_image_index(&mut self) {
        self.key_image_index.clear();
        for (i, output) in self.outputs.iter().enumerate() {
            self.key_image_index
                .insert(output.key_image.clone(), i);
        }
    }
}

pub fn is_spendable(output: &WalletOutput, height: u64) -> bool {
    let confirmations = height.saturating_sub(output.block_height);
    let required = if output.is_coinbase {
        CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
    } else {
        CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
    };
    confirmations >= required
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_output(amount: u64, height: u64, key_image: &str) -> WalletOutput {
        WalletOutput {
            tx_hash: format!("tx_{}", key_image),
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
            key_image: key_image.into(),
            is_coinbase: false,
            frozen: false,
        }
    }

    fn make_coinbase_output(amount: u64, height: u64, key_image: &str) -> WalletOutput {
        let mut o = make_output(amount, height, key_image);
        o.is_coinbase = true;
        o
    }

    fn make_account_output(
        amount: u64,
        height: u64,
        key_image: &str,
        account: u32,
    ) -> WalletOutput {
        let mut o = make_output(amount, height, key_image);
        o.subaddress_index = Some((account, 0));
        o
    }

    // ---- Balance tests ----

    #[test]
    fn test_empty_state_zero_balance() {
        let state = WalletState::new();
        let bal = state.balance();
        assert_eq!(bal.confirmed, 0);
        assert_eq!(bal.unconfirmed, 0);
    }

    #[test]
    fn test_confirmed_balance_after_10_blocks() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);
        state.current_height = 110;

        let bal = state.balance();
        assert_eq!(bal.confirmed, 1_000_000_000_000);
        assert_eq!(bal.unconfirmed, 0);
    }

    #[test]
    fn test_unconfirmed_balance_under_10_blocks() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);
        state.current_height = 105;

        let bal = state.balance();
        assert_eq!(bal.confirmed, 0);
        assert_eq!(bal.unconfirmed, 1_000_000_000_000);
    }

    #[test]
    fn test_coinbase_needs_60_confirmations() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_coinbase_output(5_000_000_000_000, 100, "ki1")]);

        // At 50 confirmations: still unconfirmed
        state.current_height = 150;
        let bal = state.balance();
        assert_eq!(bal.confirmed, 0);
        assert_eq!(bal.unconfirmed, 5_000_000_000_000);

        // At 60 confirmations: confirmed
        state.current_height = 160;
        let bal = state.balance();
        assert_eq!(bal.confirmed, 5_000_000_000_000);
        assert_eq!(bal.unconfirmed, 0);
    }

    #[test]
    fn test_spent_outputs_excluded_from_balance() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 100, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
        ]);
        state.current_height = 200;

        // Mark one as spent
        state.mark_spent_by_key_images(&["ki1".to_string()]);

        let bal = state.balance();
        assert_eq!(bal.confirmed, 2_000_000_000_000);
    }

    #[test]
    fn test_mixed_confirmed_and_unconfirmed() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),  // 20 confs -> confirmed
            make_output(2_000_000_000_000, 95, "ki2"),  // 5 confs -> unconfirmed
        ]);
        state.current_height = 100;

        let bal = state.balance();
        assert_eq!(bal.confirmed, 1_000_000_000_000);
        assert_eq!(bal.unconfirmed, 2_000_000_000_000);
    }

    // ---- Spent marking tests ----

    #[test]
    fn test_mark_spent_by_key_images() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 100, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
            make_output(3_000_000_000_000, 100, "ki3"),
        ]);

        let count = state.mark_spent_by_key_images(&["ki2".to_string()]);
        assert_eq!(count, 1);
        assert!(!state.outputs[0].spent);
        assert!(state.outputs[1].spent);
        assert!(!state.outputs[2].spent);
    }

    #[test]
    fn test_mark_spent_duplicate_key_images() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);

        let count1 = state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert_eq!(count1, 1);

        // Marking again should return 0 (already spent)
        let count2 = state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_mark_spent_unknown_key_images() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);

        let count = state.mark_spent_by_key_images(&["unknown_ki".to_string()]);
        assert_eq!(count, 0);
        assert!(!state.outputs[0].spent);
    }

    #[test]
    fn test_mark_spent_by_output_keys() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 100, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
        ]);

        let count = state.mark_spent_by_output_keys(&["tx_ki1:0".to_string()]);
        assert_eq!(count, 1);
        assert!(state.outputs[0].spent);
        assert!(!state.outputs[1].spent);
    }

    // ---- add_outputs vs replace_outputs ----

    #[test]
    fn test_add_outputs_extends() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);
        assert_eq!(state.outputs().len(), 1);

        state.add_outputs(vec![make_output(2_000_000_000_000, 101, "ki2")]);
        assert_eq!(state.outputs().len(), 2);
    }

    #[test]
    fn test_replace_outputs_replaces() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 100, "ki1"),
            make_output(2_000_000_000_000, 101, "ki2"),
        ]);
        assert_eq!(state.outputs().len(), 2);

        state.replace_outputs(vec![make_output(3_000_000_000_000, 200, "ki3")]);
        assert_eq!(state.outputs().len(), 1);
        assert_eq!(state.outputs()[0].key_image, "ki3");
    }

    #[test]
    fn test_replace_rebuilds_key_image_index() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);

        state.replace_outputs(vec![make_output(2_000_000_000_000, 200, "ki2")]);

        // Old key image should not match
        let count = state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert_eq!(count, 0);

        // New key image should match
        let count = state.mark_spent_by_key_images(&["ki2".to_string()]);
        assert_eq!(count, 1);
    }

    // ---- Spendable output queries ----

    #[test]
    fn test_spendable_outputs() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),  // spendable at height 100
            make_output(2_000_000_000_000, 95, "ki2"),  // not spendable (5 confs)
        ]);
        state.daemon_height = 100;

        let spendable = state.spendable_outputs();
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].key_image, "ki1");
    }

    #[test]
    fn test_spendable_excludes_spent() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),
            make_output(2_000_000_000_000, 80, "ki2"),
        ]);
        state.daemon_height = 100;
        state.mark_spent_by_key_images(&["ki1".to_string()]);

        let spendable = state.spendable_outputs();
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].key_image, "ki2");
    }

    #[test]
    fn test_spendable_outputs_for_accounts() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_account_output(1_000_000_000_000, 80, "ki1", 0),
            make_account_output(2_000_000_000_000, 80, "ki2", 1),
            make_account_output(3_000_000_000_000, 80, "ki3", 2),
        ]);
        state.daemon_height = 100;

        let spendable = state.spendable_outputs_for_accounts(&[0, 2]);
        assert_eq!(spendable.len(), 2);
        let ki: Vec<&str> = spendable.iter().map(|o| o.key_image.as_str()).collect();
        assert!(ki.contains(&"ki1"));
        assert!(ki.contains(&"ki3"));
    }

    // ---- Height tracking ----

    #[test]
    fn test_add_outputs_updates_current_height() {
        let mut state = WalletState::new();
        assert_eq!(state.current_height, 0);

        state.add_outputs(vec![make_output(1_000_000_000_000, 500, "ki1")]);
        assert_eq!(state.current_height, 500);

        state.add_outputs(vec![make_output(1_000_000_000_000, 300, "ki2")]);
        // Should not decrease
        assert_eq!(state.current_height, 500);

        state.add_outputs(vec![make_output(1_000_000_000_000, 600, "ki3")]);
        assert_eq!(state.current_height, 600);
    }

    // ---- Deduplication tests ----

    #[test]
    fn test_add_outputs_deduplicates_by_key_image() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]); // duplicate
        assert_eq!(state.outputs().len(), 1);

        state.current_height = 200;
        let bal = state.balance();
        assert_eq!(bal.confirmed, 1_000_000_000_000); // not double-counted
    }

    #[test]
    fn test_add_outputs_upgrades_mempool_to_confirmed() {
        let mut state = WalletState::new();
        // Add mempool output (height 0)
        let mut mempool_output = make_output(1_000_000_000_000, 0, "ki1");
        mempool_output.block_height = 0;
        state.add_outputs(vec![mempool_output]);
        assert_eq!(state.outputs()[0].block_height, 0);

        // Add confirmed version
        state.add_outputs(vec![make_output(1_000_000_000_000, 500, "ki1")]);
        assert_eq!(state.outputs().len(), 1); // still only 1 output
        assert_eq!(state.outputs()[0].block_height, 500); // upgraded to confirmed
    }

    #[test]
    fn test_spendability_boundary_exact() {
        // daemon_height = block count = top_block_height + 1.
        // Rust formula: confirmations = daemon_height - block_height.
        // At the exact boundary (10 confs required for normal outputs):
        let output = make_output(1_000_000_000_000, 100, "ki1");

        // daemon_height 109: 109 - 100 = 9 confirmations -> NOT spendable
        assert!(!is_spendable(&output, 109));

        // daemon_height 110: 110 - 100 = 10 confirmations -> spendable
        assert!(is_spendable(&output, 110));
    }

    #[test]
    fn test_coinbase_spendability_boundary_exact() {
        let output = make_coinbase_output(5_000_000_000_000, 100, "ki1");

        // daemon_height 159: 159 - 100 = 59 confirmations -> NOT spendable
        assert!(!is_spendable(&output, 159));

        // daemon_height 160: 160 - 100 = 60 confirmations -> spendable
        assert!(is_spendable(&output, 160));
    }

    #[test]
    fn test_add_outputs_skips_confirmed_duplicate() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 100, "ki1")]);
        state.add_outputs(vec![make_output(2_000_000_000_000, 200, "ki1")]); // different amount, same ki
        assert_eq!(state.outputs().len(), 1);
        assert_eq!(state.outputs()[0].block_height, 100); // original kept
        assert_eq!(state.outputs()[0].amount, 1_000_000_000_000); // original amount
    }

    // ---- BlockHashChain tests ----

    #[test]
    fn test_block_hash_chain_basics() {
        let mut chain = BlockHashChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.tip_height(), None);

        chain.record_block(100, "hash100".into());
        chain.record_block(101, "hash101".into());
        chain.record_block(102, "hash102".into());

        assert_eq!(chain.len(), 3);
        assert_eq!(chain.tip_height(), Some(102));
        assert_eq!(chain.get_hash(100), Some("hash100"));
        assert_eq!(chain.get_hash(101), Some("hash101"));
        assert_eq!(chain.get_hash(99), None);
    }

    #[test]
    fn test_block_hash_chain_rollback() {
        let mut chain = BlockHashChain::new();
        for h in 90..=100 {
            chain.record_block(h, format!("hash_{}", h));
        }
        assert_eq!(chain.tip_height(), Some(100));

        chain.rollback_to(98);
        assert_eq!(chain.tip_height(), Some(97));
        assert!(chain.get_hash(98).is_none());
        assert!(chain.get_hash(99).is_none());
        assert!(chain.get_hash(100).is_none());
        assert_eq!(chain.get_hash(97), Some("hash_97"));
    }

    #[test]
    fn test_block_hash_chain_rollback_preserves_genesis() {
        let mut chain = BlockHashChain::new();
        chain.record_block(0, "genesis".into());
        chain.record_block(1, "hash1".into());
        chain.record_block(2, "hash2".into());

        chain.rollback_to(1);
        assert_eq!(chain.get_hash(0), Some("genesis"));
        assert!(chain.get_hash(1).is_none());
    }

    #[test]
    fn test_short_chain_history_dense() {
        let mut chain = BlockHashChain::new();
        for h in 0..=5 {
            chain.record_block(h, format!("hash_{}", h));
        }

        let history = chain.get_short_chain_history();
        assert!(!history.is_empty());
        assert_eq!(history[0].0, 5);
        assert_eq!(history.last().unwrap().0, 0);
    }

    #[test]
    fn test_short_chain_history_exponential_spacing() {
        let mut chain = BlockHashChain::new();
        for h in 0..=200 {
            chain.record_block(h, format!("hash_{}", h));
        }

        let history = chain.get_short_chain_history();
        assert_eq!(history[0].0, 200);
        assert!(history.len() < 30);
        assert_eq!(history.last().unwrap().0, 0);
        for i in 0..10 {
            assert_eq!(history[i].0, 200 - i as u64);
        }
    }

    #[test]
    fn test_short_chain_history_empty() {
        let chain = BlockHashChain::new();
        let history = chain.get_short_chain_history();
        assert!(history.is_empty());
    }

    #[test]
    fn test_short_chain_history_genesis_only() {
        let mut chain = BlockHashChain::new();
        chain.record_block(0, "genesis".into());
        let history = chain.get_short_chain_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], (0, "genesis".into()));
    }

    // ---- mark_spent_by_key_images_at_height tests ----

    #[test]
    fn test_mark_spent_at_height() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 100, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
        ]);

        let count = state.mark_spent_by_key_images_at_height(&["ki1".to_string()], 150);
        assert_eq!(count, 1);
        assert!(state.outputs[0].spent);
        assert_eq!(state.outputs[0].spent_height, Some(150));
        assert!(!state.outputs[1].spent);
        assert_eq!(state.outputs[1].spent_height, None);
    }

    // ---- Rollback tests ----

    #[test]
    fn test_rollback_removes_outputs_at_and_above_split() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 90, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
            make_output(3_000_000_000_000, 110, "ki3"),
        ]);

        let result = state.rollback_to_height(100);
        assert_eq!(result.removed_outputs.len(), 2);
        assert_eq!(state.outputs().len(), 1);
        assert_eq!(state.outputs()[0].key_image, "ki1");
    }

    #[test]
    fn test_rollback_unspends_outputs_spent_in_reorg_range() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 60, "ki2"),
        ]);

        state.mark_spent_by_key_images_at_height(&["ki1".to_string()], 100);
        state.mark_spent_by_key_images_at_height(&["ki2".to_string()], 80);

        let result = state.rollback_to_height(90);
        assert_eq!(result.outputs_unspent, 1);
        assert_eq!(result.unspent_key_images, vec!["ki1".to_string()]);
        assert!(!state.outputs[0].spent);
        assert!(state.outputs[1].spent);
    }

    #[test]
    fn test_rollback_conservative_with_none_spent_height() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert_eq!(state.outputs[0].spent_height, None);

        let result = state.rollback_to_height(60);
        assert_eq!(result.outputs_unspent, 0);
        assert!(state.outputs[0].spent);
    }

    #[test]
    fn test_rollback_rebuilds_key_image_index() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
        ]);

        state.rollback_to_height(100);
        assert_eq!(state.outputs().len(), 1);

        let count = state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert_eq!(count, 1);
        let count = state.mark_spent_by_key_images(&["ki2".to_string()]);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_rollback_updates_current_height() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 200, "ki1")]);
        state.current_height = 200;

        state.rollback_to_height(150);
        assert_eq!(state.current_height, 149);
    }

    #[test]
    fn test_rollback_rolls_back_block_hashes() {
        let mut state = WalletState::new();
        for h in 90..=100 {
            state.record_block_hash(h, format!("hash_{}", h));
        }

        state.rollback_to_height(95);
        assert!(state.block_hashes.get_hash(95).is_none());
        assert_eq!(state.block_hashes.get_hash(94), Some("hash_94"));
    }

    #[test]
    fn test_rollback_below_all_outputs() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 100, "ki1"),
            make_output(2_000_000_000_000, 200, "ki2"),
        ]);

        let result = state.rollback_to_height(50);
        assert_eq!(result.removed_outputs.len(), 2);
        assert!(state.outputs().is_empty());
        assert_eq!(state.current_height, 49);
    }

    #[test]
    fn test_compact_keeps_dense_and_sparse() {
        let mut chain = BlockHashChain::new();
        for h in 0..=500 {
            chain.record_block(h, format!("hash_{}", h));
        }
        assert_eq!(chain.len(), 501);

        chain.compact();
        assert!(chain.len() < 150);
        assert_eq!(chain.get_hash(500), Some("hash_500"));
        assert_eq!(chain.get_hash(0), Some("hash_0"));
        assert_eq!(chain.get_hash(401), Some("hash_401"));
    }

    // ---- Complex rollback scenarios ----

    #[test]
    fn test_rollback_mixed_removals_and_unspends() {
        let mut state = WalletState::new();
        // Output below split: received early, spent in reorg range
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki_below")]);
        // Output at split: should be removed
        state.add_outputs(vec![make_output(2_000_000_000_000, 100, "ki_at")]);
        // Output above split: should be removed
        state.add_outputs(vec![make_output(3_000_000_000_000, 150, "ki_above")]);

        // Spend the below-split output at height 120 (in reorg range)
        state.mark_spent_by_key_images_at_height(&["ki_below".to_string()], 120);
        // Spend the at-split output at height 80 (below reorg range, stays spent)
        state.mark_spent_by_key_images_at_height(&["ki_at".to_string()], 80);

        let result = state.rollback_to_height(100);

        // ki_at and ki_above removed (block_height >= 100)
        assert_eq!(result.removed_outputs.len(), 2);
        // ki_below unspent (spent_height 120 >= 100), ki_at spent_height 80 < 100 not unspent
        assert_eq!(result.outputs_unspent, 1);
        assert_eq!(result.unspent_key_images, vec!["ki_below".to_string()]);

        // Only ki_below remains, now unspent
        assert_eq!(state.outputs().len(), 1);
        assert_eq!(state.outputs()[0].key_image, "ki_below");
        assert!(!state.outputs()[0].spent);
        assert_eq!(state.outputs()[0].spent_height, None);

        // Balance should reflect the unspent output
        state.current_height = 99;
        state.daemon_height = 200;
        let bal = state.balance_at_height(200);
        assert_eq!(bal.confirmed, 1_000_000_000_000);
    }

    #[test]
    fn test_rollback_multi_account_outputs() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_account_output(1_000_000_000_000, 50, "ki_a0", 0),
            make_account_output(2_000_000_000_000, 50, "ki_a1", 1),
            make_account_output(3_000_000_000_000, 100, "ki_a0_high", 0),
            make_account_output(4_000_000_000_000, 100, "ki_a2_high", 2),
        ]);

        let result = state.rollback_to_height(100);
        assert_eq!(result.removed_outputs.len(), 2);
        assert_eq!(state.outputs().len(), 2);

        // Remaining: account 0 and account 1 outputs below split
        let accounts: Vec<u32> = state.outputs().iter()
            .map(|o| o.subaddress_index.unwrap().0)
            .collect();
        assert!(accounts.contains(&0));
        assert!(accounts.contains(&1));
    }

    #[test]
    fn test_consecutive_rollbacks() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 80, "ki2"),
            make_output(3_000_000_000_000, 100, "ki3"),
            make_output(4_000_000_000_000, 120, "ki4"),
        ]);
        for h in 50..=120 {
            state.record_block_hash(h, format!("hash_{}", h));
        }

        // First rollback: remove ki4
        let r1 = state.rollback_to_height(110);
        assert_eq!(r1.removed_outputs.len(), 1);
        assert_eq!(state.outputs().len(), 3);
        assert_eq!(state.current_height, 109);

        // Second rollback: remove ki3
        let r2 = state.rollback_to_height(90);
        assert_eq!(r2.removed_outputs.len(), 1);
        assert_eq!(state.outputs().len(), 2);
        assert_eq!(state.current_height, 89);

        // Third rollback: remove ki2
        let r3 = state.rollback_to_height(60);
        assert_eq!(r3.removed_outputs.len(), 1);
        assert_eq!(state.outputs().len(), 1);
        assert_eq!(state.outputs()[0].key_image, "ki1");

        // Key image index still works
        let count = state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_rollback_then_add_new_outputs() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
        ]);

        state.rollback_to_height(100);
        assert_eq!(state.outputs().len(), 1);

        // Add new outputs from the new chain fork
        state.add_outputs(vec![
            make_output(5_000_000_000_000, 100, "ki_new"),
        ]);
        assert_eq!(state.outputs().len(), 2);
        assert_eq!(state.current_height, 100);

        // Both old (kept) and new outputs accessible via key image
        let c1 = state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert_eq!(c1, 1);
        let c2 = state.mark_spent_by_key_images(&["ki_new".to_string()]);
        assert_eq!(c2, 1);
    }

    #[test]
    fn test_compact_then_rollback() {
        let mut chain = BlockHashChain::new();
        for h in 0..=500 {
            chain.record_block(h, format!("hash_{}", h));
        }
        chain.compact();

        // Rollback into the dense window should work fine
        chain.rollback_to(450);
        assert!(chain.get_hash(449).is_some());
        assert!(chain.get_hash(450).is_none());
        assert!(chain.get_hash(500).is_none());
        // Genesis preserved
        assert_eq!(chain.get_hash(0), Some("hash_0"));
    }

    #[test]
    fn test_rollback_to_height_zero() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 0, "ki_genesis"),
            make_output(2_000_000_000_000, 50, "ki1"),
        ]);
        state.record_block_hash(0, "genesis".into());

        let result = state.rollback_to_height(0);
        assert_eq!(result.removed_outputs.len(), 2);
        assert!(state.outputs().is_empty());
        assert_eq!(state.current_height, 0);
    }

    #[test]
    fn test_rollback_preserves_spent_below_split() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 60, "ki2"),
        ]);

        // Spend ki1 at height 70, ki2 at height 80
        state.mark_spent_by_key_images_at_height(&["ki1".to_string()], 70);
        state.mark_spent_by_key_images_at_height(&["ki2".to_string()], 80);

        // Rollback to 90: both spends are below split, should stay spent
        let result = state.rollback_to_height(90);
        assert_eq!(result.outputs_unspent, 0);
        assert!(state.outputs()[0].spent);
        assert!(state.outputs()[1].spent);
    }

    // ---- Freeze/thaw tests ----

    #[test]
    fn test_frozen_output_excluded_from_spendable() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),
            make_output(2_000_000_000_000, 80, "ki2"),
        ]);
        state.daemon_height = 100;

        state.freeze_output("ki1");
        let spendable = state.spendable_outputs();
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].key_image, "ki2");
    }

    #[test]
    fn test_thaw_output_restores_spendability() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 80, "ki1")]);
        state.daemon_height = 100;

        state.freeze_output("ki1");
        assert_eq!(state.spendable_outputs().len(), 0);

        state.thaw_output("ki1");
        assert_eq!(state.spendable_outputs().len(), 1);
    }

    #[test]
    fn test_freeze_unknown_key_image() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 80, "ki1")]);
        assert!(!state.freeze_output("unknown"));
        assert!(!state.thaw_output("unknown"));
    }

    #[test]
    fn test_frozen_output_still_in_balance() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 80, "ki1")]);
        state.current_height = 100;

        state.freeze_output("ki1");
        let bal = state.balance();
        // Frozen outputs still count in balance, just not spendable
        assert_eq!(bal.confirmed, 1_000_000_000_000);
    }

    #[test]
    fn test_freeze_idempotent() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 80, "ki1")]);
        state.daemon_height = 100;

        assert!(state.freeze_output("ki1"));
        assert!(state.freeze_output("ki1")); // second freeze is fine
        assert_eq!(state.spendable_outputs().len(), 0);
        assert!(state.outputs()[0].frozen);
    }

    #[test]
    fn test_thaw_idempotent() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 80, "ki1")]);
        state.daemon_height = 100;

        // Thaw an already-thawed output
        assert!(state.thaw_output("ki1"));
        assert!(!state.outputs()[0].frozen);
        assert_eq!(state.spendable_outputs().len(), 1);
    }

    #[test]
    fn test_frozen_survives_rollback() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),
            make_output(2_000_000_000_000, 90, "ki2"),
        ]);
        state.daemon_height = 100;

        state.freeze_output("ki1");
        // Rollback to 95: output at height 80 survives, output at 90 survives
        state.rollback_to_height(95);
        // ki1 should still be frozen after rollback
        assert!(state.outputs().iter().find(|o| o.key_image == "ki1").unwrap().frozen);
        assert_eq!(state.spendable_outputs().len(), 1);
        assert_eq!(state.spendable_outputs()[0].key_image, "ki2");
    }

    #[test]
    fn test_frozen_excluded_from_account_spendable() {
        let mut state = WalletState::new();
        let mut o1 = make_output(1_000_000_000_000, 80, "ki1");
        o1.subaddress_index = Some((1, 0));
        let mut o2 = make_output(2_000_000_000_000, 80, "ki2");
        o2.subaddress_index = Some((1, 1));
        state.add_outputs(vec![o1, o2]);
        state.daemon_height = 100;

        state.freeze_output("ki1");
        let acct1 = state.spendable_outputs_for_accounts(&[1]);
        assert_eq!(acct1.len(), 1);
        assert_eq!(acct1[0].key_image, "ki2");
    }

    #[test]
    fn test_mark_spent_at_height_idempotent() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        let c1 = state.mark_spent_by_key_images_at_height(&["ki1".to_string()], 100);
        assert_eq!(c1, 1);
        assert_eq!(state.outputs()[0].spent_height, Some(100));

        // Marking again should return 0
        let c2 = state.mark_spent_by_key_images_at_height(&["ki1".to_string()], 200);
        assert_eq!(c2, 0);
        // Original spent_height preserved
        assert_eq!(state.outputs()[0].spent_height, Some(100));
    }

    // ---- Double-spend conflict detection tests ----

    #[test]
    fn test_conflict_different_tx() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        let (count, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 100,
        );
        assert_eq!(count, 1);
        assert!(conflicts.is_empty());

        // Same key image, different spending tx -> conflict
        let (count2, conflicts2) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_b".to_string()], 200,
        );
        assert_eq!(count2, 0);
        assert_eq!(conflicts2.len(), 1);
        assert_eq!(conflicts2[0], SpentConflict {
            key_image: "ki1".to_string(),
            previous_spent_height: Some(100),
            new_height: 200,
        });
    }

    #[test]
    fn test_no_conflict_same_tx_different_height() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        let (count, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 100,
        );
        assert_eq!(count, 1);
        assert!(conflicts.is_empty());

        // Same spending tx at different height (rescan with different batch boundary) -> no conflict
        let (count2, conflicts2) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 200,
        );
        assert_eq!(count2, 0);
        assert!(conflicts2.is_empty());
    }

    #[test]
    fn test_no_conflict_same_height() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        let (count, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 100,
        );
        assert_eq!(count, 1);
        assert!(conflicts.is_empty());

        // Same height = idempotent, no conflict (even with empty tx hash)
        let (count2, conflicts2) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &[], 100,
        );
        assert_eq!(count2, 0);
        assert!(conflicts2.is_empty());
    }

    #[test]
    fn test_no_conflict_broadcast_then_confirmed() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        // Mark spent without height (broadcast)
        state.mark_spent_by_key_images(&["ki1".to_string()]);
        assert!(state.outputs()[0].spent);
        assert_eq!(state.outputs()[0].spent_height, None);

        // Now confirmed at some height -> NOT a conflict, and updates spent_height
        let (count, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 150,
        );
        assert_eq!(count, 0);
        assert!(conflicts.is_empty());
        assert_eq!(state.outputs()[0].spent_height, Some(150));

        // Subsequent rescan with same tx at different height -> still no conflict
        let (count2, conflicts2) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 200,
        );
        assert_eq!(count2, 0);
        assert!(conflicts2.is_empty());
    }

    #[test]
    fn test_mempool_conflict_check() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 60, "ki2"),
        ]);

        // Confirm ki1 spent at height 100
        state.mark_spent_by_key_images_at_height(&["ki1".to_string()], 100);

        // Check mempool key images against confirmed spends
        let conflicts = state.check_spent_conflicts(&["ki1".to_string(), "ki2".to_string()]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0], SpentConflict {
            key_image: "ki1".to_string(),
            previous_spent_height: Some(100),
            new_height: 0,
        });
    }

    // ---- Pending spend tests ----

    fn make_pending_spend(tx_id: &str, key_image: &str, amount: u64, created_at: u64) -> PendingSpend {
        PendingSpend {
            tx_id: tx_id.to_string(),
            key_image: key_image.to_string(),
            output_key: format!("tx_{}:0", key_image),
            amount,
            created_at_secs: created_at,
        }
    }

    #[test]
    fn test_pending_spend_excludes_from_balance() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),
            make_output(2_000_000_000_000, 80, "ki2"),
        ]);
        state.current_height = 200;

        state.add_pending_spends("tx_abc", vec![
            make_pending_spend("tx_abc", "ki1", 1_000_000_000_000, 1000),
        ]);

        let bal = state.balance();
        assert_eq!(bal.confirmed, 2_000_000_000_000);
        assert_eq!(bal.pending_spend, 1_000_000_000_000);
    }

    #[test]
    fn test_pending_spend_excludes_from_spendable() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),
            make_output(2_000_000_000_000, 80, "ki2"),
        ]);
        state.daemon_height = 200;

        state.add_pending_spends("tx_abc", vec![
            make_pending_spend("tx_abc", "ki1", 1_000_000_000_000, 1000),
        ]);

        let spendable = state.spendable_outputs();
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].key_image, "ki2");
    }

    #[test]
    fn test_confirm_pending_spend() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),
        ]);
        state.current_height = 200;

        state.add_pending_spends("tx_abc", vec![
            make_pending_spend("tx_abc", "ki1", 1_000_000_000_000, 1000),
        ]);
        assert!(state.is_pending_spent("ki1"));

        let confirmed = state.confirm_pending_spend("ki1", 150);
        assert!(confirmed);
        assert!(!state.is_pending_spent("ki1"));
        assert!(state.outputs()[0].spent);
        assert_eq!(state.outputs()[0].spent_height, Some(150));
    }

    #[test]
    fn test_confirm_pending_spend_unknown() {
        let mut state = WalletState::new();
        assert!(!state.confirm_pending_spend("unknown", 100));
    }

    #[test]
    fn test_cleanup_expired_pending_spends() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 80, "ki1"),
            make_output(2_000_000_000_000, 80, "ki2"),
        ]);

        state.add_pending_spends("tx_old", vec![
            make_pending_spend("tx_old", "ki1", 1_000_000_000_000, 1000),
        ]);
        state.add_pending_spends("tx_new", vec![
            make_pending_spend("tx_new", "ki2", 2_000_000_000_000, 5000),
        ]);

        // now=8200: tx_old expired (1000 + 7200 = 8200), tx_new not (5000 + 7200 = 12200)
        let cleaned = state.cleanup_expired_pending_spends(8200);
        assert_eq!(cleaned.len(), 1);
        assert!(cleaned.contains(&"tx_old".to_string()));
        assert!(!state.is_pending_spent("ki1"));
        assert!(state.is_pending_spent("ki2"));
    }

    #[test]
    fn test_pending_spends_for_tx() {
        let mut state = WalletState::new();
        state.add_pending_spends("tx1", vec![
            make_pending_spend("tx1", "ki_a", 100, 1000),
            make_pending_spend("tx1", "ki_b", 200, 1000),
        ]);
        state.add_pending_spends("tx2", vec![
            make_pending_spend("tx2", "ki_c", 300, 1000),
        ]);

        let tx1_spends = state.pending_spends_for_tx("tx1");
        assert_eq!(tx1_spends.len(), 2);
        let tx2_spends = state.pending_spends_for_tx("tx2");
        assert_eq!(tx2_spends.len(), 1);
    }

    #[test]
    fn test_pending_key_images() {
        let mut state = WalletState::new();
        state.add_pending_spends("tx1", vec![
            make_pending_spend("tx1", "ki_a", 100, 1000),
            make_pending_spend("tx1", "ki_b", 200, 1000),
        ]);

        let ki = state.pending_key_images();
        assert_eq!(ki.len(), 2);
        assert!(ki.contains("ki_a"));
        assert!(ki.contains("ki_b"));
    }

    #[test]
    fn test_rollback_clears_pending_spends_for_removed_outputs() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 100, "ki2"),
        ]);
        state.add_pending_spends("tx_abc", vec![
            make_pending_spend("tx_abc", "ki2", 2_000_000_000_000, 1000),
        ]);

        state.rollback_to_height(80);
        // ki2 was removed (block_height 100 >= 80), so its pending spend should be cleared
        assert!(!state.is_pending_spent("ki2"));
    }

    // ---- Tracked transaction tests ----

    #[test]
    fn test_track_and_advance_transaction() {
        let mut state = WalletState::new();
        state.track_transaction(TrackedTransaction {
            tx_id: "tx1".into(),
            status: TxStatus::Created,
            spent_key_images: vec!["ki1".into()],
            spent_output_keys: vec!["tx_ki1:0".into()],
            change_outputs: vec![],
            fee: 50_000_000,
            created_at_secs: 1000,
        });

        assert_eq!(state.get_tracked_tx("tx1").unwrap().status, TxStatus::Created);

        state.advance_tx_status("tx1", TxStatus::Broadcast);
        assert_eq!(state.get_tracked_tx("tx1").unwrap().status, TxStatus::Broadcast);

        state.advance_tx_status("tx1", TxStatus::Confirmed { height: 500 });
        assert_eq!(
            state.get_tracked_tx("tx1").unwrap().status,
            TxStatus::Confirmed { height: 500 }
        );
    }

    #[test]
    fn test_find_tx_by_key_image() {
        let mut state = WalletState::new();
        state.track_transaction(TrackedTransaction {
            tx_id: "tx1".into(),
            status: TxStatus::Broadcast,
            spent_key_images: vec!["ki_a".into(), "ki_b".into()],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 1000,
        });

        assert_eq!(state.find_tx_by_key_image("ki_a").unwrap().tx_id, "tx1");
        assert_eq!(state.find_tx_by_key_image("ki_b").unwrap().tx_id, "tx1");
        assert!(state.find_tx_by_key_image("ki_c").is_none());
    }

    #[test]
    fn test_cleanup_old_tracked_txs() {
        let mut state = WalletState::new();
        state.track_transaction(TrackedTransaction {
            tx_id: "old_confirmed".into(),
            status: TxStatus::Confirmed { height: 100 },
            spent_key_images: vec![],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 1000,
        });
        state.track_transaction(TrackedTransaction {
            tx_id: "recent_confirmed".into(),
            status: TxStatus::Confirmed { height: 200 },
            spent_key_images: vec![],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 5000,
        });
        state.track_transaction(TrackedTransaction {
            tx_id: "broadcast".into(),
            status: TxStatus::Broadcast,
            spent_key_images: vec![],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 1000,
        });

        // max_age=3600, now=6000: old_confirmed (age 5000) removed, recent_confirmed (age 1000) kept
        let removed = state.cleanup_old_tracked_txs(6000, 3600);
        assert_eq!(removed, 1);
        assert!(state.get_tracked_tx("old_confirmed").is_none());
        assert!(state.get_tracked_tx("recent_confirmed").is_some());
        assert!(state.get_tracked_tx("broadcast").is_some()); // non-confirmed kept regardless
    }

    #[test]
    fn test_restore_pending_spends_filters_expired() {
        let mut state = WalletState::new();
        let mut spends = HashMap::new();
        spends.insert("ki_fresh".to_string(), PendingSpend {
            tx_id: "tx1".into(),
            key_image: "ki_fresh".into(),
            output_key: "ok1".into(),
            amount: 100,
            created_at_secs: 5000,
        });
        spends.insert("ki_expired".to_string(), PendingSpend {
            tx_id: "tx2".into(),
            key_image: "ki_expired".into(),
            output_key: "ok2".into(),
            amount: 200,
            created_at_secs: 1000,
        });

        // now=8000: ki_fresh age=3000 < 7200 (kept), ki_expired age=7000 < 7200 (kept)
        state.restore_pending_spends(spends.clone(), 8000);
        assert!(state.is_pending_spent("ki_fresh"));
        assert!(state.is_pending_spent("ki_expired"));

        // Reset and test with later time: ki_expired age=8200 >= 7200 (filtered)
        let mut state2 = WalletState::new();
        state2.restore_pending_spends(spends, 9200);
        assert!(state2.is_pending_spent("ki_fresh"));
        assert!(!state2.is_pending_spent("ki_expired"));
    }

    #[test]
    fn test_restore_tracked_transactions() {
        let mut state = WalletState::new();
        let mut txs = HashMap::new();
        txs.insert("tx1".to_string(), TrackedTransaction {
            tx_id: "tx1".into(),
            status: TxStatus::Broadcast,
            spent_key_images: vec!["ki1".into()],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 50_000_000,
            created_at_secs: 1000,
        });
        txs.insert("tx2".to_string(), TrackedTransaction {
            tx_id: "tx2".into(),
            status: TxStatus::Confirmed { height: 500 },
            spent_key_images: vec![],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 2000,
        });

        state.restore_tracked_transactions(txs);
        assert_eq!(state.get_tracked_tx("tx1").unwrap().status, TxStatus::Broadcast);
        assert_eq!(state.get_tracked_tx("tx2").unwrap().status, TxStatus::Confirmed { height: 500 });
        assert!(state.get_tracked_tx("tx3").is_none());
    }

    #[test]
    fn test_add_pending_spends_advances_tracked_tx() {
        let mut state = WalletState::new();
        state.track_transaction(TrackedTransaction {
            tx_id: "tx1".into(),
            status: TxStatus::Created,
            spent_key_images: vec!["ki1".into()],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 1000,
        });

        state.add_pending_spends("tx1", vec![
            make_pending_spend("tx1", "ki1", 1_000_000_000_000, 1000),
        ]);

        assert_eq!(state.get_tracked_tx("tx1").unwrap().status, TxStatus::Broadcast);
    }

    #[test]
    fn test_restore_tracked_transactions_rebuilds_spent_by_tx() {
        let mut state = WalletState::new();
        state.add_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 60, "ki2"),
        ]);

        // Mark both as spent at height 100 with known tx hashes
        state.mark_spent_detecting_conflicts(
            &["ki1".to_string(), "ki2".to_string()],
            &["tx_a".to_string(), "tx_b".to_string()],
            100,
        );

        // Simulate save/restore: replace outputs (clears spent_by_tx), then restore tracked txs
        let mut txs = HashMap::new();
        txs.insert("tx_a".to_string(), TrackedTransaction {
            tx_id: "tx_a".into(),
            status: TxStatus::Confirmed { height: 100 },
            spent_key_images: vec!["ki1".into()],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 1000,
        });
        txs.insert("tx_b".to_string(), TrackedTransaction {
            tx_id: "tx_b".into(),
            status: TxStatus::Broadcast,
            spent_key_images: vec!["ki2".into()],
            spent_output_keys: vec![],
            change_outputs: vec![],
            fee: 0,
            created_at_secs: 1000,
        });

        // Clear and rebuild
        state.replace_outputs(vec![
            make_output(1_000_000_000_000, 50, "ki1"),
            make_output(2_000_000_000_000, 60, "ki2"),
        ]);
        // Mark spent again (simulating output restore with spent flag)
        state.mark_spent_detecting_conflicts(
            &["ki1".to_string(), "ki2".to_string()],
            &["tx_a".to_string(), "tx_b".to_string()],
            100,
        );

        // Now clear spent_by_tx and restore from tracked txs
        state.spent_by_tx.clear();
        state.restore_tracked_transactions(txs);

        // Rescan at different height should NOT produce conflict (spent_by_tx rebuilt)
        let (_, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 200,
        );
        assert!(conflicts.is_empty(), "expected no conflict after restore, got {:?}", conflicts);
    }

    #[test]
    fn test_rollback_clears_spent_by_tx() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);
        state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 100,
        );

        // Rollback unspends ki1 and clears its spent_by_tx entry
        state.rollback_to_height(90);
        assert!(!state.outputs()[0].spent);

        // Re-spend with a DIFFERENT tx should not conflict (clean slate)
        let (count, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_b".to_string()], 95,
        );
        assert_eq!(count, 1);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_replace_outputs_clears_spent_by_tx() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);
        state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 100,
        );

        // Replace outputs clears spent_by_tx
        state.replace_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        // First spend after replace works cleanly
        let (count, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 100,
        );
        assert_eq!(count, 1);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_conflict_after_conflict_updates_spent_by_tx() {
        let mut state = WalletState::new();
        state.add_outputs(vec![make_output(1_000_000_000_000, 50, "ki1")]);

        state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_a".to_string()], 100,
        );

        // Different tx -> conflict, spent_by_tx updated to tx_b
        let (_, conflicts) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_b".to_string()], 200,
        );
        assert_eq!(conflicts.len(), 1);

        // Same tx_b again at different height -> no conflict (idempotent)
        let (_, conflicts2) = state.mark_spent_detecting_conflicts(
            &["ki1".to_string()], &["tx_b".to_string()], 300,
        );
        assert!(conflicts2.is_empty());
    }
}
