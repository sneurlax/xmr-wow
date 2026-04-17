// xmr-wow-sharechain: SwapChain consensus engine
//
// Validates incoming SwapShares, maintains the canonical chain tip, and
// drives the EscrowIndex forward as new shares are accepted.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use parking_lot::RwLock;

use crate::escrow::EscrowIndex;
use crate::share::{Difficulty, Hash, SwapShare};

// --- Constants ----------------------------------------------------------------

/// Bytes used to derive the genesis chain ID and as the P2P consensus identifier.
pub const CONSENSUS_ID: &[u8] = b"xmr-wow-swap-v1";

/// How many blocks back we look for uncle candidates.
pub const UNCLE_DEPTH: u64 = 3;

/// Uncles earn this percentage of the full difficulty weight.
pub const UNCLE_PENALTY_PCT: u64 = 20; // uncles earn 80%

// --- ChainError ---------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// Parent hash not found and height is not 0.
    UnknownParent,
    /// `share.height != parent.height + 1`.
    InvalidHeight,
    /// `share.difficulty < min_difficulty`.
    DifficultyTooLow,
    /// Cumulative difficulty field is inconsistent.
    InvalidCumulativeDifficulty,
    /// A share with the same `full_id()` was already accepted.
    DuplicateShare,
    /// An escrow operation embedded in the share was invalid.
    InvalidEscrowOp(String),
    /// The share's pow_hash does not satisfy its claimed difficulty.
    InvalidPoW,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::UnknownParent => write!(f, "unknown parent"),
            ChainError::InvalidHeight => write!(f, "invalid height"),
            ChainError::DifficultyTooLow => write!(f, "difficulty too low"),
            ChainError::InvalidCumulativeDifficulty => {
                write!(f, "invalid cumulative difficulty")
            }
            ChainError::DuplicateShare => write!(f, "duplicate share"),
            ChainError::InvalidEscrowOp(msg) => write!(f, "invalid escrow op: {msg}"),
            ChainError::InvalidPoW => write!(f, "invalid proof-of-work"),
        }
    }
}

impl std::error::Error for ChainError {}

// --- SwapChain ----------------------------------------------------------------

/// The swap sharechain: a single-threaded-safe, Arc-wrapped consensus engine.
pub struct SwapChain {
    min_difficulty: Difficulty,

    /// `share_id -> SwapShare` (canonical store).
    shares: Arc<RwLock<HashMap<[u8; 32], SwapShare>>>,

    /// `height -> Vec<share_id>` (all shares at a given height; may be >1 due to uncles).
    by_height: Arc<RwLock<BTreeMap<u64, Vec<[u8; 32]>>>>,

    /// `full_id -> ()` for duplicate detection.
    full_ids: Arc<RwLock<HashMap<[u8; 36], ()>>>,

    /// The share_id of the current heaviest-chain tip.
    tip: Arc<RwLock<Option<[u8; 32]>>>,

    /// Live escrow state derived from all accepted shares in chain order.
    pub escrow_index: Arc<RwLock<EscrowIndex>>,
}

impl SwapChain {
    /// Create an empty chain with the given minimum per-share difficulty.
    pub fn new(min_difficulty: Difficulty) -> Self {
        Self {
            min_difficulty,
            shares:       Arc::new(RwLock::new(HashMap::new())),
            by_height:    Arc::new(RwLock::new(BTreeMap::new())),
            full_ids:     Arc::new(RwLock::new(HashMap::new())),
            tip:          Arc::new(RwLock::new(None)),
            escrow_index: Arc::new(RwLock::new(EscrowIndex::new())),
        }
    }

    // -- Validation + insertion -----------------------------------------------

    /// Add a share to the chain.
    ///
    /// Returns `Ok(true)` when the share becomes the new tip (highest cumulative
    /// difficulty), `Ok(false)` when it is accepted but does not change the tip.
    ///
    /// Validation rules (mirrors p2pool's verify() logic):
    /// 1. Duplicate detection via `full_id()`.
    /// 2. Genesis (height 0): parent must be all-zeros; no parent lookup.
    /// 3. Non-genesis: parent must exist; height must equal parent.height + 1.
    /// 4. difficulty >= min_difficulty.
    /// 5. cumulative_difficulty == parent.cumulative_difficulty + difficulty.
    /// 6. All embedded EscrowOps must be valid according to the EscrowIndex.
    pub fn add_share(&self, share: SwapShare) -> Result<bool, ChainError> {
        let share_id   = share.id();
        let full_id    = share.full_id();

        // 1. Duplicate check
        {
            let ids = self.full_ids.read();
            if ids.contains_key(&full_id) {
                return Err(ChainError::DuplicateShare);
            }
        }

        // 2/3. Parent validation
        let expected_cumulative = if share.height == 0 {
            // Genesis: parent must be all-zeros
            if share.parent != [0u8; 32] {
                return Err(ChainError::UnknownParent);
            }
            // cumulative == difficulty for genesis
            share.difficulty
        } else {
            let shares = self.shares.read();
            let parent = shares
                .get(&share.parent)
                .ok_or(ChainError::UnknownParent)?;
            if share.height != parent.height + 1 {
                return Err(ChainError::InvalidHeight);
            }
            parent.cumulative_difficulty.wrapping_add(share.difficulty)
        };

        // 4. Minimum difficulty
        if share.difficulty < self.min_difficulty {
            return Err(ChainError::DifficultyTooLow);
        }

        // 4b. Proof-of-work check: pow_hash must satisfy claimed difficulty
        if !share.difficulty.check_pow(&share.pow_hash()) {
            return Err(ChainError::InvalidPoW);
        }

        // 5. Cumulative difficulty consistency
        if share.cumulative_difficulty != expected_cumulative {
            return Err(ChainError::InvalidCumulativeDifficulty);
        }

        // 6. Apply escrow ops (validate + transition state)
        {
            let mut idx = self.escrow_index.write();
            for op in &share.escrow_ops {
                idx.apply(op)
                    .map_err(|e| ChainError::InvalidEscrowOp(e.to_string()))?;
            }
        }

        // Accept the share
        {
            let mut shares   = self.shares.write();
            let mut by_height = self.by_height.write();
            let mut full_ids = self.full_ids.write();

            shares.insert(share_id, share.clone());
            by_height
                .entry(share.height)
                .or_default()
                .push(share_id);
            full_ids.insert(full_id, ());
        }

        // Update tip if this share has higher cumulative difficulty.
        // When the new tip is on a different branch from the old tip (reorg),
        // reverse the escrow ops of every orphaned share back to the common
        // ancestor before advancing the tip pointer.
        let became_tip = {
            let mut tip    = self.tip.write();
            let shares_map = self.shares.read();

            let current_cum = tip
                .and_then(|t| shares_map.get(&t))
                .map(|s| s.cumulative_difficulty)
                .unwrap_or(Difficulty::ZERO);

            if share.cumulative_difficulty > current_cum {
                // Detect reorg: the new share's parent must be an ancestor of
                // the current tip.  If the old tip is NOT an ancestor of the
                // new tip we have a fork switch and must revert orphaned escrow
                // ops.
                if let Some(old_tip_id) = *tip {
                    // Collect the ancestor set of the new share (back to height 0
                    // or until we find the old tip).
                    let mut new_ancestors: std::collections::HashSet<[u8; 32]> =
                        std::collections::HashSet::new();
                    let mut cursor = share_id;
                    loop {
                        new_ancestors.insert(cursor);
                        if cursor == old_tip_id {
                            break; // old tip is an ancestor: no reorg needed
                        }
                        match shares_map.get(&cursor) {
                            Some(s) if s.height > 0 => cursor = s.parent,
                            _ => break, // reached genesis or missing parent
                        }
                    }

                    if !new_ancestors.contains(&old_tip_id) {
                        // Full reorg: walk the old chain back to find the
                        // common ancestor, collecting orphaned shares.
                        let mut orphaned: Vec<[u8; 32]> = Vec::new();
                        let mut old_cursor = old_tip_id;
                        loop {
                            if new_ancestors.contains(&old_cursor) {
                                break; // common ancestor found
                            }
                            orphaned.push(old_cursor);
                            match shares_map.get(&old_cursor) {
                                Some(s) if s.height > 0 => old_cursor = s.parent,
                                _ => break,
                            }
                        }

                        // Revert escrow ops for orphaned shares (newest -> oldest).
                        // We need the EscrowCommitment to restore Open state when
                        // reverting a Claim or Refund.  Build a map of swap_id ->
                        // EscrowCommitment from all Open ops on the orphaned fork.
                        let mut open_map: std::collections::HashMap<[u8; 32], crate::share::EscrowCommitment> =
                            std::collections::HashMap::new();
                        for &sid in &orphaned {
                            if let Some(s) = shares_map.get(&sid) {
                                for op in &s.escrow_ops {
                                    if let crate::share::EscrowOp::Open(c) = op {
                                        open_map.insert(c.swap_id, c.clone());
                                    }
                                }
                            }
                        }

                        let mut idx = self.escrow_index.write();
                        for sid in orphaned {
                            if let Some(s) = shares_map.get(&sid) {
                                // Revert ops in reverse order (last applied first).
                                for op in s.escrow_ops.iter().rev() {
                                    let commitment = match op {
                                        crate::share::EscrowOp::Open(_) => None,
                                        crate::share::EscrowOp::Claim { swap_id, .. }
                                        | crate::share::EscrowOp::Refund { swap_id, .. } => {
                                            open_map.get(swap_id)
                                        }
                                    };
                                    idx.revert(op, commitment.map(|c| c as &_));
                                }
                            }
                        }
                    }
                }

                *tip = Some(share_id);
                true
            } else {
                false
            }
        };

        Ok(became_tip)
    }

    // -- Accessors ------------------------------------------------------------

    /// Share ID of the current tip, if any.
    pub fn tip_id(&self) -> Option<[u8; 32]> {
        *self.tip.read()
    }

    /// Height of the current tip (0 if no shares yet).
    pub fn tip_height(&self) -> u64 {
        let tip = self.tip.read();
        let shares = self.shares.read();
        tip.and_then(|t| shares.get(&t)).map(|s| s.height).unwrap_or(0)
    }

    /// Retrieve a share by its canonical ID.
    pub fn get_share(&self, id: &[u8; 32]) -> Option<SwapShare> {
        self.shares.read().get(id).cloned()
    }

    /// The difficulty of the current tip (0 if no shares).
    pub fn difficulty_at_tip(&self) -> Difficulty {
        let tip = self.tip.read();
        let shares = self.shares.read();
        tip.and_then(|t| shares.get(&t))
            .map(|s| s.difficulty)
            .unwrap_or(Difficulty::ZERO)
    }

    /// Current aux_hash for p2pool: the tip's `escrow_merkle_root`.
    ///
    /// Returns all-zeros if no tip is available.
    pub fn current_aux_hash(&self) -> Hash {
        let tip = self.tip.read();
        let shares = self.shares.read();
        tip.and_then(|t| shares.get(&t))
            .map(|s| s.escrow_merkle_root)
            .unwrap_or([0u8; 32])
    }

    /// Number of shares accepted (any height).
    pub fn share_count(&self) -> usize {
        self.shares.read().len()
    }
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{EscrowCommitment, EscrowOp, SwapShare};

    const MIN_DIFF: Difficulty = Difficulty { lo: 1, hi: 0 };

    /// Grind nonce until the share's pow_hash meets its claimed difficulty.
    fn grind_nonce(share: &mut SwapShare) {
        for n in 0u32..=u32::MAX {
            share.nonce = n;
            if share.difficulty.check_pow(&share.pow_hash()) {
                return;
            }
        }
        panic!("could not find valid nonce for difficulty {:?}", share.difficulty);
    }

    #[test]
    fn share_without_valid_pow_rejected() {
        let chain = SwapChain::new(Difficulty::from_u64(100));
        let mut g = SwapShare::genesis(Difficulty::from_u64(100));
        // find a nonce that fails PoW
        let mut found_bad = false;
        for n in 0u32..1000 {
            g.nonce = n;
            if !g.difficulty.check_pow(&g.pow_hash()) {
                found_bad = true;
                break;
            }
        }
        assert!(found_bad, "expected to find a nonce that fails PoW for difficulty=100");
        let err = chain.add_share(g).unwrap_err();
        assert_eq!(err, ChainError::InvalidPoW);
    }

    #[test]
    fn share_with_valid_pow_accepted() {
        let chain = SwapChain::new(Difficulty::from_u64(100));
        let mut g = SwapShare::genesis(Difficulty::from_u64(100));
        grind_nonce(&mut g);
        assert!(chain.add_share(g).is_ok());
    }

    #[test]
    fn genesis_share_requires_pow() {
        let chain = SwapChain::new(Difficulty::from_u64(1));
        let mut g = SwapShare::genesis(Difficulty::from_u64(1));
        grind_nonce(&mut g);
        assert!(chain.add_share(g).is_ok());
        // zero difficulty still rejected
        let chain2 = SwapChain::new(Difficulty::from_u64(100));
        let mut bad_g = SwapShare::genesis(Difficulty::from_u64(100));
        // find a nonce that fails PoW
        let mut found_bad = false;
        for n in 0u32..1000 {
            bad_g.nonce = n;
            if !bad_g.difficulty.check_pow(&bad_g.pow_hash()) {
                found_bad = true;
                break;
            }
        }
        assert!(found_bad);
        let err = chain2.add_share(bad_g).unwrap_err();
        assert_eq!(err, ChainError::InvalidPoW);
    }

    /// Build a share and grind the nonce to satisfy PoW.
    fn make_share(
        parent: Hash,
        height: u64,
        parent_cumulative: Difficulty,
        diff: Difficulty,
        _nonce: u32,
    ) -> SwapShare {
        let mut s = SwapShare {
            parent,
            uncles: Vec::new(),
            height,
            difficulty: diff,
            cumulative_difficulty: parent_cumulative.wrapping_add(diff),
            timestamp: height * 10,
            nonce: 0,
            escrow_ops: Vec::new(),
            escrow_merkle_root: [height as u8; 32],
            pow_proof: None,
        };
        grind_nonce(&mut s);
        s
    }

    fn genesis(diff: Difficulty) -> SwapShare {
        make_share([0u8; 32], 0, Difficulty::ZERO, diff, 0)
    }

    #[test]
    fn genesis_share_is_accepted() {
        let chain = SwapChain::new(MIN_DIFF);
        let g = genesis(Difficulty::from_u64(1000));
        let tip_changed = chain.add_share(g.clone()).unwrap();
        assert!(tip_changed);
        assert_eq!(chain.tip_height(), 0);
        assert_eq!(chain.share_count(), 1);
        assert_eq!(chain.tip_id(), Some(g.id()));
    }

    #[test]
    fn share_extends_chain() {
        let chain = SwapChain::new(MIN_DIFF);
        let diff = Difficulty::from_u64(1000);
        let g = genesis(diff);
        let g_id = g.id();
        let g_cum = g.cumulative_difficulty;
        chain.add_share(g).unwrap();

        let s1 = make_share(g_id, 1, g_cum, diff, 0);
        let s1_id = s1.id();
        let tip_changed = chain.add_share(s1).unwrap();
        assert!(tip_changed);
        assert_eq!(chain.tip_height(), 1);
        assert_eq!(chain.tip_id(), Some(s1_id));
    }

    #[test]
    fn duplicate_share_rejected() {
        let chain = SwapChain::new(MIN_DIFF);
        let g = genesis(Difficulty::from_u64(1000));
        chain.add_share(g.clone()).unwrap();
        let err = chain.add_share(g).unwrap_err();
        assert_eq!(err, ChainError::DuplicateShare);
    }

    #[test]
    fn low_difficulty_rejected() {
        let chain = SwapChain::new(Difficulty::from_u64(500));
        let low = genesis(Difficulty::from_u64(100));
        let err = chain.add_share(low).unwrap_err();
        assert_eq!(err, ChainError::DifficultyTooLow);
    }

    #[test]
    fn add_share_updates_escrow_index() {
        let chain = SwapChain::new(MIN_DIFF);
        let diff = Difficulty::from_u64(1);

        let mut g = genesis(diff);
        let commitment = EscrowCommitment {
            swap_id:         [0x11u8; 32],
            alice_sc_pubkey: [1u8; 32],
            bob_sc_pubkey:   [2u8; 32],
            k_b_expected:    [3u8; 32],
            k_b_prime:       [4u8; 32],
            claim_timelock:  100,
            refund_timelock: 200,
            amount:          500_000,
        };
        g.escrow_ops.push(EscrowOp::Open(commitment));
        // After adding escrow ops the share content changes; re-grind nonce.
        grind_nonce(&mut g);
        chain.add_share(g).unwrap();

        let idx = chain.escrow_index.read();
        assert_eq!(idx.open_count(), 1);
        assert!(idx.get(&[0x11u8; 32]).is_some());
    }

    #[test]
    fn wrong_height_rejected() {
        let chain = SwapChain::new(MIN_DIFF);
        let diff = Difficulty::from_u64(1);
        let g = genesis(diff);
        let g_id = g.id();
        let g_cum = g.cumulative_difficulty;
        chain.add_share(g).unwrap();

        // height should be 1, submit height 5
        let bad = make_share(g_id, 5, g_cum, diff, 0);
        let err = chain.add_share(bad).unwrap_err();
        assert_eq!(err, ChainError::InvalidHeight);
    }

    #[test]
    fn wrong_cumulative_rejected() {
        let chain = SwapChain::new(MIN_DIFF);
        let diff = Difficulty::from_u64(1000);
        let g = genesis(diff);
        let g_id = g.id();
        let g_cum = g.cumulative_difficulty;
        chain.add_share(g).unwrap();

        let mut bad = make_share(g_id, 1, g_cum, diff, 0);
        // Tamper with cumulative_difficulty
        bad.cumulative_difficulty = Difficulty::from_u64(9999);
        let err = chain.add_share(bad).unwrap_err();
        assert_eq!(err, ChainError::InvalidCumulativeDifficulty);
    }

    /// Build a share with escrow ops and grind the nonce.
    fn make_share_with_ops(
        parent: Hash,
        height: u64,
        parent_cumulative: Difficulty,
        diff: Difficulty,
        ops: Vec<crate::share::EscrowOp>,
    ) -> SwapShare {
        let mut s = SwapShare {
            parent,
            uncles: Vec::new(),
            height,
            difficulty: diff,
            cumulative_difficulty: parent_cumulative.wrapping_add(diff),
            timestamp: height * 10,
            nonce: 0,
            escrow_ops: ops,
            escrow_merkle_root: [height as u8; 32],
            pow_proof: None,
        };
        grind_nonce(&mut s);
        s
    }

    /// Reorg must revert escrow ops from orphaned fork.
    #[test]
    fn escrow_ops_reverted_on_reorg() {
        let chain = SwapChain::new(MIN_DIFF);
        let diff_low  = Difficulty::from_u64(1);
        let diff_high = Difficulty::from_u64(1000);

        // Genesis
        let g = genesis(diff_low);
        let g_id  = g.id();
        let g_cum = g.cumulative_difficulty;
        chain.add_share(g).unwrap();

        // Fork A: extends genesis at low difficulty, carries an Open escrow op.
        let swap_aa = [0xAAu8; 32];
        let commitment_aa = EscrowCommitment {
            swap_id:         swap_aa,
            alice_sc_pubkey: [1u8; 32],
            bob_sc_pubkey:   [2u8; 32],
            k_b_expected:    [3u8; 32],
            k_b_prime:       [4u8; 32],
            claim_timelock:  100,
            refund_timelock: 200,
            amount:          1_000,
        };
        let fork_a = make_share_with_ops(
            g_id, 1, g_cum, diff_low,
            vec![EscrowOp::Open(commitment_aa.clone())],
        );
        let fork_a_id = fork_a.id();
        let became_tip = chain.add_share(fork_a).unwrap();
        assert!(became_tip, "fork_a should become tip");

        {
            let idx = chain.escrow_index.read();
            assert_eq!(idx.open_count(), 1, "Open(0xAA) should be in index after fork_a");
            assert!(idx.get(&swap_aa).is_some());
        }

        // fork_b: higher difficulty, triggers reorg
        let mut fork_b = make_share_with_ops(
            g_id, 1, g_cum, diff_high,
            vec![],
        );
        fork_b.escrow_merkle_root = [0xBBu8; 32];
        fork_b.cumulative_difficulty = g_cum.wrapping_add(diff_high);
        grind_nonce(&mut fork_b);

        let fork_b_id = fork_b.id();
        let became_tip = chain.add_share(fork_b).unwrap();
        assert!(became_tip, "fork_b should become new tip (reorg)");
        assert_eq!(chain.tip_id(), Some(fork_b_id), "tip must be fork_b");
        assert_ne!(chain.tip_id(), Some(fork_a_id), "fork_a must no longer be tip");

        // orphaned Open(0xAA) must have been reverted
        {
            let idx = chain.escrow_index.read();
            assert_eq!(
                idx.open_count(), 0,
                "Open(0xAA) must be rolled back after reorg that orphans fork_a"
            );
            assert!(
                idx.get(&swap_aa).is_none(),
                "swap 0xAA must not appear in index after reorg"
            );
        }
    }

    /// Reorg must also revert Claim ops from orphaned fork.
    #[test]
    fn claim_op_reverted_on_reorg() {
        let chain = SwapChain::new(MIN_DIFF);
        let diff_low  = Difficulty::from_u64(1);
        let diff_high = Difficulty::from_u64(10_000);

        // Genesis
        let g = genesis(diff_low);
        let g_id  = g.id();
        let g_cum = g.cumulative_difficulty;
        chain.add_share(g).unwrap();

        let swap_cc = [0xCCu8; 32];
        let k_b     = [0x55u8; 32];
        let commitment_cc = EscrowCommitment {
            swap_id:         swap_cc,
            alice_sc_pubkey: [1u8; 32],
            bob_sc_pubkey:   [2u8; 32],
            k_b_expected:    k_b,
            k_b_prime:       [4u8; 32],
            claim_timelock:  100,
            refund_timelock: 200,
            amount:          2_000,
        };

        // fork_a_1: Open(0xCC)
        let fa1 = make_share_with_ops(
            g_id, 1, g_cum, diff_low,
            vec![EscrowOp::Open(commitment_cc.clone())],
        );
        let fa1_id  = fa1.id();
        let fa1_cum = fa1.cumulative_difficulty;
        chain.add_share(fa1).unwrap();

        // fork_a_2: Claim(0xCC)
        let fa2 = make_share_with_ops(
            fa1_id, 2, fa1_cum, diff_low,
            vec![EscrowOp::Claim { swap_id: swap_cc, k_b }],
        );
        chain.add_share(fa2).unwrap();

        // Confirm Claimed state is present.
        {
            let idx = chain.escrow_index.read();
            assert!(matches!(
                idx.get(&swap_cc),
                Some(crate::escrow::EscrowState::Claimed { .. })
            ), "swap 0xCC should be Claimed while fork_a is canonical");
        }

        // fork_b_1: heavy share from genesis -> reorg
        let mut fb1 = make_share_with_ops(g_id, 1, g_cum, diff_high, vec![]);
        fb1.escrow_merkle_root = [0xDDu8; 32];
        fb1.cumulative_difficulty = g_cum.wrapping_add(diff_high);
        grind_nonce(&mut fb1);
        chain.add_share(fb1).unwrap();

        // Both Open and Claim from fork_a must be gone.
        {
            let idx = chain.escrow_index.read();
            assert_eq!(idx.total_count(), 0,
                "all fork_a escrow entries must be gone after reorg");
            assert!(idx.get(&swap_cc).is_none(),
                "swap 0xCC must not appear in index after reorg");
        }
    }

    #[test]
    fn tip_not_changed_by_lower_cumulative() {
        let chain = SwapChain::new(MIN_DIFF);
        let high_diff = Difficulty::from_u64(2000);
        let low_diff  = Difficulty::from_u64(1);

        // Two genesis-like shares ; only the first is a true genesis.
        // We add a high-difficulty genesis, then add a share that extends it
        // at low difficulty; it should still be the tip only if cumulative is highest.
        let g = genesis(high_diff);
        let g_id  = g.id();
        let g_cum = g.cumulative_difficulty;
        chain.add_share(g).unwrap();

        // A competing genesis-level share with low cumulative.
        // Give it a different escrow_merkle_root so its id() differs from g.
        let mut alt_g = genesis(low_diff);
        alt_g.escrow_merkle_root = [0xAAu8; 32];
        // Recompute cumulative: for genesis expected = difficulty
        // (already set by genesis() as low_diff, so nothing to fix here)
        chain.add_share(alt_g).unwrap(); // accepted but does not change tip

        assert_eq!(chain.tip_id(), Some(g_id));
        assert_eq!(chain.tip_height(), 0);

        // Extend the high chain -> should become tip
        let s1 = make_share(g_id, 1, g_cum, high_diff, 0);
        chain.add_share(s1.clone()).unwrap();
        assert_eq!(chain.tip_id(), Some(s1.id()));
    }
}
