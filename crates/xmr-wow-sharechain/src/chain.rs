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

        // Update tip if this share has higher cumulative difficulty
        let became_tip = {
            let mut tip = self.tip.write();
            let shares  = self.shares.read();
            let current_cum = tip
                .and_then(|t| shares.get(&t))
                .map(|s| s.cumulative_difficulty)
                .unwrap_or(Difficulty::ZERO);

            if share.cumulative_difficulty > current_cum {
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

    fn make_share(
        parent: Hash,
        height: u64,
        parent_cumulative: Difficulty,
        diff: Difficulty,
        nonce: u32,
    ) -> SwapShare {
        SwapShare {
            parent,
            uncles: Vec::new(),
            height,
            difficulty: diff,
            cumulative_difficulty: parent_cumulative.wrapping_add(diff),
            timestamp: height * 10,
            nonce,
            escrow_ops: Vec::new(),
            escrow_merkle_root: [height as u8; 32],
            pow_proof: None,
        }
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
