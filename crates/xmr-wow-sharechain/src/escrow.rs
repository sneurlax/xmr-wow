// xmr-wow-sharechain: EscrowIndex state machine
//
// EscrowOp mirrors share::EscrowOp so that chain.rs can feed share ops
// directly into the index without conversion.  We re-export share::EscrowOp
// as the canonical type; lib.rs exposes it at crate root.

use std::collections::HashMap;
use thiserror::Error;

use crate::share::{EscrowCommitment, Hash};

// Re-export share::EscrowOp as the EscrowOp used by this module.
pub use crate::share::EscrowOp;

// --- State --------------------------------------------------------------------

/// The lifecycle state of an atomic swap escrow on the sharechain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowState {
    /// Escrow is open and waiting for claim or refund.
    Open(EscrowCommitment),
    /// Alice revealed `k_b`; funds have been claimed.
    Claimed { k_b: [u8; 32] },
    /// Bob took a refund after the timelock expired.
    Refunded,
}

// --- Errors -------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum EscrowError {
    #[error("swap {0} already exists")]
    AlreadyExists(String),
    #[error("swap {0} not found")]
    NotFound(String),
    #[error("swap {0} not in Open state")]
    WrongState(String),
    #[error("swap {0}: invalid claim key")]
    InvalidKey(String),
}

fn fmt_id(id: &Hash) -> String {
    hex::encode(id)
}

// --- EscrowIndex -------------------------------------------------------------

/// In-memory index of all swap escrow states on the sharechain.
pub struct EscrowIndex {
    states: HashMap<Hash, EscrowState>,
}

impl Default for EscrowIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl EscrowIndex {
    pub fn new() -> Self {
        Self { states: HashMap::new() }
    }

    /// Apply an escrow operation, transitioning state.
    ///
    /// Rules:
    /// - `Open`:   swap_id must not already exist.
    /// - `Claim`:  swap must be in `Open` state.
    /// - `Refund`: swap must be in `Open` state.
    pub fn apply(&mut self, op: &EscrowOp) -> Result<(), EscrowError> {
        match op {
            EscrowOp::Open(commitment) => {
                if self.states.contains_key(&commitment.swap_id) {
                    return Err(EscrowError::AlreadyExists(fmt_id(&commitment.swap_id)));
                }
                self.states.insert(
                    commitment.swap_id,
                    EscrowState::Open(commitment.clone()),
                );
                Ok(())
            }

            EscrowOp::Claim { swap_id, k_b } => {
                let entry = self
                    .states
                    .get_mut(swap_id)
                    .ok_or_else(|| EscrowError::NotFound(fmt_id(swap_id)))?;
                match entry {
                    EscrowState::Open(commitment) => {
                        if *k_b != commitment.k_b_expected {
                            return Err(EscrowError::InvalidKey(fmt_id(swap_id)));
                        }
                        *entry = EscrowState::Claimed { k_b: *k_b };
                        Ok(())
                    }
                    _ => Err(EscrowError::WrongState(fmt_id(swap_id))),
                }
            }

            EscrowOp::Refund { swap_id, sig: _ } => {
                let entry = self
                    .states
                    .get_mut(swap_id)
                    .ok_or_else(|| EscrowError::NotFound(fmt_id(swap_id)))?;
                match entry {
                    EscrowState::Open(_) => {
                        *entry = EscrowState::Refunded;
                        Ok(())
                    }
                    _ => Err(EscrowError::WrongState(fmt_id(swap_id))),
                }
            }
        }
    }

    /// Look up the current state for a swap.
    pub fn get(&self, swap_id: &Hash) -> Option<&EscrowState> {
        self.states.get(swap_id)
    }

    /// Number of swaps currently in the `Open` state.
    pub fn open_count(&self) -> usize {
        self.states
            .values()
            .filter(|s| matches!(s, EscrowState::Open(_)))
            .count()
    }

    /// Total number of tracked swaps (any state).
    pub fn total_count(&self) -> usize {
        self.states.len()
    }
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_commitment(n: u8) -> EscrowCommitment {
        EscrowCommitment {
            swap_id:         [n; 32],
            alice_sc_pubkey: [n + 1; 32],
            bob_sc_pubkey:   [n + 2; 32],
            k_b_expected:    [n + 3; 32],
            k_b_prime:       [n + 4; 32],
            claim_timelock:  100,
            refund_timelock: 200,
            amount:          1_000_000,
        }
    }

    #[test]
    fn open_escrow_is_stored() {
        let mut idx = EscrowIndex::new();
        let c = sample_commitment(1);
        let id = c.swap_id;
        idx.apply(&EscrowOp::Open(c.clone())).unwrap();
        assert_eq!(idx.open_count(), 1);
        assert!(matches!(idx.get(&id), Some(EscrowState::Open(_))));
    }

    #[test]
    fn claim_transitions_state() {
        let mut idx = EscrowIndex::new();
        let c = sample_commitment(2);
        let id = c.swap_id;
        let expected_k_b = c.k_b_expected; // [5u8; 32]
        idx.apply(&EscrowOp::Open(c)).unwrap();
        idx.apply(&EscrowOp::Claim { swap_id: id, k_b: expected_k_b }).unwrap();
        assert!(matches!(
            idx.get(&id),
            Some(EscrowState::Claimed { .. })
        ));
        assert_eq!(idx.open_count(), 0);
    }

    #[test]
    fn refund_transitions_state() {
        let mut idx = EscrowIndex::new();
        let c = sample_commitment(3);
        let id = c.swap_id;
        idx.apply(&EscrowOp::Open(c)).unwrap();
        idx.apply(&EscrowOp::Refund { swap_id: id, sig: [0u8; 64] })
            .unwrap();
        assert!(matches!(idx.get(&id), Some(EscrowState::Refunded)));
        assert_eq!(idx.open_count(), 0);
    }

    #[test]
    fn double_open_rejected() {
        let mut idx = EscrowIndex::new();
        let c = sample_commitment(4);
        idx.apply(&EscrowOp::Open(c.clone())).unwrap();
        let err = idx.apply(&EscrowOp::Open(c)).unwrap_err();
        assert!(matches!(err, EscrowError::AlreadyExists(_)));
    }

    #[test]
    fn claim_wrong_state_rejected() {
        let mut idx = EscrowIndex::new();
        let c = sample_commitment(5);
        let id = c.swap_id;
        let expected_k_b = c.k_b_expected; // [8u8; 32]
        idx.apply(&EscrowOp::Open(c)).unwrap();
        // First claim succeeds with correct k_b
        idx.apply(&EscrowOp::Claim { swap_id: id, k_b: expected_k_b })
            .unwrap();
        // Second claim on an already-Claimed swap must fail
        let err = idx
            .apply(&EscrowOp::Claim { swap_id: id, k_b: expected_k_b })
            .unwrap_err();
        assert!(matches!(err, EscrowError::WrongState(_)));
    }

    #[test]
    fn wrong_k_b_claim_rejected() {
        let mut idx = EscrowIndex::new();
        let c = sample_commitment(6);
        let id = c.swap_id;
        idx.apply(&EscrowOp::Open(c)).unwrap();
        let wrong_k_b = [0xABu8; 32];
        let err = idx.apply(&EscrowOp::Claim { swap_id: id, k_b: wrong_k_b }).unwrap_err();
        assert!(matches!(err, EscrowError::InvalidKey(_)));
    }

    #[test]
    fn refund_on_unknown_swap_is_not_found() {
        let mut idx = EscrowIndex::new();
        let err = idx
            .apply(&EscrowOp::Refund { swap_id: [9u8; 32], sig: [0u8; 64] })
            .unwrap_err();
        assert!(matches!(err, EscrowError::NotFound(_)));
    }
}
