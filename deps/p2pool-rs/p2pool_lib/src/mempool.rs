// P2Pool for Monero - In-memory mempool mirror
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// p2pool mirrors the Monero mempool locally so it can build block templates
// that include as many fee-paying transactions as possible. Transactions are
// added via ZMQ and removed when they appear in a main-chain block.

use dashmap::DashMap;
use p2pool_crypto::Hash;
use p2pool_monero::tx::TxMempoolData;
use std::time::{SystemTime, UNIX_EPOCH};

/// Thread-safe, concurrent mempool.
pub struct Mempool {
    txs: DashMap<Hash, TxMempoolData>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            txs: DashMap::new(),
        }
    }

    /// Add or update a transaction.
    pub fn add(&self, mut tx: TxMempoolData) {
        if tx.time_received == 0 {
            tx.time_received = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        self.txs.insert(tx.id, tx);
    }

    /// Remove a transaction by ID (e.g., it was included in a block).
    pub fn remove(&self, id: &Hash) {
        self.txs.remove(id);
    }

    /// Return transactions sorted by fee-per-byte descending, up to `max_weight` bytes total.
    ///
    /// This mirrors the C++ `BlockTemplate::select_mempool_transactions()` logic.
    pub fn select_transactions(&self, max_weight: u64) -> Vec<TxMempoolData> {
        let mut txs: Vec<TxMempoolData> = self.txs.iter().map(|r| r.value().clone()).collect();
        // Sort: higher fee*weight first (the Ord impl on TxMempoolData)
        txs.sort();

        let mut selected = Vec::new();
        let mut total_weight = 0u64;
        for tx in txs {
            if total_weight + tx.weight > max_weight {
                continue;
            }
            total_weight += tx.weight;
            selected.push(tx);
        }
        selected
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}
