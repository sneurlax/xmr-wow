//! Wownero Wallet Core Library (fork of monero-rust, using wownero-oxide / dalek v4)
//!
//! A portable wallet library for Wownero, forked from monero-rust and ported
//! to use wownero-oxide (dalek v4) as the crypto backend.
//!
//! wownero-oxide handles WOW-specific differences automatically:
//! - RctType::WowneroClsagBulletproofPlus (wire type 8)
//! - Ring size 22
//! - INV_EIGHT commitment scaling (output commitments stored as C/8)
//! - Default spendable age: 4 blocks (vs Monero's 10)

// Core modules
pub mod abstractions;
pub mod chain_config;
pub mod coin_selection;
pub mod scan_coordinator;
pub mod scanner;
pub mod wallet_output;
pub mod wallet_state;

// Transaction building
pub mod tx_builder;
pub mod tx_prepare;
pub mod tx_utils;

// RPC
pub mod rpc_serai;

// -- Wallet state & output types --
pub use wallet_output::WalletOutput;
pub use wallet_state::{
    Balance, BlockHashChain, ChangeOutputRef, PendingSpend, RollbackResult, SpentConflict,
    TrackedTransaction, TxStatus, WalletState, MAX_REORG_DEPTH, PENDING_SPEND_TTL_SECS,
};

// -- Coin selection --
pub use coin_selection::{
    estimate_fee, find_best_combination, select_inputs, CoinSelectionResult, DUST_THRESHOLD,
};

// -- Scan coordination --
pub use scan_coordinator::{
    compute_lookahead, filter_outputs_by_accounts, process_batch_with_reorg_detection,
    process_single_wallet_batch, sync_progress, BlockOutputSummary, ProcessedBatch, ReorgInfo,
    ScanBatchOutcome, SyncProgress,
};

// -- Scanning --
pub use scanner::{
    // Types
    BlockScanResult, DerivedKeys, Lookahead, MempoolScanResult, MultiWalletScanResult,
    WalletScanConfig, WalletScanData,
    // Constants
    DEFAULT_LOOKAHEAD,
};

// -- Transaction building --
pub use tx_builder::native;
pub use tx_prepare::{prepare_send_inputs, prepare_sweep_inputs, PreparedInputs};
pub use tx_utils::{adjust_recipients_for_fee, classify_broadcast_error};

/// Simple integration test function
pub fn test_integration() -> String {
    "wownero-rust works (wownero-oxide backend)".to_string()
}

// -- Abstractions (RPC, storage, time) --
pub use abstractions::{
    AbError, AbResult, BlockData, BlockHeader, BlockResponse, GetOutsParams, HeightResponse,
    MemoryStorage, OutEntry, OutsResponse, OutputIndex, RpcClient, TimeProvider,
    TransactionData, TxSubmitResponse, WalletStorage,
};

// -- Platform-specific implementations --
pub mod native_impl;
pub use native_impl::SystemTimeProvider;
