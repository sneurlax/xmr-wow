//! CryptoNoteWallet trait -- shared interface for XMR and WOW wallet operations.
//!
//! Both XmrWallet and WowWallet implement this trait. The swap state machine
//! is generic over it, enabling chain-agnostic swap logic.
//!
//! Per D-06: Crypto crate handles joint key math (keysplit.rs). This trait
//! takes `(spend_point, view_scalar)` pairs as input. Clean separation:
//! crypto = key math, wallet = on-chain ops.

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

use crate::error::WalletError;

/// A confirmed transaction hash (32 bytes).
pub type TxHash = [u8; 32];

/// Result of scanning for outputs at a joint address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub found: bool,
    pub amount: u64,
    pub tx_hash: TxHash,
    pub output_index: u8,
    pub block_height: u64,
}

/// Result of polling for transaction confirmation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfirmationStatus {
    pub confirmed: bool,
    pub confirmations: u64,
    pub block_height: Option<u64>,
}

/// Shared interface for XMR and WOW wallet operations.
///
/// Both chains use the same CryptoNote protocol, so the interface is
/// identical. The swap state machine operates generically over this trait.
#[async_trait::async_trait]
pub trait CryptoNoteWallet: Send + Sync {
    /// Lock funds to the joint address derived from (spend_point, view_scalar).
    ///
    /// The joint address is constructed from the provided spend point (the
    /// combined public key of both parties) and view scalar. The wallet
    /// sends `amount` atomic units to this address.
    async fn lock(
        &self,
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
        amount: u64,
    ) -> Result<TxHash, WalletError>;

    /// Sweep all funds from the joint address using the combined secret.
    ///
    /// Uses `spend_secret` (the combined private spend key) and `view_scalar`
    /// to construct the full keypair, then sends all outputs to `destination`.
    async fn sweep(
        &self,
        spend_secret: &Scalar,
        view_scalar: &Scalar,
        destination: &str,
    ) -> Result<TxHash, WalletError>;

    /// Scan the chain for outputs at the joint address.
    ///
    /// Uses the view scalar and spend point to derive the joint address,
    /// then scans blocks from `from_height` onward for outputs.
    async fn scan(
        &self,
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
        from_height: u64,
    ) -> Result<Vec<ScanResult>, WalletError>;

    /// Poll whether a transaction has been confirmed.
    ///
    /// Returns the confirmation status including the number of confirmations
    /// and the block height where the transaction was included.
    async fn poll_confirmation(
        &self,
        tx_hash: &TxHash,
        required_confirmations: u64,
    ) -> Result<ConfirmationStatus, WalletError>;

    /// Sweep all funds from the joint address with a timelock on the transaction.
    ///
    /// Like `sweep()`, but the resulting transaction has `unlock_time` set to
    /// `refund_height` (block height). The daemon will reject broadcast of
    /// this tx before that block height.
    ///
    /// Returns `(tx_hash, serialized_tx_bytes)` -- the caller stores the raw bytes
    /// so they can be broadcast later after the timelock expires.
    async fn sweep_timelocked(
        &self,
        spend_secret: &Scalar,
        view_scalar: &Scalar,
        destination: &str,
        refund_height: u64,
    ) -> Result<(TxHash, Vec<u8>), WalletError>;

    /// Broadcast a pre-signed raw transaction to the daemon.
    ///
    /// Takes serialized transaction bytes (as returned by `sweep_timelocked`)
    /// and submits them to the daemon's `/sendrawtransaction` endpoint.
    /// Returns the tx hash on success, or an error containing the daemon's
    /// rejection message (useful for premature timelock rejection testing).
    async fn broadcast_raw_tx(&self, tx_bytes: &[u8]) -> Result<TxHash, WalletError>;

    /// Get the current block height from the daemon.
    ///
    /// Uses JSON-RPC `get_block_count` to query the daemon for the current
    /// chain height. Needed for timelock validation (computing refund heights
    /// from current height + lock period).
    async fn get_current_height(&self) -> Result<u64, WalletError>;
}
