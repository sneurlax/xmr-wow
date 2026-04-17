//! CryptoNoteWallet trait -- shared interface for XMR and WOW wallet operations.
//!
//! Both XmrWallet and WowWallet implement this trait. The swap state machine
//! is generic over it, enabling chain-agnostic swap logic.
//!
//! Per D-06: Crypto crate handles joint key math (keysplit.rs). This trait
//! takes `(spend_point, view_scalar)` pairs as input. Clean separation:
//! crypto = key math, wallet = on-chain ops.
//!
//! ## VTS Refund Guarantees (v1.6)
//!
//! Refund artifacts now lock the refund spend secret behind a VTS time-lock
//! puzzle instead of embedding `unlock_time` in a pre-signed transaction.
//! The solver recovers the secret after the difficulty period, then uses
//! `sweep()` with the recovered secret to claim the refund.

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use sha2::{Digest, Sha256};

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

/// Chain identifier for typed refund artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RefundChain {
    Xmr,
    Wow,
}

/// Metadata that binds a refund artifact to a specific lock and destination.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefundArtifactMetadata {
    pub chain: RefundChain,
    pub lock_tx_hash: TxHash,
    pub destination: String,
    /// Time-lock duration in seconds (replaces legacy `refund_height` block count).
    pub refund_delay_seconds: u64,
    /// SHA-256 of the locked refund secret (for post-solve verification).
    pub secret_hash: [u8; 32],
}

/// VTS-based refund artifact produced by the wallet layer.
///
/// Instead of containing a pre-signed time-locked transaction (which Monero
/// relay policy rejects for non-coinbase), this artifact locks the refund
/// spend secret behind a VTS time-lock puzzle. The secret is recovered by
/// sequential squaring after the configured delay period.
///
/// ## Refund Flow
///
/// 1. **Generate**: `build_refund_artifact()` locks `spend_secret` behind a
///    VTS puzzle calibrated for `refund_delay_seconds`.
/// 2. **Wait**: The solving party performs sequential squarings for the delay
///    period to recover the spend secret.
/// 3. **Sweep**: Once the secret is recovered, call `sweep()` with the
///    recovered secret to claim funds from the joint address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RefundArtifact {
    pub metadata: RefundArtifactMetadata,
    /// VTS time-lock puzzle containing the locked refund spend secret.
    pub puzzle: xmr_wow_vts::TimeLockPuzzle,
}

impl RefundArtifact {
    /// Create a new VTS-based refund artifact.
    ///
    /// Locks `secret` (the refund spend secret) behind a time-lock puzzle
    /// calibrated for `refund_delay_seconds` of sequential computation.
    pub fn new(
        chain: RefundChain,
        lock_tx_hash: TxHash,
        destination: impl Into<String>,
        refund_delay_seconds: u64,
        secret: &[u8],
        squarings_per_second: u64,
    ) -> Result<Self, WalletError> {
        let secret_hash = Self::secret_hash(secret);
        let (puzzle, _modulus) = xmr_wow_vts::TimeLockPuzzle::generate(
            secret, refund_delay_seconds, squarings_per_second,
        )
        .map_err(|e| WalletError::ArtifactInvalid(format!("VTS puzzle generation failed: {}", e)))?;

        let metadata = RefundArtifactMetadata {
            chain,
            lock_tx_hash,
            destination: destination.into(),
            refund_delay_seconds,
            secret_hash,
        };

        Ok(Self { metadata, puzzle })
    }

    /// Compute SHA-256 of the refund secret for post-solve verification.
    pub fn secret_hash(secret: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }

    /// Solve the VTS puzzle to recover the locked refund secret.
    ///
    /// This performs `t` sequential squarings; intentionally slow.
    /// The solve time is proportional to `refund_delay_seconds`.
    pub fn solve(&self) -> Result<Vec<u8>, WalletError> {
        self.puzzle
            .solve()
            .map_err(|e| WalletError::ArtifactInvalid(format!("puzzle solve failed: {}", e)))
    }

    /// Validate that a solved secret matches the stored hash.
    pub fn validate_solved_secret(&self, secret: &[u8]) -> Result<(), WalletError> {
        let actual_hash = Self::secret_hash(secret);
        if self.metadata.secret_hash != actual_hash {
            return Err(WalletError::ArtifactInvalid(format!(
                "secret hash mismatch: stored={} actual={}",
                hex::encode(self.metadata.secret_hash),
                hex::encode(actual_hash),
            )));
        }
        Ok(())
    }

    /// Validate basic structural properties of the artifact and its puzzle.
    pub fn validate_structure(&self) -> Result<(), WalletError> {
        self.puzzle
            .validate()
            .map_err(|e| WalletError::ArtifactInvalid(format!("invalid puzzle structure: {}", e)))
    }

    /// Validate that the artifact is bound to the expected parameters.
    pub fn validate_binding(
        &self,
        expected_chain: RefundChain,
        expected_lock_tx_hash: TxHash,
        expected_destination: &str,
    ) -> Result<(), WalletError> {
        self.validate_structure()?;

        if self.metadata.chain != expected_chain {
            return Err(WalletError::ArtifactInvalid(format!(
                "artifact chain mismatch: expected {:?}, got {:?}",
                expected_chain, self.metadata.chain,
            )));
        }

        if self.metadata.lock_tx_hash != expected_lock_tx_hash {
            return Err(WalletError::ArtifactInvalid(format!(
                "artifact lock tx mismatch: expected {}, got {}",
                hex::encode(expected_lock_tx_hash),
                hex::encode(self.metadata.lock_tx_hash),
            )));
        }

        if self.metadata.destination != expected_destination {
            return Err(WalletError::ArtifactInvalid(format!(
                "artifact destination mismatch: expected {}, got {}",
                expected_destination, self.metadata.destination,
            )));
        }

        Ok(())
    }
}

/// Shared interface for XMR and WOW wallet operations.
///
/// Both chains use the same CryptoNote protocol, so the interface is
/// identical. The swap state machine operates generically over this trait.
#[async_trait::async_trait]
pub trait CryptoNoteWallet: Send + Sync {
    /// Which chain this wallet instance targets for typed refund artifacts.
    fn refund_chain(&self) -> RefundChain;

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

    /// Build a VTS-based refund artifact for the given swap parameters.
    ///
    /// Locks the refund spend secret behind a VTS time-lock puzzle calibrated
    /// for `refund_delay_seconds` of sequential computation. After solving the
    /// puzzle, the recovered secret can be used with `sweep()` to reclaim funds.
    ///
    /// This replaces the legacy `sweep_timelocked` / `build_refund_artifact` flow
    /// that embedded `unlock_time` in a pre-signed transaction (rejected by modern
    /// Monero relay policy for non-coinbase transactions).
    async fn build_refund_artifact(
        &self,
        spend_secret: &Scalar,
        _view_scalar: &Scalar,
        destination: &str,
        refund_delay_seconds: u64,
        lock_tx_hash: TxHash,
    ) -> Result<RefundArtifact, WalletError> {
        // The refund secret is the spend secret bytes; this is what gets
        // locked behind the VTS puzzle. After the delay, the solver recovers
        // these bytes and uses them with sweep() to claim the refund.
        let secret = spend_secret.as_bytes();
        RefundArtifact::new(
            self.refund_chain(),
            lock_tx_hash,
            destination,
            refund_delay_seconds,
            secret,
            xmr_wow_vts::calibration::DEFAULT_SQUARINGS_PER_SECOND,
        )
    }

    /// Broadcast a pre-signed raw transaction to the daemon.
    ///
    /// Takes serialized transaction bytes and submits them to the daemon's
    /// `/sendrawtransaction` endpoint. Returns the tx hash on success, or
    /// an error containing the daemon's rejection message.
    async fn broadcast_raw_tx(&self, tx_bytes: &[u8]) -> Result<TxHash, WalletError>;

    /// Get the current block height from the daemon.
    ///
    /// Uses JSON-RPC `get_block_count` to query the daemon for the current
    /// chain height.
    async fn get_current_height(&self) -> Result<u64, WalletError>;
}
