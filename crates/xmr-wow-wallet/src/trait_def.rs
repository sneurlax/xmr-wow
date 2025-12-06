//! CryptoNoteWallet trait -- shared interface for XMR and WOW wallet operations.
//!
//! Both XmrWallet and WowWallet implement this trait. The swap state machine
//! is generic over it, enabling chain-agnostic swap logic.
//!
//! Per D-06: Crypto crate handles joint key math (keysplit.rs). This trait
//! takes `(spend_point, view_scalar)` pairs as input. Clean separation:
//! crypto = key math, wallet = on-chain ops.

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
    pub refund_height: u64,
    pub payload_hash: [u8; 32],
}

/// Typed refund artifact produced by the wallet layer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefundArtifact {
    pub metadata: RefundArtifactMetadata,
    pub tx_hash: TxHash,
    pub tx_bytes: Vec<u8>,
}

impl RefundArtifact {
    pub fn new(
        chain: RefundChain,
        lock_tx_hash: TxHash,
        destination: impl Into<String>,
        refund_height: u64,
        tx_hash: TxHash,
        tx_bytes: Vec<u8>,
    ) -> Self {
        let metadata = RefundArtifactMetadata {
            chain,
            lock_tx_hash,
            destination: destination.into(),
            refund_height,
            payload_hash: Self::payload_hash(&tx_bytes),
        };

        Self {
            metadata,
            tx_hash,
            tx_bytes,
        }
    }

    pub fn payload_hash(tx_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(tx_bytes);
        let digest = hasher.finalize();
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&digest);
        payload_hash
    }

    pub fn validate_self_integrity(&self) -> Result<(), WalletError> {
        let actual = Self::payload_hash(&self.tx_bytes);
        if self.metadata.payload_hash != actual {
            return Err(WalletError::ArtifactInvalid(format!(
                "payload hash mismatch: stored={} actual={}",
                hex::encode(self.metadata.payload_hash),
                hex::encode(actual),
            )));
        }

        Ok(())
    }

    pub fn validate_binding(
        &self,
        expected_chain: RefundChain,
        expected_lock_tx_hash: TxHash,
        expected_destination: &str,
        expected_refund_height: u64,
    ) -> Result<(), WalletError> {
        self.validate_self_integrity()?;

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

        if self.metadata.refund_height != expected_refund_height {
            return Err(WalletError::ArtifactInvalid(format!(
                "artifact refund height mismatch: expected {}, got {}",
                expected_refund_height, self.metadata.refund_height,
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

    /// Build a typed refund artifact bound to a specific lock and destination.
    async fn build_refund_artifact(
        &self,
        spend_secret: &Scalar,
        view_scalar: &Scalar,
        destination: &str,
        refund_height: u64,
        lock_tx_hash: TxHash,
    ) -> Result<RefundArtifact, WalletError> {
        let (tx_hash, tx_bytes) = self
            .sweep_timelocked(spend_secret, view_scalar, destination, refund_height)
            .await?;

        Ok(RefundArtifact::new(
            self.refund_chain(),
            lock_tx_hash,
            destination,
            refund_height,
            tx_hash,
            tx_bytes,
        ))
    }

    /// Validate a typed refund artifact before storing or broadcasting it.
    fn validate_refund_artifact(&self, artifact: &RefundArtifact) -> Result<(), WalletError> {
        artifact.validate_binding(
            self.refund_chain(),
            artifact.metadata.lock_tx_hash,
            &artifact.metadata.destination,
            artifact.metadata.refund_height,
        )
    }

    /// Broadcast a pre-signed raw transaction to the daemon.
    ///
    /// Takes serialized transaction bytes (as returned by `sweep_timelocked`)
    /// and submits them to the daemon's `/sendrawtransaction` endpoint.
    /// Returns the tx hash on success, or an error containing the daemon's
    /// rejection message (useful for premature timelock rejection testing).
    async fn broadcast_raw_tx(&self, tx_bytes: &[u8]) -> Result<TxHash, WalletError>;

    /// Validate and broadcast a typed refund artifact.
    async fn broadcast_refund_artifact(
        &self,
        artifact: &RefundArtifact,
    ) -> Result<TxHash, WalletError> {
        self.validate_refund_artifact(artifact)?;
        let tx_hash = self.broadcast_raw_tx(&artifact.tx_bytes).await?;
        if tx_hash != artifact.tx_hash {
            return Err(WalletError::ArtifactInvalid(format!(
                "broadcast tx hash mismatch: expected {}, got {}",
                hex::encode(artifact.tx_hash),
                hex::encode(tx_hash),
            )));
        }
        Ok(tx_hash)
    }

    /// Get the current block height from the daemon.
    ///
    /// Uses JSON-RPC `get_block_count` to query the daemon for the current
    /// chain height. Needed for timelock validation (computing refund heights
    /// from current height + lock period).
    async fn get_current_height(&self) -> Result<u64, WalletError>;
}
