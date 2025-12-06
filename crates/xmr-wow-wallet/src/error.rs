//! Wallet error types.

use thiserror::Error;

/// Wallet operation errors.
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("RPC connection failed: {0}")]
    RpcConnection(String),

    #[error("RPC request failed: {0}")]
    RpcRequest(String),

    #[error("transaction broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("insufficient funds: need {need} atomic units, have {have}")]
    InsufficientFunds { need: u64, have: u64 },

    #[error("no outputs found at joint address")]
    NoOutputsFound,

    #[error("scan failed: {0}")]
    ScanFailed(String),

    #[error("transaction not found: {0}")]
    TxNotFound(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("key error: {0}")]
    KeyError(String),

    #[error("transaction building failed: {0}")]
    TxBuildFailed(String),

    #[error("refund artifact invalid: {0}")]
    ArtifactInvalid(String),
}
