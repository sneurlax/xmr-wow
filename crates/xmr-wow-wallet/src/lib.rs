//! Wallet adapters for XMR and WOW atomic swap operations.
//!
//! This crate provides the `CryptoNoteWallet` trait and concrete
//! implementations for Monero (XmrWallet) and Wownero (WowWallet).
//!
//! The trait defines four operations needed for atomic swaps:
//! - `lock`: Send funds to a joint address
//! - `sweep`: Claim funds from a joint address using the revealed secret
//! - `scan`: Check for outputs at a joint address
//! - `poll_confirmation`: Wait for transaction confirmations

pub mod error;
pub mod rpc_transport;
pub mod trait_def;
pub mod view_key;
pub mod wow;
pub mod xmr;

pub use error::WalletError;
pub use rpc_transport::ReqwestTransport;
pub use trait_def::{
    ConfirmationStatus, CryptoNoteWallet, RefundArtifact, RefundArtifactMetadata, RefundChain,
    ScanResult, TxHash,
};
pub use view_key::verify_lock;
pub use wow::WowWallet;
pub use xmr::XmrWallet;
