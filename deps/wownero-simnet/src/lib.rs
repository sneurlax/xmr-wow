#![recursion_limit = "256"]
//! In-process Wownero simulation network for testing.
//!
//! This is a fork of `cuprate-simnet` with Wownero consensus parameters:
//! - Ring size: 22 (vs Monero's 16)
//! - Coinbase lock window (spendable age): 4 blocks (vs Monero's 60)
//! - RctType: WowneroClsagBulletproofPlus (wire type 8)
//!
//! **Note:** The wallet-layer `wownero_wallet` dep is currently aliased from
//! `monero-wallet` at the same rev cuprate pins (7c288b0). This rev does not
//! have `RctType::WowneroClsagBulletproofPlus` or ring-size-22 validation.
//! The ring_len constant is set to 22 for correctness, but `SignableTransaction`
//! will reject it at runtime until wownero-wallet (HEAD) replaces the git dep.
//! Scanning, mining, and block operations are fully functional with WOW params.
//!
//! ```rust,no_run
//! # #[tokio::main] async fn main() {
//! use wownero_simnet::WowSimnetNode;
//! let mut node = WowSimnetNode::start().await.unwrap();
//! node.mine_blocks(10).await.unwrap();
//! assert_eq!(node.height().await.unwrap(), 11);
//! # }
//! ```

pub mod child_chain;
pub mod config;
pub mod error;
pub mod miner;
pub mod network;
pub mod node;
pub mod rpc;
pub mod wallet;

pub use child_chain::ChildBlock;
pub use config::WowSimnetConfig;
pub use error::SimnetError;
pub use network::WowSimnet;
pub use node::{PendingTx, WowSimnetDecoyRpc, WowSimnetNode};
pub use rpc::start_rpc_server;

pub use wallet::WowSimnetWallet;

// Wallet scanning primitives re-exported for convenience.
pub use curve25519_dalek::{EdwardsPoint, Scalar};
pub use wownero_wallet::{Scanner, ViewPair, WalletOutput};
