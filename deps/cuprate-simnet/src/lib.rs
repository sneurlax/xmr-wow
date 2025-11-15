#![recursion_limit = "256"]
//! In-process Monero simulation network for testing.
//!
//! ```rust,no_run
//! # #[tokio::main] async fn main() {
//! use cuprate_simnet::SimnetNode;
//! let mut node = SimnetNode::start().await.unwrap();
//! node.mine_blocks(60).await.unwrap();
//! assert_eq!(node.height().await.unwrap(), 61);
//! # }
//! ```

pub mod child_chain;
pub mod config;
pub mod error;
pub mod miner;
pub mod network;
pub mod node;
pub mod rpc;
#[cfg(feature = "merge-mining")]
pub mod two_chain;
pub mod wallet;

pub use child_chain::ChildBlock;
pub use config::SimnetConfig;
pub use error::SimnetError;
pub use network::Simnet;
pub use node::{PendingTx, SimnetDecoyRpc, SimnetNode};
pub use rpc::start_rpc_server;
#[cfg(feature = "merge-mining")]
pub use two_chain::TwoChainSimnet;

pub use wallet::SimnetWallet;

// Wallet scanning primitives re-exported for convenience.
pub use curve25519_dalek::{EdwardsPoint, Scalar};
pub use monero_wallet::{
    address::Network,
    interface::FeeRate,
    transaction::Timelock,
    Scanner, ViewPair, WalletOutput,
};
