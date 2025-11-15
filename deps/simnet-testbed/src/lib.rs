//! Dual-chain simnet harness for swap integration tests.
//!
//! This crate stays outside the main workspace because the simnet forks pin an
//! older `monero-oxide` revision. `SimnetTestbed::new()` boots both chains,
//! mines maturity blocks, and exposes RPC URLs.

pub mod adaptor;

use std::sync::Arc;
use tokio::sync::Mutex;
use thiserror::Error;

use cuprate_simnet::{SimnetNode, start_rpc_server as xmr_start_rpc};
use wownero_simnet::{WowSimnetNode, start_rpc_server as wow_start_rpc};

// Re-export simnet crates for test helpers.
pub use cuprate_simnet;
pub use wownero_simnet;
pub use curve25519_dalek;

/// XMR maturity margin.
const XMR_MATURITY_BLOCKS: u64 = 80;

/// WOW maturity margin.
const WOW_MATURITY_BLOCKS: u64 = 30;

/// Simnet testbed errors.
#[derive(Debug, Error)]
pub enum TestbedError {
    #[error("XMR simnet error: {0}")]
    Xmr(#[from] cuprate_simnet::SimnetError),

    #[error("WOW simnet error: {0}")]
    Wow(#[from] wownero_simnet::SimnetError),
}

/// Dual-chain simnet harness.
pub struct SimnetTestbed {
    /// Shared XMR node.
    xmr_node: Arc<Mutex<SimnetNode>>,
    /// Shared WOW node.
    wow_node: Arc<Mutex<WowSimnetNode>>,
    /// XMR RPC URL.
    xmr_rpc_url: String,
    /// WOW RPC URL.
    wow_rpc_url: String,
}

impl SimnetTestbed {
    /// Start both simnets, mine maturity blocks, and bind RPC servers.
    pub async fn new() -> Result<Self, TestbedError> {
        // Bring up XMR and mine past maturity.
        let mut xmr_node = SimnetNode::start().await.map_err(TestbedError::Xmr)?;
        xmr_node.mine_blocks(XMR_MATURITY_BLOCKS).await.map_err(TestbedError::Xmr)?;

        // Bring up WOW and do the same.
        let mut wow_node = WowSimnetNode::start().await.map_err(TestbedError::Wow)?;
        wow_node.mine_blocks(WOW_MATURITY_BLOCKS).await.map_err(TestbedError::Wow)?;

        // Shared nodes back the RPC servers.
        let xmr_shared = Arc::new(Mutex::new(xmr_node));
        let wow_shared = Arc::new(Mutex::new(wow_node));

        // Bind both RPC servers on ephemeral ports.
        let xmr_addr = xmr_start_rpc(xmr_shared.clone(), 0).await.map_err(TestbedError::Xmr)?;
        let wow_addr = wow_start_rpc(wow_shared.clone(), 0).await.map_err(TestbedError::Wow)?;

        let xmr_rpc_url = format!("http://{}", xmr_addr);
        let wow_rpc_url = format!("http://{}", wow_addr);

        Ok(Self {
            xmr_node: xmr_shared,
            wow_node: wow_shared,
            xmr_rpc_url,
            wow_rpc_url,
        })
    }

    /// XMR RPC URL.
    pub fn xmr_rpc_url(&self) -> &str {
        &self.xmr_rpc_url
    }

    /// WOW RPC URL.
    pub fn wow_rpc_url(&self) -> &str {
        &self.wow_rpc_url
    }

    /// Mine `n` blocks on the XMR chain.
    pub async fn mine_xmr(&self, n: u64) -> Result<u64, TestbedError> {
        let mut node = self.xmr_node.lock().await;
        node.mine_blocks(n).await.map_err(TestbedError::Xmr)
    }

    /// Mine `n` blocks on the WOW chain.
    pub async fn mine_wow(&self, n: u64) -> Result<u64, TestbedError> {
        let mut node = self.wow_node.lock().await;
        node.mine_blocks(n).await.map_err(TestbedError::Wow)
    }

    /// Mine `n` blocks on XMR with coinbase payable to the given wallet keys.
    pub async fn mine_xmr_to(
        &self,
        spend_pub: &curve25519_dalek::EdwardsPoint,
        view_scalar: &curve25519_dalek::Scalar,
        n: u64,
    ) -> Result<u64, TestbedError> {
        let mut node = self.xmr_node.lock().await;
        node.mine_to(spend_pub, view_scalar, n).await.map_err(TestbedError::Xmr)
    }

    /// Mine `n` blocks on WOW with coinbase payable to the given wallet keys.
    pub async fn mine_wow_to(
        &self,
        spend_pub: &curve25519_dalek::EdwardsPoint,
        view_scalar: &curve25519_dalek::Scalar,
        n: u64,
    ) -> Result<u64, TestbedError> {
        let mut node = self.wow_node.lock().await;
        node.mine_to(spend_pub, view_scalar, n).await.map_err(TestbedError::Wow)
    }

    /// Current XMR height.
    pub async fn xmr_height(&self) -> Result<u64, TestbedError> {
        let mut node = self.xmr_node.lock().await;
        node.height().await.map_err(TestbedError::Xmr)
    }

    /// Current WOW height.
    pub async fn wow_height(&self) -> Result<u64, TestbedError> {
        let mut node = self.wow_node.lock().await;
        node.height().await.map_err(TestbedError::Wow)
    }

    /// Shared XMR node handle.
    pub fn xmr_node(&self) -> &Arc<Mutex<SimnetNode>> {
        &self.xmr_node
    }

    /// Shared WOW node handle.
    pub fn wow_node(&self) -> &Arc<Mutex<WowSimnetNode>> {
        &self.wow_node
    }
}
