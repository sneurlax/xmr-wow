//! High-level Monero wallet testing harness backed by `cuprate-simnet`.
//!
//! # Example
//! ```rust,no_run
//! # #[tokio::main] async fn main() {
//! use monero_simnet::MoneroSimnet;
//! let mut sim = MoneroSimnet::new().await.unwrap();
//! sim.add_funded_wallet("alice", 2, 61).await.unwrap();
//! assert!(sim.unlocked_balance("alice").await.unwrap() > 0);
//! # }
//! ```

use anyhow::{anyhow, Context};
use cuprate_simnet::{FeeRate, Network, SimnetNode, SimnetWallet, Timelock};

/// Default fee rate used for spend transactions (generous so fee arithmetic works).
const DEFAULT_FEE_PER_WEIGHT: u64 = 20_000;
const DEFAULT_FEE_MASK: u64 = 10_000;

/// High-level Monero simulation network with named wallets.
///
/// All wallets operate against a shared in-process [`SimnetNode`].
pub struct MoneroSimnet {
    /// The underlying in-process Monero node.
    pub node: SimnetNode,
    /// Named wallets: `(name, wallet)`.
    wallets: Vec<(String, SimnetWallet)>,
}

impl MoneroSimnet {
    /// Start a fresh simulation network with no wallets and no blocks (beyond genesis).
    pub async fn new() -> anyhow::Result<Self> {
        let node = SimnetNode::start()
            .await
            .context("failed to start SimnetNode")?;
        Ok(Self {
            node,
            wallets: Vec::new(),
        })
    }

    /// Add a named wallet, mine `fund_blocks` coinbase blocks to it, then mine
    /// `maturity_blocks` additional padding blocks (to satisfy the 60-block
    /// coinbase maturity requirement), and finally refresh the wallet.
    ///
    /// Returns the index of the new wallet in the internal list.
    pub async fn add_funded_wallet(
        &mut self,
        name: &str,
        fund_blocks: u64,
        maturity_blocks: u64,
    ) -> anyhow::Result<usize> {
        let wallet = SimnetWallet::generate();

        // Mine coinbase blocks directly to this wallet.
        if fund_blocks > 0 {
            self.node
                .mine_to(&wallet.spend_pub, &wallet.view_scalar, fund_blocks)
                .await
                .with_context(|| format!("mine_to failed for wallet '{name}'"))?;
        }

        // Mine padding blocks (coinbase to random keys) to satisfy maturity.
        if maturity_blocks > 0 {
            self.node
                .mine_blocks(maturity_blocks)
                .await
                .with_context(|| format!("mine_blocks failed for maturity of wallet '{name}'"))?;
        }

        let idx = self.wallets.len();
        self.wallets.push((name.to_owned(), wallet));

        // Refresh so the wallet sees its funded outputs.
        self.wallets[idx]
            .1
            .refresh(&mut self.node)
            .await
            .with_context(|| format!("refresh failed for wallet '{name}'"))?;

        Ok(idx)
    }

    // ── wallet accessors ──────────────────────────────────────────────────

    fn find(&self, name: &str) -> anyhow::Result<usize> {
        self.wallets
            .iter()
            .position(|(n, _)| n == name)
            .ok_or_else(|| anyhow!("wallet '{}' not found", name))
    }

    /// Get a reference to the named wallet.
    pub fn wallet(&self, name: &str) -> &SimnetWallet {
        let idx = self.find(name).expect("wallet not found");
        &self.wallets[idx].1
    }

    /// Get a mutable reference to the named wallet.
    pub fn wallet_mut(&mut self, name: &str) -> &mut SimnetWallet {
        let idx = self.find(name).expect("wallet not found");
        &mut self.wallets[idx].1
    }

    // ── bulk operations ───────────────────────────────────────────────────

    /// Refresh all wallets by scanning any new blocks.
    pub async fn refresh_all(&mut self) -> anyhow::Result<()> {
        // We need &mut self.node, but also iterate over wallets.
        // Collect indices first to avoid borrow conflicts.
        let count = self.wallets.len();
        for i in 0..count {
            self.wallets[i]
                .1
                .refresh(&mut self.node)
                .await
                .with_context(|| format!("refresh failed for wallet '{}'", self.wallets[i].0))?;
        }
        Ok(())
    }

    // ── chain helpers ─────────────────────────────────────────────────────

    /// Mine `n` blocks with coinbase outputs paid to a random, un-scannable key.
    /// Returns the new chain height.
    pub async fn mine_blocks(&mut self, n: u64) -> anyhow::Result<u64> {
        self.node
            .mine_blocks(n)
            .await
            .context("mine_blocks failed")
    }

    /// Current chain height (number of blocks committed, genesis = height 1).
    pub async fn height(&mut self) -> anyhow::Result<u64> {
        self.node.height().await.context("height() failed")
    }

    // ── balance ───────────────────────────────────────────────────────────

    /// Unlocked balance of the named wallet at the current chain tip.
    ///
    /// Refreshes the wallet first to ensure outputs are up to date.
    pub async fn unlocked_balance(&mut self, name: &str) -> anyhow::Result<u64> {
        let idx = self.find(name)?;
        self.wallets[idx]
            .1
            .refresh(&mut self.node)
            .await
            .with_context(|| format!("refresh failed before unlocked_balance for '{name}'"))?;
        let height = self.node.height().await.context("height() failed")?;
        Ok(self.wallets[idx].1.unlocked_balance(height as usize))
    }

    // ── transfers ─────────────────────────────────────────────────────────

    /// Send `amount` piconero from wallet `from` to wallet `to`.
    ///
    /// Internally:
    /// 1. Uses the sender's currently known unlocked outputs to build and sign a spend transaction.
    /// 2. Submits the transaction to the mempool.
    /// 3. Mines one block to confirm it.
    ///
    /// The current Cuprate-backed simnet stack cannot scan blocks containing regular
    /// transactions because `BlockchainReadRequest::Transactions` is still `todo!()`.
    /// Callers should refresh wallets before transfer construction, and treat successful
    /// submit+mine as transfer confirmation.
    pub async fn transfer(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> anyhow::Result<[u8; 32]> {
        let from_idx = self.find(from)?;
        let height = self.node.height().await.context("height() failed")?;

        // Fee headroom: generous upper bound so the output can cover amount + fee.
        // A typical CLSAG+BulletproofPlus tx weighs ~2500 bytes at 20_000 per weight.
        const FEE_HEADROOM: u64 = 20_000 * 3000;

        // Find the first unlocked output that can cover amount + fee.
        let output = {
            let w = &self.wallets[from_idx].1;
            w.outputs()
                .iter()
                .find(|o| {
                    let tl = o.additional_timelock();
                    let unlocked = matches!(tl, Timelock::None)
                        || matches!(tl, Timelock::Block(b) if b <= height as usize);
                    unlocked
                        && o.commitment().amount.saturating_sub(FEE_HEADROOM) > amount
                })
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "wallet '{from}' has no unlocked output with amount > {amount}+fee_headroom \
                         (height={height}, outputs={})",
                        w.output_count()
                    )
                })?
        };

        // Get recipient address.
        let to_idx = self.find(to)?;
        let recipient = self.wallets[to_idx].1.address(Network::Mainnet);

        // Build decoy RPC and fee rate.
        let decoy_rpc = self.node.decoy_rpc();
        let fee_rate =
            FeeRate::new(DEFAULT_FEE_PER_WEIGHT, DEFAULT_FEE_MASK).expect("valid fee rate");

        // Build and sign the transaction (requires &self on wallet, &decoy_rpc).
        let tx = self.wallets[from_idx]
            .1
            .build_spend_tx(output, recipient, amount, fee_rate, &decoy_rpc)
            .await
            .with_context(|| format!("build_spend_tx failed for '{from}' -> '{to}'"))?;

        // Submit to mempool.
        let tx_hash = self
            .node
            .submit_tx(tx.serialize())
            .with_context(|| "submit_tx failed")?;

        // Mine one block to confirm.
        self.node
            .mine_blocks(1)
            .await
            .context("mine_blocks(1) after submit_tx failed")?;

        Ok(tx_hash)
    }
}
