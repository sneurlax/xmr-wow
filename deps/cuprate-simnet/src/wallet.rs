//! Stateful Monero wallet for simnet testing.
//!
//! Provides key generation, address derivation, block scanning, output
//! accumulation, and balance reporting against a live [`SimnetNode`].

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, EdwardsPoint, Scalar};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use monero_oxide::{
    ed25519::CompressedPoint,
    transaction::Transaction as OxideTransaction,
};
use monero_wallet::{
    address::{MoneroAddress, Network, SubaddressIndex},
    interface::FeeRate,
    ringct::RctType,
    send::{Change, SendError, SignableTransaction},
    transaction::Timelock,
    OutputWithDecoys, Scanner, ViewPair, ViewPairError, WalletOutput,
};

use crate::{error::SimnetError, node::{SimnetDecoyRpc, SimnetNode}};

/// A stateful Monero wallet that can scan blocks produced by a [`SimnetNode`].
pub struct SimnetWallet {
    /// Private spend key.
    pub spend_scalar: Zeroizing<Scalar>,
    /// Public spend key.
    pub spend_pub: EdwardsPoint,
    /// Private view key.
    pub view_scalar: Zeroizing<Scalar>,
    /// Public view key.
    pub view_pub: EdwardsPoint,
    /// Persistent scanner that holds registered subaddresses.
    scanner: Scanner,
    /// Accumulated outputs found by scanning.
    outputs: Vec<WalletOutput>,
    /// Next height to scan (exclusive upper bound of already-scanned range).
    last_scanned_height: usize,
}

impl SimnetWallet {
    // ── constructors ──────────────────────────────────────────────────────

    fn random_scalar() -> Scalar {
        use rand::RngCore as _;

        let mut wide = [0u8; 64];
        OsRng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    /// Generate a fresh wallet with random keys.
    pub fn generate() -> Self {
        let spend_scalar = Zeroizing::new(Self::random_scalar());
        let view_scalar = Zeroizing::new(Self::random_scalar());
        Self::from_scalars(spend_scalar, view_scalar)
    }

    /// Construct a wallet from existing scalars.
    pub fn from_scalars(
        spend_scalar: Zeroizing<Scalar>,
        view_scalar: Zeroizing<Scalar>,
    ) -> Self {
        let spend_pub = &*spend_scalar * ED25519_BASEPOINT_TABLE;
        let view_pub = &*view_scalar * ED25519_BASEPOINT_TABLE;
        let scanner = {
            let vp = ViewPair::new(
                monero_oxide::ed25519::Point::from(spend_pub),
                Zeroizing::new(monero_oxide::ed25519::Scalar::from(*view_scalar)),
            )
                .expect("freshly derived spend_pub is always torsion-free");
            Scanner::new(vp)
        };
        Self {
            spend_scalar,
            spend_pub,
            view_scalar,
            view_pub,
            scanner,
            outputs: Vec::new(),
            last_scanned_height: 0,
        }
    }

    // ── key helpers ───────────────────────────────────────────────────────

    /// Build a `ViewPair` for external callers (does not require the spend scalar).
    pub fn view_pair(&self) -> Result<ViewPair, ViewPairError> {
        ViewPair::new(
            monero_oxide::ed25519::Point::from(self.spend_pub),
            Zeroizing::new(monero_oxide::ed25519::Scalar::from(*self.view_scalar)),
        )
    }

    /// Build a fresh `Scanner` for external callers.
    ///
    /// This scanner is independent of the wallet's internal stateful scanner
    /// and does not share registered subaddresses.
    pub fn scanner(&self) -> Result<Scanner, ViewPairError> {
        self.view_pair().map(Scanner::new)
    }

    /// The wallet's primary (legacy) address on the given network.
    pub fn address(&self, network: Network) -> MoneroAddress {
        let vp = self.view_pair().expect("valid keys");
        vp.legacy_address(network)
    }

    /// Register a subaddress so the internal scanner will detect outputs sent
    /// to it, and return that subaddress's `MoneroAddress`.
    ///
    /// Panics if `(account, index) == (0, 0)` since that is the primary
    /// address, not a subaddress.
    pub fn subaddress(
        &mut self,
        account: u32,
        index: u32,
        network: Network,
    ) -> Result<MoneroAddress, SimnetError> {
        let sub_idx = SubaddressIndex::new(account, index).ok_or_else(|| {
            SimnetError::Consensus(
                "(0, 0) is the primary address, not a valid subaddress".into(),
            )
        })?;
        self.scanner.register_subaddress(sub_idx);
        let vp = self.view_pair().map_err(|e| {
            SimnetError::Consensus(format!("view_pair: {e}").into())
        })?;
        Ok(vp.subaddress(network, sub_idx))
    }

    // ── scanning ──────────────────────────────────────────────────────────

    /// Scan a single block at `height`.
    ///
    /// Returns immediately if `height < self.last_scanned_height`.
    pub async fn scan_block(
        &mut self,
        node: &mut SimnetNode,
        height: usize,
    ) -> Result<(), SimnetError> {
        if height < self.last_scanned_height {
            return Ok(());
        }
        let scannable = node.scannable_block_at(height).await?;
        let timelocked = self.scanner.scan(scannable)
            .map_err(|e| SimnetError::Consensus(format!("scan error: {e}").into()))?;
        self.outputs.extend(timelocked.ignore_additional_timelock());
        self.last_scanned_height = height + 1;
        Ok(())
    }

    /// Scan every block from `last_scanned_height` to the current chain tip.
    pub async fn refresh(&mut self, node: &mut SimnetNode) -> Result<(), SimnetError> {
        let tip = node.height().await? as usize;
        let start = self.last_scanned_height;
        for h in start..tip {
            self.scan_block(node, h).await?;
        }
        Ok(())
    }

    // ── balance ───────────────────────────────────────────────────────────

    /// Sum of all accumulated output amounts (ignoring timelocks).
    pub fn balance(&self) -> u64 {
        self.outputs.iter().map(|o| o.commitment().amount).sum()
    }

    /// Balance excluding outputs whose additional timelock has not yet been
    /// satisfied.
    ///
    /// `current_height` is the current chain height (number of blocks mined,
    /// i.e. what `SimnetNode::height()` returns cast to `usize`).
    pub fn unlocked_balance(&self, current_height: usize) -> u64 {
        self.outputs
            .iter()
            .filter(|o| {
                let tl = o.additional_timelock();
                matches!(tl, Timelock::None)
                    || matches!(tl, Timelock::Block(b) if b <= current_height)
            })
            .map(|o| o.commitment().amount)
            .sum()
    }

    /// References to outputs whose additional timelock is satisfied at
    /// `current_height`.
    pub fn unlocked_outputs(&self, current_height: usize) -> Vec<&WalletOutput> {
        self.outputs
            .iter()
            .filter(|o| {
                let tl = o.additional_timelock();
                matches!(tl, Timelock::None)
                    || matches!(tl, Timelock::Block(b) if b <= current_height)
            })
            .collect()
    }

    /// Greedy coin selection: returns a minimal set of unlocked outputs whose
    /// combined amount is ≥ `target`, or `None` if funds are insufficient.
    ///
    /// Outputs are sorted descending by amount so the fewest inputs are used.
    pub fn coin_select(&self, current_height: usize, target: u64) -> Option<Vec<WalletOutput>> {
        let mut candidates: Vec<&WalletOutput> = self.unlocked_outputs(current_height);
        candidates.sort_by(|a, b| b.commitment().amount.cmp(&a.commitment().amount));

        let mut selected = Vec::new();
        let mut accumulated: u64 = 0;
        for output in candidates {
            selected.push(output.clone());
            accumulated = accumulated.saturating_add(output.commitment().amount);
            if accumulated >= target {
                return Some(selected);
            }
        }
        None
    }

    // ── accessors ─────────────────────────────────────────────────────────

    /// The last scanned height (exclusive upper bound).
    ///
    /// Blocks `[0, last_scanned_height)` have been scanned.
    pub fn last_scanned_height(&self) -> usize {
        self.last_scanned_height
    }

    /// All accumulated outputs.
    pub fn outputs(&self) -> &[WalletOutput] {
        &self.outputs
    }

    /// Number of accumulated outputs.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    // ── spending ──────────────────────────────────────────────────────────

    /// Compute the key image for the output at `index` in `self.outputs`.
    ///
    /// The key image is `spend_key * Hp(output_key)` where
    /// `spend_key = spend_scalar + key_offset`.
    ///
    /// Returns `None` if `index` is out of bounds.
    /// Returns `CompressedPoint` = `monero_oxide::ed25519::CompressedPoint`.
    pub fn key_image_for_output(&self, index: usize) -> Option<CompressedPoint> {
        let output = self.outputs.get(index)?;
        let key_offset: curve25519_dalek::Scalar = output.key_offset().into();
        let full_key = *self.spend_scalar + key_offset;
        let hp = monero_oxide::ed25519::Point::biased_hash(output.key().compress().to_bytes());
        let key_image = full_key * hp.into();
        Some(CompressedPoint::from(key_image.compress().to_bytes()))
    }

    /// Build and sign a transaction that spends `output`, sending `amount` to
    /// `recipient` with any change returned to this wallet.
    ///
    /// # Arguments
    /// * `output` – a scanned `WalletOutput` owned by this wallet
    /// * `recipient` – destination address
    /// * `amount` – piconero amount to send (must be ≤ output amount minus fee)
    /// * `fee_rate` – fee rate from `FeeRate::new(per_weight, mask)`
    /// * `decoy_rpc` – a `SimnetDecoyRpc` obtained from `node.decoy_rpc()`
    ///
    /// The CLSAG ring size for HF16 is 16 (1 real + 15 decoys). You must have
    /// at least 75 blocks in the chain (60 for coinbase maturity + 15 for
    /// decoys) before this succeeds.
    ///
    /// Returns the signed `Transaction` ready for submission via
    /// `node.submit_tx(tx.serialize())`.
    pub async fn build_spend_tx(
        &self,
        output: WalletOutput,
        recipient: MoneroAddress,
        amount: u64,
        fee_rate: FeeRate,
        decoy_rpc: &SimnetDecoyRpc,
    ) -> Result<OxideTransaction, SimnetError> {
        // HF16 uses ClsagBulletproofPlus with ring size 16.
        let rct_type = RctType::ClsagBulletproofPlus;
        let ring_len: u8 = 16;

        // Decoy selection expects the latest block number, not the chain height.
        let block_number = {
            use monero_wallet::interface::ProvidesBlockchainMeta;
            decoy_rpc
                .latest_block_number()
                .await
                .map_err(|e| SimnetError::Consensus(format!("get latest block number: {e}").into()))?
        };

        // Select decoys.
        let output_with_decoys = OutputWithDecoys::fingerprintable_deterministic_new(
            &mut OsRng,
            decoy_rpc,
            ring_len,
            block_number,
            output,
        )
        .await
        .map_err(|e| SimnetError::Consensus(format!("decoy selection: {e}").into()))?;

        // Build the change specification (send change back to this wallet).
        let change_view_pair = self
            .view_pair()
            .map_err(|e| SimnetError::Consensus(format!("view_pair: {e}").into()))?;
        let change = Change::new(change_view_pair, None);

        // Random outgoing view key (privacy requirement of SignableTransaction).
        let mut outgoing_view_key = Zeroizing::new([0u8; 32]);
        use rand::RngCore as _;
        OsRng.fill_bytes(outgoing_view_key.as_mut());

        // Build the signable transaction.
        let signable = SignableTransaction::new(
            rct_type,
            outgoing_view_key,
            vec![output_with_decoys],
            vec![(recipient, amount)],
            change,
            vec![],
            fee_rate,
        )
        .map_err(|e: SendError| SimnetError::Consensus(format!("build tx: {e}").into()))?;

        let oxide_spend_key =
            Zeroizing::new(monero_oxide::ed25519::Scalar::from(*self.spend_scalar));
        let tx = signable
            .sign(&mut OsRng, &oxide_spend_key)
            .map_err(|e: SendError| SimnetError::Consensus(format!("sign tx: {e}").into()))?;

        Ok(tx)
    }

    /// Build and sign a transaction that spends multiple `outputs`, sending
    /// `amount` to `recipient` with any change returned to this wallet.
    ///
    /// Each output gets its own CLSAG ring (ring size 16). The chain must have
    /// enough outputs and depth for decoy selection to succeed for every input.
    pub async fn build_spend_tx_multi(
        &self,
        outputs: Vec<WalletOutput>,
        recipient: MoneroAddress,
        amount: u64,
        fee_rate: FeeRate,
        decoy_rpc: &SimnetDecoyRpc,
    ) -> Result<OxideTransaction, SimnetError> {
        let rct_type = RctType::ClsagBulletproofPlus;
        let ring_len: u8 = 16;

        let block_number = {
            use monero_wallet::interface::ProvidesBlockchainMeta;
            decoy_rpc
                .latest_block_number()
                .await
                .map_err(|e| SimnetError::Consensus(format!("get latest block number: {e}").into()))?
        };

        let mut inputs = Vec::with_capacity(outputs.len());
        for output in outputs {
            let owd = OutputWithDecoys::fingerprintable_deterministic_new(
                &mut OsRng,
                decoy_rpc,
                ring_len,
                block_number,
                output,
            )
            .await
            .map_err(|e| SimnetError::Consensus(format!("decoy selection: {e}").into()))?;
            inputs.push(owd);
        }

        let change_view_pair = self
            .view_pair()
            .map_err(|e| SimnetError::Consensus(format!("view_pair: {e}").into()))?;
        let change = Change::new(change_view_pair, None);

        let mut outgoing_view_key = Zeroizing::new([0u8; 32]);
        use rand::RngCore as _;
        OsRng.fill_bytes(outgoing_view_key.as_mut());

        let signable = SignableTransaction::new(
            rct_type,
            outgoing_view_key,
            inputs,
            vec![(recipient, amount)],
            change,
            vec![],
            fee_rate,
        )
        .map_err(|e: SendError| SimnetError::Consensus(format!("build tx: {e}").into()))?;

        let oxide_spend_key =
            Zeroizing::new(monero_oxide::ed25519::Scalar::from(*self.spend_scalar));
        let tx = signable
            .sign(&mut OsRng, &oxide_spend_key)
            .map_err(|e: SendError| SimnetError::Consensus(format!("sign tx: {e}").into()))?;

        Ok(tx)
    }
}
