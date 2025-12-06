//! XMR wallet adapter for Monero stagenet.
//!
//! Uses monero-oxide's wallet APIs (Scanner, ViewPair, SignableTransaction) directly
//! for output scanning and transaction construction. Block fetching and tx submission
//! use reqwest HTTP calls to monerod, consistent with the existing NativeRpcClient pattern.
//!
//! ## Architecture
//!
//! XmrWallet holds a daemon URL and optional sender credentials. The four trait methods
//! map to monerod endpoints via reqwest:
//!
//! - `lock` -> scan sender wallet, build SignableTransaction to joint address, broadcast
//! - `sweep` -> scan joint address for outputs, build sweep tx, broadcast
//! - `scan` -> fetch blocks from monerod, parse with monero-oxide, scan with Scanner
//! - `poll_confirmation` -> `/get_transactions` + `/json_rpc get_block_count`
//!
//! ## monero-oxide Integration
//!
//! This module bypasses monero-rust's scanner.rs (26 stubs) and tx_builder.rs (3 stubs)
//! by using monero-oxide's wallet APIs directly:
//! - `monero_wallet::ViewPair` + `monero_wallet::Scanner` for output detection
//! - `monero_wallet::send::SignableTransaction` for transaction construction
//! - `monero_oxide::block::Block` and `monero_oxide::transaction::Transaction` for parsing

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::EdwardsPoint,
    scalar::Scalar,
};
use zeroize::Zeroizing;
use tracing;

use monero_rust::rpc_serai::NativeRpcClient;
use monero_rust::abstractions::RpcClient;

use crate::error::WalletError;
use crate::trait_def::{ConfirmationStatus, CryptoNoteWallet, RefundChain, ScanResult, TxHash};

/// XMR wallet adapter for Monero stagenet.
///
/// Implements `CryptoNoteWallet` using monero-oxide's wallet APIs directly for
/// scanning (Scanner + ViewPair) and transaction construction (SignableTransaction).
///
/// The wallet operates in two modes:
/// - **Scan-only** (`new` / `stagenet_default`): Can scan and poll, but not lock or sweep
/// - **Full** (`with_sender_keys`): Can also lock funds using sender's private keys
pub struct XmrWallet {
    daemon_url: String,
    /// Shared reqwest client with 30-second timeout for all daemon RPC calls.
    client: reqwest::Client,
    /// Optional sender spend key (needed for lock -- Alice's personal wallet key)
    sender_spend_key: Option<Zeroizing<Scalar>>,
    /// Optional sender view key (needed for lock -- to scan sender's wallet for inputs)
    sender_view_key: Option<Zeroizing<Scalar>>,
    /// Block height to start scanning from (0 = full rescan)
    scan_from_height: u64,
}

impl XmrWallet {
    /// Create a new XmrWallet pointing at the given monerod URL.
    ///
    /// This wallet can scan and poll but cannot lock (no sender keys).
    pub fn new(daemon_url: &str) -> Self {
        XmrWallet {
            daemon_url: daemon_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build reqwest client"),
            sender_spend_key: None,
            sender_view_key: None,
            scan_from_height: 0,
        }
    }

    /// Create a wallet with the default XMR stagenet daemon URL.
    ///
    /// Default: `http://127.0.0.1:38081` (monerod stagenet RPC).
    pub fn stagenet_default() -> Self {
        Self::new("http://127.0.0.1:38081")
    }

    /// Create a wallet with sender credentials for locking funds.
    ///
    /// `spend_key` and `view_key` are the sender's personal wallet keys,
    /// used to find spendable outputs and sign lock transactions.
    pub fn with_sender_keys(
        daemon_url: &str,
        spend_key: Scalar,
        view_key: Scalar,
    ) -> Self {
        XmrWallet {
            daemon_url: daemon_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build reqwest client"),
            sender_spend_key: Some(Zeroizing::new(spend_key)),
            sender_view_key: Some(Zeroizing::new(view_key)),
            scan_from_height: 0,
        }
    }

    /// Set the block height to start scanning from (avoids full rescan).
    pub fn with_scan_from(mut self, height: u64) -> Self {
        self.scan_from_height = height;
        self
    }

    /// Get the daemon URL.
    pub fn daemon_url(&self) -> &str {
        &self.daemon_url
    }

    /// Create the RPC client for daemon communication.
    fn rpc_client(&self) -> NativeRpcClient {
        NativeRpcClient::new(self.daemon_url.clone())
    }

    /// Derive the CryptoNote standard address from (spend_point, view_scalar).
    ///
    /// The address encodes (spend_point, view_scalar * G) with the Monero
    /// stagenet network prefix (24). This is the address funds are locked to
    /// and scanned at during the atomic swap.
    pub fn derive_address(spend_point: &EdwardsPoint, view_scalar: &Scalar) -> String {
        let view_pubkey = view_scalar * G;
        // Use xmr-wow-crypto's address encoding for Monero stagenet
        xmr_wow_crypto::address::encode_address(
            spend_point,
            &view_pubkey,
            xmr_wow_crypto::address::Network::MoneroStagenet,
        )
    }

    /// Create a monero-oxide ViewPair from dalek types.
    ///
    /// Converts curve25519-dalek EdwardsPoint and Scalar to monero-oxide's
    /// Point and Scalar newtypes, then constructs a ViewPair for scanning.
    fn create_view_pair(
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
    ) -> Result<monero_wallet::ViewPair, WalletError> {
        let oxide_spend = monero_oxide::ed25519::Point::from(*spend_point);
        let oxide_view = Zeroizing::new(monero_oxide::ed25519::Scalar::from(*view_scalar));

        monero_wallet::ViewPair::new(oxide_spend, oxide_view)
            .map_err(|e| WalletError::KeyError(format!("ViewPair creation failed: {}", e)))
    }

    /// Fetch current chain height from monerod.
    async fn get_chain_height(client: &reqwest::Client, daemon_url: &str) -> Result<u64, WalletError> {
        let resp = client
            .post(&format!("{}/json_rpc", daemon_url))
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "method": "get_block_count",
            }))
            .send()
            .await
            .map_err(|e| WalletError::RpcConnection(format!("get_block_count (daemon: {}): {}", daemon_url, e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::RpcRequest(format!("parse get_block_count: {}", e)))?;

        json["result"]["count"]
            .as_u64()
            .ok_or_else(|| WalletError::RpcRequest("missing count in get_block_count".into()))
    }

    /// Fetch a block by height and its transactions, constructing a ScannableBlock.
    ///
    /// Uses monerod JSON-RPC `get_block` to get the block blob, then
    /// `/get_transactions` to fetch the non-miner transactions. Constructs
    /// a `ScannableBlock` suitable for monero-oxide's Scanner.
    async fn fetch_scannable_block(
        client: &reqwest::Client,
        daemon_url: &str,
        height: u64,
    ) -> Result<monero_interface::ScannableBlock, WalletError> {
        // Step 1: Fetch block blob via get_block
        let resp = client
            .post(&format!("{}/json_rpc", daemon_url))
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "method": "get_block",
                "params": { "height": height },
            }))
            .send()
            .await
            .map_err(|e| WalletError::RpcConnection(format!("get_block({}) (daemon: {}): {}", height, daemon_url, e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::RpcRequest(format!("parse get_block({}): {}", height, e)))?;

        let blob_hex = json["result"]["blob"]
            .as_str()
            .ok_or_else(|| WalletError::RpcRequest(format!("no blob in get_block({})", height)))?;

        let blob_bytes = hex::decode(blob_hex)
            .map_err(|e| WalletError::RpcRequest(format!("invalid hex in block blob: {}", e)))?;

        let block = monero_oxide::block::Block::read(&mut blob_bytes.as_slice())
            .map_err(|e| WalletError::ScanFailed(format!("failed to parse block {}: {}", height, e)))?;

        // Step 2: Fetch non-miner transactions if any exist
        let mut pruned_txs: Vec<monero_oxide::transaction::Transaction<monero_oxide::transaction::Pruned>> = Vec::new();

        if !block.transactions.is_empty() {
            let tx_hashes: Vec<String> = block.transactions.iter().map(hex::encode).collect();

            let tx_resp = client
                .post(&format!("{}/get_transactions", daemon_url))
                .json(&serde_json::json!({
                    "txs_hashes": tx_hashes,
                    "decode_as_json": false,
                    "prune": false,
                }))
                .send()
                .await
                .map_err(|e| WalletError::RpcConnection(format!("get_transactions (daemon: {}): {}", daemon_url, e)))?;

            let tx_json: serde_json::Value = tx_resp
                .json()
                .await
                .map_err(|e| WalletError::RpcRequest(format!("parse get_transactions: {}", e)))?;

            if let Some(txs) = tx_json["txs"].as_array() {
                for tx_entry in txs {
                    // Use `as_hex` field which contains the full serialized transaction
                    let tx_hex = tx_entry["as_hex"]
                        .as_str()
                        .ok_or_else(|| WalletError::ScanFailed("missing as_hex in tx".into()))?;

                    let tx_bytes = hex::decode(tx_hex)
                        .map_err(|e| WalletError::ScanFailed(format!("invalid tx hex: {}", e)))?;

                    // Parse as full transaction, then convert to pruned
                    let full_tx = monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
                        &mut tx_bytes.as_slice(),
                    )
                    .map_err(|e| WalletError::ScanFailed(format!("failed to parse tx: {}", e)))?;

                    pruned_txs.push(full_tx.into());
                }
            }
        }

        // Step 3: Get output_index_for_first_ringct_output
        // For the miner transaction's first output, query its global output index.
        // This is needed by the Scanner to correctly track output indexes on the blockchain.
        let output_index = Self::get_first_ringct_output_index(
            client,
            daemon_url,
            &block,
            &pruned_txs,
        )
        .await?;

        Ok(monero_interface::ScannableBlock {
            block,
            transactions: pruned_txs,
            output_index_for_first_ringct_output: output_index,
        })
    }

    /// Get the global output index for the first RingCT output in a block.
    ///
    /// Queries monerod's `/get_o_indexes.bin` endpoint (via the JSON-RPC
    /// `get_tx_global_outputs_indexes` equivalent) for the miner transaction.
    async fn get_first_ringct_output_index(
        client: &reqwest::Client,
        daemon_url: &str,
        block: &monero_oxide::block::Block,
        _txs: &[monero_oxide::transaction::Transaction<monero_oxide::transaction::Pruned>],
    ) -> Result<Option<u64>, WalletError> {
        // Check if the miner tx is v2 (has RingCT outputs)
        let miner_tx = block.miner_transaction();
        let is_v2_miner = matches!(miner_tx, monero_oxide::transaction::Transaction::V2 { .. });

        if !is_v2_miner || miner_tx.prefix().outputs.is_empty() {
            return Ok(None);
        }

        // Query the output indexes for the miner transaction
        let miner_hash = hex::encode(miner_tx.hash());

        let resp = client
            .post(&format!("{}/get_o_indexes.bin", daemon_url))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "txid": miner_hash }))
            .send()
            .await;

        // If the binary endpoint doesn't work, try the JSON fallback approach:
        // use get_transactions with decode_as_json to extract output global indexes
        match resp {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                if let Some(indexes) = body["o_indexes"].as_array() {
                    if let Some(first) = indexes.first() {
                        return Ok(first.as_u64());
                    }
                }
            }
            _ => {}
        }

        // Fallback: query via get_transactions which may include output_indices
        let tx_resp = client
            .post(&format!("{}/get_transactions", daemon_url))
            .json(&serde_json::json!({
                "txs_hashes": [miner_hash],
                "decode_as_json": true,
            }))
            .send()
            .await
            .map_err(|e| WalletError::RpcConnection(format!("get_transactions for o_indexes (daemon: {}): {}", daemon_url, e)))?;

        let tx_json: serde_json::Value = tx_resp
            .json()
            .await
            .map_err(|e| WalletError::RpcRequest(format!("parse o_indexes response: {}", e)))?;

        if let Some(txs) = tx_json["txs"].as_array() {
            if let Some(tx) = txs.first() {
                if let Some(indices) = tx["output_indices"].as_array() {
                    if let Some(first) = indices.first() {
                        return Ok(first.as_u64());
                    }
                }
            }
        }

        // If we cannot determine the output index, return None
        // The Scanner will skip blocks without a known output index
        tracing::warn!(
            target: "xmr_wallet",
            "could not determine output_index_for_first_ringct_output at height {}",
            block.number()
        );
        Ok(None)
    }

    /// Broadcast a serialized transaction to monerod.
    ///
    /// Used by lock() and sweep() after signing a transaction.
    async fn broadcast_tx(
        client: &reqwest::Client,
        daemon_url: &str,
        tx_hex: &str,
    ) -> Result<TxHash, WalletError> {
        let resp = client
            .post(&format!("{}/sendrawtransaction", daemon_url))
            .json(&serde_json::json!({
                "tx_as_hex": tx_hex,
                "do_not_relay": false,
            }))
            .send()
            .await
            .map_err(|e| WalletError::BroadcastFailed(format!("sendrawtransaction (daemon: {}): {}", daemon_url, e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::BroadcastFailed(format!("parse broadcast response: {}", e)))?;

        // Check for errors in response
        let status = json["status"].as_str().unwrap_or("unknown");
        if status != "OK" {
            return Err(WalletError::BroadcastFailed(format!(
                "daemon rejected tx: {}",
                json
            )));
        }

        // Compute the tx hash from the hex blob
        let tx_bytes = hex::decode(tx_hex)
            .map_err(|e| WalletError::TxBuildFailed(format!("invalid tx hex: {}", e)))?;

        let tx = monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
            &mut tx_bytes.as_slice(),
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("failed to parse built tx: {}", e)))?;

        let hash = tx.hash();
        tracing::info!(
            target: "xmr_wallet",
            tx_hash = %hex::encode(hash),
            "transaction broadcast successful"
        );
        Ok(hash)
    }

    /// Scan for outputs using monero-oxide Scanner.
    ///
    /// This is the core scanning logic shared between `scan()`, `lock()` (to find
    /// sender's spendable outputs), and `sweep()` (to find joint address outputs).
    async fn scan_with_scanner(
        client: &reqwest::Client,
        daemon_url: &str,
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
        from_height: u64,
        to_height: u64,
    ) -> Result<(Vec<ScanResult>, Vec<monero_wallet::WalletOutput>), WalletError> {
        let view_pair = Self::create_view_pair(spend_point, view_scalar)?;
        let mut scanner = monero_wallet::Scanner::new(view_pair);

        let mut results = Vec::new();
        let mut wallet_outputs = Vec::new();

        // Scan blocks in range (batch-friendly: scan one block at a time)
        for height in from_height..to_height {
            let scannable = Self::fetch_scannable_block(client, daemon_url, height).await?;

            match scanner.scan(scannable) {
                Ok(timelocked) => {
                    // Use ignore_additional_timelock to find ALL outputs including
                    // coinbase. Maturity is checked when spending, not scanning.
                    let outputs = timelocked.ignore_additional_timelock();
                    for output in &outputs {
                        let tx_hash = output.transaction();
                        let amount = output.commitment().amount;
                        let output_index = output.index_in_transaction() as u8;

                        results.push(ScanResult {
                            found: true,
                            amount,
                            tx_hash,
                            output_index,
                            block_height: height,
                        });

                        tracing::debug!(
                            target: "xmr_wallet",
                            tx_hash = %hex::encode(tx_hash),
                            amount = amount,
                            height = height,
                            "found output"
                        );
                    }
                    wallet_outputs.extend(outputs);
                }
                Err(monero_wallet::ScanError::UnsupportedProtocol(v)) => {
                    tracing::warn!(
                        target: "xmr_wallet",
                        height = height,
                        version = v,
                        "skipping block with unsupported protocol version"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        target: "xmr_wallet",
                        height = height,
                        error = %e,
                        "scan error, skipping block"
                    );
                }
            }
        }

        Ok((results, wallet_outputs))
    }

    /// Compute the key image for a WalletOutput given the sender's spend key.
    ///
    /// key_image = (spend_key + key_offset) * Hp(output_one_time_key)
    fn compute_key_image(
        sender_spend: &Scalar,
        output: &monero_wallet::WalletOutput,
    ) -> [u8; 32] {
        use monero_oxide::ed25519::Point as OxidePoint;
        // input_key = spend_key + key_offset (dalek scalars)
        let key_offset_dalek: Scalar = output.key_offset().into();
        let input_key_scalar = sender_spend + key_offset_dalek;
        // Hp = hash-to-point of the output's one-time public key
        let hp: OxidePoint = OxidePoint::biased_hash(output.key().compress().to_bytes());
        let hp_dalek: EdwardsPoint = hp.into();
        // key_image = input_key_scalar * Hp
        let ki_dalek: EdwardsPoint = input_key_scalar * hp_dalek;
        let ki = OxidePoint::from(ki_dalek);
        ki.compress().to_bytes()
    }

    /// Filter out already-spent outputs by checking key images against the daemon.
    async fn filter_unspent(
        client: &reqwest::Client,
        daemon_url: &str,
        sender_spend: &Scalar,
        outputs: Vec<monero_wallet::WalletOutput>,
    ) -> Result<Vec<monero_wallet::WalletOutput>, WalletError> {
        if outputs.is_empty() {
            return Ok(outputs);
        }

        // Compute key images for all outputs
        let key_images: Vec<String> = outputs.iter()
            .map(|o| hex::encode(Self::compute_key_image(sender_spend, o)))
            .collect();

        // Query daemon for spent status
        let resp = client
            .post(&format!("{}/is_key_image_spent", daemon_url))
            .json(&serde_json::json!({ "key_images": key_images }))
            .send()
            .await
            .map_err(|e| WalletError::BroadcastFailed(format!("is_key_image_spent (daemon: {}): {}", daemon_url, e)))?;

        let json: serde_json::Value = resp.json().await
            .map_err(|e| WalletError::BroadcastFailed(format!("parse key image response (daemon: {}): {}", daemon_url, e)))?;

        let spent_statuses = json["spent_status"].as_array()
            .ok_or_else(|| WalletError::BroadcastFailed("no spent_status in response".into()))?;

        let mut unspent = Vec::new();
        for (i, output) in outputs.into_iter().enumerate() {
            let status = spent_statuses.get(i)
                .and_then(|v| v.as_u64())
                .unwrap_or(1); // default to "spent" if unknown
            if status == 0 {
                // 0 = unspent
                unspent.push(output);
            } else {
                tracing::debug!(
                    target: "xmr_wallet",
                    key_image = %key_images[i],
                    status = status,
                    "filtering out spent output"
                );
            }
        }

        Ok(unspent)
    }
}

#[async_trait::async_trait]
impl CryptoNoteWallet for XmrWallet {
    fn refund_chain(&self) -> RefundChain {
        RefundChain::Xmr
    }

    /// Lock funds to the joint address derived from (spend_point, view_scalar).
    ///
    /// Builds a transaction sending `amount` atomic units to the CryptoNote
    /// address derived from the joint spend point and view scalar, then
    /// broadcasts it to monerod.
    ///
    /// Requires sender credentials (use `with_sender_keys` constructor).
    /// The sender's wallet is scanned to find spendable outputs, a
    /// `SignableTransaction` is constructed with those outputs as inputs,
    /// signed with the sender's spend key, and broadcast.
    async fn lock(
        &self,
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
        amount: u64,
    ) -> Result<TxHash, WalletError> {
        let address = Self::derive_address(spend_point, view_scalar);
        tracing::info!(
            target: "xmr_wallet",
            address = %address,
            amount = amount,
            "locking funds to joint address"
        );

        // Require sender keys for lock
        let sender_spend = self.sender_spend_key.as_ref()
            .ok_or_else(|| WalletError::KeyError(
                "lock requires sender keys -- use XmrWallet::with_sender_keys()".into()
            ))?;
        let sender_view = self.sender_view_key.as_ref()
            .ok_or_else(|| WalletError::KeyError(
                "lock requires sender view key".into()
            ))?;

        // Derive sender's spend public key
        let sender_spend_point = &**sender_spend * G;

        // Step 1: Scan sender's wallet for spendable outputs
        let client = &self.client;
        let current_height = Self::get_chain_height(client, &self.daemon_url).await?;

        // Scan for sender's outputs then filter out already-spent ones
        let (_scan_results, all_outputs) = Self::scan_with_scanner(
            &self.client,
            &self.daemon_url,
            &sender_spend_point,
            &**sender_view,
            self.scan_from_height,
            current_height,
        )
        .await?;

        tracing::info!(
            target: "xmr_wallet",
            from_height = self.scan_from_height,
            to_height = current_height,
            blocks = current_height.saturating_sub(self.scan_from_height),
            outputs = all_outputs.len(),
            "sender scan complete"
        );

        // Filter out immature coinbase outputs
        let total_found = all_outputs.len();
        let mature_outputs: Vec<_> = all_outputs.into_iter().filter(|o| {
            match o.additional_timelock() {
                monero_oxide::transaction::Timelock::None => true,
                monero_oxide::transaction::Timelock::Block(b) => (current_height as usize) >= b,
                monero_oxide::transaction::Timelock::Time(t) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    now >= t
                }
            }
        }).collect();

        if mature_outputs.len() < total_found {
            tracing::info!(
                target: "xmr_wallet",
                filtered = total_found - mature_outputs.len(),
                mature = mature_outputs.len(),
                "filtered immature coinbase outputs"
            );
        }

        let sender_outputs = Self::filter_unspent(
            client,
            &self.daemon_url,
            &**sender_spend,
            mature_outputs,
        ).await?;

        tracing::info!(
            target: "xmr_wallet",
            unspent = sender_outputs.len(),
            "completed spent-output filtering"
        );
        for o in &sender_outputs {
            tracing::debug!(
                target: "xmr_wallet",
                amount = o.commitment().amount,
                "available unspent output"
            );
        }

        if sender_outputs.is_empty() {
            return Err(WalletError::NoOutputsFound);
        }

        // Step 2: Select outputs covering amount + fee estimate
        // Simple selection: use all outputs (for PoC; production would optimize)
        let total_available: u64 = sender_outputs.iter()
            .map(|o| o.commitment().amount)
            .sum();

        if total_available < amount {
            return Err(WalletError::InsufficientFunds {
                need: amount,
                have: total_available,
            });
        }

        // Step 3: Build the recipient address as monero-oxide MoneroAddress
        let oxide_spend = monero_oxide::ed25519::Point::from(*spend_point);
        let view_pubkey = monero_oxide::ed25519::Point::from(view_scalar * G);
        let recipient_addr = monero_wallet::address::MoneroAddress::new(
            monero_wallet::address::Network::Stagenet,
            monero_wallet::address::AddressType::Legacy,
            oxide_spend,
            view_pubkey,
        );

        // Step 4: Build and sign transaction using monero-oxide via MoneroDaemon
        use crate::rpc_transport::ReqwestTransport;
        use monero_interface::ProvidesFeeRates;

        let transport = ReqwestTransport::new(&self.daemon_url);
        let daemon = transport.monero_daemon().await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        // Get fee rate from daemon
        let fee_rate = daemon.fee_rate(
            monero_interface::FeePriority::Normal,
            100_000, // max per_weight sanity bound
        ).await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        // Get current block number for decoy selection
        use monero_interface::ProvidesBlockchainMeta;
        let block_number = daemon.latest_block_number().await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        // Select decoys for each input
        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 16; // XMR ring size

        let mut inputs_with_decoys = Vec::with_capacity(sender_outputs.len());
        for output in sender_outputs {
            let owd = monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &daemon,
                ring_len,
                block_number,
                output,
            ).await
                .map_err(|e| WalletError::TxBuildFailed(format!("decoy selection: {}", e)))?;
            inputs_with_decoys.push(owd);
        }

        // Build the outgoing view key (SHA-256 of sender view scalar bytes)
        let outgoing_view_key = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(sender_view.as_bytes());
            let hash = hasher.finalize();
            Zeroizing::new(<[u8; 32]>::try_from(&hash[..]).expect("SHA-256 is 32 bytes"))
        };

        // Build SignableTransaction
        let payments = vec![(recipient_addr, amount)];

        // Change goes back to sender's address
        let sender_view_point = &**sender_view * G;
        let oxide_sender_spend = monero_oxide::ed25519::Point::from(sender_spend_point);
        let oxide_sender_view = monero_oxide::ed25519::Point::from(sender_view_point);
        let sender_address = monero_wallet::address::MoneroAddress::new(
            monero_wallet::address::Network::Stagenet,
            monero_wallet::address::AddressType::Legacy,
            oxide_sender_spend,
            oxide_sender_view,
        );
        let change = monero_wallet::send::Change::fingerprintable(Some(sender_address));

        let signable = monero_wallet::send::SignableTransaction::new(
            monero_oxide::ringct::RctType::ClsagBulletproofPlus,
            outgoing_view_key,
            inputs_with_decoys,
            payments,
            change,
            vec![], // no extra data
            fee_rate,
        ).map_err(|e| WalletError::TxBuildFailed(format!("build tx: {}", e)))?;

        // Sign with sender's spend key
        let oxide_spend_key = Zeroizing::new(
            monero_oxide::ed25519::Scalar::from(**sender_spend),
        );
        let signed_tx = signable.sign(&mut rng, &oxide_spend_key)
            .map_err(|e| WalletError::TxBuildFailed(format!("sign tx: {}", e)))?;

        // Broadcast
        let tx_hex = hex::encode(signed_tx.serialize());
        let client = &self.client;
        Self::broadcast_tx(client, &self.daemon_url, &tx_hex).await
    }

    /// Sweep all funds from the joint address to a destination address.
    ///
    /// Uses `spend_secret` (the combined private spend key k_a + k_b) and
    /// `view_scalar` to scan for outputs at the joint address, then builds
    /// a transaction spending all found outputs to `destination`.
    ///
    /// Per Pitfall 5: sweep MUST scan first to discover outputs -- you cannot
    /// sweep without knowing the outputs' one-time keys and metadata.
    async fn sweep(
        &self,
        spend_secret: &Scalar,
        view_scalar: &Scalar,
        destination: &str,
    ) -> Result<TxHash, WalletError> {
        // Derive the joint spend public key from the combined secret
        let spend_point = spend_secret * G;
        let address = Self::derive_address(&spend_point, view_scalar);
        tracing::info!(
            target: "xmr_wallet",
            source_address = %address,
            destination = %destination,
            "sweeping funds from joint address"
        );

        // Step 1: Scan for outputs at the joint address
        let client = &self.client;
        let current_height = Self::get_chain_height(client, &self.daemon_url).await?;

        let (_scan_results, joint_outputs) = Self::scan_with_scanner(
            &self.client,
            &self.daemon_url,
            &spend_point,
            view_scalar,
            self.scan_from_height,
            current_height,
        )
        .await?;

        if joint_outputs.is_empty() {
            return Err(WalletError::NoOutputsFound);
        }

        let total_amount: u64 = joint_outputs.iter()
            .map(|o| o.commitment().amount)
            .sum();

        tracing::info!(
            target: "xmr_wallet",
            outputs = joint_outputs.len(),
            total_amount = total_amount,
            "found outputs at joint address, building sweep transaction"
        );

        // Step 2: Parse destination address
        let dest_addr = monero_wallet::address::MoneroAddress::from_str_with_unchecked_network(
            destination,
        )
        .map_err(|e| WalletError::InvalidAddress(format!("invalid destination: {:?}", e)))?;

        // Step 3: Build sweep transaction via MoneroDaemon
        use crate::rpc_transport::ReqwestTransport;
        use monero_interface::ProvidesFeeRates;

        let transport = ReqwestTransport::new(&self.daemon_url);
        let daemon = transport.monero_daemon().await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        let fee_rate = daemon.fee_rate(
            monero_interface::FeePriority::Normal,
            100_000,
        ).await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        use monero_interface::ProvidesBlockchainMeta;
        let block_number = daemon.latest_block_number().await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 16; // XMR ring size

        let mut inputs_with_decoys = Vec::with_capacity(joint_outputs.len());
        for output in joint_outputs {
            let owd = monero_wallet::OutputWithDecoys::new(
                &mut rng, &daemon, ring_len, block_number, output,
            ).await
                .map_err(|e| WalletError::TxBuildFailed(format!("decoy selection: {}", e)))?;
            inputs_with_decoys.push(owd);
        }

        let outgoing_view_key = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(view_scalar.as_bytes());
            let hash = hasher.finalize();
            Zeroizing::new(<[u8; 32]>::try_from(&hash[..]).expect("SHA-256 is 32 bytes"))
        };

        // Sweep: send (total - estimated_fee) to destination.
        // Monero requires at least 2 outputs, so we use a change output
        // back to the destination which will receive any fee overshoot.
        let change = monero_wallet::send::Change::fingerprintable(Some(dest_addr.clone()));

        // Estimate fee conservatively (2 inputs, 2 outputs at normal priority)
        // The actual fee is computed by SignableTransaction based on weight.
        // We subtract a generous estimate; any excess goes to the change output.
        let estimated_fee = fee_rate.calculate_fee_from_weight(2000); // ~2KB weight estimate
        let sweep_amount = total_amount.saturating_sub(estimated_fee);
        if sweep_amount == 0 {
            return Err(WalletError::InsufficientFunds {
                need: estimated_fee,
                have: total_amount,
            });
        }

        let payments = vec![(dest_addr, sweep_amount)];

        let signable = monero_wallet::send::SignableTransaction::new(
            monero_oxide::ringct::RctType::ClsagBulletproofPlus,
            outgoing_view_key,
            inputs_with_decoys,
            payments,
            change,
            vec![],
            fee_rate,
        ).map_err(|e| WalletError::TxBuildFailed(format!("build sweep tx: {}", e)))?;

        let oxide_spend_secret = Zeroizing::new(
            monero_oxide::ed25519::Scalar::from(*spend_secret),
        );
        let signed_tx = signable.sign(&mut rng, &oxide_spend_secret)
            .map_err(|e| WalletError::TxBuildFailed(format!("sign sweep tx: {}", e)))?;

        let tx_hex = hex::encode(signed_tx.serialize());
        let client = &self.client;
        Self::broadcast_tx(client, &self.daemon_url, &tx_hex).await
    }

    /// Scan the chain for outputs at the joint address.
    ///
    /// Creates a monero-oxide Scanner with ViewPair from (spend_point, view_scalar),
    /// fetches blocks from monerod via reqwest, parses them with monero-oxide's
    /// Block and Transaction types, constructs ScannableBlocks, and runs the Scanner
    /// to detect outputs belonging to the joint address.
    async fn scan(
        &self,
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
        from_height: u64,
    ) -> Result<Vec<ScanResult>, WalletError> {
        let address = Self::derive_address(spend_point, view_scalar);
        tracing::info!(
            target: "xmr_wallet",
            address = %address,
            from_height = from_height,
            "scanning for outputs at joint address using monero-oxide Scanner"
        );

        // Get current chain height
        let client = &self.client;
        let current_height = Self::get_chain_height(client, &self.daemon_url).await?;

        if from_height >= current_height {
            return Ok(Vec::new());
        }

        let (results, _wallet_outputs) = Self::scan_with_scanner(
            &self.client,
            &self.daemon_url,
            spend_point,
            view_scalar,
            from_height,
            current_height,
        )
        .await?;

        tracing::info!(
            target: "xmr_wallet",
            found = results.len(),
            scanned_blocks = current_height - from_height,
            "scan complete"
        );

        Ok(results)
    }

    /// Poll whether a transaction has been confirmed.
    ///
    /// Queries monerod's `/get_transactions` endpoint for the tx status,
    /// then calculates confirmations from current height - tx block height.
    async fn poll_confirmation(
        &self,
        tx_hash: &TxHash,
        required_confirmations: u64,
    ) -> Result<ConfirmationStatus, WalletError> {
        let tx_hash_hex = hex::encode(tx_hash);
        tracing::debug!(
            target: "xmr_wallet",
            tx_hash = %tx_hash_hex,
            required = required_confirmations,
            "polling transaction confirmation"
        );

        let rpc = self.rpc_client();

        // Query /get_transactions for the tx status
        let client = &self.client;
        let resp = client
            .post(&format!("{}/get_transactions", self.daemon_url))
            .json(&serde_json::json!({
                "txs_hashes": [tx_hash_hex],
                "decode_as_json": true,
            }))
            .send()
            .await
            .map_err(|e| WalletError::RpcConnection(format!("get_transactions failed (daemon: {}): {}", self.daemon_url, e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::RpcRequest(format!("parse get_transactions: {}", e)))?;

        // Check if transaction exists in the response
        let txs = json["txs"]
            .as_array()
            .ok_or_else(|| WalletError::TxNotFound(tx_hash_hex.clone()))?;

        if txs.is_empty() {
            return Err(WalletError::TxNotFound(tx_hash_hex));
        }

        let tx = &txs[0];

        // Check if tx is in a block
        let in_pool = tx["in_pool"].as_bool().unwrap_or(true);
        let block_height = tx["block_height"].as_u64();

        if in_pool || block_height.is_none() {
            // Transaction is in mempool, not yet confirmed
            return Ok(ConfirmationStatus {
                confirmed: false,
                confirmations: 0,
                block_height: None,
            });
        }

        let tx_height = block_height.unwrap();

        // Get current chain height
        let current_height = rpc
            .get_height()
            .await
            .map_err(|e| WalletError::RpcRequest(format!("get_height failed (daemon: {}): {}", self.daemon_url, e)))?;

        let confirmations = if current_height > tx_height {
            current_height - tx_height
        } else {
            0
        };

        Ok(ConfirmationStatus {
            confirmed: confirmations >= required_confirmations,
            confirmations,
            block_height: Some(tx_height),
        })
    }

    /// Sweep all funds from the joint address with a timelock on the transaction.
    ///
    /// Same as `sweep()` but uses `new_with_timelock()` to embed `Timelock::Block(refund_height)`
    /// in the transaction prefix. Returns `(tx_hash, serialized_tx_bytes)` without broadcasting.
    async fn sweep_timelocked(
        &self,
        spend_secret: &Scalar,
        view_scalar: &Scalar,
        destination: &str,
        refund_height: u64,
    ) -> Result<(TxHash, Vec<u8>), WalletError> {
        let spend_point = spend_secret * G;
        let address = Self::derive_address(&spend_point, view_scalar);
        tracing::info!(
            target: "xmr_wallet",
            source_address = %address,
            destination = %destination,
            refund_height = refund_height,
            "building timelocked sweep from joint address"
        );

        // Step 1: Scan for outputs at the joint address
        let client = &self.client;
        let current_height = Self::get_chain_height(client, &self.daemon_url).await?;

        let (_scan_results, joint_outputs) = Self::scan_with_scanner(
            &self.client,
            &self.daemon_url,
            &spend_point,
            view_scalar,
            self.scan_from_height,
            current_height,
        )
        .await?;

        if joint_outputs.is_empty() {
            return Err(WalletError::NoOutputsFound);
        }

        let total_amount: u64 = joint_outputs.iter()
            .map(|o| o.commitment().amount)
            .sum();

        tracing::info!(
            target: "xmr_wallet",
            outputs = joint_outputs.len(),
            total_amount = total_amount,
            "found outputs, building timelocked sweep transaction"
        );

        // Step 2: Parse destination address
        let dest_addr = monero_wallet::address::MoneroAddress::from_str_with_unchecked_network(
            destination,
        )
        .map_err(|e| WalletError::InvalidAddress(format!("invalid destination: {:?}", e)))?;

        // Step 3: Build timelocked sweep transaction
        use crate::rpc_transport::ReqwestTransport;
        use monero_interface::ProvidesFeeRates;

        let transport = ReqwestTransport::new(&self.daemon_url);
        let daemon = transport.monero_daemon().await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        let fee_rate = daemon.fee_rate(
            monero_interface::FeePriority::Normal,
            100_000,
        ).await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        use monero_interface::ProvidesBlockchainMeta;
        let block_number = daemon.latest_block_number().await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 16;

        let mut inputs_with_decoys = Vec::with_capacity(joint_outputs.len());
        for output in joint_outputs {
            let owd = monero_wallet::OutputWithDecoys::new(
                &mut rng, &daemon, ring_len, block_number, output,
            ).await
                .map_err(|e| WalletError::TxBuildFailed(format!("decoy selection: {}", e)))?;
            inputs_with_decoys.push(owd);
        }

        let outgoing_view_key = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(view_scalar.as_bytes());
            let hash = hasher.finalize();
            Zeroizing::new(<[u8; 32]>::try_from(&hash[..]).expect("SHA-256 is 32 bytes"))
        };

        let change = monero_wallet::send::Change::fingerprintable(Some(dest_addr.clone()));
        let estimated_fee = fee_rate.calculate_fee_from_weight(2000);
        let sweep_amount = total_amount.saturating_sub(estimated_fee);
        if sweep_amount == 0 {
            return Err(WalletError::InsufficientFunds {
                need: estimated_fee,
                have: total_amount,
            });
        }

        let payments = vec![(dest_addr, sweep_amount)];

        // Use new_with_timelock to embed the refund height as unlock_time
        let signable = monero_wallet::send::SignableTransaction::new_with_timelock(
            monero_oxide::ringct::RctType::ClsagBulletproofPlus,
            outgoing_view_key,
            inputs_with_decoys,
            payments,
            change,
            vec![],
            fee_rate,
            monero_oxide::transaction::Timelock::Block(refund_height as usize),
        ).map_err(|e| WalletError::TxBuildFailed(format!("build timelocked sweep tx: {}", e)))?;

        let oxide_spend_secret = Zeroizing::new(
            monero_oxide::ed25519::Scalar::from(*spend_secret),
        );
        let signed_tx = signable.sign(&mut rng, &oxide_spend_secret)
            .map_err(|e| WalletError::TxBuildFailed(format!("sign timelocked sweep tx: {}", e)))?;

        // Serialize the signed transaction
        let tx_bytes = signed_tx.serialize();

        // Compute the tx hash
        let tx = monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
            &mut tx_bytes.as_slice(),
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("failed to parse built tx: {}", e)))?;
        let tx_hash = tx.hash();

        tracing::info!(
            target: "xmr_wallet",
            tx_hash = %hex::encode(tx_hash),
            refund_height = refund_height,
            tx_size = tx_bytes.len(),
            "timelocked sweep transaction built (not yet broadcast)"
        );

        Ok((tx_hash, tx_bytes))
    }

    /// Broadcast a pre-signed raw transaction to the Monero daemon.
    ///
    /// Hex-encodes the raw bytes and POSTs to `/sendrawtransaction`.
    /// Returns the tx hash on success, or an error with the daemon's rejection reason.
    async fn broadcast_raw_tx(&self, tx_bytes: &[u8]) -> Result<TxHash, WalletError> {
        let tx_hex = hex::encode(tx_bytes);
        tracing::info!(
            target: "xmr_wallet",
            tx_size = tx_bytes.len(),
            "broadcasting pre-signed raw transaction"
        );

        let client = &self.client;
        let resp = client
            .post(&format!("{}/sendrawtransaction", self.daemon_url))
            .json(&serde_json::json!({
                "tx_as_hex": tx_hex,
                "do_not_relay": false,
            }))
            .send()
            .await
            .map_err(|e| WalletError::BroadcastFailed(format!("sendrawtransaction (daemon: {}): {}", self.daemon_url, e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::BroadcastFailed(format!("parse broadcast response (daemon: {}): {}", self.daemon_url, e)))?;

        let status = json["status"].as_str().unwrap_or("unknown");
        if status != "OK" {
            return Err(WalletError::BroadcastFailed(format!(
                "daemon rejected tx (daemon: {}): {}",
                self.daemon_url, json
            )));
        }

        // Compute the tx hash from the bytes
        let tx = monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
            &mut tx_bytes.to_vec().as_slice(),
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("failed to parse tx for hash: {}", e)))?;

        let hash = tx.hash();
        tracing::info!(
            target: "xmr_wallet",
            tx_hash = %hex::encode(hash),
            "raw transaction broadcast successful"
        );
        Ok(hash)
    }

    /// Get the current block height from the Monero daemon.
    ///
    /// Delegates to the existing `get_chain_height` helper which calls
    /// monerod's `get_block_count` JSON-RPC method.
    async fn get_current_height(&self) -> Result<u64, WalletError> {
        let client = &self.client;
        Self::get_chain_height(client, &self.daemon_url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmr_wow_crypto::keysplit::KeyContribution;
    use rand::rngs::OsRng;

    #[test]
    fn test_xmr_wallet_new() {
        let wallet = XmrWallet::new("http://localhost:38081");
        assert_eq!(wallet.daemon_url, "http://localhost:38081");
    }

    #[test]
    fn test_xmr_wallet_stagenet_default() {
        let wallet = XmrWallet::stagenet_default();
        assert_eq!(wallet.daemon_url, "http://127.0.0.1:38081");
    }

    #[test]
    fn test_xmr_wallet_custom_url() {
        let wallet = XmrWallet::new("http://192.168.1.100:28081");
        assert_eq!(wallet.daemon_url, "http://192.168.1.100:28081");
    }

    #[test]
    fn test_xmr_wallet_with_sender_keys() {
        let spend = Scalar::random(&mut OsRng);
        let view = Scalar::random(&mut OsRng);
        let wallet = XmrWallet::with_sender_keys("http://localhost:38081", spend, view);
        assert_eq!(wallet.daemon_url, "http://localhost:38081");
        assert!(wallet.sender_spend_key.is_some());
        assert!(wallet.sender_view_key.is_some());
    }

    #[test]
    fn test_xmr_wallet_scan_only_has_no_sender_keys() {
        let wallet = XmrWallet::new("http://localhost:38081");
        assert!(wallet.sender_spend_key.is_none());
        assert!(wallet.sender_view_key.is_none());
    }

    #[test]
    fn test_create_view_pair_succeeds() {
        let contrib = KeyContribution::generate(&mut OsRng);
        let view_scalar = Scalar::random(&mut OsRng);

        let result = XmrWallet::create_view_pair(&contrib.public, &view_scalar);
        assert!(result.is_ok(), "ViewPair creation should succeed with valid keys");
    }

    #[test]
    fn test_derive_address_matches_crypto_crate() {
        // Generate two key contributions (simulating Alice and Bob)
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);

        // Combine public keys to get joint spend point
        let joint_spend = xmr_wow_crypto::keysplit::combine_public_keys(
            &alice.public,
            &bob.public,
        );

        // Generate a view scalar (in real protocol, both parties agree on this)
        let view_scalar = Scalar::random(&mut OsRng);
        let view_pubkey = view_scalar * G;

        // Derive address via XmrWallet helper
        let wallet_address = XmrWallet::derive_address(&joint_spend, &view_scalar);

        // Derive address directly via xmr-wow-crypto
        let crypto_address = xmr_wow_crypto::address::encode_address(
            &joint_spend,
            &view_pubkey,
            xmr_wow_crypto::address::Network::MoneroStagenet,
        );

        assert_eq!(
            wallet_address, crypto_address,
            "XmrWallet::derive_address must produce the same address as xmr_wow_crypto::encode_address"
        );

        // Verify it's a valid 95-char Monero stagenet address
        assert_eq!(wallet_address.len(), 95, "stagenet address should be 95 chars");
    }

    #[test]
    fn test_derive_address_deterministic() {
        // Same inputs must produce the same address
        let contrib = KeyContribution::generate(&mut OsRng);
        let view_scalar = Scalar::random(&mut OsRng);

        let addr1 = XmrWallet::derive_address(&contrib.public, &view_scalar);
        let addr2 = XmrWallet::derive_address(&contrib.public, &view_scalar);

        assert_eq!(addr1, addr2, "derive_address must be deterministic");
    }

    #[test]
    fn test_derive_address_different_keys_different_addresses() {
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);
        let view_scalar = Scalar::random(&mut OsRng);

        let addr_a = XmrWallet::derive_address(&alice.public, &view_scalar);
        let addr_b = XmrWallet::derive_address(&bob.public, &view_scalar);

        assert_ne!(
            addr_a, addr_b,
            "different spend points must produce different addresses"
        );
    }
}
