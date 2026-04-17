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

use std::cmp::Reverse;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use tracing;
use zeroize::Zeroizing;

use monero_rust::abstractions::RpcClient;
use monero_rust::rpc_serai::NativeRpcClient;

use crate::error::WalletError;
use crate::trait_def::{ConfirmationStatus, CryptoNoteWallet, RefundChain, ScanResult, TxHash};

const XMR_FEE_RATE_SANITY_BOUND: u64 = 100_000_000;
const XMR_LOCK_BASE_FEE_ESTIMATE: u64 = 60_000_000;
const XMR_LOCK_FEE_PER_INPUT_ESTIMATE: u64 = 20_000_000;

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
    fn estimate_lock_fee(num_inputs: usize) -> u64 {
        XMR_LOCK_BASE_FEE_ESTIMATE + (num_inputs as u64 * XMR_LOCK_FEE_PER_INPUT_ESTIMATE)
    }

    fn select_lock_output_indices(amounts: &[u64], amount: u64) -> Result<Vec<usize>, WalletError> {
        if amounts.is_empty() {
            return Err(WalletError::NoOutputsFound);
        }

        let total_available: u64 = amounts.iter().sum();
        let single_output_target = amount.saturating_add(Self::estimate_lock_fee(1));

        // Prefer the smallest single output which can fund the lock by itself.
        // Fewer inputs means fewer decoy sets and a smaller XMR lock transaction.
        let mut ascending: Vec<(usize, u64)> = amounts.iter().copied().enumerate().collect();
        ascending.sort_by_key(|(_, output_amount)| *output_amount);
        if let Some((selected_idx, _)) = ascending
            .into_iter()
            .find(|(_, output_amount)| *output_amount >= single_output_target)
        {
            return Ok(vec![selected_idx]);
        }

        // Otherwise greedily choose the largest outputs first to minimize
        // input count while still covering amount plus a conservative fee.
        let mut descending: Vec<(usize, u64)> = amounts.iter().copied().enumerate().collect();
        descending.sort_by_key(|(_, output_amount)| Reverse(*output_amount));

        let mut selected = Vec::new();
        let mut selected_total = 0u64;
        for (selected_idx, output_amount) in descending {
            selected.push(selected_idx);
            selected_total = selected_total.saturating_add(output_amount);
            let estimated_fee = Self::estimate_lock_fee(selected.len());
            if selected_total >= amount.saturating_add(estimated_fee) {
                return Ok(selected);
            }
        }

        Err(WalletError::InsufficientFunds {
            need: amount.saturating_add(Self::estimate_lock_fee(amounts.len().max(1))),
            have: total_available,
        })
    }

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
    pub fn with_sender_keys(daemon_url: &str, spend_key: Scalar, view_key: Scalar) -> Self {
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
    async fn get_chain_height(
        client: &reqwest::Client,
        daemon_url: &str,
    ) -> Result<u64, WalletError> {
        let resp = client
            .post(format!("{}/json_rpc", daemon_url))
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "method": "get_block_count",
            }))
            .send()
            .await
            .map_err(|e| {
                WalletError::RpcConnection(format!(
                    "get_block_count (daemon: {}): {}",
                    daemon_url, e
                ))
            })?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::RpcRequest(format!("parse get_block_count: {}", e)))?;

        json["result"]["count"]
            .as_u64()
            .ok_or_else(|| WalletError::RpcRequest("missing count in get_block_count".into()))
    }

    /// Fetch a block by height and any non-miner transactions it contains.
    ///
    /// Uses monerod JSON-RPC `get_block` to get the block blob, then
    /// `/get_transactions` to fetch the non-miner transactions.
    async fn fetch_scannable_block_parts(
        client: &reqwest::Client,
        daemon_url: &str,
        height: u64,
    ) -> Result<
        (
            monero_oxide::block::Block,
            Vec<monero_oxide::transaction::Transaction<monero_oxide::transaction::Pruned>>,
        ),
        WalletError,
    > {
        // Step 1: Fetch block blob via get_block
        let resp = client
            .post(format!("{}/json_rpc", daemon_url))
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "method": "get_block",
                "params": { "height": height },
            }))
            .send()
            .await
            .map_err(|e| {
                WalletError::RpcConnection(format!(
                    "get_block({}) (daemon: {}): {}",
                    height, daemon_url, e
                ))
            })?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::RpcRequest(format!("parse get_block({}): {}", height, e)))?;

        let blob_hex = json["result"]["blob"]
            .as_str()
            .ok_or_else(|| WalletError::RpcRequest(format!("no blob in get_block({})", height)))?;

        let blob_bytes = hex::decode(blob_hex)
            .map_err(|e| WalletError::RpcRequest(format!("invalid hex in block blob: {}", e)))?;

        let block = monero_oxide::block::Block::read(&mut blob_bytes.as_slice()).map_err(|e| {
            WalletError::ScanFailed(format!("failed to parse block {}: {}", height, e))
        })?;

        // Step 2: Fetch non-miner transactions if any exist
        let mut pruned_txs: Vec<
            monero_oxide::transaction::Transaction<monero_oxide::transaction::Pruned>,
        > = Vec::new();

        if !block.transactions.is_empty() {
            let tx_hashes: Vec<String> = block.transactions.iter().map(hex::encode).collect();
            let request_body = serde_json::to_vec(&serde_json::json!({
                "txs_hashes": tx_hashes,
                "decode_as_json": false,
                "prune": false,
            }))
            .map_err(|e| WalletError::RpcRequest(format!("serialize get_transactions: {}", e)))?;

            let body_bytes = crate::rpc_transport::post_json_http1_identity_raw(
                daemon_url,
                "get_transactions",
                &request_body,
            )
            .await
            .map_err(|e| {
                WalletError::RpcConnection(format!(
                    "get_transactions (daemon: {}): {}",
                    daemon_url, e
                ))
            })?;

            let tx_json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
                WalletError::RpcRequest(format!(
                    "parse get_transactions ({} bytes, first 500: {:?}): {}",
                    body_bytes.len(),
                    String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(500)]),
                    e
                ))
            })?;

            if let Some(txs) = tx_json["txs"].as_array() {
                for tx_entry in txs {
                    // Use `as_hex` field which contains the full serialized transaction
                    let tx_hex = tx_entry["as_hex"]
                        .as_str()
                        .ok_or_else(|| WalletError::ScanFailed("missing as_hex in tx".into()))?;

                    let tx_bytes = hex::decode(tx_hex)
                        .map_err(|e| WalletError::ScanFailed(format!("invalid tx hex: {}", e)))?;

                    // Parse as full transaction, then convert to pruned
                    let full_tx = monero_oxide::transaction::Transaction::<
                        monero_oxide::transaction::NotPruned,
                    >::read(&mut tx_bytes.as_slice())
                    .map_err(|e| WalletError::ScanFailed(format!("failed to parse tx: {}", e)))?;

                    pruned_txs.push(full_tx.into());
                }
            }
        }

        Ok((block, pruned_txs))
    }

    fn block_ringct_output_count(
        block: &monero_oxide::block::Block,
        txs: &[monero_oxide::transaction::Transaction<monero_oxide::transaction::Pruned>],
    ) -> Result<u64, WalletError> {
        let mut total = 0u64;

        if matches!(
            block.miner_transaction(),
            monero_oxide::transaction::Transaction::V2 { .. }
        ) {
            total = total
                .checked_add(
                    u64::try_from(block.miner_transaction().prefix().outputs.len()).map_err(
                        |_| {
                            WalletError::ScanFailed(
                                "miner transaction output count overflow".into(),
                            )
                        },
                    )?,
                )
                .ok_or_else(|| WalletError::ScanFailed("RingCT output index overflow".into()))?;
        }

        for tx in txs {
            if matches!(tx, monero_oxide::transaction::Transaction::V2 { .. }) {
                total = total
                    .checked_add(u64::try_from(tx.prefix().outputs.len()).map_err(|_| {
                        WalletError::ScanFailed("transaction output count overflow".into())
                    })?)
                    .ok_or_else(|| {
                        WalletError::ScanFailed("RingCT output index overflow".into())
                    })?;
            }
        }

        Ok(total)
    }

    /// Fetch a ScannableBlock while carrying forward the RingCT output index
    /// across a sequential height scan.
    async fn fetch_scannable_block(
        client: &reqwest::Client,
        daemon_url: &str,
        height: u64,
        next_ringct_output_index: &mut Option<u64>,
    ) -> Result<monero_interface::ScannableBlock, WalletError> {
        let (block, pruned_txs) =
            Self::fetch_scannable_block_parts(client, daemon_url, height).await?;
        let ringct_output_count = Self::block_ringct_output_count(&block, &pruned_txs)?;

        let output_index_for_first_ringct_output = if ringct_output_count == 0 {
            None
        } else {
            if next_ringct_output_index.is_none() {
                *next_ringct_output_index =
                    Self::get_first_ringct_output_index(daemon_url, &block, &pruned_txs).await?;
            }

            let current_index = *next_ringct_output_index;
            if let Some(next_index) = next_ringct_output_index.as_mut() {
                *next_index = next_index.checked_add(ringct_output_count).ok_or_else(|| {
                    WalletError::ScanFailed("RingCT output index overflow".into())
                })?;
            }
            current_index
        };

        Ok(monero_interface::ScannableBlock {
            block,
            transactions: pruned_txs,
            output_index_for_first_ringct_output,
        })
    }

    /// Get the global output index for the first RingCT output in a block.
    ///
    /// Uses `/get_transactions` to recover the first RingCT transaction's
    /// output indexes.
    ///
    /// The old scan path attempted to POST JSON to monerod's binary
    /// `/get_o_indexes.bin` route. Real daemons reject that body format, so
    /// the JSON fallback is used as the primary path until this adapter is
    /// wired to the daemon interface's real EPEE transport.
    async fn get_first_ringct_output_index(
        daemon_url: &str,
        block: &monero_oxide::block::Block,
        txs: &[monero_oxide::transaction::Transaction<monero_oxide::transaction::Pruned>],
    ) -> Result<Option<u64>, WalletError> {
        let ringct_hash = if matches!(
            block.miner_transaction(),
            monero_oxide::transaction::Transaction::V2 { .. }
        ) && !block.miner_transaction().prefix().outputs.is_empty()
        {
            Some(block.miner_transaction().hash())
        } else {
            block
                .transactions
                .iter()
                .zip(txs.iter())
                .find(|(_, tx)| {
                    matches!(tx, monero_oxide::transaction::Transaction::V2 { .. })
                        && !tx.prefix().outputs.is_empty()
                })
                .map(|(hash, _)| *hash)
        };

        let Some(ringct_hash) = ringct_hash else {
            return Ok(None);
        };
        let ringct_hash = hex::encode(ringct_hash);

        // Query via get_transactions, which carries output_indices for the
        // mined transaction without relying on the broken JSON->EPEE bridge.
        let request_body = serde_json::to_vec(&serde_json::json!({
            "txs_hashes": [ringct_hash],
            "decode_as_json": true,
        }))
        .map_err(|e| WalletError::RpcRequest(format!("serialize o_indexes fallback: {}", e)))?;

        let body_bytes = crate::rpc_transport::post_json_http1_identity_raw(
            daemon_url,
            "get_transactions",
            &request_body,
        )
        .await
        .map_err(|e| {
            WalletError::RpcConnection(format!(
                "get_transactions for o_indexes (daemon: {}): {}",
                daemon_url, e
            ))
        })?;

        let tx_json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
            WalletError::RpcRequest(format!(
                "parse o_indexes response ({} bytes, first 500: {:?}): {}",
                body_bytes.len(),
                String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(500)]),
                e
            ))
        })?;

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
            .post(format!("{}/sendrawtransaction", daemon_url))
            .json(&serde_json::json!({
                "tx_as_hex": tx_hex,
                "do_not_relay": false,
            }))
            .send()
            .await
            .map_err(|e| {
                WalletError::BroadcastFailed(format!(
                    "sendrawtransaction (daemon: {}): {}",
                    daemon_url, e
                ))
            })?;

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            WalletError::BroadcastFailed(format!("parse broadcast response: {}", e))
        })?;

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

        let tx =
            monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
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
        let mut next_ringct_output_index = None;

        let mut results = Vec::new();
        let mut wallet_outputs = Vec::new();

        // Scan blocks in range (batch-friendly: scan one block at a time)
        for height in from_height..to_height {
            let scannable = Self::fetch_scannable_block(
                client,
                daemon_url,
                height,
                &mut next_ringct_output_index,
            )
            .await?;

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
    fn compute_key_image(sender_spend: &Scalar, output: &monero_wallet::WalletOutput) -> [u8; 32] {
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
        let key_images: Vec<String> = outputs
            .iter()
            .map(|o| hex::encode(Self::compute_key_image(sender_spend, o)))
            .collect();

        // Query daemon for spent status
        let resp = client
            .post(format!("{}/is_key_image_spent", daemon_url))
            .json(&serde_json::json!({ "key_images": key_images }))
            .send()
            .await
            .map_err(|e| {
                WalletError::BroadcastFailed(format!(
                    "is_key_image_spent (daemon: {}): {}",
                    daemon_url, e
                ))
            })?;

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            WalletError::BroadcastFailed(format!(
                "parse key image response (daemon: {}): {}",
                daemon_url, e
            ))
        })?;

        let spent_statuses = json["spent_status"]
            .as_array()
            .ok_or_else(|| WalletError::BroadcastFailed("no spent_status in response".into()))?;

        let mut unspent = Vec::new();
        for (i, output) in outputs.into_iter().enumerate() {
            let status = spent_statuses.get(i).and_then(|v| v.as_u64()).unwrap_or(1); // default to "spent" if unknown
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

    /// Scan sender outputs in ascending block order and stop once enough mature,
    /// unspent funds exist to satisfy a lock attempt.
    async fn scan_lock_ready_outputs(
        client: &reqwest::Client,
        daemon_url: &str,
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
        sender_spend: &Scalar,
        from_height: u64,
        to_height: u64,
        current_height: u64,
        amount: u64,
    ) -> Result<Vec<monero_wallet::WalletOutput>, WalletError> {
        let view_pair = Self::create_view_pair(spend_point, view_scalar)?;
        let mut scanner = monero_wallet::Scanner::new(view_pair);
        let mut mature_outputs = Vec::new();
        let mut next_ringct_output_index = None;

        let mut scanned = 0u64;
        let mut skipped_proto = 0u64;
        for height in from_height..to_height {
            let scannable = Self::fetch_scannable_block(
                client,
                daemon_url,
                height,
                &mut next_ringct_output_index,
            )
            .await?;

            match scanner.scan(scannable) {
                Ok(timelocked) => {
                    for output in timelocked.ignore_additional_timelock() {
                        let is_mature = match output.additional_timelock() {
                            monero_oxide::transaction::Timelock::None => true,
                            monero_oxide::transaction::Timelock::Block(unlock_height) => {
                                (current_height as usize) >= unlock_height
                            }
                            monero_oxide::transaction::Timelock::Time(unlock_time) => {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                now >= unlock_time
                            }
                        };
                        if !is_mature {
                            continue;
                        }

                        tracing::debug!(
                            target: "xmr_wallet",
                            amount = output.commitment().amount,
                            height = height,
                            "found mature XMR lock candidate"
                        );
                        mature_outputs.push(output);
                    }
                }
                Err(monero_wallet::ScanError::UnsupportedProtocol(version)) => {
                    tracing::warn!(
                        target: "xmr_wallet",
                        height = height,
                        version = version,
                        "skipping block with unsupported protocol version during lock scan"
                    );
                    skipped_proto += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        target: "xmr_wallet",
                        height = height,
                        error = %err,
                        "scan error, skipping block during lock scan"
                    );
                }
            }
            scanned += 1;

            if mature_outputs.is_empty() {
                continue;
            }

            let mature_amounts: Vec<u64> = mature_outputs
                .iter()
                .map(|output| output.commitment().amount)
                .collect();
            if Self::select_lock_output_indices(&mature_amounts, amount).is_err() {
                continue;
            }

            let unspent =
                Self::filter_unspent(client, daemon_url, sender_spend, mature_outputs.clone())
                    .await?;
            let unspent_amounts: Vec<u64> = unspent
                .iter()
                .map(|output| output.commitment().amount)
                .collect();
            if Self::select_lock_output_indices(&unspent_amounts, amount).is_ok() {
                tracing::info!(
                    target: "xmr_wallet",
                    from_height = from_height,
                    to_height = to_height,
                    scanned = scanned,
                    skipped_proto = skipped_proto,
                    candidates = unspent.len(),
                    "lock scan found sufficient mature unspent XMR outputs before tip"
                );
                return Ok(unspent);
            }

            mature_outputs = unspent;
        }

        tracing::info!(
            target: "xmr_wallet",
            from_height = from_height,
            to_height = to_height,
            scanned = scanned,
            skipped_proto = skipped_proto,
            candidates = mature_outputs.len(),
            "lock scan exhausted range without early exit"
        );

        Self::filter_unspent(client, daemon_url, sender_spend, mature_outputs).await
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
        let sender_spend = self.sender_spend_key.as_ref().ok_or_else(|| {
            WalletError::KeyError(
                "lock requires sender keys -- use XmrWallet::with_sender_keys()".into(),
            )
        })?;
        let sender_view = self
            .sender_view_key
            .as_ref()
            .ok_or_else(|| WalletError::KeyError("lock requires sender view key".into()))?;

        // Derive sender's spend public key
        let sender_spend_point = **sender_spend * G;

        // Step 1: Scan sender's wallet for spendable outputs
        let client = &self.client;
        let current_height = Self::get_chain_height(client, &self.daemon_url).await?;

        let sender_outputs = Self::scan_lock_ready_outputs(
            client,
            &self.daemon_url,
            &sender_spend_point,
            sender_view,
            sender_spend,
            self.scan_from_height,
            current_height,
            current_height,
            amount,
        )
        .await?;

        tracing::info!(
            target: "xmr_wallet",
            from_height = self.scan_from_height,
            to_height = current_height,
            blocks = current_height.saturating_sub(self.scan_from_height),
            unspent = sender_outputs.len(),
            "completed XMR sender scan for lock"
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

        // Step 2: Select outputs covering amount + a conservative fee estimate.
        let sender_amounts: Vec<u64> = sender_outputs
            .iter()
            .map(|o| o.commitment().amount)
            .collect();
        let selected_indices = Self::select_lock_output_indices(&sender_amounts, amount)?;
        let mut selected_total = 0u64;
        let mut selected_outputs = Vec::with_capacity(selected_indices.len());
        for selected_idx in selected_indices {
            let output = sender_outputs.get(selected_idx).cloned().ok_or_else(|| {
                WalletError::TxBuildFailed("selected sender output out of range".into())
            })?;
            selected_total = selected_total.saturating_add(output.commitment().amount);
            selected_outputs.push(output);
        }
        let estimated_fee = Self::estimate_lock_fee(selected_outputs.len());
        tracing::info!(
            target: "xmr_wallet",
            available_unspent = sender_amounts.len(),
            selected_inputs = selected_outputs.len(),
            selected_total = selected_total,
            estimated_fee = estimated_fee,
            amount = amount,
            "selected sender outputs for XMR lock"
        );

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
        let daemon = transport
            .monero_daemon()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        // Get fee rate from daemon
        let fee_rate = daemon
            .fee_rate(
                monero_interface::FeePriority::Normal,
                XMR_FEE_RATE_SANITY_BOUND,
            )
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        // Get current block number for decoy selection
        use monero_interface::ProvidesBlockchainMeta;
        let block_number = daemon
            .latest_block_number()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        // Select decoys for each input
        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 16; // XMR ring size

        let mut inputs_with_decoys = Vec::with_capacity(selected_outputs.len());
        for output in selected_outputs {
            let owd = monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &daemon,
                ring_len,
                block_number,
                output,
            )
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("decoy selection: {}", e)))?;
            inputs_with_decoys.push(owd);
        }

        // Build the outgoing view key (SHA-256 of sender view scalar bytes)
        let outgoing_view_key = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(sender_view.as_bytes());
            let hash = hasher.finalize();
            Zeroizing::new(<[u8; 32]>::try_from(&hash[..]).expect("SHA-256 is 32 bytes"))
        };

        // Build SignableTransaction
        let payments = vec![(recipient_addr, amount)];

        // Change goes back to sender's address
        let sender_view_point = **sender_view * G;
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
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("build tx: {}", e)))?;

        // Sign with sender's spend key
        let oxide_spend_key = Zeroizing::new(monero_oxide::ed25519::Scalar::from(**sender_spend));
        let signed_tx = signable
            .sign(&mut rng, &oxide_spend_key)
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
    /// sweep MUST scan first to discover outputs -- you cannot
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

        let total_amount: u64 = joint_outputs.iter().map(|o| o.commitment().amount).sum();

        tracing::info!(
            target: "xmr_wallet",
            outputs = joint_outputs.len(),
            total_amount = total_amount,
            "found outputs at joint address, building sweep transaction"
        );

        // Step 2: Parse destination address
        let dest_addr =
            monero_wallet::address::MoneroAddress::from_str_with_unchecked_network(destination)
                .map_err(|e| {
                    WalletError::InvalidAddress(format!("invalid destination: {:?}", e))
                })?;

        // Step 3: Build sweep transaction via MoneroDaemon
        use crate::rpc_transport::ReqwestTransport;
        use monero_interface::ProvidesFeeRates;

        let transport = ReqwestTransport::new(&self.daemon_url);
        let daemon = transport
            .monero_daemon()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        let fee_rate = daemon
            .fee_rate(
                monero_interface::FeePriority::Normal,
                XMR_FEE_RATE_SANITY_BOUND,
            )
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        use monero_interface::ProvidesBlockchainMeta;
        let block_number = daemon
            .latest_block_number()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 16; // XMR ring size

        let mut inputs_with_decoys = Vec::with_capacity(joint_outputs.len());
        for output in joint_outputs {
            let owd = monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &daemon,
                ring_len,
                block_number,
                output,
            )
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("decoy selection: {}", e)))?;
            inputs_with_decoys.push(owd);
        }

        let outgoing_view_key = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(view_scalar.as_bytes());
            let hash = hasher.finalize();
            Zeroizing::new(<[u8; 32]>::try_from(&hash[..]).expect("SHA-256 is 32 bytes"))
        };

        // Sweep: send (total - estimated_fee) to destination.
        // Monero requires at least 2 outputs, so we use a change output
        // back to the destination which will receive any fee overshoot.
        let change = monero_wallet::send::Change::fingerprintable(Some(dest_addr));

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
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("build sweep tx: {}", e)))?;

        let oxide_spend_secret = Zeroizing::new(monero_oxide::ed25519::Scalar::from(*spend_secret));
        let signed_tx = signable
            .sign(&mut rng, &oxide_spend_secret)
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

        let request_body = serde_json::to_vec(&serde_json::json!({
            "txs_hashes": [tx_hash_hex],
            "decode_as_json": false,
            "prune": true,
        }))
        .map_err(|e| WalletError::RpcRequest(format!("serialize get_transactions: {}", e)))?;

        // Phase 38.1 iteration 10: bypass reqwest/hyper entirely for this
        // endpoint so Shadow cannot fail inside reqwest's body decoder.
        let body_bytes = crate::rpc_transport::post_json_http1_identity_raw(
            &self.daemon_url,
            "get_transactions",
            &request_body,
        )
        .await
        .map_err(|e| {
            WalletError::RpcRequest(format!(
                "read get_transactions bytes (daemon: {}): {}",
                self.daemon_url, e
            ))
        })?;
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
            WalletError::RpcRequest(format!(
                "parse get_transactions ({} bytes, first 500: {:?}): {}",
                body_bytes.len(),
                String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(500)]),
                e
            ))
        })?;

        // Defensive: daemon may return a response with no `txs` field on
        // error paths. Return a diagnostic error rather than TxNotFound.
        let txs = match json.get("txs").and_then(|v| v.as_array()) {
            Some(t) => t,
            None => {
                let status = json
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<no status>");
                return Err(WalletError::RpcRequest(format!(
                    "get_transactions response missing `txs` array (daemon: {}, status: {}): {}",
                    self.daemon_url,
                    status,
                    String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(200)]),
                )));
            }
        };

        if txs.is_empty() {
            // Empty txs can mean "tx not yet indexed" (retryable). Return
            // not-yet-confirmed so the retry loop keeps polling.
            return Ok(ConfirmationStatus {
                confirmed: false,
                confirmations: 0,
                block_height: None,
            });
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
        let current_height = rpc.get_height().await.map_err(|e| {
            WalletError::RpcRequest(format!(
                "get_height failed (daemon: {}): {}",
                self.daemon_url, e
            ))
        })?;

        let confirmations = current_height.saturating_sub(tx_height);

        Ok(ConfirmationStatus {
            confirmed: confirmations >= required_confirmations,
            confirmations,
            block_height: Some(tx_height),
        })
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
            .post(format!("{}/sendrawtransaction", self.daemon_url))
            .json(&serde_json::json!({
                "tx_as_hex": tx_hex,
                "do_not_relay": false,
            }))
            .send()
            .await
            .map_err(|e| {
                WalletError::BroadcastFailed(format!(
                    "sendrawtransaction (daemon: {}): {}",
                    self.daemon_url, e
                ))
            })?;

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            WalletError::BroadcastFailed(format!(
                "parse broadcast response (daemon: {}): {}",
                self.daemon_url, e
            ))
        })?;

        let status = json["status"].as_str().unwrap_or("unknown");
        if status != "OK" {
            return Err(WalletError::BroadcastFailed(format!(
                "daemon rejected tx (daemon: {}): {}",
                self.daemon_url, json
            )));
        }

        // Compute the tx hash from the bytes
        let tx =
            monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
                &mut tx_bytes.to_vec().as_slice(),
            )
            .map_err(|e| {
                WalletError::TxBuildFailed(format!("failed to parse tx for hash: {}", e))
            })?;

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
    use rand::rngs::OsRng;
    use xmr_wow_crypto::keysplit::KeyContribution;

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
        assert!(
            result.is_ok(),
            "ViewPair creation should succeed with valid keys"
        );
    }

    #[test]
    fn test_derive_address_matches_crypto_crate() {
        // Generate two key contributions (simulating Alice and Bob)
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);

        // Combine public keys to get joint spend point
        let joint_spend = xmr_wow_crypto::keysplit::combine_public_keys(&alice.public, &bob.public);

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
        assert_eq!(
            wallet_address.len(),
            95,
            "stagenet address should be 95 chars"
        );
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

    #[test]
    fn test_xmr_fee_rate_sanity_bound() {
        assert!(
            XMR_FEE_RATE_SANITY_BOUND >= 1_000_000,
            "XMR fee sanity bound must stay well above the old 100k ceiling"
        );
    }

    #[test]
    fn test_xmr_lock_selection_prefers_smallest_sufficient_single_output() {
        let amounts = vec![1_900_000_000_000, 1_200_000_000_000, 1_600_000_000_000];
        let selected = XmrWallet::select_lock_output_indices(&amounts, 1_000_000_000_000).unwrap();
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn test_xmr_lock_selection_prefers_minimal_input_count() {
        let amounts = vec![520_000_000_000, 510_000_000_000, 90_000_000_000];
        let selected = XmrWallet::select_lock_output_indices(&amounts, 1_000_000_000_000).unwrap();
        assert_eq!(selected.len(), 2);
        let total: u64 = selected.iter().map(|idx| amounts[*idx]).sum();
        assert!(total >= 1_000_000_000_000 + XmrWallet::estimate_lock_fee(selected.len()));
    }
}
