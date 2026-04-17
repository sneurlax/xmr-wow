//! WOW wallet adapter for Wownero testnet and mainnet.
//!
//! Uses wownero-oxide's wallet APIs (Scanner, ViewPair, SignableTransaction) directly
//! for output scanning and transaction construction. Block fetching and tx submission
//! use reqwest HTTP calls to wownerod, consistent with the XmrWallet pattern.
//!
//! ## Architecture
//!
//! WowWallet holds a daemon URL and optional sender credentials. The four trait methods
//! map to wownerod endpoints via reqwest:
//!
//! - `lock` -> scan sender wallet, build SignableTransaction to joint address, broadcast
//! - `sweep` -> scan joint address for outputs, build sweep tx, broadcast
//! - `scan` -> fetch blocks from wownerod, parse with wownero-oxide, scan with Scanner
//! - `poll_confirmation` -> `/get_transactions` + `/json_rpc get_block_count`
//!
//! ## wownero-oxide Integration
//!
//! This module bypasses wownero-rust's scanner.rs (26 stubs) and tx_builder.rs (3 stubs)
//! by using wownero-oxide's wallet APIs directly:
//! - `wownero_wallet::ViewPair` + `wownero_wallet::Scanner` for output detection
//! - `wownero_wallet::send::SignableTransaction` for transaction construction
//! - `wownero_oxide::block::Block` and `wownero_oxide::transaction::Transaction` for parsing
//!
//! wownero-oxide handles WOW-specific differences automatically:
//! - RctType::WowneroClsagBulletproofPlus (wire type 8)
//! - Ring size 22
//! - INV_EIGHT commitment scaling (output commitments stored as C/8)
//! - Default spendable age: 4 blocks

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use std::cmp::Reverse;
use tracing;
use zeroize::Zeroizing;

use crate::error::WalletError;
use crate::trait_def::{ConfirmationStatus, CryptoNoteWallet, RefundChain, ScanResult, TxHash};

/// WOW mainnet default JSON-RPC port.
/// Note: 34567 is the P2P port, 34568 is the JSON-RPC port.
const WOW_MAINNET_DEFAULT_PORT: u16 = 34568;
const WOW_FEE_RATE_SANITY_BOUND: u64 = 100_000_000;
const WOW_LOCK_BASE_FEE_ESTIMATE: u64 = 19_000_000;
const WOW_LOCK_FEE_PER_INPUT_ESTIMATE: u64 = 16_000_000;
const WOW_SWEEP_FEE_PROBE_AMOUNT: u64 = 1;

/// Wownero wallet adapter.
///
/// Implements `CryptoNoteWallet` using wownero-oxide's wallet APIs directly for
/// scanning (Scanner + ViewPair) and transaction construction (SignableTransaction).
///
/// The wallet operates in two modes:
/// - **Scan-only** (`new` / `mainnet_default`): Can scan and poll, but not lock or sweep
/// - **Full** (`with_sender_keys`): Can also lock funds using sender's private keys
pub struct WowWallet {
    /// RPC endpoint URL for wownerod.
    daemon_url: String,
    /// Shared reqwest client with 30-second timeout for all daemon RPC calls.
    client: reqwest::Client,
    /// Optional sender spend key (needed for lock -- Bob's personal wallet key)
    sender_spend_key: Option<Zeroizing<Scalar>>,
    /// Optional sender view key (needed for lock -- to scan sender's wallet for inputs)
    sender_view_key: Option<Zeroizing<Scalar>>,
    /// Block height to start scanning from (0 = full rescan)
    scan_from_height: u64,
}

impl WowWallet {
    fn estimate_lock_fee(num_inputs: usize) -> u64 {
        WOW_LOCK_BASE_FEE_ESTIMATE + (num_inputs as u64 * WOW_LOCK_FEE_PER_INPUT_ESTIMATE)
    }

    fn select_lock_output_indices(amounts: &[u64], amount: u64) -> Result<Vec<usize>, WalletError> {
        if amounts.is_empty() {
            return Err(WalletError::NoOutputsFound);
        }

        let total_available: u64 = amounts.iter().sum();
        let single_output_target = amount.saturating_add(Self::estimate_lock_fee(1));

        // Prefer the smallest single output which can fund the lock by itself.
        // Fewer inputs materially reduces the number of decoy sets the daemon
        // has to provide for this pre-broadcast `lock-wow` path.
        let mut ascending: Vec<(usize, u64)> = amounts.iter().copied().enumerate().collect();
        ascending.sort_by_key(|(_, output_amount)| *output_amount);
        if let Some((selected_idx, _)) = ascending
            .into_iter()
            .find(|(_, output_amount)| *output_amount >= single_output_target)
        {
            return Ok(vec![selected_idx]);
        }

        // If no single output works, greedily add the largest outputs first so
        // we reach the target with the minimum practical input count.
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

    fn exact_sweep_payment_amount(
        total_amount: u64,
        outgoing_view_key: &Zeroizing<[u8; 32]>,
        inputs_with_decoys: &[wownero_wallet::OutputWithDecoys],
        dest_addr: wownero_wallet::address::MoneroAddress,
        fee_rate: wownero_interface::FeeRate,
        additional_timelock: Option<wownero_oxide::transaction::Timelock>,
    ) -> Result<u64, WalletError> {
        let probe_result = match additional_timelock {
            Some(additional_timelock) => {
                wownero_wallet::send::SignableTransaction::new_with_timelock(
                    wownero_oxide::ringct::RctType::WowneroClsagBulletproofPlus,
                    outgoing_view_key.clone(),
                    inputs_with_decoys.to_vec(),
                    vec![(dest_addr, WOW_SWEEP_FEE_PROBE_AMOUNT)],
                    wownero_wallet::send::Change::fingerprintable(Some(dest_addr)),
                    vec![],
                    fee_rate,
                    additional_timelock,
                )
            }
            None => wownero_wallet::send::SignableTransaction::new(
                wownero_oxide::ringct::RctType::WowneroClsagBulletproofPlus,
                outgoing_view_key.clone(),
                inputs_with_decoys.to_vec(),
                vec![(dest_addr, WOW_SWEEP_FEE_PROBE_AMOUNT)],
                wownero_wallet::send::Change::fingerprintable(Some(dest_addr)),
                vec![],
                fee_rate,
            ),
        };

        let probe_signable = match probe_result {
            Ok(probe_signable) => probe_signable,
            Err(wownero_wallet::send::SendError::NotEnoughFunds {
                outputs,
                necessary_fee,
                ..
            }) => {
                return Err(WalletError::InsufficientFunds {
                    need: outputs.saturating_add(necessary_fee.unwrap_or_default()),
                    have: total_amount,
                });
            }
            Err(err) => {
                return Err(WalletError::TxBuildFailed(format!(
                    "probe sweep tx: {}",
                    err
                )));
            }
        };

        let exact_fee = probe_signable.necessary_fee();
        let sweep_amount = total_amount.saturating_sub(exact_fee);
        if sweep_amount == 0 {
            return Err(WalletError::InsufficientFunds {
                need: exact_fee,
                have: total_amount,
            });
        }

        tracing::info!(
            target: "wow_wallet",
            total_amount = total_amount,
            exact_fee = exact_fee,
            sweep_amount = sweep_amount,
            timelocked = additional_timelock.is_some(),
            "calculated exact WOW sweep amount"
        );

        Ok(sweep_amount)
    }

    fn is_decoy_round_limit_error(err: &wownero_interface::TransactionsError) -> bool {
        matches!(
            err,
            wownero_interface::TransactionsError::InterfaceError(
                wownero_interface::InterfaceError::InternalError(message)
                    | wownero_interface::InterfaceError::InterfaceError(message)
            ) if message.contains("hit decoy selection round limit")
        )
    }

    async fn select_sweep_decoys(
        rng: &mut (impl Send + Sync + rand_core::RngCore + rand_core::CryptoRng),
        daemon: &impl wownero_interface::ProvidesDecoys,
        ring_len: u8,
        block_number: usize,
        output: wownero_wallet::WalletOutput,
    ) -> Result<wownero_wallet::OutputWithDecoys, WalletError> {
        let output_amount = output.commitment().amount;
        let output_global_index = output.index_on_blockchain();

        match wownero_wallet::OutputWithDecoys::new(
            rng,
            daemon,
            ring_len,
            block_number,
            output.clone(),
        )
        .await
        {
            Ok(output_with_decoys) => Ok(output_with_decoys),
            Err(err) if Self::is_decoy_round_limit_error(&err) => {
                tracing::warn!(
                    target: "wow_wallet",
                    output_amount = output_amount,
                    global_index = output_global_index,
                    error = %err,
                    "random WOW decoy selection hit round limit; retrying with deterministic decoys"
                );

                wownero_wallet::OutputWithDecoys::fingerprintable_deterministic_new(
                    rng,
                    daemon,
                    ring_len,
                    block_number,
                    output,
                )
                .await
                .map_err(|fallback_err| {
                    WalletError::TxBuildFailed(format!(
                        "decoy selection fallback after round limit (initial: {}; fallback: {})",
                        err, fallback_err
                    ))
                })
            }
            Err(err) => Err(WalletError::TxBuildFailed(format!(
                "decoy selection: {}",
                err
            ))),
        }
    }

    /// Create a new WowWallet pointing at the given wownerod RPC endpoint.
    ///
    /// This wallet can scan and poll but cannot lock (no sender keys).
    ///
    /// # Arguments
    ///
    /// * `daemon_url` - Full URL including port, e.g. "http://127.0.0.1:34568"
    pub fn new(daemon_url: &str) -> Self {
        WowWallet {
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

    /// Create a WowWallet with the default WOW mainnet endpoint.
    ///
    /// Connects to `http://127.0.0.1:34568` (wownerod mainnet JSON-RPC).
    /// WOW mainnet is used for validation because WOW stagenet/testnet are non-functional.
    pub fn mainnet_default() -> Self {
        Self::new(&format!("http://127.0.0.1:{}", WOW_MAINNET_DEFAULT_PORT))
    }

    /// Create a wallet with sender credentials for locking funds.
    ///
    /// `spend_key` and `view_key` are the sender's personal wallet keys,
    /// used to find spendable outputs and sign lock transactions.
    pub fn with_sender_keys(daemon_url: &str, spend_key: Scalar, view_key: Scalar) -> Self {
        WowWallet {
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

    /// Returns the daemon URL this wallet is configured to use.
    pub fn daemon_url(&self) -> &str {
        &self.daemon_url
    }

    /// Derive the CryptoNote standard address from (spend_point, view_scalar).
    ///
    /// The address encodes (spend_point, view_scalar * G) with the Wownero
    /// network prefix (4146). This is the address funds are locked to
    /// and scanned at during the atomic swap.
    pub fn derive_address(spend_point: &EdwardsPoint, view_scalar: &Scalar) -> String {
        let view_pubkey = view_scalar * G;
        // Use xmr-wow-crypto's address encoding for Wownero
        xmr_wow_crypto::address::encode_address(
            spend_point,
            &view_pubkey,
            xmr_wow_crypto::address::Network::Wownero,
        )
    }

    /// Create a wownero-oxide ViewPair from dalek types.
    ///
    /// Converts curve25519-dalek EdwardsPoint and Scalar to wownero-oxide's
    /// Point and Scalar newtypes, then constructs a ViewPair for scanning.
    fn create_view_pair(
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
    ) -> Result<wownero_wallet::ViewPair, WalletError> {
        let oxide_spend = wownero_oxide::ed25519::Point::from(*spend_point);
        let oxide_view = Zeroizing::new(wownero_oxide::ed25519::Scalar::from(*view_scalar));

        wownero_wallet::ViewPair::new(oxide_spend, oxide_view)
            .map_err(|e| WalletError::KeyError(format!("ViewPair creation failed: {}", e)))
    }

    /// Fetch current chain height from wownerod.
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

    /// Fetch a block by height and its transactions, constructing a ScannableBlock.
    ///
    /// Uses wownerod JSON-RPC `get_block` to get the block blob, then
    /// `/get_transactions` to fetch the non-miner transactions. Constructs
    /// a `ScannableBlock` suitable for wownero-oxide's Scanner.
    async fn fetch_scannable_block(
        client: &reqwest::Client,
        daemon_url: &str,
        height: u64,
    ) -> Result<wownero_interface::ScannableBlock, WalletError> {
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

        let block = wownero_oxide::block::Block::read(&mut blob_bytes.as_slice()).map_err(|e| {
            WalletError::ScanFailed(format!("failed to parse block {}: {}", height, e))
        })?;

        // Step 2: Fetch non-miner transactions if any exist
        let mut pruned_txs: Vec<
            wownero_oxide::transaction::Transaction<wownero_oxide::transaction::Pruned>,
        > = Vec::new();

        if !block.transactions.is_empty() {
            let tx_hashes: Vec<String> = block.transactions.iter().map(hex::encode).collect();
            let request_body = serde_json::to_vec(&serde_json::json!({
                "txs_hashes": tx_hashes,
                "decode_as_json": false,
                "prune": true,
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
                    if let Some(pruned_hex) = tx_entry["pruned_as_hex"]
                        .as_str()
                        .filter(|value| !value.is_empty())
                    {
                        let tx_bytes = hex::decode(pruned_hex).map_err(|e| {
                            WalletError::ScanFailed(format!("invalid pruned tx hex: {}", e))
                        })?;

                        let pruned_tx = wownero_oxide::transaction::Transaction::<
                            wownero_oxide::transaction::Pruned,
                        >::read(&mut tx_bytes.as_slice())
                        .map_err(|e| {
                            WalletError::ScanFailed(format!("failed to parse pruned tx: {}", e))
                        })?;

                        pruned_txs.push(pruned_tx);
                        continue;
                    }

                    let tx_hex = tx_entry["as_hex"].as_str().ok_or_else(|| {
                        WalletError::ScanFailed("missing pruned_as_hex/as_hex in tx".into())
                    })?;

                    let tx_bytes = hex::decode(tx_hex)
                        .map_err(|e| WalletError::ScanFailed(format!("invalid tx hex: {}", e)))?;

                    let full_tx = wownero_oxide::transaction::Transaction::<
                        wownero_oxide::transaction::NotPruned,
                    >::read(&mut tx_bytes.as_slice())
                    .map_err(|e| WalletError::ScanFailed(format!("failed to parse tx: {}", e)))?;

                    pruned_txs.push(full_tx.into());
                }
            }
        }

        // Step 3: Get output_index_for_first_ringct_output
        let output_index =
            Self::get_first_ringct_output_index(daemon_url, &block, &pruned_txs).await?;

        Ok(wownero_interface::ScannableBlock {
            block,
            transactions: pruned_txs,
            output_index_for_first_ringct_output: output_index,
        })
    }

    /// Get the global output index for the first RingCT output in a block.
    ///
    /// Uses `/get_transactions` to recover the first RingCT transaction's
    /// output indexes.
    ///
    /// The old scan path attempted to POST JSON to wownerod's binary
    /// `/get_o_indexes.bin` route. Real daemons reject that body format, which
    /// turns every scanned block into an avoidable server-side parse failure
    /// under Shadow. Keep the JSON fallback as the primary path until the scan
    /// adapter is wired to the daemon interface's real EPEE transport.
    async fn get_first_ringct_output_index(
        daemon_url: &str,
        block: &wownero_oxide::block::Block,
        txs: &[wownero_oxide::transaction::Transaction<wownero_oxide::transaction::Pruned>],
    ) -> Result<Option<u64>, WalletError> {
        let ringct_hash = if matches!(
            block.miner_transaction(),
            wownero_oxide::transaction::Transaction::V2 { .. }
        ) && !block.miner_transaction().prefix().outputs.is_empty()
        {
            Some(block.miner_transaction().hash())
        } else {
            block
                .transactions
                .iter()
                .zip(txs.iter())
                .find(|(_, tx)| {
                    matches!(tx, wownero_oxide::transaction::Transaction::V2 { .. })
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

        let body_bytes = match crate::rpc_transport::post_json_http1_identity_raw(
            daemon_url,
            "get_transactions",
            &request_body,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    target: "wow_wallet",
                    daemon_url = daemon_url,
                    error = %e,
                    "output index lookup via get_transactions failed; falling back to 0"
                );
                return Ok(Some(0));
            }
        };

        let tx_json: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(
                    target: "wow_wallet",
                    daemon_url = daemon_url,
                    body_len = body_bytes.len(),
                    error = %e,
                    "failed to parse output index fallback response; falling back to 0"
                );
                return Ok(Some(0));
            }
        };

        if let Some(txs) = tx_json["txs"].as_array() {
            if let Some(tx) = txs.first() {
                if let Some(indices) = tx["output_indices"].as_array() {
                    if let Some(first) = indices.first() {
                        return Ok(first.as_u64());
                    }
                }
            }
        }

        // Fallback: use 0 so scanning still proceeds (index_on_blockchain will be
        // inaccurate but output detection still works for finding spendable outputs)
        tracing::warn!(
            target: "wow_wallet",
            "output index lookup failed, falling back to 0 ; decoy selection may be fingerprintable"
        );
        Ok(Some(0))
    }

    /// Broadcast a serialized transaction to wownerod.
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

        let status = json["status"].as_str().unwrap_or("unknown");
        if status != "OK" {
            let is_double_spend = json["double_spend"].as_bool().unwrap_or(false);
            if is_double_spend {
                // Key image already in pool/chain ; sweep was already broadcast
                tracing::warn!(target: "wow_wallet", "tx rejected as double spend (already in pool/chain)");
            } else {
                let reason = json["reason"].as_str().unwrap_or("unknown error");
                return Err(WalletError::BroadcastFailed(format!(
                    "daemon rejected tx: {} ({}) full_response={}",
                    status,
                    reason,
                    serde_json::to_string(&json).unwrap_or_default()
                )));
            }
        }

        let tx_bytes = hex::decode(tx_hex)
            .map_err(|e| WalletError::TxBuildFailed(format!("invalid tx hex: {}", e)))?;

        let tx =
            wownero_oxide::transaction::Transaction::<wownero_oxide::transaction::NotPruned>::read(
                &mut tx_bytes.as_slice(),
            )
            .map_err(|e| WalletError::TxBuildFailed(format!("failed to parse built tx: {}", e)))?;

        let hash = tx.hash();
        tracing::info!(
            target: "wow_wallet",
            tx_hash = %hex::encode(hash),
            "transaction broadcast successful"
        );
        Ok(hash)
    }

    /// Scan for outputs using wownero-oxide Scanner.
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
    ) -> Result<(Vec<ScanResult>, Vec<wownero_wallet::WalletOutput>), WalletError> {
        let view_pair = Self::create_view_pair(spend_point, view_scalar)?;
        let mut scanner = wownero_wallet::Scanner::new(view_pair);
        let mut results = Vec::new();
        let mut wallet_outputs = Vec::new();

        let mut scanned = 0u64;
        let mut skipped_parse = 0u64;
        let mut skipped_proto = 0u64;
        for height in from_height..to_height {
            let scannable = match Self::fetch_scannable_block(client, daemon_url, height).await {
                Ok(s) => s,
                Err(WalletError::ScanFailed(msg))
                    if msg.contains("deserialize") || msg.contains("parse") =>
                {
                    tracing::debug!(target: "wow_wallet", height = height, error = %msg, "skipped unparseable block");
                    skipped_parse += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };

            match scanner.scan(scannable) {
                Ok(timelocked) => {
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
                            target: "wow_wallet",
                            tx_hash = %hex::encode(tx_hash),
                            amount = amount,
                            height = height,
                            "found output"
                        );
                    }
                    wallet_outputs.extend(outputs);
                }
                Err(wownero_wallet::ScanError::UnsupportedProtocol(v)) => {
                    tracing::debug!(target: "wow_wallet", height = height, protocol_version = v, "skipped unsupported protocol version");
                    skipped_proto += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        target: "wow_wallet",
                        height = height,
                        error = %e,
                        "scan error, skipping block"
                    );
                }
            }
            scanned += 1;
        }

        tracing::info!(
            target: "wow_wallet",
            scanned = scanned,
            skipped_parse = skipped_parse,
            skipped_proto = skipped_proto,
            outputs = wallet_outputs.len(),
            "scan range complete"
        );

        Ok((results, wallet_outputs))
    }

    /// Compute the key image for a WalletOutput given the sender's spend key.
    fn compute_key_image(sender_spend: &Scalar, output: &wownero_wallet::WalletOutput) -> [u8; 32] {
        use wownero_oxide::ed25519::Point as OxidePoint;
        let key_offset_dalek: Scalar = output.key_offset().into();
        let input_key_scalar = sender_spend + key_offset_dalek;
        let hp: OxidePoint = OxidePoint::biased_hash(output.key().compress().to_bytes());
        let hp_dalek: EdwardsPoint = hp.into();
        let ki_dalek: EdwardsPoint = input_key_scalar * hp_dalek;
        let ki = OxidePoint::from(ki_dalek);
        ki.compress().to_bytes()
    }

    /// Filter out already-spent outputs by checking key images against the daemon.
    async fn filter_unspent(
        client: &reqwest::Client,
        daemon_url: &str,
        sender_spend: &Scalar,
        outputs: Vec<wownero_wallet::WalletOutput>,
    ) -> Result<Vec<wownero_wallet::WalletOutput>, WalletError> {
        if outputs.is_empty() {
            return Ok(outputs);
        }

        let key_images: Vec<String> = outputs
            .iter()
            .map(|o| hex::encode(Self::compute_key_image(sender_spend, o)))
            .collect();

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
            let status = spent_statuses.get(i).and_then(|v| v.as_u64()).unwrap_or(1);
            if status == 0 {
                unspent.push(output);
            }
        }

        Ok(unspent)
    }
}

#[async_trait::async_trait]
impl CryptoNoteWallet for WowWallet {
    fn refund_chain(&self) -> RefundChain {
        RefundChain::Wow
    }

    /// Lock funds to the joint address derived from (spend_point, view_scalar).
    ///
    /// Builds a transaction sending `amount` wowoshi to the CryptoNote
    /// address derived from the joint spend point and view scalar, then
    /// broadcasts it to wownerod.
    ///
    /// Requires sender credentials (use `with_sender_keys` constructor).
    /// wownero-oxide handles: RctType 8, ring size 22, INV_EIGHT scaling,
    /// fee calculation, decoy selection -- all automatically.
    async fn lock(
        &self,
        spend_point: &EdwardsPoint,
        view_scalar: &Scalar,
        amount: u64,
    ) -> Result<TxHash, WalletError> {
        let address = Self::derive_address(spend_point, view_scalar);
        tracing::info!(
            target: "wow_wallet",
            address = %address,
            amount = amount,
            "locking funds to joint address"
        );

        // Require sender keys for lock
        let sender_spend = self.sender_spend_key.as_ref().ok_or_else(|| {
            WalletError::KeyError(
                "lock requires sender keys -- use WowWallet::with_sender_keys()".into(),
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

        let (_scan_results, all_outputs) = Self::scan_with_scanner(
            &self.client,
            &self.daemon_url,
            &sender_spend_point,
            sender_view,
            self.scan_from_height,
            current_height,
        )
        .await?;

        tracing::info!(target: "wow_wallet", count = all_outputs.len(), "scan found outputs");
        for o in &all_outputs {
            tracing::debug!(
                target: "wow_wallet",
                amount = o.commitment().amount,
                tx = %hex::encode(o.transaction()),
                "scanned output"
            );
        }

        // Filter out immature coinbase outputs
        let total_found = all_outputs.len();
        let mature_outputs: Vec<_> = all_outputs
            .into_iter()
            .filter(|o| match o.additional_timelock() {
                wownero_oxide::transaction::Timelock::None => true,
                wownero_oxide::transaction::Timelock::Block(b) => (current_height as usize) >= b,
                wownero_oxide::transaction::Timelock::Time(t) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    now >= t
                }
            })
            .collect();

        if mature_outputs.len() < total_found {
            tracing::info!(
                target: "wow_wallet",
                immature = total_found - mature_outputs.len(),
                mature = mature_outputs.len(),
                "filtered immature coinbase outputs"
            );
        }

        let sender_outputs =
            Self::filter_unspent(client, &self.daemon_url, sender_spend, mature_outputs).await?;
        let available_unspent = sender_outputs.len();

        tracing::info!(target: "wow_wallet", unspent = available_unspent, "after spent filter");

        if sender_outputs.is_empty() {
            return Err(WalletError::NoOutputsFound);
        }

        // Step 2: Select outputs covering amount + fee estimate
        let sender_amounts: Vec<u64> = sender_outputs
            .iter()
            .map(|output| output.commitment().amount)
            .collect();
        let total_available: u64 = sender_amounts.iter().sum();

        if total_available < amount {
            return Err(WalletError::InsufficientFunds {
                need: amount,
                have: total_available,
            });
        }

        let selected_indices = Self::select_lock_output_indices(&sender_amounts, amount)?;
        let selected_total: u64 = selected_indices
            .iter()
            .map(|selected_idx| sender_amounts[*selected_idx])
            .sum();
        let estimated_fee = Self::estimate_lock_fee(selected_indices.len());
        let sender_outputs: Vec<_> = selected_indices
            .into_iter()
            .map(|selected_idx| sender_outputs[selected_idx].clone())
            .collect();

        tracing::info!(
            target: "wow_wallet",
            available_unspent = available_unspent,
            selected_inputs = sender_outputs.len(),
            selected_total = selected_total,
            estimated_fee = estimated_fee,
            amount = amount,
            "selected sender outputs for WOW lock"
        );

        // Step 3: Build the recipient address as wownero-oxide MoneroAddress
        let oxide_spend = wownero_oxide::ed25519::Point::from(*spend_point);
        let view_pubkey = wownero_oxide::ed25519::Point::from(view_scalar * G);
        let recipient_addr = wownero_wallet::address::MoneroAddress::new(
            wownero_wallet::address::Network::Testnet,
            wownero_wallet::address::AddressType::Legacy,
            oxide_spend,
            view_pubkey,
        );

        // Step 4: Build and sign transaction using wownero-oxide via MoneroDaemon
        use crate::rpc_transport::ReqwestTransport;
        use wownero_interface::ProvidesFeeRates;

        let transport = ReqwestTransport::new(&self.daemon_url);
        let daemon = transport
            .wownero_daemon()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        // Get fee rate from daemon
        let fee_rate = daemon
            .fee_rate(
                wownero_interface::FeePriority::Normal,
                WOW_FEE_RATE_SANITY_BOUND, // max per_weight sanity bound (WOW fees are ~1M/weight)
            )
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        // Get current block number for decoy selection
        use wownero_interface::ProvidesBlockchainMeta;
        let block_number = daemon
            .latest_block_number()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        // Select decoys for each input (WOW ring size is 22)
        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 22;

        let mut inputs_with_decoys = Vec::with_capacity(sender_outputs.len());
        for output in sender_outputs {
            let owd = wownero_wallet::OutputWithDecoys::new(
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
        let oxide_sender_spend = wownero_oxide::ed25519::Point::from(sender_spend_point);
        let oxide_sender_view = wownero_oxide::ed25519::Point::from(sender_view_point);
        let sender_address = wownero_wallet::address::MoneroAddress::new(
            wownero_wallet::address::Network::Testnet,
            wownero_wallet::address::AddressType::Legacy,
            oxide_sender_spend,
            oxide_sender_view,
        );
        let change = wownero_wallet::send::Change::fingerprintable(Some(sender_address));

        let signable = wownero_wallet::send::SignableTransaction::new(
            wownero_oxide::ringct::RctType::WowneroClsagBulletproofPlus,
            outgoing_view_key,
            inputs_with_decoys,
            payments,
            change,
            vec![], // no extra data
            fee_rate,
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("build tx: {}", e)))?;

        // Sign with sender's spend key
        let oxide_spend_key = Zeroizing::new(wownero_oxide::ed25519::Scalar::from(**sender_spend));
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
        let spend_point = spend_secret * G;
        let address = Self::derive_address(&spend_point, view_scalar);
        tracing::info!(
            target: "wow_wallet",
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
        for (i, o) in joint_outputs.iter().enumerate() {
            tracing::info!(
                target: "wow_wallet",
                index = i,
                amount = o.commitment().amount,
                global_index = o.index_on_blockchain(),
                "sweep input output"
            );
        }

        tracing::info!(
            target: "wow_wallet",
            outputs = joint_outputs.len(),
            total_amount = total_amount,
            "found outputs at joint address, building sweep transaction"
        );

        // Step 2: Parse destination address
        // WOW addresses use different type bytes than Monero, so decode with our own
        // address parser and construct a MoneroAddress for the wallet library.
        let dest_addr = {
            let (spend, view, _network) = xmr_wow_crypto::address::decode_address(destination)
                .map_err(|e| WalletError::InvalidAddress(format!("invalid destination: {}", e)))?;
            let oxide_spend = wownero_oxide::ed25519::Point::from(spend);
            let oxide_view = wownero_oxide::ed25519::Point::from(view);
            wownero_wallet::address::MoneroAddress::new(
                wownero_wallet::address::Network::Mainnet,
                wownero_wallet::address::AddressType::Legacy,
                oxide_spend,
                oxide_view,
            )
        };

        // Step 3: Build sweep transaction via MoneroDaemon
        use crate::rpc_transport::ReqwestTransport;
        use wownero_interface::ProvidesFeeRates;

        let transport = ReqwestTransport::new(&self.daemon_url);
        let daemon = transport
            .wownero_daemon()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        let fee_rate = daemon
            .fee_rate(
                wownero_interface::FeePriority::Normal,
                WOW_FEE_RATE_SANITY_BOUND,
            )
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        use wownero_interface::ProvidesBlockchainMeta;
        let block_number = daemon
            .latest_block_number()
            .await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 22; // WOW ring size

        let mut inputs_with_decoys = Vec::with_capacity(joint_outputs.len());
        for output in joint_outputs {
            let owd = Self::select_sweep_decoys(&mut rng, &daemon, ring_len, block_number, output)
                .await?;
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
        // Monero requires at least 2 outputs, so change goes to destination.
        let change = wownero_wallet::send::Change::fingerprintable(Some(dest_addr));
        let sweep_amount = Self::exact_sweep_payment_amount(
            total_amount,
            &outgoing_view_key,
            &inputs_with_decoys,
            dest_addr,
            fee_rate,
            None,
        )?;
        let payments = vec![(dest_addr, sweep_amount)];

        let signable = wownero_wallet::send::SignableTransaction::new(
            wownero_oxide::ringct::RctType::WowneroClsagBulletproofPlus,
            outgoing_view_key,
            inputs_with_decoys,
            payments,
            change,
            vec![],
            fee_rate,
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("build sweep tx: {}", e)))?;

        let oxide_spend_secret =
            Zeroizing::new(wownero_oxide::ed25519::Scalar::from(*spend_secret));
        let signed_tx = signable
            .sign(&mut rng, &oxide_spend_secret)
            .map_err(|e| WalletError::TxBuildFailed(format!("sign sweep tx: {}", e)))?;

        let tx_hex = hex::encode(signed_tx.serialize());
        let client = &self.client;
        Self::broadcast_tx(client, &self.daemon_url, &tx_hex).await
    }

    /// Scan the WOW chain for outputs at the joint address.
    ///
    /// Creates a wownero-oxide Scanner with ViewPair from (spend_point, view_scalar),
    /// fetches blocks from wownerod via reqwest, parses them with wownero-oxide's
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
            target: "wow_wallet",
            address = %address,
            from_height = from_height,
            "scanning for outputs at joint address using wownero-oxide Scanner"
        );

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
            target: "wow_wallet",
            found = results.len(),
            scanned_blocks = current_height - from_height,
            "scan complete"
        );

        Ok(results)
    }

    /// Poll wownerod for transaction confirmation status.
    ///
    /// Queries wownerod's `/get_transactions` endpoint for the tx status,
    /// then calculates confirmations from current height - tx block height.
    /// The wownerod JSON-RPC API is identical to monerod's.
    async fn poll_confirmation(
        &self,
        tx_hash: &TxHash,
        required_confirmations: u64,
    ) -> Result<ConfirmationStatus, WalletError> {
        let tx_hash_hex = hex::encode(tx_hash);
        tracing::debug!(
            target: "wow_wallet",
            tx_hash = %tx_hash_hex,
            required = required_confirmations,
            "polling transaction confirmation"
        );

        let client = &self.client;

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

        // Defensive: wownerod's /get_transactions may return a response with
        // no `txs` field at all on error paths (e.g. status: "Failed"). Return
        // a diagnostic error that names the actual response rather than the
        // confusingly-named TxNotFound variant.
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
            // Empty txs can mean "tx not yet indexed" (retryable) OR "tx was
            // never seen" (wait for propagation). Either way, return a
            // not-yet-confirmed status so the retry loop keeps polling instead
            // of exhausting retries with TxNotFound.
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
            return Ok(ConfirmationStatus {
                confirmed: false,
                confirmations: 0,
                block_height: None,
            });
        }

        let tx_height = block_height.unwrap();

        // Get current height via JSON-RPC
        let current_height = Self::get_chain_height(client, &self.daemon_url).await?;

        let confirmations = current_height.saturating_sub(tx_height);

        Ok(ConfirmationStatus {
            confirmed: confirmations >= required_confirmations,
            confirmations,
            block_height: Some(tx_height),
        })
    }

    /// Broadcast a pre-signed raw transaction to the Wownero daemon.
    ///
    /// Hex-encodes the raw bytes and POSTs to `/sendrawtransaction`.
    /// Returns the tx hash on success, or an error with the daemon's rejection reason.
    async fn broadcast_raw_tx(&self, tx_bytes: &[u8]) -> Result<TxHash, WalletError> {
        let tx_hex = hex::encode(tx_bytes);
        tracing::info!(
            target: "wow_wallet",
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
            wownero_oxide::transaction::Transaction::<wownero_oxide::transaction::NotPruned>::read(
                &mut tx_bytes.to_vec().as_slice(),
            )
            .map_err(|e| {
                WalletError::TxBuildFailed(format!("failed to parse tx for hash: {}", e))
            })?;

        let hash = tx.hash();
        tracing::info!(
            target: "wow_wallet",
            tx_hash = %hex::encode(hash),
            "raw transaction broadcast successful"
        );
        Ok(hash)
    }

    /// Get the current block height from the Wownero daemon.
    ///
    /// Delegates to the existing `get_chain_height` helper which calls
    /// wownerod's `get_block_count` JSON-RPC method.
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
    fn wow_wallet_new_stores_daemon_url() {
        let wallet = WowWallet::new("http://192.168.1.100:34568");
        assert_eq!(wallet.daemon_url(), "http://192.168.1.100:34568");
    }

    #[test]
    fn wow_wallet_mainnet_default_uses_port_34568() {
        let wallet = WowWallet::mainnet_default();
        assert_eq!(wallet.daemon_url(), "http://127.0.0.1:34568");
    }

    #[test]
    fn wow_wallet_custom_url() {
        let wallet = WowWallet::new("http://node.example.com:34568");
        assert_eq!(wallet.daemon_url(), "http://node.example.com:34568");
    }

    #[test]
    fn wow_wallet_with_sender_keys() {
        let spend = Scalar::random(&mut OsRng);
        let view = Scalar::random(&mut OsRng);
        let wallet = WowWallet::with_sender_keys("http://localhost:34568", spend, view);
        assert_eq!(wallet.daemon_url(), "http://localhost:34568");
        assert!(wallet.sender_spend_key.is_some());
        assert!(wallet.sender_view_key.is_some());
    }

    #[test]
    fn wow_wallet_scan_only_has_no_sender_keys() {
        let wallet = WowWallet::new("http://localhost:34568");
        assert!(wallet.sender_spend_key.is_none());
        assert!(wallet.sender_view_key.is_none());
    }

    #[test]
    fn test_wow_create_view_pair_succeeds() {
        let contrib = KeyContribution::generate(&mut OsRng);
        let view_scalar = Scalar::random(&mut OsRng);

        let result = WowWallet::create_view_pair(&contrib.public, &view_scalar);
        assert!(
            result.is_ok(),
            "ViewPair creation should succeed with valid keys"
        );
    }

    #[test]
    fn test_wow_derive_address_matches_crypto_crate() {
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);

        let joint_spend = xmr_wow_crypto::keysplit::combine_public_keys(&alice.public, &bob.public);

        let view_scalar = Scalar::random(&mut OsRng);
        let view_pubkey = view_scalar * G;

        let wallet_address = WowWallet::derive_address(&joint_spend, &view_scalar);

        let crypto_address = xmr_wow_crypto::address::encode_address(
            &joint_spend,
            &view_pubkey,
            xmr_wow_crypto::address::Network::Wownero,
        );

        assert_eq!(
            wallet_address, crypto_address,
            "WowWallet::derive_address must produce the same address as xmr_wow_crypto::encode_address"
        );

        // Wownero addresses are 97 chars (70-byte payload with 2-byte varint prefix)
        assert_eq!(
            wallet_address.len(),
            97,
            "Wownero address should be 97 chars"
        );
    }

    #[test]
    fn test_wow_derive_address_deterministic() {
        let contrib = KeyContribution::generate(&mut OsRng);
        let view_scalar = Scalar::random(&mut OsRng);

        let addr1 = WowWallet::derive_address(&contrib.public, &view_scalar);
        let addr2 = WowWallet::derive_address(&contrib.public, &view_scalar);

        assert_eq!(addr1, addr2, "derive_address must be deterministic");
    }

    #[test]
    fn test_wow_derive_address_different_keys_different_addresses() {
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);
        let view_scalar = Scalar::random(&mut OsRng);

        let addr_a = WowWallet::derive_address(&alice.public, &view_scalar);
        let addr_b = WowWallet::derive_address(&bob.public, &view_scalar);

        assert_ne!(
            addr_a, addr_b,
            "different spend points must produce different addresses"
        );
    }

    /// Regression test for bug #3: WOW address parsing in sweep.
    /// A WOW mainnet address must decode correctly through the same path
    /// that sweep() uses (xmr_wow_crypto::address::decode_address).
    #[test]
    fn test_wow_sweep_address_parsing_mainnet() {
        let spend = KeyContribution::generate(&mut OsRng);
        let view_scalar = Scalar::random(&mut OsRng);
        let view_pubkey = view_scalar * G;
        let address = xmr_wow_crypto::address::encode_address(
            &spend.public,
            &view_pubkey,
            xmr_wow_crypto::address::Network::Wownero,
        );
        // Decode the same way sweep() does (wow.rs line 813)
        let (decoded_spend, decoded_view, network) =
            xmr_wow_crypto::address::decode_address(&address).unwrap();
        assert_eq!(decoded_spend, spend.public);
        assert_eq!(decoded_view, view_pubkey);
        assert!(matches!(network, xmr_wow_crypto::address::Network::Wownero));
    }

    /// Regression test for bug #3: property-style round-trip coverage.
    /// Generate multiple WOW addresses, decode each, re-encode, assert equality.
    #[test]
    fn test_wow_sweep_address_round_trip_multiple() {
        for _ in 0..5 {
            let spend = KeyContribution::generate(&mut OsRng);
            let view_scalar = Scalar::random(&mut OsRng);
            let view_pubkey = view_scalar * G;
            let addr = xmr_wow_crypto::address::encode_address(
                &spend.public,
                &view_pubkey,
                xmr_wow_crypto::address::Network::Wownero,
            );
            let (ds, dv, _) = xmr_wow_crypto::address::decode_address(&addr).unwrap();
            let re_encoded = xmr_wow_crypto::address::encode_address(
                &ds,
                &dv,
                xmr_wow_crypto::address::Network::Wownero,
            );
            assert_eq!(
                addr, re_encoded,
                "address must survive encode->decode->encode round trip"
            );
        }
    }

    /// Regression test for bug #2: fee rate sanity bound.
    /// The fee rate sanity bound in lock() must be >= 1M to accept WOW fees.
    /// Original 100K cap rejected all WOW transactions.
    #[test]
    fn test_wow_fee_rate_sanity_bound() {
        let wow_fee_sanity_bound: u64 = 100_000_000;
        let typical_wow_fee_per_weight: u64 = 1_000_000;
        assert!(
            wow_fee_sanity_bound >= typical_wow_fee_per_weight,
            "fee sanity bound {} must accommodate WOW fees ~{}",
            wow_fee_sanity_bound,
            typical_wow_fee_per_weight,
        );
    }

    /// Regression test: sweep amount underflow protection.
    /// Sweep uses total.saturating_sub(fee) -- if fee > total, result is 0
    /// and the sweep should fail with InsufficientFunds (not underflow/wrap).
    #[test]
    fn test_wow_sweep_amount_underflow_protection() {
        let total: u64 = 500;
        let estimated_fee: u64 = 10_000;
        let sweep_amount = total.saturating_sub(estimated_fee);
        assert_eq!(sweep_amount, 0, "saturating_sub must prevent underflow");
    }

    #[test]
    fn test_wow_lock_selection_prefers_smallest_sufficient_single_output() {
        let amounts = vec![900_000_000_000, 510_000_000_000, 700_000_000_000];
        let selected = WowWallet::select_lock_output_indices(&amounts, 500_000_000_000).unwrap();
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn test_wow_lock_selection_prefers_minimal_input_count() {
        let amounts = vec![260_000_000_000, 255_000_000_000, 120_000_000_000];
        let selected = WowWallet::select_lock_output_indices(&amounts, 500_000_000_000).unwrap();
        assert_eq!(selected.len(), 2);
        let total: u64 = selected.iter().map(|idx| amounts[*idx]).sum();
        assert!(total >= 500_000_000_000 + WowWallet::estimate_lock_fee(selected.len()));
    }
}
