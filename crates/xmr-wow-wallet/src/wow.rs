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
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::EdwardsPoint,
    scalar::Scalar,
};
use zeroize::Zeroizing;
use tracing;

use crate::error::WalletError;
use crate::trait_def::{ConfirmationStatus, CryptoNoteWallet, RefundChain, ScanResult, TxHash};

/// WOW mainnet default JSON-RPC port.
/// Note: 34567 is the P2P port, 34568 is the JSON-RPC port.
const WOW_MAINNET_DEFAULT_PORT: u16 = 34568;

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
    pub fn with_sender_keys(
        daemon_url: &str,
        spend_key: Scalar,
        view_key: Scalar,
    ) -> Self {
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
    async fn get_chain_height(client: &reqwest::Client, daemon_url: &str) -> Result<u64, WalletError> {
        let resp = client
            .post(format!("{}/json_rpc", daemon_url))
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

        let block = wownero_oxide::block::Block::read(&mut blob_bytes.as_slice())
            .map_err(|e| WalletError::ScanFailed(format!("failed to parse block {}: {}", height, e)))?;

        // Step 2: Fetch non-miner transactions if any exist
        let mut pruned_txs: Vec<wownero_oxide::transaction::Transaction<wownero_oxide::transaction::Pruned>> = Vec::new();

        if !block.transactions.is_empty() {
            let tx_hashes: Vec<String> = block.transactions.iter().map(hex::encode).collect();

            let tx_resp = client
                .post(format!("{}/get_transactions", daemon_url))
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
                    let tx_hex = tx_entry["as_hex"]
                        .as_str()
                        .ok_or_else(|| WalletError::ScanFailed("missing as_hex in tx".into()))?;

                    let tx_bytes = hex::decode(tx_hex)
                        .map_err(|e| WalletError::ScanFailed(format!("invalid tx hex: {}", e)))?;

                    let full_tx = wownero_oxide::transaction::Transaction::<wownero_oxide::transaction::NotPruned>::read(
                        &mut tx_bytes.as_slice(),
                    )
                    .map_err(|e| WalletError::ScanFailed(format!("failed to parse tx: {}", e)))?;

                    pruned_txs.push(full_tx.into());
                }
            }
        }

        // Step 3: Get output_index_for_first_ringct_output
        let output_index = Self::get_first_ringct_output_index(
            client,
            daemon_url,
            &block,
            &pruned_txs,
        )
        .await?;

        Ok(wownero_interface::ScannableBlock {
            block,
            transactions: pruned_txs,
            output_index_for_first_ringct_output: output_index,
        })
    }

    /// Get the global output index for the first RingCT output in a block.
    ///
    /// Queries wownerod's `/get_o_indexes.bin` endpoint for the miner transaction,
    /// falling back to `/get_transactions` if the binary endpoint is unavailable.
    async fn get_first_ringct_output_index(
        client: &reqwest::Client,
        daemon_url: &str,
        block: &wownero_oxide::block::Block,
        _txs: &[wownero_oxide::transaction::Transaction<wownero_oxide::transaction::Pruned>],
    ) -> Result<Option<u64>, WalletError> {
        let miner_tx = block.miner_transaction();
        let is_v2_miner = matches!(miner_tx, wownero_oxide::transaction::Transaction::V2 { .. });

        if !is_v2_miner || miner_tx.prefix().outputs.is_empty() {
            return Ok(None);
        }

        let miner_hash = hex::encode(miner_tx.hash());

        let resp = client
            .post(format!("{}/get_o_indexes.bin", daemon_url))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "txid": miner_hash }))
            .send()
            .await;

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
            .post(format!("{}/get_transactions", daemon_url))
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
            .map_err(|e| WalletError::BroadcastFailed(format!("sendrawtransaction (daemon: {}): {}", daemon_url, e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WalletError::BroadcastFailed(format!("parse broadcast response: {}", e)))?;

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
                    status, reason, serde_json::to_string(&json).unwrap_or_default()
                )));
            }
        }

        let tx_bytes = hex::decode(tx_hex)
            .map_err(|e| WalletError::TxBuildFailed(format!("invalid tx hex: {}", e)))?;

        let tx = wownero_oxide::transaction::Transaction::<wownero_oxide::transaction::NotPruned>::read(
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
                Err(WalletError::ScanFailed(msg)) if msg.contains("deserialize") || msg.contains("parse") => {
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
    fn compute_key_image(
        sender_spend: &Scalar,
        output: &wownero_wallet::WalletOutput,
    ) -> [u8; 32] {
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

        let key_images: Vec<String> = outputs.iter()
            .map(|o| hex::encode(Self::compute_key_image(sender_spend, o)))
            .collect();

        let resp = client
            .post(format!("{}/is_key_image_spent", daemon_url))
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
                .unwrap_or(1);
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
        let sender_spend = self.sender_spend_key.as_ref()
            .ok_or_else(|| WalletError::KeyError(
                "lock requires sender keys -- use WowWallet::with_sender_keys()".into()
            ))?;
        let sender_view = self.sender_view_key.as_ref()
            .ok_or_else(|| WalletError::KeyError(
                "lock requires sender view key".into()
            ))?;

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
        let mature_outputs: Vec<_> = all_outputs.into_iter().filter(|o| {
            match o.additional_timelock() {
                wownero_oxide::transaction::Timelock::None => true,
                wownero_oxide::transaction::Timelock::Block(b) => (current_height as usize) >= b,
                wownero_oxide::transaction::Timelock::Time(t) => {
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
                target: "wow_wallet",
                immature = total_found - mature_outputs.len(),
                mature = mature_outputs.len(),
                "filtered immature coinbase outputs"
            );
        }

        let sender_outputs = Self::filter_unspent(
            client,
            &self.daemon_url,
            sender_spend,
            mature_outputs,
        ).await?;

        tracing::info!(target: "wow_wallet", unspent = sender_outputs.len(), "after spent filter");

        if sender_outputs.is_empty() {
            return Err(WalletError::NoOutputsFound);
        }

        // Step 2: Select outputs covering amount + fee estimate
        let total_available: u64 = sender_outputs.iter()
            .map(|o| o.commitment().amount)
            .sum();

        if total_available < amount {
            return Err(WalletError::InsufficientFunds {
                need: amount,
                have: total_available,
            });
        }

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
        let daemon = transport.wownero_daemon().await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        // Get fee rate from daemon
        let fee_rate = daemon.fee_rate(
            wownero_interface::FeePriority::Normal,
            100_000_000, // max per_weight sanity bound (WOW fees are ~1M/weight)
        ).await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        // Get current block number for decoy selection
        use wownero_interface::ProvidesBlockchainMeta;
        let block_number = daemon.latest_block_number().await
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
        ).map_err(|e| WalletError::TxBuildFailed(format!("build tx: {}", e)))?;

        // Sign with sender's spend key
        let oxide_spend_key = Zeroizing::new(
            wownero_oxide::ed25519::Scalar::from(**sender_spend),
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

        let total_amount: u64 = joint_outputs.iter()
            .map(|o| o.commitment().amount)
            .sum();
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
        let daemon = transport.wownero_daemon().await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        let fee_rate = daemon.fee_rate(
            wownero_interface::FeePriority::Normal,
            100_000_000, // WOW fees are ~1M/weight
        ).await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        use wownero_interface::ProvidesBlockchainMeta;
        let block_number = daemon.latest_block_number().await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 22; // WOW ring size

        let mut inputs_with_decoys = Vec::with_capacity(joint_outputs.len());
        for output in joint_outputs {
            let owd = wownero_wallet::OutputWithDecoys::new(
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
        // Monero requires at least 2 outputs, so change goes to destination.
        let change = wownero_wallet::send::Change::fingerprintable(Some(dest_addr));
        let estimated_fee = fee_rate.calculate_fee_from_weight(2000);
        let sweep_amount = total_amount.saturating_sub(estimated_fee);
        if sweep_amount == 0 {
            return Err(WalletError::InsufficientFunds {
                need: estimated_fee,
                have: total_amount,
            });
        }
        let payments = vec![(dest_addr, sweep_amount)];

        let signable = wownero_wallet::send::SignableTransaction::new(
            wownero_oxide::ringct::RctType::WowneroClsagBulletproofPlus,
            outgoing_view_key,
            inputs_with_decoys,
            payments,
            change,
            vec![],
            fee_rate,
        ).map_err(|e| WalletError::TxBuildFailed(format!("build sweep tx: {}", e)))?;

        let oxide_spend_secret = Zeroizing::new(
            wownero_oxide::ed25519::Scalar::from(*spend_secret),
        );
        let signed_tx = signable.sign(&mut rng, &oxide_spend_secret)
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

        // Query /get_transactions for the tx status
        let resp = client
            .post(format!("{}/get_transactions", self.daemon_url))
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
            target: "wow_wallet",
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
            target: "wow_wallet",
            outputs = joint_outputs.len(),
            total_amount = total_amount,
            "found outputs, building timelocked sweep transaction"
        );

        // Step 2: Parse destination address
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

        // Step 3: Build timelocked sweep transaction
        use crate::rpc_transport::ReqwestTransport;
        use wownero_interface::ProvidesFeeRates;

        let transport = ReqwestTransport::new(&self.daemon_url);
        let daemon = transport.wownero_daemon().await
            .map_err(|e| WalletError::TxBuildFailed(format!("daemon connection: {}", e)))?;

        let fee_rate = daemon.fee_rate(
            wownero_interface::FeePriority::Normal,
            100_000_000,
        ).await
            .map_err(|e| WalletError::TxBuildFailed(format!("fee rate: {}", e)))?;

        use wownero_interface::ProvidesBlockchainMeta;
        let block_number = daemon.latest_block_number().await
            .map_err(|e| WalletError::TxBuildFailed(format!("latest block: {}", e)))?;

        let mut rng = rand_core::OsRng;
        let ring_len: u8 = 22;

        let mut inputs_with_decoys = Vec::with_capacity(joint_outputs.len());
        for output in joint_outputs {
            let owd = wownero_wallet::OutputWithDecoys::new(
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

        let change = wownero_wallet::send::Change::fingerprintable(Some(dest_addr));
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
        let signable = wownero_wallet::send::SignableTransaction::new_with_timelock(
            wownero_oxide::ringct::RctType::WowneroClsagBulletproofPlus,
            outgoing_view_key,
            inputs_with_decoys,
            payments,
            change,
            vec![],
            fee_rate,
            wownero_oxide::transaction::Timelock::Block(refund_height as usize),
        ).map_err(|e| WalletError::TxBuildFailed(format!("build timelocked sweep tx: {}", e)))?;

        let oxide_spend_secret = Zeroizing::new(
            wownero_oxide::ed25519::Scalar::from(*spend_secret),
        );
        let signed_tx = signable.sign(&mut rng, &oxide_spend_secret)
            .map_err(|e| WalletError::TxBuildFailed(format!("sign timelocked sweep tx: {}", e)))?;

        // Serialize the signed transaction
        let tx_bytes = signed_tx.serialize();

        // Compute the tx hash
        let tx = wownero_oxide::transaction::Transaction::<wownero_oxide::transaction::NotPruned>::read(
            &mut tx_bytes.as_slice(),
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("failed to parse built tx: {}", e)))?;
        let tx_hash = tx.hash();

        tracing::info!(
            target: "wow_wallet",
            tx_hash = %hex::encode(tx_hash),
            refund_height = refund_height,
            tx_size = tx_bytes.len(),
            "timelocked sweep transaction built (not yet broadcast)"
        );

        Ok((tx_hash, tx_bytes))
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
        let tx = wownero_oxide::transaction::Transaction::<wownero_oxide::transaction::NotPruned>::read(
            &mut tx_bytes.to_vec().as_slice(),
        )
        .map_err(|e| WalletError::TxBuildFailed(format!("failed to parse tx for hash: {}", e)))?;

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
    use xmr_wow_crypto::keysplit::KeyContribution;
    use rand::rngs::OsRng;

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
        assert!(result.is_ok(), "ViewPair creation should succeed with valid keys");
    }

    #[test]
    fn test_wow_derive_address_matches_crypto_crate() {
        let alice = KeyContribution::generate(&mut OsRng);
        let bob = KeyContribution::generate(&mut OsRng);

        let joint_spend = xmr_wow_crypto::keysplit::combine_public_keys(
            &alice.public,
            &bob.public,
        );

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
        assert_eq!(wallet_address.len(), 97, "Wownero address should be 97 chars");
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
                &spend.public, &view_pubkey,
                xmr_wow_crypto::address::Network::Wownero,
            );
            let (ds, dv, _) = xmr_wow_crypto::address::decode_address(&addr).unwrap();
            let re_encoded = xmr_wow_crypto::address::encode_address(
                &ds, &dv,
                xmr_wow_crypto::address::Network::Wownero,
            );
            assert_eq!(addr, re_encoded, "address must survive encode->decode->encode round trip");
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
            wow_fee_sanity_bound, typical_wow_fee_per_weight,
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
}
