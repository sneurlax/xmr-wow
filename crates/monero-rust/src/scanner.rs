//! Unified scanning implementation for Monero wallets.
//!
//! This module provides wallet scanning functionality. Ported from monero-serai-mirror
//! (dalek v3) to monero-oxide (dalek v4). Functions that relied on monero-serai's
//! `Scanner`, `ViewPair`, `Rpc`, `Block`, and `Transaction` types are stubbed with
//! `todo!()` -- they will be implemented when the wallet adapters are ready.
//!
//! All data types, constants, and utility functions are preserved.
//!
// todo!() stubs: deferred until monero-oxide port.

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::wallet_output::WalletOutput;
use std::collections::HashMap;

/// How often to yield during batch processing (retained for API compat).
#[allow(dead_code)]
const YIELD_EVERY_N_BLOCKS: usize = 50;

/// Fallback key image extraction from raw tx bytes when `Transaction::read()` fails.
pub fn extract_key_images_from_raw_tx(tx_blob: &[u8]) -> Vec<String> {
    use std::io::{Cursor, Read};

    fn read_varint(r: &mut Cursor<&[u8]>) -> Option<u64> {
        let mut bits = 0u32;
        let mut res = 0u64;
        loop {
            let mut b = [0u8; 1];
            r.read_exact(&mut b).ok()?;
            let b = b[0];
            res += u64::from(b & 0x7f) << bits;
            bits += 7;
            if bits > 64 {
                return None;
            }
            if b & 0x80 == 0 {
                return Some(res);
            }
        }
    }

    let mut key_images = Vec::new();
    let mut cursor = Cursor::new(tx_blob);

    let Some(_version) = read_varint(&mut cursor) else {
        return key_images;
    };
    let Some(_timelock) = read_varint(&mut cursor) else {
        return key_images;
    };
    let Some(num_inputs) = read_varint(&mut cursor) else {
        return key_images;
    };

    for _ in 0..num_inputs {
        let mut type_byte = [0u8; 1];
        if cursor.read_exact(&mut type_byte).is_err() {
            break;
        }

        match type_byte[0] {
            0xff => {
                // Gen input: varint height
                if read_varint(&mut cursor).is_none() {
                    break;
                }
            }
            0x02 => {
                // ToKey input: amount, key_offsets, 32-byte key_image
                let Some(_amount) = read_varint(&mut cursor) else {
                    break;
                };
                let Some(num_offsets) = read_varint(&mut cursor) else {
                    break;
                };
                for _ in 0..num_offsets {
                    if read_varint(&mut cursor).is_none() {
                        break;
                    }
                }
                let mut ki = [0u8; 32];
                if cursor.read_exact(&mut ki).is_err() {
                    break;
                }
                key_images.push(hex::encode(ki));
            }
            _ => break,
        }
    }

    key_images
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockScanResult {
    pub block_height: u64,
    pub block_hash: String,
    pub block_timestamp: u64,
    pub tx_count: usize,
    pub outputs: Vec<WalletOutput>,
    pub daemon_height: u64,
    pub spent_key_images: Vec<String>,
    pub spent_key_image_tx_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolScanResult {
    pub tx_count: usize,
    pub outputs: Vec<WalletOutput>,
    pub spent_key_images: Vec<String>,
    pub spent_key_image_tx_hashes: Vec<String>,
}

/// Multi-wallet scan result containing outputs for each wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiWalletScanResult {
    pub block_height: u64,
    pub block_hash: String,
    pub block_timestamp: u64,
    pub tx_count: usize,
    pub daemon_height: u64,
    pub spent_key_images: Vec<String>,
    pub spent_key_image_tx_hashes: Vec<String>,
    /// Map of wallet address to its scan result.
    pub wallet_results: HashMap<String, WalletScanData>,
}

/// Individual wallet's scan data within a multi-wallet scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletScanData {
    pub address: String,
    pub outputs: Vec<WalletOutput>,
}

/// Configuration for a single wallet in multi-wallet scanning.
#[derive(Debug, Clone)]
pub struct WalletScanConfig {
    pub mnemonic: String,
    pub network: String,
    pub lookahead: Lookahead,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DerivedKeys {
    pub secret_spend_key: String,
    pub secret_view_key: String,
    pub public_spend_key: String,
    pub public_view_key: String,
    pub address: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lookahead {
    pub account: u32,
    pub subaddress: u32,
}

pub const DEFAULT_LOOKAHEAD: Lookahead = Lookahead {
    account: 0,
    subaddress: 20,
};

#[allow(dead_code)]
pub const WALLET_CLI_SOFTWARE_LOOKAHEAD: Lookahead = Lookahead {
    account: 50,
    subaddress: 200,
};

#[allow(dead_code)]
pub const WALLET_CLI_HARDWARE_LOOKAHEAD: Lookahead = Lookahead {
    account: 5,
    subaddress: 20,
};

/// Parse network string to chain_config::Network.
pub fn parse_network(network_str: &str) -> Result<crate::chain_config::Network, String> {
    match network_str.to_lowercase().as_str() {
        "mainnet" => Ok(crate::chain_config::Network::Mainnet),
        "testnet" => Ok(crate::chain_config::Network::Testnet),
        "stagenet" => Ok(crate::chain_config::Network::Stagenet),
        _ => Err(format!("Invalid network: {}", network_str)),
    }
}

/// Derive the public spend key from a spend scalar.
pub fn spend_key_from_scalar(spend_scalar: &Scalar) -> EdwardsPoint {
    spend_scalar * ED25519_BASEPOINT_TABLE
}

/// Derive the view key scalar from a spend scalar (keccak256 of spend bytes).
pub fn view_key_from_spend_scalar(spend_scalar: &Scalar) -> Scalar {
    let view: [u8; 32] = Keccak256::digest(spend_scalar.to_bytes()).into();
    Scalar::from_bytes_mod_order(view)
}

/// A single block entry: (height, block_hash, timestamp, [(tx_hash, tx_blob)])
pub type BlockEntry = (u64, String, u64, Vec<(String, Vec<u8>)>);

/// Pre-fetched block data for pipelined scanning.
pub struct FetchedBlocks {
    pub start_height: u64,
    pub count: u64,
    pub blocks: Vec<BlockEntry>,
}

// ---------------------------------------------------------------------------
// Stubbed scanning functions
//
// These functions previously depended on monero-serai's Scanner, ViewPair,
// Block, Transaction, Rpc, and RpcConnection types. They are stubbed with
// todo!() to allow compilation. They will be implemented using monero-oxide's
// wallet module when the XmrWallet adapter is ready.
// ---------------------------------------------------------------------------

/// Get the current daemon height via JSON-RPC.
pub async fn get_daemon_height(url: &str) -> Result<u64, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "method": "get_block_count"
    });
    let resp = client
        .post(format!("{}/json_rpc", url))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("RPC connection failed: {}", e))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("RPC parse failed: {}", e))?;
    json["result"]["count"]
        .as_u64()
        .ok_or_else(|| "Missing count in response".to_string())
}

/// Derive keys from a hex-encoded seed and network string.
///
/// TODO: Implement using monero-oxide key derivation.
pub fn derive_keys(_seed_hex: &str, _network: &str) -> Result<DerivedKeys, String> {
    todo!("derive_keys: port from monero-serai Seed to monero-oxide key derivation")
}

/// Derive an address from spend/view keys and network.
///
/// TODO: Implement using monero-oxide address encoding.
pub fn derive_address(
    _public_spend: &EdwardsPoint,
    _public_view: &EdwardsPoint,
    _network: &str,
) -> Result<String, String> {
    todo!("derive_address: port to monero-oxide address module")
}

/// Derive a subaddress.
///
/// TODO: Implement using monero-oxide subaddress derivation.
pub fn derive_subaddress(
    _secret_view: &Scalar,
    _public_spend: &EdwardsPoint,
    _account: u32,
    _index: u32,
    _network: &str,
) -> Result<String, String> {
    todo!("derive_subaddress: port to monero-oxide subaddress derivation")
}

/// Generate a random seed.
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    seed
}

/// Resolve a mnemonic seed string to a 32-byte seed.
///
/// TODO: Implement using monero-oxide seed handling.
pub fn resolve_seed(_mnemonic: &str) -> Result<[u8; 32], String> {
    todo!("resolve_seed: port from monero-serai Seed to monero-oxide")
}

/// Resolve a BIP39 mnemonic to a Monero-compatible seed.
///
/// TODO: Implement (BIP39 was excluded from this port).
pub fn resolve_seed_bip39(_mnemonic: &str) -> Result<[u8; 32], String> {
    Err("BIP39 support excluded from monero-rust port".to_string())
}

/// Get the birthday height for a seed.
///
/// TODO: Implement.
pub fn seed_birthday(_seed_hex: &str) -> Option<u64> {
    todo!("seed_birthday: port from monero-serai Seed")
}

/// Validate a mnemonic seed string.
///
/// TODO: Implement using monero-oxide seed handling.
pub fn validate_seed(_mnemonic: &str) -> bool {
    todo!("validate_seed: port from monero-serai Seed")
}

/// Scan a single block for outputs belonging to a wallet.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_block_for_outputs_with_url(
    _url: &str,
    _height: u64,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
) -> Result<BlockScanResult, String> {
    todo!("scan_block_for_outputs_with_url: port to monero-oxide Scanner")
}

/// Scan a single block with custom lookahead.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_block_for_outputs_with_url_and_lookahead(
    _url: &str,
    _height: u64,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
    _lookahead: Lookahead,
) -> Result<BlockScanResult, String> {
    todo!("scan_block_for_outputs_with_url_and_lookahead: port to monero-oxide Scanner")
}

/// Scan a single block for multiple wallets.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_block_multi_wallet_with_url(
    _url: &str,
    _height: u64,
    _wallets: &[WalletScanConfig],
) -> Result<MultiWalletScanResult, String> {
    todo!("scan_block_multi_wallet_with_url: port to monero-oxide Scanner")
}

/// Scan a single block for multiple wallets (native, parallel).
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_block_multi_wallet(
    _url: &str,
    _height: u64,
    _wallets: &[WalletScanConfig],
) -> Result<MultiWalletScanResult, String> {
    todo!("scan_block_multi_wallet: port to monero-oxide Scanner")
}

/// Scan mempool for outputs.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_mempool_for_outputs(
    _url: &str,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
) -> Result<MempoolScanResult, String> {
    todo!("scan_mempool_for_outputs: port to monero-oxide Scanner")
}

/// Scan mempool with custom lookahead.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_mempool_for_outputs_with_lookahead(
    _url: &str,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
    _lookahead: Lookahead,
) -> Result<MempoolScanResult, String> {
    todo!("scan_mempool_for_outputs_with_lookahead: port to monero-oxide Scanner")
}

/// Scan mempool with account-specific lookahead.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_mempool_for_outputs_with_account_lookahead(
    _url: &str,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
    _account_lookahead: u32,
    _subaddress_lookahead: u32,
) -> Result<MempoolScanResult, String> {
    todo!("scan_mempool_for_outputs_with_account_lookahead: port to monero-oxide Scanner")
}

/// Batch-scan blocks for outputs.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_blocks_batch_with_url(
    _url: &str,
    _start_height: u64,
    _count: u64,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
) -> Result<Vec<BlockScanResult>, String> {
    todo!("scan_blocks_batch_with_url: port to monero-oxide Scanner")
}

/// Batch-scan blocks for multiple wallets.
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_blocks_batch_multi_wallet_with_url(
    _url: &str,
    _start_height: u64,
    _count: u64,
    _wallets: &[WalletScanConfig],
) -> Result<Vec<MultiWalletScanResult>, String> {
    todo!("scan_blocks_batch_multi_wallet_with_url: port to monero-oxide Scanner")
}

/// Process a raw batch response into scan results.
///
/// TODO: Implement using monero-oxide transaction parsing.
pub fn process_batch_response(
    _batch_data: &[u8],
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
    _daemon_height: u64,
) -> Result<Vec<BlockScanResult>, String> {
    todo!("process_batch_response: port to monero-oxide transaction parsing")
}

/// Process a raw batch response for multiple wallets.
///
/// TODO: Implement using monero-oxide transaction parsing.
pub fn process_batch_multi_wallet_response(
    _batch_data: &[u8],
    _wallets: &[WalletScanConfig],
    _daemon_height: u64,
) -> Result<Vec<MultiWalletScanResult>, String> {
    todo!("process_batch_multi_wallet_response: port to monero-oxide")
}

/// Fetch a batch of blocks for pipelined scanning.
///
/// TODO: Implement using monero-oxide RPC.
pub async fn fetch_blocks_batch_with_url(
    _url: &str,
    _start_height: u64,
    _count: u64,
) -> Result<FetchedBlocks, String> {
    todo!("fetch_blocks_batch_with_url: port to monero-oxide RPC")
}

/// Process pre-fetched blocks for scanning.
///
/// TODO: Implement using monero-oxide Scanner.
pub fn process_fetched_batch(
    _fetched: &FetchedBlocks,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
    _daemon_height: u64,
) -> Result<Vec<BlockScanResult>, String> {
    todo!("process_fetched_batch: port to monero-oxide Scanner")
}

/// Process pre-fetched blocks with a cached scanner.
///
/// TODO: Implement using monero-oxide Scanner.
pub fn process_fetched_batch_cached(
    _fetched: &FetchedBlocks,
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
    _daemon_height: u64,
    _lookahead: Lookahead,
) -> Result<Vec<BlockScanResult>, String> {
    todo!("process_fetched_batch_cached: port to monero-oxide Scanner")
}

/// Process pre-fetched blocks for multiple wallets.
///
/// TODO: Implement using monero-oxide Scanner.
pub fn process_fetched_batch_multi_wallet(
    _fetched: &FetchedBlocks,
    _wallets: &[WalletScanConfig],
    _daemon_height: u64,
) -> Result<Vec<MultiWalletScanResult>, String> {
    todo!("process_fetched_batch_multi_wallet: port to monero-oxide Scanner")
}

/// Process pre-fetched blocks for multiple wallets with cached scanners.
///
/// TODO: Implement using monero-oxide Scanner.
pub fn process_fetched_batch_multi_wallet_cached(
    _fetched: &FetchedBlocks,
    _wallets: &[WalletScanConfig],
    _daemon_height: u64,
) -> Result<Vec<MultiWalletScanResult>, String> {
    todo!("process_fetched_batch_multi_wallet_cached: port to monero-oxide Scanner")
}

/// Batch-scan blocks with history (for reorg detection).
///
/// TODO: Implement using monero-oxide Scanner.
pub async fn scan_blocks_batch_with_history_url(
    _url: &str,
    _block_ids: &[(u64, String)],
    _spend_key_hex: &str,
    _view_key_hex: &str,
    _network: &str,
) -> Result<Vec<BlockScanResult>, String> {
    todo!("scan_blocks_batch_with_history_url: port to monero-oxide Scanner")
}

/// Fetch blocks with history for pipelined scanning.
///
/// TODO: Implement using monero-oxide RPC.
pub async fn fetch_blocks_batch_with_history_url(
    _url: &str,
    _block_ids: &[(u64, String)],
) -> Result<FetchedBlocks, String> {
    todo!("fetch_blocks_batch_with_history_url: port to monero-oxide RPC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_key_images_empty() {
        let result = extract_key_images_from_raw_tx(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_network() {
        assert_eq!(
            parse_network("mainnet").unwrap(),
            crate::chain_config::Network::Mainnet
        );
        assert_eq!(
            parse_network("stagenet").unwrap(),
            crate::chain_config::Network::Stagenet
        );
        assert!(parse_network("invalid").is_err());
    }

    #[test]
    fn test_view_key_derivation_deterministic() {
        let spend = Scalar::from_bytes_mod_order([42u8; 32]);
        let view1 = view_key_from_spend_scalar(&spend);
        let view2 = view_key_from_spend_scalar(&spend);
        assert_eq!(view1, view2);
    }

    #[test]
    fn test_spend_key_on_curve() {
        let spend_scalar = Scalar::from_bytes_mod_order([7u8; 32]);
        let point = spend_key_from_scalar(&spend_scalar);
        // Verify it's a valid point by checking it's not the identity
        assert_ne!(
            point,
            curve25519_dalek::edwards::EdwardsPoint::default()
        );
    }
}
