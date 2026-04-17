//! Chain configuration for Wownero networks.
//!
//! RPC URL: passed by caller at scan time. Not hardcoded.
//! Genesis: known-correct hash for height 0, enabling anchor verification.
//! Network: used for address derivation.
//!
//! WOW-specific parameters vs Monero:
//! - Default spendable age: 4 blocks (vs Monero's 10)
//! - Default ring size: 22 (vs Monero's 16)
//! - Coin decimal places: 11 (wowoshi) (vs Monero's 12, piconero)
//! - RctType: WowneroClsagBulletproofPlus (wire type 8) -- handled by wownero-oxide
//! - INV_EIGHT commitment scaling -- handled by wownero-oxide

/// Network type for Wownero-compatible chains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

/// Default spendable age for Wownero (4 blocks vs Monero's 10).
pub const WOW_DEFAULT_SPENDABLE_AGE: u64 = 4;

/// Default ring size for Wownero (22 vs Monero's 16).
pub const WOW_DEFAULT_RING_SIZE: usize = 22;

/// Coin decimal places for Wownero (11 wowoshi vs Monero's 12 piconero).
pub const WOW_COIN_DECIMALS: u32 = 11;

/// Configuration for a specific Wownero chain.
/// Passed to WalletActor at startup.
#[derive(Clone, Debug)]
pub struct ChainConfig {
    /// JSON-RPC endpoint URL, e.g. "http://127.0.0.1:11181"
    pub rpc_url: String,
    /// Network type (mainnet / stagenet / testnet)
    pub network: Network,
    /// Genesis block hash (used as the scanner's starting anchor)
    pub genesis_hash: [u8; 32],
    /// Human-readable label for logging
    pub label: &'static str,
}

impl ChainConfig {
    /// Wownero testnet configuration.
    ///
    /// Default RPC port: 11181
    /// Genesis block hash for Wownero testnet (height 0):
    /// 2b19c367b9d6c62ca23e8bb11a5ed89a42075b8a0a55b8e6adab4a46b012c8f8
    pub fn wownero_testnet(rpc_url: String) -> Self {
        ChainConfig {
            rpc_url,
            network: Network::Testnet,
            genesis_hash: [
                0x2b, 0x19, 0xc3, 0x67, 0xb9, 0xd6, 0xc6, 0x2c, 0xa2, 0x3e, 0x8b, 0xb1, 0x1a, 0x5e,
                0xd8, 0x9a, 0x42, 0x07, 0x5b, 0x8a, 0x0a, 0x55, 0xb8, 0xe6, 0xad, 0xab, 0x4a, 0x46,
                0xb0, 0x12, 0xc8, 0xf8,
            ],
            label: "wownero-testnet",
        }
    }

    /// Wownero mainnet configuration.
    ///
    /// Default RPC port: 34568
    /// Genesis block hash for Wownero mainnet (height 0):
    /// a8db07c0cd3372e6e36a1aa5b1004a44c6446f77cdc8c52a40dc1944014e6e23
    pub fn wownero_mainnet(rpc_url: String) -> Self {
        ChainConfig {
            rpc_url,
            network: Network::Mainnet,
            genesis_hash: [
                0xa8, 0xdb, 0x07, 0xc0, 0xcd, 0x33, 0x72, 0xe6, 0xe3, 0x6a, 0x1a, 0xa5, 0xb1, 0x00,
                0x4a, 0x44, 0xc6, 0x44, 0x6f, 0x77, 0xcd, 0xc8, 0xc5, 0x2a, 0x40, 0xdc, 0x19, 0x44,
                0x01, 0x4e, 0x6e, 0x23,
            ],
            label: "wownero-mainnet",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_config_has_correct_defaults() {
        let config = ChainConfig::wownero_testnet("http://127.0.0.1:11181".into());
        assert_eq!(config.network, Network::Testnet);
        assert_eq!(config.label, "wownero-testnet");
    }

    #[test]
    fn mainnet_and_testnet_have_different_genesis() {
        let testnet = ChainConfig::wownero_testnet("http://127.0.0.1:11181".into());
        let mainnet = ChainConfig::wownero_mainnet("http://127.0.0.1:34568".into());
        assert_ne!(testnet.genesis_hash, mainnet.genesis_hash);
    }

    #[test]
    fn wow_specific_constants() {
        assert_eq!(WOW_DEFAULT_SPENDABLE_AGE, 4);
        assert_eq!(WOW_DEFAULT_RING_SIZE, 22);
        assert_eq!(WOW_COIN_DECIMALS, 11);
    }
}
