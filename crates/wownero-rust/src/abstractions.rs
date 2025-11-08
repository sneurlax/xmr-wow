//! Platform abstraction traits for wallet operations.
//!
//! Provides RPC client, storage, and time abstractions. WASM support has been
//! stripped -- this crate targets native only (aligned with xmr-wow's requirements).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub type AbResult<T> = Result<T, AbError>;

#[derive(Debug, thiserror::Error)]
pub enum AbError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Trait for persistent key-value storage.
#[async_trait]
pub trait WalletStorage {
    async fn save(&self, key: &str, data: &[u8]) -> AbResult<()>;
    async fn load(&self, key: &str) -> AbResult<Vec<u8>>;
    async fn delete(&self, key: &str) -> AbResult<()>;
    async fn list_keys(&self) -> AbResult<Vec<String>>;
    async fn exists(&self, key: &str) -> AbResult<bool>;
}

/// Trait for obtaining current time.
pub trait TimeProvider {
    fn now(&self) -> u64;
    fn now_ms(&self) -> u64;
}

/// Response from get_height RPC call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeightResponse {
    pub height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub blocks: Vec<BlockData>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub block_header: BlockHeader,
    pub txs: Vec<TransactionData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub timestamp: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub tx_hash: String,
    pub tx_blob: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutsResponse {
    pub outs: Vec<OutEntry>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutEntry {
    pub height: u64,
    pub key: String,
    pub mask: String,
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSubmitResponse {
    pub status: String,
    pub tx_hash: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOutsParams {
    pub outputs: Vec<OutputIndex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputIndex {
    pub amount: u64,
    pub index: u64,
}

/// Trait for async RPC client operations.
#[async_trait]
pub trait RpcClient {
    async fn call<T>(&self, method: &str, params: Value) -> AbResult<T>
    where
        T: for<'de> Deserialize<'de>;

    async fn get_height(&self) -> AbResult<u64>;
    async fn get_blocks(&self, start_height: u64, count: u64) -> AbResult<BlockResponse>;
    async fn get_outs(&self, params: &GetOutsParams) -> AbResult<OutsResponse>;
    async fn submit_transaction(&self, tx_blob: &str) -> AbResult<TxSubmitResponse>;
    async fn get_fee_estimate(&self) -> AbResult<u64>;
}

/// In-memory storage for testing.
pub struct MemoryStorage {
    data: std::sync::Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            data: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WalletStorage for MemoryStorage {
    async fn save(&self, key: &str, data: &[u8]) -> AbResult<()> {
        let mut storage = self
            .data
            .lock()
            .map_err(|e| AbError::Storage(format!("Mutex lock poisoned: {}", e)))?;
        storage.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    async fn load(&self, key: &str) -> AbResult<Vec<u8>> {
        let storage = self
            .data
            .lock()
            .map_err(|e| AbError::Storage(format!("Mutex lock poisoned: {}", e)))?;
        storage
            .get(key)
            .cloned()
            .ok_or_else(|| AbError::NotFound(format!("Key '{}' not found", key)))
    }

    async fn delete(&self, key: &str) -> AbResult<()> {
        let mut storage = self
            .data
            .lock()
            .map_err(|e| AbError::Storage(format!("Mutex lock poisoned: {}", e)))?;
        storage.remove(key);
        Ok(())
    }

    async fn list_keys(&self) -> AbResult<Vec<String>> {
        let storage = self
            .data
            .lock()
            .map_err(|e| AbError::Storage(format!("Mutex lock poisoned: {}", e)))?;
        Ok(storage.keys().cloned().collect())
    }

    async fn exists(&self, key: &str) -> AbResult<bool> {
        let storage = self
            .data
            .lock()
            .map_err(|e| AbError::Storage(format!("Mutex lock poisoned: {}", e)))?;
        Ok(storage.contains_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::new();

        let data = b"test data";
        storage.save("key1", data).await.unwrap();
        let loaded = storage.load("key1").await.unwrap();
        assert_eq!(loaded, data);

        assert!(storage.exists("key1").await.unwrap());
        assert!(!storage.exists("key2").await.unwrap());

        storage.save("key2", b"more data").await.unwrap();
        let keys = storage.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);

        storage.delete("key1").await.unwrap();
        assert!(!storage.exists("key1").await.unwrap());
        assert!(storage.load("key1").await.is_err());
    }

    #[test]
    fn test_aberror_display() {
        let storage_err = AbError::Storage("test error".to_string());
        assert!(storage_err.to_string().contains("Storage error"));

        let rpc_err = AbError::Rpc("rpc failed".to_string());
        assert!(rpc_err.to_string().contains("RPC error"));

        let not_found_err = AbError::NotFound("key".to_string());
        assert!(not_found_err.to_string().contains("Not found"));
    }
}
