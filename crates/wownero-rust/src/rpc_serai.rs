//! RPC client for Monero daemon communication.
//!
//! Ported from monero-serai-mirror's `RpcConnection` trait to use `reqwest`
//! directly for JSON-RPC calls to monerod. This eliminates the dependency on
//! monero-serai's `Rpc<HttpRpc>` and `RpcConnection` trait.
//!
//! The client provides methods matching the monerod JSON-RPC API surface
//! needed for wallet operations.

use async_trait::async_trait;
use serde::Deserialize;

use crate::abstractions::{
    AbError, AbResult, BlockResponse, GetOutsParams, OutsResponse, RpcClient, TxSubmitResponse,
};

/// Native HTTP RPC client for monerod / wownerod JSON-RPC.
#[derive(Clone, Debug)]
pub struct NativeRpcClient {
    url: String,
    client: reqwest::Client,
}

impl NativeRpcClient {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
        }
    }

    /// Post a JSON-RPC request and return the raw response body.
    async fn post_json_rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> AbResult<serde_json::Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });

        let resp = self
            .client
            .post(&format!("{}/json_rpc", self.url))
            .json(&body)
            .send()
            .await
            .map_err(|e| AbError::Network(format!("RPC connection failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AbError::Serialization(format!("RPC parse failed: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(AbError::Rpc(format!("RPC error: {}", error)));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| AbError::Rpc("Missing result in RPC response".to_string()))
    }

    /// Post to a non-JSON-RPC endpoint (e.g., /sendrawtransaction).
    async fn post_other(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> AbResult<serde_json::Value> {
        let resp = self
            .client
            .post(&format!("{}{}", self.url, path))
            .json(&body)
            .send()
            .await
            .map_err(|e| AbError::Network(format!("RPC connection failed: {}", e)))?;

        resp.json()
            .await
            .map_err(|e| AbError::Serialization(format!("RPC parse failed: {}", e)))
    }
}

#[async_trait]
impl RpcClient for NativeRpcClient {
    async fn call<T>(&self, method: &str, params: serde_json::Value) -> AbResult<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let result = self.post_json_rpc(method, params).await?;
        serde_json::from_value(result)
            .map_err(|e| AbError::Serialization(format!("Failed to deserialize: {}", e)))
    }

    async fn get_height(&self) -> AbResult<u64> {
        let result = self
            .post_json_rpc("get_block_count", serde_json::json!({}))
            .await?;
        result["count"]
            .as_u64()
            .ok_or_else(|| AbError::Rpc("Missing count in get_block_count".to_string()))
    }

    async fn get_blocks(&self, start_height: u64, count: u64) -> AbResult<BlockResponse> {
        // Use get_block_headers_range for the block headers
        let result = self
            .post_json_rpc(
                "get_block_headers_range",
                serde_json::json!({
                    "start_height": start_height,
                    "end_height": start_height + count - 1,
                }),
            )
            .await?;

        let headers = result["headers"]
            .as_array()
            .ok_or_else(|| AbError::Rpc("Missing headers in response".to_string()))?;

        let blocks = headers
            .iter()
            .map(|h| crate::abstractions::BlockData {
                block_header: crate::abstractions::BlockHeader {
                    height: h["height"].as_u64().unwrap_or(0),
                    timestamp: h["timestamp"].as_u64().unwrap_or(0),
                    hash: h["hash"].as_str().unwrap_or("").to_string(),
                },
                txs: Vec::new(), // Transaction data fetched separately when needed
            })
            .collect();

        Ok(BlockResponse {
            blocks,
            status: "OK".to_string(),
        })
    }

    async fn get_outs(&self, params: &GetOutsParams) -> AbResult<OutsResponse> {
        let outputs: Vec<serde_json::Value> = params
            .outputs
            .iter()
            .map(|o| {
                serde_json::json!({
                    "amount": o.amount,
                    "index": o.index,
                })
            })
            .collect();

        let result = self
            .post_other(
                "/get_outs",
                serde_json::json!({
                    "outputs": outputs,
                    "get_txid": true,
                }),
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| AbError::Serialization(format!("Failed to parse get_outs: {}", e)))
    }

    async fn submit_transaction(&self, tx_blob: &str) -> AbResult<TxSubmitResponse> {
        let result = self
            .post_other(
                "/sendrawtransaction",
                serde_json::json!({
                    "tx_as_hex": tx_blob,
                }),
            )
            .await?;

        Ok(TxSubmitResponse {
            status: result["status"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string(),
            tx_hash: result["tx_hash"].as_str().map(|s| s.to_string()),
            reason: result["reason"].as_str().map(|s| s.to_string()),
        })
    }

    async fn get_fee_estimate(&self) -> AbResult<u64> {
        let result = self
            .post_other(
                "/get_fee_estimate",
                serde_json::json!({}),
            )
            .await?;

        result["fee"]
            .as_u64()
            .ok_or_else(|| AbError::Rpc("Missing fee in estimate".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_rpc_client_new() {
        let client = NativeRpcClient::new("http://localhost:38081".to_string());
        assert_eq!(client.url, "http://localhost:38081");
    }
}
