// P2Pool for Monero - Monero daemon JSON-RPC client
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// p2pool communicates with monerod via:
//   1. The JSON-RPC HTTP API (get_info, get_miner_data, submit_block, etc.)
//   2. The ZMQ pub/sub API (new blocks, mempool txs)
//
// This module implements the JSON-RPC HTTP client. The ZMQ reader is in zmq/.

use super::types::*;
use p2pool_config::HostConfig;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc { code: i64, message: String },
    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("daemon returned status: {0}")]
    DaemonStatus(String),
}

/// An async Monero daemon JSON-RPC client.
pub struct MoneroRpcClient {
    http: reqwest::Client,
    json_rpc_url: String,
    daemon_url: String,
    auth: Option<(String, String)>,
}

impl MoneroRpcClient {
    pub fn new(config: &HostConfig) -> Self {
        let auth = config.rpc_login.as_ref().and_then(|login| {
            let mut parts = login.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next().unwrap_or("").to_string();
            Some((user, pass))
        });

        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
            json_rpc_url: config.rpc_url(),
            daemon_url: format!("http://{}:{}", config.address, config.rpc_port),
            auth,
        }
    }

    async fn call<P: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<T, RpcError> {
        let req = RpcRequest::new(method, params);
        let mut builder = self.http.post(&self.json_rpc_url).json(&req);
        if let Some((user, pass)) = &self.auth {
            builder = builder.basic_auth(user, Some(pass));
        }
        let resp: RpcResponse<T> = builder.send().await?.json().await?;
        if let Some(err) = resp.error {
            return Err(RpcError::JsonRpc {
                code: err.code,
                message: err.message,
            });
        }
        resp.result.ok_or_else(|| RpcError::JsonRpc {
            code: -1,
            message: "missing result".to_string(),
        })
    }

    /// Retrieve basic node info (height, top block hash, difficulty, etc.).
    pub async fn get_info(&self) -> Result<GetInfoResponse, RpcError> {
        self.call("get_info", serde_json::json!({})).await
    }

    /// Retrieve the data needed to build the next block template.
    ///
    /// Requires monerod ≥ 0.17.3 (Fluorine Fermi).
    pub async fn get_miner_data(&self) -> Result<GetMinerDataResponse, RpcError> {
        self.call("get_miner_data", serde_json::json!({})).await
    }

    /// Retrieve a range of block headers.
    pub async fn get_block_headers_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<GetBlockHeadersRangeResponse, RpcError> {
        self.call(
            "get_block_headers_range",
            serde_json::json!({
                "start_height": start_height,
                "end_height": end_height,
            }),
        )
        .await
    }

    /// Submit a fully serialized Monero block (hex-encoded) to the daemon.
    pub async fn submit_block(&self, blob_hex: &str) -> Result<SubmitBlockResponse, RpcError> {
        let resp: SubmitBlockResponse = self
            .call("submit_block", serde_json::json!([blob_hex]))
            .await?;
        if resp.status != "OK" {
            return Err(RpcError::DaemonStatus(resp.status));
        }
        Ok(resp)
    }

    /// Use the /get_transactions endpoint to fetch raw transaction blobs.
    ///
    /// This is used to include transactions in the Monero block when p2pool
    /// finds a main-chain block.
    pub async fn get_transactions(&self, txids: &[String]) -> Result<Vec<String>, RpcError> {
        let req_body = serde_json::json!({
            "txs_hashes": txids,
            "decode_as_json": false,
        });
        let mut builder = self
            .http
            .post(format!("{}/get_transactions", self.daemon_url))
            .json(&req_body);
        if let Some((user, pass)) = &self.auth {
            builder = builder.basic_auth(user, Some(pass));
        }
        let resp: serde_json::Value = builder.send().await?.json().await?;
        let txs_as_hex = resp["txs_as_hex"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(txs_as_hex)
    }
}
