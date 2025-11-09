/// JSON-RPC 2.0 client for the xmr-wow-node.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use xmr_wow_sharechain::EscrowOp;

pub struct NodeClient {
    base_url: String,
    http: reqwest::Client,
}

impl NodeClient {
    pub fn new(url: &str) -> Self {
        NodeClient {
            base_url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn submit_escrow_op(&self, op: &EscrowOp) -> anyhow::Result<()> {
        let params = json!({ "op": op, "share_nonce": 0u64 });
        let _result: Value = rpc_call(
            &self.http,
            &format!("{}/json_rpc", self.base_url),
            "submit_escrow_op",
            params,
        ).await?;
        Ok(())
    }

    pub async fn get_swap_status(&self, swap_id: &[u8; 32]) -> anyhow::Result<SwapStatusResponse> {
        let params = json!({ "swap_id": hex::encode(swap_id) });
        let result: Value = rpc_call(
            &self.http,
            &format!("{}/json_rpc", self.base_url),
            "get_swap_status",
            params,
        ).await?;
        let state = result["state"].as_str().unwrap_or("unknown").to_string();
        let k_b = result["k_b"].as_str().map(|s| s.to_string());
        Ok(SwapStatusResponse { state, k_b })
    }

    pub async fn get_chain_height(&self) -> anyhow::Result<u64> {
        let result: Value = rpc_call(
            &self.http,
            &format!("{}/json_rpc", self.base_url),
            "get_chain_height",
            Value::Null,
        ).await?;
        let height = result["height"].as_u64().unwrap_or(0);
        Ok(height)
    }
}

/// Response from get_swap_status.
#[derive(Debug, Serialize, Deserialize)]
pub struct SwapStatusResponse {
    pub state: String,
    pub k_b: Option<String>,
}

async fn rpc_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    method: &str,
    params: P,
) -> anyhow::Result<R> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let resp = http.post(url)
        .json(&body)
        .send()
        .await?;

    let json: Value = resp.json().await?;

    if let Some(err) = json.get("error") {
        if !err.is_null() {
            anyhow::bail!("RPC error: {}", err);
        }
    }

    let result = json.get("result")
        .ok_or_else(|| anyhow::anyhow!("RPC response missing 'result' field"))?;

    Ok(serde_json::from_value(result.clone())?)
}
