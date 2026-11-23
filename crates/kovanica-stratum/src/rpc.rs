//! Upstream Kovanica node JSON-RPC client for `kovanica_getWork` and `kovanica_submitWork`.

use anyhow::{anyhow, Context, Result};
use kovanica_types::block::{BlockHeader, BlockReference};
use kovanica_types::{Address, Hash};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

/// Candidate work template returned by `kovanica_getWork`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkTemplate {
    pub chain_id: u64,
    pub round: u64,
    pub author: u16,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub parent_refs: Vec<BlockReference>,
    pub merkle_root: String,
    pub timestamp: u64,
    pub target_bits: Value,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub preimage: Option<String>,
    #[serde(default)]
    pub payout_address: Option<String>,
    #[serde(default)]
    pub header: Option<BlockHeader>,
}

impl WorkTemplate {
    /// Parse `target_bits` from either a hex string (e.g. `"0x207fffff"`) or a number.
    pub fn parse_target_bits(&self) -> Result<u32> {
        match &self.target_bits {
            Value::Number(n) => n
                .as_u64()
                .map(|v| v as u32)
                .context("target_bits integer overflow"),
            Value::String(s) => {
                let stripped = s
                    .trim()
                    .strip_prefix("0x")
                    .or_else(|| s.trim().strip_prefix("0X"))
                    .unwrap_or(s.trim());
                u32::from_str_radix(stripped, 16)
                    .with_context(|| format!("invalid hex target_bits: {s}"))
            }
            other => anyhow::bail!("unexpected target_bits JSON value: {other:?}"),
        }
    }

    /// Construct a candidate `BlockHeader` from this work template.
    pub fn to_candidate_header(&self) -> Result<BlockHeader> {
        if let Some(h) = &self.header {
            return Ok(h.clone());
        }

        let target_bits = self.parse_target_bits()?;
        let merkle_root_clean = self
            .merkle_root
            .trim()
            .strip_prefix("0x")
            .or_else(|| self.merkle_root.trim().strip_prefix("0X"))
            .unwrap_or(self.merkle_root.trim());
        let merkle_bytes =
            hex::decode(merkle_root_clean).context("invalid merkle_root hex string")?;
        if merkle_bytes.len() != 32 {
            anyhow::bail!(
                "invalid merkle_root byte length: {} (expected 32)",
                merkle_bytes.len()
            );
        }
        let mut merkle_arr = [0u8; 32];
        merkle_arr.copy_from_slice(&merkle_bytes);

        let parent_refs = if !self.parent_refs.is_empty() {
            self.parent_refs.clone()
        } else {
            let mut refs = Vec::new();
            for p_hex in &self.parents {
                let clean = p_hex
                    .trim()
                    .strip_prefix("0x")
                    .or_else(|| p_hex.trim().strip_prefix("0X"))
                    .unwrap_or(p_hex.trim());
                let bytes = hex::decode(clean).context("invalid parent hash hex")?;
                if bytes.len() != 32 {
                    anyhow::bail!(
                        "invalid parent hash byte length: {} (expected 32)",
                        bytes.len()
                    );
                }
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&bytes);
                refs.push(BlockReference {
                    author: 0,
                    round: self.round.saturating_sub(1),
                    digest: Hash(digest),
                });
            }
            refs
        };

        let mut header = BlockHeader::new(
            self.chain_id,
            self.round,
            self.author,
            parent_refs,
            Hash(merkle_arr),
            self.timestamp,
            target_bits,
            0,
        );
        if let Some(ref pa) = self.payout_address {
            if let Ok(addr) = Address::decode(pa) {
                header.payout = Some(addr);
            }
        }
        Ok(header)
    }
}

/// Upstream node JSON-RPC client.
#[derive(Debug, Clone)]
pub struct NodeRpcClient {
    client: reqwest::Client,
    rpc_url: String,
    rpc_token: Option<String>,
}

impl NodeRpcClient {
    /// Create a new RPC client for `rpc_url`.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self::with_token(rpc_url, crate::config::resolve_rpc_token_from_env())
    }

    /// Create a new RPC client for `rpc_url` with an optional bearer token.
    pub fn with_token(rpc_url: impl Into<String>, rpc_token: Option<String>) -> Self {
        let mut url = rpc_url.into();
        if !url.ends_with("/rpc") && !url.ends_with('/') {
            url = format!("{url}/rpc");
        }
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            rpc_url: url,
            rpc_token: rpc_token.filter(|t| !t.is_empty()),
        }
    }

    /// Generic JSON-RPC 2.0 POST request.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut builder = self.client.post(&self.rpc_url).json(&req);
        if let Some(ref token) = self.rpc_token {
            builder = builder.bearer_auth(token);
        }

        let resp = builder
            .send()
            .await
            .with_context(|| format!("failed to send RPC request to {}", self.rpc_url))?;

        if !resp.status().is_success() {
            anyhow::bail!("RPC endpoint returned HTTP error: {}", resp.status());
        }

        let resp_json: Value = resp
            .json()
            .await
            .context("failed to parse JSON-RPC response")?;

        if let Some(err) = resp_json.get("error") {
            if !err.is_null() {
                anyhow::bail!("JSON-RPC error from node: {err:?}");
            }
        }

        resp_json
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("missing result field in JSON-RPC response"))
    }

    /// Fetch candidate work template via `kovanica_getWork`.
    pub async fn get_work(&self, payout_address: &str) -> Result<WorkTemplate> {
        let result = self
            .call("kovanica_getWork", json!([payout_address]))
            .await
            .context("kovanica_getWork RPC failed")?;

        serde_json::from_value(result).context("failed to deserialize WorkTemplate")
    }

    /// Submit a solved block header via `kovanica_submitWork`.
    pub async fn submit_work(&self, header: &BlockHeader) -> Result<bool> {
        let params = json!({ "header": header });
        let result = self
            .call("kovanica_submitWork", params)
            .await
            .context("kovanica_submitWork RPC failed")?;

        debug!(result = ?result, "submitWork result");
        if let Some(accepted) = result.get("accepted").and_then(Value::as_bool) {
            Ok(accepted)
        } else if let Some(b) = result.as_bool() {
            Ok(b)
        } else {
            Err(anyhow!(
                "unexpected kovanica_submitWork result shape: {result}"
            ))
        }
    }
}
