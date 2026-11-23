//! Read-only pre-flight node diagnostics (`kovanica node doctor`).
//!
//! Runs a structured checklist against a Kovanica JSON-RPC endpoint (and an
//! optional Stratum observability endpoint) without mutating node state or
//! touching private keys:
//! 1. RPC reachability & latency (`kovanica_chainId`)
//! 2. Chain ID & frozen network tag check (`1-f35df34c92001436` mainnet, `2-24cdb5fadd98b207` testnet)
//! 3. JSON-RPC 2.0 batch probe (`[kovanica_chainId, kovanica_blockNumber]`)
//! 4. Sync & peer health (`kovanica_syncStatus` with `/health` peer fallback)
//! 5. Optional Stratum `/health` + `/workers` probe (`--stratum-health-url`)

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Serialize;
use serde_json::{json, Value};

use crate::node::{parse_sync_status, SyncSnapshot};
use crate::output;
use crate::rpc::{parse_quantity, RpcClient};

/// Canonical chain IDs.
pub const MAINNET_CHAIN_ID: u64 = 1;
pub const TESTNET_CHAIN_ID: u64 = 2;
pub const DEVNET_CHAIN_ID: u64 = 3;

/// Frozen canonical network tag for mainnet (chain ID 1).
pub const MAINNET_NETWORK_TAG: &str = "1-f35df34c92001436";

/// Frozen canonical network tag for testnet (chain ID 2).
pub const TESTNET_NETWORK_TAG: &str = "2-24cdb5fadd98b207";

/// Latency threshold above which RPC reachability emits a warning.
pub const SLOW_RPC_LATENCY_MS: u64 = 2_000;

/// HTTP timeout for optional Stratum observability probes.
const STRATUM_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Arguments for `kovanica node doctor`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct NodeDoctorArgs {
    /// Optional Stratum observability base or `/health` URL (e.g. `http://127.0.0.1:9100/health`)
    #[arg(long)]
    pub stratum_health_url: Option<String>,
    /// Expected chain ID to verify against the node (1 mainnet, 2 testnet, 3 devnet)
    #[arg(long)]
    pub expected_chain_id: Option<u64>,
}

/// Verdict for a single diagnostic check or the overall report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    /// Lowercase machine-readable representation (`"pass"`, `"warn"`, `"fail"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    /// Uppercase label for human-readable tables.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// Outcome of one diagnostic check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Complete structured report produced by `kovanica node doctor`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorReport {
    pub rpc_url: String,
    pub overall: CheckStatus,
    pub checks: Vec<DoctorCheck>,
}

/// Return the frozen canonical network tag for mainnet (1) and testnet (2).
pub fn canonical_network_tag(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        MAINNET_CHAIN_ID => Some(MAINNET_NETWORK_TAG),
        TESTNET_CHAIN_ID => Some(TESTNET_NETWORK_TAG),
        _ => None,
    }
}

/// Aggregate individual check verdicts into an overall report verdict.
pub fn compute_overall(checks: &[DoctorCheck]) -> CheckStatus {
    if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        CheckStatus::Fail
    } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    }
}

/// Extract `networkTag` / `network_tag` from a JSON object returned by
/// `kovanica_syncStatus` or `kovanica_getNodeInfo`.
pub fn extract_network_tag(value: &Value) -> Option<String> {
    value
        .get("networkTag")
        .or_else(|| value.get("network_tag"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// Evaluate RPC reachability and latency from `kovanica_chainId`.
pub fn evaluate_rpc_reachability(
    chain_id_result: Result<u64, &str>,
    latency_ms: u64,
) -> (Option<u64>, DoctorCheck) {
    match chain_id_result {
        Ok(chain_id) => {
            let (status, summary) = if latency_ms > SLOW_RPC_LATENCY_MS {
                (
                    CheckStatus::Warn,
                    format!("reachable but slow ({latency_ms} ms), chain_id={chain_id}"),
                )
            } else {
                (
                    CheckStatus::Pass,
                    format!("reachable ({latency_ms} ms), chain_id={chain_id}"),
                )
            };
            (
                Some(chain_id),
                DoctorCheck {
                    name: "rpc_reachability".to_string(),
                    status,
                    summary,
                    latency_ms: Some(latency_ms),
                    details: Some(json!({
                        "chainId": chain_id,
                        "latencyMs": latency_ms,
                    })),
                },
            )
        }
        Err(err) => (
            None,
            DoctorCheck {
                name: "rpc_reachability".to_string(),
                status: CheckStatus::Fail,
                summary: format!("RPC unreachable: {err}"),
                latency_ms: Some(latency_ms),
                details: Some(json!({ "error": err })),
            },
        ),
    }
}

/// Evaluate chain ID expectations and frozen network tag compliance.
pub fn evaluate_chain_and_network_tag(
    reported_chain_id: Option<u64>,
    expected_chain_id: Option<u64>,
    network_tag: Option<&str>,
) -> DoctorCheck {
    let Some(chain_id) = reported_chain_id else {
        return DoctorCheck {
            name: "chain_id_and_network_tag".to_string(),
            status: CheckStatus::Fail,
            summary: "node chain_id unavailable".to_string(),
            latency_ms: None,
            details: Some(json!({
                "expectedChainId": expected_chain_id,
                "reportedChainId": Value::Null,
                "networkTag": network_tag,
            })),
        };
    };

    if let Some(expected) = expected_chain_id {
        if chain_id != expected {
            return DoctorCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Fail,
                summary: format!(
                    "chain_id mismatch: expected {expected}, node reported {chain_id}"
                ),
                latency_ms: None,
                details: Some(json!({
                    "expectedChainId": expected,
                    "reportedChainId": chain_id,
                    "networkTag": network_tag,
                })),
            };
        }
    }

    if let Some(expected_tag) = canonical_network_tag(chain_id) {
        match network_tag {
            Some(actual_tag) if actual_tag == expected_tag => DoctorCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Pass,
                summary: format!(
                    "chain_id={chain_id}, canonical network tag `{expected_tag}` verified"
                ),
                latency_ms: None,
                details: Some(json!({
                    "chainId": chain_id,
                    "expectedNetworkTag": expected_tag,
                    "networkTag": actual_tag,
                })),
            },
            Some(actual_tag) => DoctorCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Fail,
                summary: format!(
                    "network tag mismatch for chain {chain_id}: expected `{expected_tag}`, got `{actual_tag}`"
                ),
                latency_ms: None,
                details: Some(json!({
                    "chainId": chain_id,
                    "expectedNetworkTag": expected_tag,
                    "networkTag": actual_tag,
                })),
            },
            None => DoctorCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Warn,
                summary: format!(
                    "chain_id={chain_id} ok, but node did not report networkTag (expected `{expected_tag}`)"
                ),
                latency_ms: None,
                details: Some(json!({
                    "chainId": chain_id,
                    "expectedNetworkTag": expected_tag,
                    "networkTag": Value::Null,
                })),
            },
        }
    } else {
        let expected_prefix = format!("{chain_id}-");
        match network_tag {
            Some(actual_tag) if !actual_tag.starts_with(&expected_prefix) => DoctorCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Fail,
                summary: format!(
                    "network tag `{actual_tag}` does not match chain_id prefix `{expected_prefix}`"
                ),
                latency_ms: None,
                details: Some(json!({
                    "chainId": chain_id,
                    "networkTag": actual_tag,
                })),
            },
            Some(actual_tag) => DoctorCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Pass,
                summary: format!("chain_id={chain_id}, network tag `{actual_tag}`"),
                latency_ms: None,
                details: Some(json!({
                    "chainId": chain_id,
                    "networkTag": actual_tag,
                })),
            },
            None => DoctorCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Pass,
                summary: format!("chain_id={chain_id} (non-canonical network)"),
                latency_ms: None,
                details: Some(json!({
                    "chainId": chain_id,
                    "networkTag": Value::Null,
                })),
            },
        }
    }
}

/// Evaluate the JSON-RPC 2.0 batch probe response for `[kovanica_chainId, kovanica_blockNumber]`.
pub fn evaluate_batch_response(
    items: &[Value],
    expected_chain_id: Option<u64>,
    latency_ms: u64,
) -> DoctorCheck {
    if items.len() != 2 {
        return DoctorCheck {
            name: "json_rpc_batch".to_string(),
            status: CheckStatus::Fail,
            summary: format!("expected 2 batch responses, got {}", items.len()),
            latency_ms: Some(latency_ms),
            details: Some(json!({ "responseCount": items.len() })),
        };
    }

    let find_by_id = |target: u64| {
        items
            .iter()
            .find(|item| item.get("id").and_then(Value::as_u64) == Some(target))
    };

    let Some(chain_item) = find_by_id(1) else {
        return DoctorCheck {
            name: "json_rpc_batch".to_string(),
            status: CheckStatus::Fail,
            summary: "batch response missing id=1 (kovanica_chainId)".to_string(),
            latency_ms: Some(latency_ms),
            details: None,
        };
    };
    let Some(block_item) = find_by_id(2) else {
        return DoctorCheck {
            name: "json_rpc_batch".to_string(),
            status: CheckStatus::Fail,
            summary: "batch response missing id=2 (kovanica_blockNumber)".to_string(),
            latency_ms: Some(latency_ms),
            details: None,
        };
    };

    if let Some(err) = chain_item.get("error").filter(|v| !v.is_null()) {
        return DoctorCheck {
            name: "json_rpc_batch".to_string(),
            status: CheckStatus::Fail,
            summary: format!("batch kovanica_chainId returned error: {err}"),
            latency_ms: Some(latency_ms),
            details: Some(json!({ "error": err })),
        };
    }
    if let Some(err) = block_item.get("error").filter(|v| !v.is_null()) {
        return DoctorCheck {
            name: "json_rpc_batch".to_string(),
            status: CheckStatus::Fail,
            summary: format!("batch kovanica_blockNumber returned error: {err}"),
            latency_ms: Some(latency_ms),
            details: Some(json!({ "error": err })),
        };
    }

    let chain_id = match chain_item.get("result").map(parse_quantity) {
        Some(Ok(id)) => id,
        _ => {
            return DoctorCheck {
                name: "json_rpc_batch".to_string(),
                status: CheckStatus::Fail,
                summary: "batch kovanica_chainId result missing or invalid".to_string(),
                latency_ms: Some(latency_ms),
                details: None,
            };
        }
    };
    let block_number = match block_item.get("result").map(parse_quantity) {
        Some(Ok(n)) => n,
        _ => {
            return DoctorCheck {
                name: "json_rpc_batch".to_string(),
                status: CheckStatus::Fail,
                summary: "batch kovanica_blockNumber result missing or invalid".to_string(),
                latency_ms: Some(latency_ms),
                details: None,
            };
        }
    };

    if let Some(expected) = expected_chain_id {
        if chain_id != expected {
            return DoctorCheck {
                name: "json_rpc_batch".to_string(),
                status: CheckStatus::Fail,
                summary: format!(
                    "batch chain_id={chain_id} disagrees with single-call chain_id={expected}"
                ),
                latency_ms: Some(latency_ms),
                details: Some(json!({
                    "chainId": chain_id,
                    "expectedChainId": expected,
                    "blockNumber": block_number,
                })),
            };
        }
    }

    DoctorCheck {
        name: "json_rpc_batch".to_string(),
        status: CheckStatus::Pass,
        summary: format!("batch ok (chain_id={chain_id}, block={block_number})"),
        latency_ms: Some(latency_ms),
        details: Some(json!({
            "chainId": chain_id,
            "blockNumber": block_number,
        })),
    }
}

/// Evaluate node sync state, committed height, and peer count.
pub fn evaluate_sync_and_peers(
    sync: Option<&SyncSnapshot>,
    health_peers: Option<usize>,
    sync_error: Option<&str>,
) -> DoctorCheck {
    let Some(snap) = sync else {
        return match health_peers {
            Some(peers) => DoctorCheck {
                name: "sync_and_peers".to_string(),
                status: CheckStatus::Warn,
                summary: format!(
                    "kovanica_syncStatus unavailable ({}); /health reports {peers} peer(s)",
                    sync_error.unwrap_or("unknown error")
                ),
                latency_ms: None,
                details: Some(json!({
                    "syncing": Value::Null,
                    "peerCount": peers,
                    "committedHeight": Value::Null,
                })),
            },
            None => DoctorCheck {
                name: "sync_and_peers".to_string(),
                status: CheckStatus::Fail,
                summary: format!(
                    "kovanica_syncStatus unavailable: {}",
                    sync_error.unwrap_or("unknown error")
                ),
                latency_ms: None,
                details: None,
            },
        };
    };

    let peer_count = snap.peer_count.or(health_peers).unwrap_or(snap.peers.len());
    let height_label = snap
        .height
        .map(|h| h.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let (status, summary) = match snap.catching_up {
        Some(true) => {
            let behind = snap
                .behind_by
                .map(|b| format!(", behind={b}"))
                .unwrap_or_default();
            (
                CheckStatus::Warn,
                format!("catching up (height={height_label}{behind}, peers={peer_count})"),
            )
        }
        Some(false) if peer_count == 0 => (
            CheckStatus::Warn,
            format!("in sync (height={height_label}), but 0 peers connected"),
        ),
        Some(false) => (
            CheckStatus::Pass,
            format!("in sync (height={height_label}, peers={peer_count})"),
        ),
        None => (
            CheckStatus::Warn,
            format!("sync state unknown (height={height_label}, peers={peer_count})"),
        ),
    };

    DoctorCheck {
        name: "sync_and_peers".to_string(),
        status,
        summary,
        latency_ms: None,
        details: Some(json!({
            "syncing": snap.catching_up,
            "committedHeight": snap.height,
            "localTipRound": snap.round,
            "peerCount": peer_count,
            "behindBy": snap.behind_by,
            "catchUpTarget": snap.target,
        })),
    }
}

/// Validate a Stratum observability URL and resolve both `/health` and `/workers` endpoints.
///
/// Accepts `http://` and `https://` URLs with a non-empty host (including loopback
/// addresses such as `http://127.0.0.1:9100` or `http://127.0.0.1:9100/health`).
pub fn resolve_stratum_urls(raw: &str) -> Result<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("--stratum-health-url must not be empty");
    }
    let parsed = reqwest::Url::parse(trimmed)
        .with_context(|| format!("invalid --stratum-health-url `{trimmed}`"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            bail!("unsupported scheme `{other}` in --stratum-health-url (expected http or https)")
        }
    }
    if parsed.host_str().is_none() {
        bail!("--stratum-health-url must include a host");
    }

    let without_trailing = trimmed.trim_end_matches('/');
    let base = without_trailing
        .strip_suffix("/health")
        .unwrap_or(without_trailing);
    Ok((format!("{base}/health"), format!("{base}/workers")))
}

/// Evaluate Stratum `/health` and `/workers` JSON payloads.
pub fn evaluate_stratum_probe(
    health_json: Option<&Value>,
    workers_json: Option<&Value>,
    health_err: Option<&str>,
    workers_err: Option<&str>,
    latency_ms: u64,
) -> DoctorCheck {
    let Some(health) = health_json else {
        return DoctorCheck {
            name: "stratum_gateway".to_string(),
            status: CheckStatus::Fail,
            summary: format!(
                "Stratum /health probe failed: {}",
                health_err.unwrap_or("no response")
            ),
            latency_ms: Some(latency_ms),
            details: Some(json!({ "error": health_err })),
        };
    };

    let gateway_status = health
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let active_connections = health.get("active_connections").and_then(Value::as_u64);
    let uptime_seconds = health.get("uptime_seconds").and_then(Value::as_u64);

    let active_workers = workers_json.and_then(|w| {
        w.get("active_workers").and_then(Value::as_u64).or_else(|| {
            w.get("workers")
                .and_then(Value::as_array)
                .map(|arr| arr.len() as u64)
        })
    });

    let normalized = gateway_status.trim().to_ascii_lowercase();
    let (status, summary) = match normalized.as_str() {
        "healthy" | "ok" => match (active_workers, workers_err) {
            (Some(workers), _) => (
                CheckStatus::Pass,
                format!("status={gateway_status}, active_workers={workers}"),
            ),
            (None, Some(err)) => (
                CheckStatus::Warn,
                format!("status={gateway_status}, but /workers probe failed: {err}"),
            ),
            (None, None) => (
                CheckStatus::Warn,
                format!("status={gateway_status}, active_workers unavailable"),
            ),
        },
        "draining" | "degraded" => {
            let workers_note = active_workers
                .map(|w| format!(", active_workers={w}"))
                .unwrap_or_default();
            (
                CheckStatus::Warn,
                format!("status={gateway_status}{workers_note}"),
            )
        }
        _ => (
            CheckStatus::Fail,
            format!("unhealthy Stratum gateway status: `{gateway_status}`"),
        ),
    };

    DoctorCheck {
        name: "stratum_gateway".to_string(),
        status,
        summary,
        latency_ms: Some(latency_ms),
        details: Some(json!({
            "gatewayStatus": gateway_status,
            "activeWorkers": active_workers,
            "activeConnections": active_connections,
            "uptimeSeconds": uptime_seconds,
            "workersError": workers_err,
        })),
    }
}

/// Format a [`DoctorReport`] into table rows for human-readable output.
pub fn format_doctor_rows(report: &DoctorReport) -> Vec<Vec<String>> {
    report
        .checks
        .iter()
        .map(|check| {
            vec![
                check.name.clone(),
                check.status.label().to_string(),
                check
                    .latency_ms
                    .map(|ms| format!("{ms} ms"))
                    .unwrap_or_else(|| "-".to_string()),
                check.summary.clone(),
            ]
        })
        .collect()
}

/// Execute all pre-flight diagnostics and return the structured [`DoctorReport`].
pub async fn run_doctor(client: &RpcClient, args: &NodeDoctorArgs) -> DoctorReport {
    let mut checks = Vec::with_capacity(5);

    // 1. RPC reachability & latency (`kovanica_chainId`)
    let t0 = Instant::now();
    let chain_id_res = match client.call("kovanica_chainId", json!([])).await {
        Ok(val) => parse_quantity(&val).map_err(|e| e.to_string()),
        Err(err) => Err(err.to_string()),
    };
    let rpc_latency_ms = t0.elapsed().as_millis() as u64;
    let (reported_chain_id, reachability_check) = evaluate_rpc_reachability(
        chain_id_res.as_ref().copied().map_err(String::as_str),
        rpc_latency_ms,
    );
    checks.push(reachability_check);

    // Query `kovanica_syncStatus` once; reused by both check 2 (networkTag) and check 4 (sync/peers).
    let (sync_raw, sync_snapshot, sync_err) =
        match client.call("kovanica_syncStatus", json!([])).await {
            Ok(val) => match parse_sync_status(&val) {
                Ok(snap) => (Some(val), Some(snap), None),
                Err(err) => (Some(val), None, Some(err.to_string())),
            },
            Err(err) => (None, None, Some(err.to_string())),
        };

    // 2. Chain ID & frozen network tag check
    let mut network_tag = sync_raw.as_ref().and_then(extract_network_tag);
    if network_tag.is_none() {
        if let Ok(node_info) = client.call("kovanica_getNodeInfo", json!([])).await {
            network_tag = extract_network_tag(&node_info);
        }
    }
    checks.push(evaluate_chain_and_network_tag(
        reported_chain_id,
        args.expected_chain_id,
        network_tag.as_deref(),
    ));

    // 3. JSON-RPC 2.0 batch probe (`[kovanica_chainId, kovanica_blockNumber]`)
    let batch_requests = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "kovanica_chainId", "params": []}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "kovanica_blockNumber", "params": []}),
    ];
    let t_batch = Instant::now();
    let batch_check = match client.call_batch(&batch_requests).await {
        Ok(items) => evaluate_batch_response(
            &items,
            reported_chain_id,
            t_batch.elapsed().as_millis() as u64,
        ),
        Err(err) => DoctorCheck {
            name: "json_rpc_batch".to_string(),
            status: CheckStatus::Fail,
            summary: format!("JSON-RPC batch probe failed: {err}"),
            latency_ms: Some(t_batch.elapsed().as_millis() as u64),
            details: Some(json!({ "error": err.to_string() })),
        },
    };
    checks.push(batch_check);

    // 4. Sync & peer health
    let health_peers = if sync_snapshot.as_ref().and_then(|s| s.peer_count).is_none() {
        client.health_peer_count().await
    } else {
        None
    };
    checks.push(evaluate_sync_and_peers(
        sync_snapshot.as_ref(),
        health_peers,
        sync_err.as_deref(),
    ));

    // 5. Optional Stratum `/health` + `/workers` probe
    if let Some(raw_url) = args.stratum_health_url.as_deref() {
        let stratum_check = probe_stratum(raw_url).await;
        checks.push(stratum_check);
    }

    let overall = compute_overall(&checks);
    DoctorReport {
        rpc_url: client.url().to_string(),
        overall,
        checks,
    }
}

async fn probe_stratum(raw_url: &str) -> DoctorCheck {
    let (health_url, workers_url) = match resolve_stratum_urls(raw_url) {
        Ok(urls) => urls,
        Err(err) => {
            return DoctorCheck {
                name: "stratum_gateway".to_string(),
                status: CheckStatus::Fail,
                summary: format!("invalid Stratum URL: {err}"),
                latency_ms: None,
                details: Some(json!({ "url": raw_url })),
            };
        }
    };

    let http = match reqwest::Client::builder()
        .timeout(STRATUM_PROBE_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            return DoctorCheck {
                name: "stratum_gateway".to_string(),
                status: CheckStatus::Fail,
                summary: format!("failed to build HTTP client: {err}"),
                latency_ms: None,
                details: None,
            };
        }
    };

    let t0 = Instant::now();
    let health_res = fetch_json(&http, &health_url).await;
    let workers_res = fetch_json(&http, &workers_url).await;
    let latency_ms = t0.elapsed().as_millis() as u64;

    evaluate_stratum_probe(
        health_res.as_ref().ok(),
        workers_res.as_ref().ok(),
        health_res.as_ref().err().map(String::as_str),
        workers_res.as_ref().err().map(String::as_str),
        latency_ms,
    )
}

async fn fetch_json(http: &reqwest::Client, url: &str) -> Result<Value, String> {
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request to `{url}` failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status} from `{url}`"));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("invalid JSON from `{url}`: {e}"))
}

/// CLI entry point for `kovanica node doctor`.
pub async fn run(client: &RpcClient, args: NodeDoctorArgs, json_output: bool) -> Result<()> {
    let report = run_doctor(client, &args).await;
    if json_output {
        return output::print_json(&serde_json::to_value(&report)?);
    }

    output::print_kv(&[
        ("RPC", report.rpc_url.clone()),
        ("Overall", report.overall.label().to_string()),
    ]);
    println!();
    let rows = format_doctor_rows(&report);
    output::print_table(&["CHECK", "STATUS", "LATENCY", "SUMMARY"], &rows);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_network_tags_match_frozen_values() {
        assert_eq!(canonical_network_tag(1), Some("1-f35df34c92001436"));
        assert_eq!(canonical_network_tag(2), Some("2-24cdb5fadd98b207"));
        assert_eq!(canonical_network_tag(3), None);
    }

    #[test]
    fn network_tag_evaluation_covers_mainnet_testnet_mismatch_and_missing() {
        // Mainnet canonical pass
        let mainnet_ok =
            evaluate_chain_and_network_tag(Some(1), Some(1), Some("1-f35df34c92001436"));
        assert_eq!(mainnet_ok.status, CheckStatus::Pass);

        // Testnet canonical pass
        let testnet_ok =
            evaluate_chain_and_network_tag(Some(2), Some(2), Some("2-24cdb5fadd98b207"));
        assert_eq!(testnet_ok.status, CheckStatus::Pass);

        // Wrong tag on mainnet -> fail
        let bad_tag = evaluate_chain_and_network_tag(Some(1), Some(1), Some("1-deadbeefdeadbeef"));
        assert_eq!(bad_tag.status, CheckStatus::Fail);
        assert!(bad_tag.summary.contains("1-f35df34c92001436"));

        // Missing tag on testnet -> warn
        let missing_tag = evaluate_chain_and_network_tag(Some(2), Some(2), None);
        assert_eq!(missing_tag.status, CheckStatus::Warn);

        // Expected chain_id mismatch -> fail
        let wrong_chain =
            evaluate_chain_and_network_tag(Some(2), Some(1), Some("2-24cdb5fadd98b207"));
        assert_eq!(wrong_chain.status, CheckStatus::Fail);
        assert!(wrong_chain.summary.contains("expected 1"));

        // Devnet chain 3 with matching prefix -> pass
        let devnet_ok =
            evaluate_chain_and_network_tag(Some(3), Some(3), Some("3-0123456789abcdef"));
        assert_eq!(devnet_ok.status, CheckStatus::Pass);
    }

    #[test]
    fn overall_verdict_aggregation_prefers_fail_over_warn_over_pass() {
        let pass = DoctorCheck {
            name: "a".into(),
            status: CheckStatus::Pass,
            summary: "ok".into(),
            latency_ms: None,
            details: None,
        };
        let warn = DoctorCheck {
            name: "b".into(),
            status: CheckStatus::Warn,
            summary: "warn".into(),
            latency_ms: None,
            details: None,
        };
        let fail = DoctorCheck {
            name: "c".into(),
            status: CheckStatus::Fail,
            summary: "fail".into(),
            latency_ms: None,
            details: None,
        };

        assert_eq!(
            compute_overall(std::slice::from_ref(&pass)),
            CheckStatus::Pass
        );
        assert_eq!(
            compute_overall(&[pass.clone(), warn.clone()]),
            CheckStatus::Warn
        );
        assert_eq!(compute_overall(&[pass, warn, fail]), CheckStatus::Fail);
    }

    #[test]
    fn sync_and_peers_verdicts_cover_pass_warn_and_fail() {
        let healthy = SyncSnapshot {
            height: Some(1200),
            round: Some(1250),
            catching_up: Some(false),
            behind_by: None,
            target: None,
            peer_count: Some(4),
            peers: vec![],
            node_chain_id: Some(2),
        };
        assert_eq!(
            evaluate_sync_and_peers(Some(&healthy), None, None).status,
            CheckStatus::Pass
        );

        let catching_up = SyncSnapshot {
            catching_up: Some(true),
            behind_by: Some(42),
            target: Some(1292),
            ..healthy.clone()
        };
        assert_eq!(
            evaluate_sync_and_peers(Some(&catching_up), None, None).status,
            CheckStatus::Warn
        );

        let no_peers = SyncSnapshot {
            peer_count: Some(0),
            ..healthy
        };
        assert_eq!(
            evaluate_sync_and_peers(Some(&no_peers), None, None).status,
            CheckStatus::Warn
        );

        assert_eq!(
            evaluate_sync_and_peers(None, None, Some("connection refused")).status,
            CheckStatus::Fail
        );
    }

    #[test]
    fn stratum_url_validation_and_probe_evaluation() {
        assert_eq!(
            resolve_stratum_urls("http://127.0.0.1:9100").unwrap(),
            (
                "http://127.0.0.1:9100/health".to_string(),
                "http://127.0.0.1:9100/workers".to_string()
            )
        );
        assert_eq!(
            resolve_stratum_urls("https://pool.example.com:9100/health").unwrap(),
            (
                "https://pool.example.com:9100/health".to_string(),
                "https://pool.example.com:9100/workers".to_string()
            )
        );
        assert!(resolve_stratum_urls("ftp://127.0.0.1:9100").is_err());
        assert!(resolve_stratum_urls("not-a-url").is_err());
        assert!(resolve_stratum_urls("").is_err());

        let ok_health = json!({"status": "healthy", "active_connections": 3, "uptime_seconds": 60});
        let ok_workers = json!({"active_workers": 2, "workers": []});
        let pass = evaluate_stratum_probe(Some(&ok_health), Some(&ok_workers), None, None, 15);
        assert_eq!(pass.status, CheckStatus::Pass);
        assert!(pass.summary.contains("active_workers=2"));

        let draining = json!({"status": "draining"});
        let warn = evaluate_stratum_probe(Some(&draining), Some(&ok_workers), None, None, 10);
        assert_eq!(warn.status, CheckStatus::Warn);

        let fail = evaluate_stratum_probe(None, None, Some("timeout"), Some("timeout"), 5000);
        assert_eq!(fail.status, CheckStatus::Fail);
    }

    #[test]
    fn doctor_report_json_serialization_matches_expected_schema() {
        let report = DoctorReport {
            rpc_url: "http://127.0.0.1:8545/rpc".to_string(),
            overall: CheckStatus::Warn,
            checks: vec![
                DoctorCheck {
                    name: "rpc_reachability".to_string(),
                    status: CheckStatus::Pass,
                    summary: "reachable (8 ms), chain_id=2".to_string(),
                    latency_ms: Some(8),
                    details: Some(json!({"chainId": 2})),
                },
                DoctorCheck {
                    name: "sync_and_peers".to_string(),
                    status: CheckStatus::Warn,
                    summary: "catching up".to_string(),
                    latency_ms: None,
                    details: None,
                },
            ],
        };
        let val = serde_json::to_value(&report).unwrap();
        assert_eq!(val["overall"], "warn");
        assert_eq!(val["rpc_url"], "http://127.0.0.1:8545/rpc");
        assert_eq!(val["checks"].as_array().unwrap().len(), 2);
        assert_eq!(val["checks"][0]["status"], "pass");
        assert_eq!(val["checks"][1]["status"], "warn");

        let rows = format_doctor_rows(&report);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][1], "PASS");
        assert_eq!(rows[0][2], "8 ms");
        assert_eq!(rows[1][1], "WARN");
        assert_eq!(rows[1][2], "-");
    }

    #[tokio::test]
    async fn run_doctor_end_to_end_against_mock_rpc_and_stratum_servers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let rpc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_addr = rpc_listener.local_addr().unwrap();

        let rpc_server = tokio::spawn(async move {
            // Serve 3 requests: kovanica_chainId, kovanica_syncStatus, batch [chainId, blockNumber]
            for _ in 0..3 {
                let (mut stream, _) = rpc_listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
                let parsed: Value = serde_json::from_str(body).unwrap();

                let resp_body = if parsed.is_array() {
                    json!([
                        {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
                        {"jsonrpc": "2.0", "id": 2, "result": "0x64"}
                    ])
                    .to_string()
                } else {
                    match parsed["method"].as_str().unwrap_or("") {
                        "kovanica_chainId" => {
                            json!({"jsonrpc": "2.0", "id": 1, "result": "0x2"}).to_string()
                        }
                        "kovanica_syncStatus" => json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "committedHeight": 100,
                                "localTipRound": 105,
                                "catchingUp": false,
                                "peerCount": 3,
                                "peers": [],
                                "networkTag": "2-24cdb5fadd98b207"
                            }
                        })
                        .to_string(),
                        _ => json!({"jsonrpc": "2.0", "id": 1, "result": null}).to_string(),
                    }
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let stratum_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stratum_addr = stratum_listener.local_addr().unwrap();

        let stratum_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = stratum_listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let resp_body = if req.starts_with("GET /health ") {
                    json!({
                        "status": "healthy",
                        "uptime_seconds": 420,
                        "active_connections": 2
                    })
                    .to_string()
                } else {
                    json!({
                        "active_workers": 2,
                        "vardiff_enabled": true,
                        "workers": [{"session_id": 1}, {"session_id": 2}]
                    })
                    .to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client = RpcClient::new(format!("http://{rpc_addr}"));
        let report = run_doctor(
            &client,
            &NodeDoctorArgs {
                stratum_health_url: Some(format!("http://{stratum_addr}/health")),
                expected_chain_id: Some(2),
            },
        )
        .await;

        assert_eq!(report.overall, CheckStatus::Pass);
        assert_eq!(report.checks.len(), 5);
        assert!(report.checks.iter().all(|c| c.status == CheckStatus::Pass));
        assert_eq!(report.checks[0].name, "rpc_reachability");
        assert_eq!(report.checks[1].name, "chain_id_and_network_tag");
        assert_eq!(report.checks[2].name, "json_rpc_batch");
        assert_eq!(report.checks[3].name, "sync_and_peers");
        assert_eq!(report.checks[4].name, "stratum_gateway");
        assert!(report.checks[4].summary.contains("active_workers=2"));

        rpc_server.await.unwrap();
        stratum_server.await.unwrap();
    }
}
