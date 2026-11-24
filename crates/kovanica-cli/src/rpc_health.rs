//! Operator RPC `/health` check (`kovanica rpc health <url>`).
//!
//! Fetches `GET <url>/health`, parses `status`, `height`, `mempool_pending`,
//! `rpc_version`, component health, and any extra fields gracefully, and
//! prints a clean human-readable summary or `--json`. URL credentials
//! (`user:pass@`) and sensitive query parameters (`token`, `api_key`, etc.)
//! are always redacted from output and error messages.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::output;
use crate::rpc::parse_quantity;
use crate::rpc_probe::{
    extract_header, redact_parsed_url, RpcProbeHeaders, ValidatedProbeUrl, CHAIN_ID_HEADER,
    NETWORK_TAG_HEADER, RPC_VERSION_HEADER,
};

/// Default HTTP timeout in milliseconds for `kovanica rpc health`.
pub const DEFAULT_HEALTH_TIMEOUT_MS: u64 = 5_000;

/// Known top-level JSON keys extracted directly into [`RpcHealthReport`].
const KNOWN_HEALTH_KEYS: &[&str] = &[
    "status",
    "healthy",
    "height",
    "block_height",
    "peer_count",
    "mempool_pending",
    "rpc_version",
    "execution",
    "consensus",
    "last_error",
];

/// Arguments for `kovanica rpc health <url>`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct RpcHealthArgs {
    /// Node base URL or `/health` URL (`http://` or `https://`; `/health` is appended automatically)
    pub url: String,
    /// HTTP request timeout in milliseconds
    #[arg(long, default_value_t = DEFAULT_HEALTH_TIMEOUT_MS)]
    pub timeout_ms: u64,
}

/// Structured report emitted by `kovanica rpc health`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcHealthReport {
    pub url: String,
    pub ok: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mempool_pending: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_committed_round: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub headers: RpcProbeHeaders,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Validate a node URL (`http://` or `https://`), normalize its path to `/health`,
/// and produce a redacted representation safe for logs and CLI output.
pub fn validate_and_redact_health_url(raw: &str) -> Result<ValidatedProbeUrl> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("RPC health URL must not be empty");
    }

    let mut parsed = reqwest::Url::parse(trimmed)
        .with_context(|| "invalid RPC health URL (expected http:// or https://)")?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => bail!("unsupported URL scheme `{other}` (expected http or https)"),
    }
    if parsed.host_str().is_none() {
        bail!("RPC health URL must include a host");
    }

    let path = parsed.path().trim_end_matches('/');
    let normalized_path = if path.is_empty() {
        "/health".to_string()
    } else if path.ends_with("/health") {
        path.to_string()
    } else if let Some(prefix) = path.strip_suffix("/rpc") {
        format!("{prefix}/health")
    } else {
        format!("{path}/health")
    };
    parsed.set_path(&normalized_path);

    let request_url = parsed.to_string();
    let redacted_url = redact_parsed_url(&parsed);
    Ok(ValidatedProbeUrl {
        request_url,
        redacted_url,
    })
}

fn parse_optional_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    parse_quantity(value).ok()
}

/// Evaluate a parsed `/health` JSON body, HTTP status, and headers into an [`RpcHealthReport`].
pub fn evaluate_health_response(
    redacted_url: String,
    http_status: u16,
    latency_ms: u64,
    headers: RpcProbeHeaders,
    body: &Value,
) -> RpcHealthReport {
    let mut errors = Vec::new();
    if !(200..300).contains(&http_status) {
        errors.push(format!("unexpected HTTP status {http_status}"));
    }

    let Some(obj) = body.as_object() else {
        errors.push("expected JSON object from /health endpoint".to_string());
        return RpcHealthReport {
            url: redacted_url,
            ok: false,
            status: "error".to_string(),
            http_status: Some(http_status),
            latency_ms,
            healthy: None,
            height: None,
            peer_count: None,
            mempool_pending: None,
            rpc_version: headers.rpc_version.clone(),
            execution_state: None,
            consensus_state: None,
            last_committed_round: None,
            last_error: None,
            headers,
            extra: BTreeMap::new(),
            errors,
        };
    };

    let status = obj
        .get("status")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string();

    let healthy = obj.get("healthy").and_then(Value::as_bool);
    let height = obj
        .get("height")
        .or_else(|| obj.get("block_height"))
        .and_then(parse_optional_u64);
    let peer_count = obj
        .get("peer_count")
        .and_then(Value::as_u64)
        .and_then(|v| usize::try_from(v).ok());
    let mempool_pending = obj
        .get("mempool_pending")
        .and_then(Value::as_u64)
        .and_then(|v| usize::try_from(v).ok());
    let rpc_version = obj
        .get("rpc_version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| headers.rpc_version.clone());

    let execution_state = obj
        .get("execution")
        .and_then(|v| v.get("state"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let consensus_state = obj
        .get("consensus")
        .and_then(|v| v.get("state"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let last_committed_round = obj
        .get("consensus")
        .and_then(|v| v.get("last_committed_round"))
        .and_then(Value::as_u64);
    let last_error = obj
        .get("last_error")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let mut extra = BTreeMap::new();
    for (k, v) in obj {
        if !KNOWN_HEALTH_KEYS.contains(&k.as_str()) {
            extra.insert(k.clone(), v.clone());
        }
    }

    if healthy == Some(false) {
        errors.push("node reported healthy=false".to_string());
    }
    let status_lower = status.to_ascii_lowercase();
    if status_lower != "ok" && status_lower != "healthy" {
        errors.push(format!("node reported status `{status}`"));
    }

    let ok = errors.is_empty();
    RpcHealthReport {
        url: redacted_url,
        ok,
        status,
        http_status: Some(http_status),
        latency_ms,
        healthy,
        height,
        peer_count,
        mempool_pending,
        rpc_version,
        execution_state,
        consensus_state,
        last_committed_round,
        last_error,
        headers,
        extra,
        errors,
    }
}

/// Format an [`RpcHealthReport`] into a clean human-readable summary string.
pub fn format_health_report(report: &RpcHealthReport) -> String {
    let mut rows = vec![
        ("Endpoint", report.url.clone()),
        ("Status", report.status.to_ascii_uppercase()),
        (
            "HTTP Status",
            report
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        ("Latency", format!("{} ms", report.latency_ms)),
    ];

    if let Some(healthy) = report.healthy {
        rows.push(("Healthy", if healthy { "yes" } else { "no" }.to_string()));
    }
    if let Some(height) = report.height {
        rows.push(("Height", height.to_string()));
    }
    if let Some(peers) = report.peer_count {
        rows.push(("Peers", peers.to_string()));
    }
    rows.push((
        "Mempool Pending",
        report
            .mempool_pending
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".to_string()),
    ));
    rows.push((
        "RPC Version",
        report
            .rpc_version
            .clone()
            .unwrap_or_else(|| "-".to_string()),
    ));

    if let Some(exec) = &report.execution_state {
        rows.push(("Execution", exec.clone()));
    }
    if let Some(cons) = &report.consensus_state {
        rows.push(("Consensus", cons.clone()));
    }
    if let Some(round) = report.last_committed_round {
        rows.push(("Committed Round", round.to_string()));
    }
    if let Some(tag) = &report.headers.network_tag {
        rows.push(("Network Tag", tag.clone()));
    }
    if let Some(chain_id) = &report.headers.chain_id {
        rows.push(("Chain ID", chain_id.clone()));
    }
    if let Some(err) = &report.last_error {
        rows.push(("Last Error", err.clone()));
    }
    if !report.extra.is_empty() {
        let keys: Vec<&str> = report.extra.keys().map(String::as_str).collect();
        rows.push(("Extra Fields", keys.join(", ")));
    }

    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in &rows {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }

    if !report.errors.is_empty() {
        out.push('\n');
        for err in &report.errors {
            let _ = writeln!(out, "ERROR: {err}");
        }
    }

    out
}

/// Fetch `GET <url>/health` and evaluate the response.
pub async fn fetch_health(args: &RpcHealthArgs) -> Result<RpcHealthReport> {
    if args.timeout_ms == 0 {
        bail!("--timeout-ms must be greater than 0");
    }

    let target = validate_and_redact_health_url(&args.url)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout_ms))
        .build()
        .context("failed to build HTTP client")?;

    let t0 = Instant::now();
    let resp = match http.get(&target.request_url).send().await {
        Ok(r) => r,
        Err(err) => {
            let latency_ms = t0.elapsed().as_millis() as u64;
            return Ok(RpcHealthReport {
                url: target.redacted_url.clone(),
                ok: false,
                status: "unreachable".to_string(),
                http_status: None,
                latency_ms,
                healthy: None,
                height: None,
                peer_count: None,
                mempool_pending: None,
                rpc_version: None,
                execution_state: None,
                consensus_state: None,
                last_committed_round: None,
                last_error: None,
                headers: RpcProbeHeaders::default(),
                extra: BTreeMap::new(),
                errors: vec![format!(
                    "network request to `{}` failed: {}",
                    target.redacted_url,
                    err.without_url()
                )],
            });
        }
    };

    let http_status = resp.status().as_u16();
    let headers = RpcProbeHeaders {
        network_tag: extract_header(resp.headers(), NETWORK_TAG_HEADER),
        rpc_version: extract_header(resp.headers(), RPC_VERSION_HEADER),
        chain_id: extract_header(resp.headers(), CHAIN_ID_HEADER),
    };

    let body_res = resp.json::<Value>().await;
    let latency_ms = t0.elapsed().as_millis() as u64;

    match body_res {
        Ok(body) => Ok(evaluate_health_response(
            target.redacted_url,
            http_status,
            latency_ms,
            headers,
            &body,
        )),
        Err(err) => Ok(RpcHealthReport {
            url: target.redacted_url.clone(),
            ok: false,
            status: "error".to_string(),
            http_status: Some(http_status),
            latency_ms,
            healthy: None,
            height: None,
            peer_count: None,
            mempool_pending: None,
            rpc_version: headers.rpc_version.clone(),
            execution_state: None,
            consensus_state: None,
            last_committed_round: None,
            last_error: None,
            headers,
            extra: BTreeMap::new(),
            errors: vec![format!(
                "invalid JSON response from `{}` (HTTP {http_status}): {}",
                target.redacted_url,
                err.without_url()
            )],
        }),
    }
}

/// CLI entry point for `kovanica rpc health`.
pub async fn run(args: RpcHealthArgs, json_output: bool) -> Result<()> {
    let report = fetch_health(&args).await?;

    if json_output {
        output::print_json(&serde_json::to_value(&report)?)?;
    } else {
        print!("{}", format_health_report(&report));
    }

    if !report.ok {
        return Err(anyhow!(
            "RPC health check failed for {}: {}",
            report.url,
            report.errors.join("; ")
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn health_url_normalization_and_credential_redaction() {
        let base = validate_and_redact_health_url("http://127.0.0.1:8545").unwrap();
        assert_eq!(base.request_url, "http://127.0.0.1:8545/health");
        assert_eq!(base.redacted_url, "http://127.0.0.1:8545/health");

        let from_rpc = validate_and_redact_health_url("http://127.0.0.1:8545/rpc").unwrap();
        assert_eq!(from_rpc.request_url, "http://127.0.0.1:8545/health");

        let already_health =
            validate_and_redact_health_url("http://127.0.0.1:8545/health").unwrap();
        assert_eq!(already_health.request_url, "http://127.0.0.1:8545/health");

        let prefixed = validate_and_redact_health_url("https://node.example.com/v1/rpc").unwrap();
        assert_eq!(prefixed.request_url, "https://node.example.com/v1/health");

        let creds = validate_and_redact_health_url(
            "https://ops:topsecret@rpc.kovanica.org:8545/rpc?token=tok_abc&api_key=key_xyz&env=prod",
        )
        .unwrap();
        assert_eq!(
            creds.request_url,
            "https://ops:topsecret@rpc.kovanica.org:8545/health?token=tok_abc&api_key=key_xyz&env=prod"
        );
        assert!(!creds.redacted_url.contains("ops"));
        assert!(!creds.redacted_url.contains("topsecret"));
        assert!(!creds.redacted_url.contains("tok_abc"));
        assert!(!creds.redacted_url.contains("key_xyz"));
        assert!(creds.redacted_url.contains("REDACTED:REDACTED@"));
        assert!(creds.redacted_url.contains("token=REDACTED"));
        assert!(creds.redacted_url.contains("api_key=REDACTED"));
        assert!(creds.redacted_url.contains("env=prod"));

        // Invalid URLs fail without echoing raw credentials
        let bad_err = validate_and_redact_health_url("ftp://user:pass@127.0.0.1:8545")
            .unwrap_err()
            .to_string();
        assert!(!bad_err.contains("pass"));
        assert!(validate_and_redact_health_url("").is_err());
        assert!(validate_and_redact_health_url("not-a-url").is_err());
    }

    #[test]
    fn evaluate_healthy_node_response_and_extra_fields() {
        let body = json!({
            "status": "ok",
            "peer_count": 7,
            "mempool_pending": 14,
            "rpc_version": "0.1.0",
            "height": 12345,
            "healthy": true,
            "execution": {
                "state": "running",
                "executed_subdags": 50,
                "last_executed_round": 100
            },
            "consensus": {
                "state": "running",
                "committed_leaders": 48,
                "last_committed_round": 99
            },
            "custom_flag": true,
            "region": "eu-central"
        });

        let headers = RpcProbeHeaders {
            network_tag: Some("2-24cdb5fadd98b207".to_string()),
            rpc_version: Some("0.1.0".to_string()),
            chain_id: Some("2".to_string()),
        };

        let report = evaluate_health_response(
            "http://127.0.0.1:8545/health".to_string(),
            200,
            12,
            headers,
            &body,
        );

        assert!(report.ok);
        assert_eq!(report.status, "ok");
        assert_eq!(report.http_status, Some(200));
        assert_eq!(report.healthy, Some(true));
        assert_eq!(report.height, Some(12345));
        assert_eq!(report.peer_count, Some(7));
        assert_eq!(report.mempool_pending, Some(14));
        assert_eq!(report.rpc_version.as_deref(), Some("0.1.0"));
        assert_eq!(report.execution_state.as_deref(), Some("running"));
        assert_eq!(report.consensus_state.as_deref(), Some("running"));
        assert_eq!(report.last_committed_round, Some(99));
        assert_eq!(report.extra.len(), 2);
        assert_eq!(report.extra.get("custom_flag"), Some(&json!(true)));
        assert_eq!(report.extra.get("region"), Some(&json!("eu-central")));

        let rendered = format_health_report(&report);
        assert!(rendered.contains("Status"));
        assert!(rendered.contains("OK"));
        assert!(rendered.contains("12345"));
        assert!(rendered.contains("14"));
        assert!(rendered.contains("0.1.0"));
        assert!(rendered.contains("2-24cdb5fadd98b207"));
        assert!(rendered.contains("custom_flag, region"));
    }

    #[test]
    fn evaluate_degraded_503_response_fails_closed() {
        let body = json!({
            "status": "degraded",
            "peer_count": 0,
            "mempool_pending": 3,
            "rpc_version": "0.1.0",
            "healthy": false,
            "execution": {"state": "failed"},
            "consensus": {"state": "running"},
            "last_error": "execution: state root mismatch"
        });

        let report = evaluate_health_response(
            "http://REDACTED:REDACTED@127.0.0.1:8545/health".to_string(),
            503,
            8,
            RpcProbeHeaders::default(),
            &body,
        );

        assert!(!report.ok);
        assert_eq!(report.status, "degraded");
        assert_eq!(report.healthy, Some(false));
        assert_eq!(
            report.last_error.as_deref(),
            Some("execution: state root mismatch")
        );
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("unexpected HTTP status 503")));
        assert!(report.errors.iter().any(|e| e.contains("healthy=false")));

        let rendered = format_health_report(&report);
        assert!(rendered.contains("DEGRADED"));
        assert!(rendered.contains("ERROR:"));
        assert!(rendered.contains("execution: state root mismatch"));
    }

    #[test]
    fn evaluate_non_object_body_fails_closed() {
        let report = evaluate_health_response(
            "http://127.0.0.1:8545/health".to_string(),
            200,
            4,
            RpcProbeHeaders::default(),
            &json!(["unexpected"]),
        );
        assert!(!report.ok);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("expected JSON object")));
    }

    #[tokio::test]
    async fn zero_timeout_ms_is_rejected() {
        let err = fetch_health(&RpcHealthArgs {
            url: "http://127.0.0.1:8545".to_string(),
            timeout_ms: 0,
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--timeout-ms"));
    }
}
