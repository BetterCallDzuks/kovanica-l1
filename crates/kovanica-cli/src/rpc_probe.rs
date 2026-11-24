//! Single-shot JSON-RPC endpoint probe (`kovanica rpc probe <url>`).
//!
//! Validates a Kovanica JSON-RPC endpoint in a single HTTP POST batch request
//! (`kovanica_chainId`, `kovanica_blockNumber`, `kovanica_estimateFee`),
//! correlates responses by `id`, measures round-trip latency, inspects
//! `X-Kovanica-*` response headers, and verifies canonical network tags for
//! mainnet (`1-f35df34c92001436`) and testnet (`2-24cdb5fadd98b207`).

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::node_doctor::{canonical_network_tag, CheckStatus};
use crate::output;
use crate::rpc::parse_quantity;

/// Default HTTP timeout for `kovanica rpc probe`.
pub const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 10;

/// Response header advertising the node's network tag.
pub const NETWORK_TAG_HEADER: &str = "x-kovanica-network-tag";
/// Response header advertising the node's RPC version.
pub const RPC_VERSION_HEADER: &str = "x-kovanica-rpc-version";
/// Response header advertising the node's chain ID.
pub const CHAIN_ID_HEADER: &str = "x-kovanica-chain-id";

/// Sensitive query parameter names whose values are redacted from output.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "auth",
    "authorization",
    "bearer",
    "password",
    "passwd",
    "pwd",
    "jwt",
    "sig",
    "signature",
];

/// Subcommands under `kovanica rpc`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RpcCommand {
    /// Probe a Kovanica JSON-RPC endpoint (batch support, headers, canonical network tag, latency)
    Probe(RpcProbeArgs),
    /// Inspect a Kovanica node's HTTP `/health` endpoint
    Health(crate::rpc_health::RpcHealthArgs),
}

/// Arguments for `kovanica rpc probe <url>`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct RpcProbeArgs {
    /// JSON-RPC endpoint URL (`http://` or `https://`; `/rpc` is appended when path is empty or `/`)
    pub url: String,
    /// Expected chain ID to verify against the endpoint (1 mainnet, 2 testnet, 3 devnet)
    #[arg(long)]
    pub expected_chain_id: Option<u64>,
    /// HTTP request timeout in seconds
    #[arg(long, default_value_t = DEFAULT_PROBE_TIMEOUT_SECS)]
    pub timeout_secs: u64,
}

/// Kovanica-specific HTTP response headers captured during a probe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcProbeHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
}

/// Structured report emitted by `kovanica rpc probe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcProbeReport {
    pub url: String,
    pub ok: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub latency_ms: u64,
    pub batch_supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_chain_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_fee_atoms_per_byte: Option<u64>,
    pub headers: RpcProbeHeaders,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_network_tag: Option<String>,
    pub canonical_tag_verified: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Validated probe target URL along with its redacted display form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedProbeUrl {
    pub request_url: String,
    pub redacted_url: String,
}

/// Validate an RPC URL (`http://` or `https://`), normalize root paths to `/rpc`,
/// and produce a redacted representation safe for logs and CLI output.
pub fn validate_and_redact_url(raw: &str) -> Result<ValidatedProbeUrl> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("RPC URL must not be empty");
    }

    let mut parsed = reqwest::Url::parse(trimmed)
        .with_context(|| "invalid RPC URL (expected http:// or https://)")?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => bail!("unsupported URL scheme `{other}` (expected http or https)"),
    }
    if parsed.host_str().is_none() {
        bail!("RPC URL must include a host");
    }

    if parsed.path().is_empty() || parsed.path() == "/" {
        parsed.set_path("/rpc");
    }

    let request_url = parsed.to_string();
    let redacted_url = redact_parsed_url(&parsed);
    Ok(ValidatedProbeUrl {
        request_url,
        redacted_url,
    })
}

/// Redact embedded userinfo credentials and sensitive query parameter values from a URL.
pub fn redact_url(raw: &str) -> String {
    match reqwest::Url::parse(raw.trim()) {
        Ok(parsed) => redact_parsed_url(&parsed),
        Err(_) => "<invalid-url>".to_string(),
    }
}

pub(crate) fn redact_parsed_url(parsed: &reqwest::Url) -> String {
    let mut sanitized = parsed.clone();

    let has_user = !sanitized.username().is_empty();
    let has_pass = sanitized.password().is_some();
    if has_user || has_pass {
        let _ = sanitized.set_username("REDACTED");
        if has_pass {
            let _ = sanitized.set_password(Some("REDACTED"));
        }
    }

    if parsed.query().is_some() {
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| {
                let normalized = k.to_ascii_lowercase().replace('-', "_");
                let is_sensitive = SENSITIVE_QUERY_KEYS
                    .iter()
                    .any(|sensitive| normalized == *sensitive || normalized.ends_with(sensitive));
                if is_sensitive {
                    (k.into_owned(), "REDACTED".to_string())
                } else {
                    (k.into_owned(), v.into_owned())
                }
            })
            .collect();
        sanitized.query_pairs_mut().clear().extend_pairs(pairs);
    }

    sanitized.to_string()
}

pub(crate) fn extract_header(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_header_chain_id(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if let Some(hex_str) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex_str, 16)
            .with_context(|| format!("invalid hex chain ID header `{trimmed}`"))
    } else {
        trimmed
            .parse::<u64>()
            .with_context(|| format!("invalid chain ID header `{trimmed}`"))
    }
}

fn parse_batch_quantity(
    items: &[Value],
    target_id: u64,
    method: &str,
    errors: &mut Vec<String>,
) -> Option<u64> {
    let Some(item) = items
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_u64) == Some(target_id))
    else {
        errors.push(format!("batch response missing id={target_id} ({method})"));
        return None;
    };

    if let Some(err) = item.get("error").filter(|v| !v.is_null()) {
        errors.push(format!("{method} returned JSON-RPC error: {err}"));
        return None;
    }

    match item.get("result").map(parse_quantity) {
        Some(Ok(val)) => Some(val),
        Some(Err(err)) => {
            errors.push(format!("{method} returned invalid quantity: {err}"));
            None
        }
        None => {
            errors.push(format!("{method} response missing `result` field"));
            None
        }
    }
}

/// Evaluate a parsed JSON body, HTTP status, and captured headers into an [`RpcProbeReport`].
#[allow(clippy::too_many_arguments)]
pub fn evaluate_probe_response(
    redacted_url: String,
    http_status: u16,
    latency_ms: u64,
    headers: RpcProbeHeaders,
    body: &Value,
    expected_chain_id: Option<u64>,
) -> RpcProbeReport {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if !(200..300).contains(&http_status) {
        errors.push(format!("unexpected HTTP status {http_status}"));
    }

    let (batch_supported, body_chain_id, block_number, estimated_fee_atoms_per_byte) = match body {
        Value::Array(items) => {
            let cid = parse_batch_quantity(items, 1, "kovanica_chainId", &mut errors);
            let blk = parse_batch_quantity(items, 2, "kovanica_blockNumber", &mut errors);
            let fee = parse_batch_quantity(items, 3, "kovanica_estimateFee", &mut errors);
            (true, cid, blk, fee)
        }
        other => {
            if let Some(err) = other.get("error").filter(|v| !v.is_null()) {
                errors.push(format!(
                    "endpoint returned non-array JSON-RPC error (batch unsupported): {err}"
                ));
            } else {
                errors.push(
                    "endpoint returned non-array JSON response (JSON-RPC 2.0 batch unsupported)"
                        .to_string(),
                );
            }
            (false, None, None, None)
        }
    };

    let header_chain_id = match headers.chain_id.as_deref() {
        Some(raw) => match parse_header_chain_id(raw) {
            Ok(id) => Some(id),
            Err(err) => {
                errors.push(err.to_string());
                None
            }
        },
        None => None,
    };

    if let (Some(body_id), Some(hdr_id)) = (body_chain_id, header_chain_id) {
        if body_id != hdr_id {
            errors.push(format!(
                "chain_id header mismatch: X-Kovanica-Chain-Id={hdr_id} disagrees with kovanica_chainId={body_id}"
            ));
        }
    }

    let chain_id = body_chain_id.or(header_chain_id);

    if let Some(expected) = expected_chain_id {
        match chain_id {
            Some(actual) if actual != expected => {
                errors.push(format!(
                    "chain_id mismatch: expected {expected}, endpoint reported {actual}"
                ));
            }
            None => {
                errors.push(format!(
                    "chain_id mismatch: expected {expected}, but endpoint did not report a chain_id"
                ));
            }
            _ => {}
        }
    }

    let tag_check_chain_id = chain_id.or(expected_chain_id);
    let expected_network_tag = tag_check_chain_id
        .and_then(canonical_network_tag)
        .map(ToOwned::to_owned);

    let mut canonical_tag_verified = false;
    match (&expected_network_tag, headers.network_tag.as_deref()) {
        (Some(expected_tag), Some(actual_tag)) if actual_tag == expected_tag => {
            canonical_tag_verified = true;
        }
        (Some(expected_tag), Some(actual_tag)) => {
            errors.push(format!(
                "canonical network tag mismatch: expected `{expected_tag}`, got `{actual_tag}`"
            ));
        }
        (Some(expected_tag), None) => {
            warnings.push(format!(
                "missing X-Kovanica-Network-Tag header (expected canonical tag `{expected_tag}`)"
            ));
        }
        (None, Some(actual_tag)) => {
            if let Some(cid) = tag_check_chain_id {
                let prefix = format!("{cid}-");
                if !actual_tag.starts_with(&prefix) {
                    errors.push(format!(
                        "network tag `{actual_tag}` does not match chain_id prefix `{prefix}`"
                    ));
                }
            }
        }
        (None, None) => {}
    }

    let ok = errors.is_empty();
    let check_status = if !ok {
        CheckStatus::Fail
    } else if !warnings.is_empty() {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };

    RpcProbeReport {
        url: redacted_url,
        ok,
        status: check_status.as_str().to_string(),
        http_status: Some(http_status),
        latency_ms,
        batch_supported,
        chain_id,
        expected_chain_id,
        block_number,
        estimated_fee_atoms_per_byte,
        headers,
        expected_network_tag,
        canonical_tag_verified,
        warnings,
        errors,
    }
}

/// Execute the single-POST JSON-RPC 2.0 batch probe against the target endpoint.
pub async fn probe_endpoint(args: &RpcProbeArgs) -> Result<RpcProbeReport> {
    if args.timeout_secs == 0 {
        bail!("--timeout-secs must be greater than 0");
    }

    let target = validate_and_redact_url(&args.url)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    let batch_payload = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "kovanica_chainId", "params": []},
        {"jsonrpc": "2.0", "id": 2, "method": "kovanica_blockNumber", "params": []},
        {"jsonrpc": "2.0", "id": 3, "method": "kovanica_estimateFee", "params": []},
    ]);

    let t0 = Instant::now();
    let resp = match http
        .post(&target.request_url)
        .json(&batch_payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            let latency_ms = t0.elapsed().as_millis() as u64;
            return Ok(RpcProbeReport {
                url: target.redacted_url.clone(),
                ok: false,
                status: CheckStatus::Fail.as_str().to_string(),
                http_status: None,
                latency_ms,
                batch_supported: false,
                chain_id: None,
                expected_chain_id: args.expected_chain_id,
                block_number: None,
                estimated_fee_atoms_per_byte: None,
                headers: RpcProbeHeaders::default(),
                expected_network_tag: args
                    .expected_chain_id
                    .and_then(canonical_network_tag)
                    .map(ToOwned::to_owned),
                canonical_tag_verified: false,
                warnings: Vec::new(),
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
        Ok(body) => Ok(evaluate_probe_response(
            target.redacted_url,
            http_status,
            latency_ms,
            headers,
            &body,
            args.expected_chain_id,
        )),
        Err(err) => Ok(RpcProbeReport {
            url: target.redacted_url.clone(),
            ok: false,
            status: CheckStatus::Fail.as_str().to_string(),
            http_status: Some(http_status),
            latency_ms,
            batch_supported: false,
            chain_id: None,
            expected_chain_id: args.expected_chain_id,
            block_number: None,
            estimated_fee_atoms_per_byte: None,
            headers,
            expected_network_tag: args
                .expected_chain_id
                .and_then(canonical_network_tag)
                .map(ToOwned::to_owned),
            canonical_tag_verified: false,
            warnings: Vec::new(),
            errors: vec![format!(
                "invalid JSON response from `{}` (HTTP {http_status}): {}",
                target.redacted_url,
                err.without_url()
            )],
        }),
    }
}

/// CLI entry point for `kovanica rpc probe`.
///
/// Emits either a JSON [`RpcProbeReport`] or a human-readable summary, then
/// fails closed with a non-zero exit error whenever `report.ok` is `false`.
pub async fn run(args: RpcProbeArgs, json_output: bool) -> Result<()> {
    let report = probe_endpoint(&args).await?;

    if json_output {
        output::print_json(&serde_json::to_value(&report)?)?;
    } else {
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
            (
                "Batch Support",
                if report.batch_supported { "yes" } else { "no" }.to_string(),
            ),
            (
                "Chain ID",
                report
                    .chain_id
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Block Number",
                report
                    .block_number
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Estimated Fee",
                report
                    .estimated_fee_atoms_per_byte
                    .map(|f| format!("{f} atoms/byte"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Network Tag",
                report
                    .headers
                    .network_tag
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Canonical Tag",
                if report.canonical_tag_verified {
                    "verified".to_string()
                } else if report.expected_network_tag.is_some() {
                    "unverified".to_string()
                } else {
                    "n/a".to_string()
                },
            ),
            (
                "RPC Version",
                report
                    .headers
                    .rpc_version
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Header Chain ID",
                report
                    .headers
                    .chain_id
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ];
        if let Some(expected) = report.expected_chain_id {
            rows.push(("Expected Chain", expected.to_string()));
        }
        output::print_kv(&rows);

        if !report.warnings.is_empty() {
            println!();
            for warning in &report.warnings {
                println!("WARN: {warning}");
            }
        }
        if !report.errors.is_empty() {
            println!();
            for error in &report.errors {
                println!("ERROR: {error}");
            }
        }
    }

    if !report.ok {
        return Err(anyhow!(
            "RPC probe failed for {}: {}",
            report.url,
            report.errors.join("; ")
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a one-shot mock HTTP/1.1 server on loopback returning the given
    /// status line, headers, and body.
    async fn spawn_mock_rpc_server(
        status_line: &'static str,
        extra_headers: Vec<(&'static str, &'static str)>,
        body: String,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await;

            let mut response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (k, v) in extra_headers {
                response.push_str(&format!("{k}: {v}\r\n"));
            }
            response.push_str("\r\n");
            response.push_str(&body);
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });

        format!("http://{addr}")
    }

    #[tokio::test]
    async fn healthy_batch_with_canonical_chain2_headers_passes() {
        // Deliberately return batch items out of order to verify `id` correlation.
        let body = json!([
            {"jsonrpc": "2.0", "id": 3, "result": "0x5"},
            {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x1a4"},
        ])
        .to_string();

        let base_url = spawn_mock_rpc_server(
            "200 OK",
            vec![
                ("X-Kovanica-Network-Tag", "2-24cdb5fadd98b207"),
                ("X-Kovanica-Rpc-Version", "1.0.0"),
                ("X-Kovanica-Chain-Id", "2"),
            ],
            body,
        )
        .await;

        let args = RpcProbeArgs {
            url: base_url.clone(),
            expected_chain_id: Some(2),
            timeout_secs: 5,
        };
        let report = probe_endpoint(&args).await.unwrap();

        assert!(report.ok, "expected PASS, errors: {:?}", report.errors);
        assert_eq!(report.status, "pass");
        assert_eq!(report.http_status, Some(200));
        assert!(report.batch_supported);
        assert_eq!(report.chain_id, Some(2));
        assert_eq!(report.expected_chain_id, Some(2));
        assert_eq!(report.block_number, Some(0x1a4));
        assert_eq!(report.estimated_fee_atoms_per_byte, Some(5));
        assert_eq!(
            report.headers.network_tag.as_deref(),
            Some("2-24cdb5fadd98b207")
        );
        assert_eq!(report.headers.rpc_version.as_deref(), Some("1.0.0"));
        assert_eq!(report.headers.chain_id.as_deref(), Some("2"));
        assert_eq!(
            report.expected_network_tag.as_deref(),
            Some("2-24cdb5fadd98b207")
        );
        assert!(report.canonical_tag_verified);
        assert!(report.warnings.is_empty());
        assert!(report.errors.is_empty());
        assert!(report.url.ends_with("/rpc"));
    }

    #[tokio::test]
    async fn spoofed_network_tag_header_fails_closed() {
        let body = json!([
            {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x10"},
            {"jsonrpc": "2.0", "id": 3, "result": "0x1"},
        ])
        .to_string();

        let base_url = spawn_mock_rpc_server(
            "200 OK",
            vec![
                ("X-Kovanica-Network-Tag", "2-deadbeefcafebabe"),
                ("X-Kovanica-Rpc-Version", "1.0.0"),
                ("X-Kovanica-Chain-Id", "2"),
            ],
            body,
        )
        .await;

        let args = RpcProbeArgs {
            url: base_url,
            expected_chain_id: Some(2),
            timeout_secs: 5,
        };
        let report = probe_endpoint(&args).await.unwrap();

        assert!(!report.ok);
        assert_eq!(report.status, "fail");
        assert!(!report.canonical_tag_verified);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("canonical network tag mismatch")));
    }

    #[tokio::test]
    async fn expected_chain_id_mismatch_fails_closed() {
        let body = json!([
            {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x20"},
            {"jsonrpc": "2.0", "id": 3, "result": "0x1"},
        ])
        .to_string();

        let base_url = spawn_mock_rpc_server(
            "200 OK",
            vec![
                ("X-Kovanica-Network-Tag", "2-24cdb5fadd98b207"),
                ("X-Kovanica-Chain-Id", "2"),
            ],
            body,
        )
        .await;

        let args = RpcProbeArgs {
            url: base_url,
            expected_chain_id: Some(1),
            timeout_secs: 5,
        };
        let report = probe_endpoint(&args).await.unwrap();

        assert!(!report.ok);
        assert_eq!(report.status, "fail");
        assert_eq!(report.chain_id, Some(2));
        assert_eq!(report.expected_chain_id, Some(1));
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("chain_id mismatch: expected 1, endpoint reported 2")));
    }

    #[tokio::test]
    async fn legacy_non_array_response_marks_batch_unsupported_and_fails() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": -32600, "message": "batch requests not supported"}
        })
        .to_string();

        let base_url = spawn_mock_rpc_server(
            "200 OK",
            vec![
                ("X-Kovanica-Network-Tag", "2-24cdb5fadd98b207"),
                ("X-Kovanica-Chain-Id", "2"),
            ],
            body,
        )
        .await;

        let args = RpcProbeArgs {
            url: base_url,
            expected_chain_id: Some(2),
            timeout_secs: 5,
        };
        let report = probe_endpoint(&args).await.unwrap();

        assert!(!report.ok);
        assert_eq!(report.status, "fail");
        assert!(!report.batch_supported);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("batch unsupported")));
    }

    #[test]
    fn url_validation_and_credential_redaction() {
        // Basic credential & token redaction
        let validated = validate_and_redact_url(
            "https://alice:super-secret@rpc.kovanica.org:8443/?api_key=tok_123&mode=fast",
        )
        .unwrap();
        assert_eq!(
            validated.request_url,
            "https://alice:super-secret@rpc.kovanica.org:8443/rpc?api_key=tok_123&mode=fast"
        );
        assert!(!validated.redacted_url.contains("alice"));
        assert!(!validated.redacted_url.contains("super-secret"));
        assert!(!validated.redacted_url.contains("tok_123"));
        assert!(validated.redacted_url.contains("REDACTED:REDACTED@"));
        assert!(validated.redacted_url.contains("api_key=REDACTED"));
        assert!(validated.redacted_url.contains("mode=fast"));

        // Custom path is preserved without appending `/rpc`
        let custom = validate_and_redact_url("https://rpc.example.com/v1/node?token=abc").unwrap();
        assert!(custom
            .request_url
            .starts_with("https://rpc.example.com/v1/node"));
        assert!(!custom.redacted_url.contains("abc"));
        assert!(custom.redacted_url.contains("token=REDACTED"));

        // Invalid schemes and empty URLs are rejected
        assert!(validate_and_redact_url("").is_err());
        assert!(validate_and_redact_url("ftp://rpc.example.com").is_err());
        assert!(validate_and_redact_url("ws://127.0.0.1:8545").is_err());
        assert!(validate_and_redact_url("not-a-url").is_err());
    }
}
