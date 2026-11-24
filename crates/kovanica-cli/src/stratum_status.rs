//! Operator Stratum gateway status (`kovanica stratum status <url>`).
//!
//! Fetches `GET <url>/workers`, parses `active_workers` / `worker_count`,
//! `summary` (`min_difficulty`, `median_difficulty`, `max_difficulty`,
//! `total_accepted_shares`, `total_rejected_shares`, `total_stale_shares`,
//! `stale_ratio`), and the per-worker session list (falling back to local
//! summary calculation if an older server omits `summary`). URL credentials
//! (`user:pass@`) and sensitive query parameters (`token`, `api_key`, etc.)
//! are always redacted from output and error messages.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::output;
use crate::rpc_probe::{redact_parsed_url, ValidatedProbeUrl};

/// Default HTTP timeout in milliseconds for `kovanica stratum status`.
pub const DEFAULT_STATUS_TIMEOUT_MS: u64 = 5_000;

/// Subcommands under `kovanica stratum`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum StratumCommand {
    /// Inspect Stratum gateway worker sessions and aggregate difficulty/share statistics
    Status(StratumStatusArgs),
}

/// Arguments for `kovanica stratum status <url>`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct StratumStatusArgs {
    /// Stratum observability base URL or `/workers` URL (`http://` or `https://`; `/workers` is appended automatically)
    pub url: String,
    /// HTTP request timeout in milliseconds
    #[arg(long, default_value_t = DEFAULT_STATUS_TIMEOUT_MS)]
    pub timeout_ms: u64,
}

/// Sanitized per-worker session summary matching `kovanica-stratum`'s `WorkerSessionSummary`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StratumWorkerSession {
    pub session_id: u64,
    pub worker_name: String,
    pub authorized: bool,
    #[serde(default)]
    pub extranonce_subscribed: bool,
    pub difficulty: f64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    #[serde(default)]
    pub shares_stale: u64,
    #[serde(default)]
    pub connected_secs: u64,
    #[serde(default)]
    pub idle_secs: u64,
}

/// Aggregate summary statistics matching `kovanica-stratum`'s `WorkersSummary`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StratumWorkersSummary {
    pub min_difficulty: Option<f64>,
    pub median_difficulty: Option<f64>,
    pub max_difficulty: Option<f64>,
    pub total_accepted_shares: u64,
    pub total_rejected_shares: u64,
    pub total_stale_shares: u64,
    pub stale_ratio: f64,
}

impl StratumWorkersSummary {
    /// Compute aggregate difficulty and share statistics from a slice of per-worker summaries.
    ///
    /// Used as a fallback when querying an older Stratum gateway that omits `summary`.
    pub fn from_workers(workers: &[StratumWorkerSession]) -> Self {
        let mut difficulties: Vec<f64> = workers
            .iter()
            .map(|w| w.difficulty)
            .filter(|d| d.is_finite())
            .collect();
        difficulties.sort_by(f64::total_cmp);

        let (min_difficulty, median_difficulty, max_difficulty) = if difficulties.is_empty() {
            (None, None, None)
        } else {
            let len = difficulties.len();
            let min = difficulties[0];
            let max = difficulties[len - 1];
            let median = if len % 2 == 1 {
                difficulties[len / 2]
            } else {
                (difficulties[len / 2 - 1] + difficulties[len / 2]) / 2.0
            };
            (Some(min), Some(median), Some(max))
        };

        let mut total_accepted_shares = 0u64;
        let mut total_rejected_shares = 0u64;
        let mut total_stale_shares = 0u64;
        for w in workers {
            total_accepted_shares = total_accepted_shares.saturating_add(w.shares_accepted);
            total_rejected_shares = total_rejected_shares.saturating_add(w.shares_rejected);
            total_stale_shares = total_stale_shares.saturating_add(w.shares_stale);
        }

        let total_shares = total_accepted_shares.saturating_add(total_rejected_shares);
        let stale_ratio = if total_shares == 0 {
            0.0
        } else {
            total_stale_shares as f64 / total_shares as f64
        };

        Self {
            min_difficulty,
            median_difficulty,
            max_difficulty,
            total_accepted_shares,
            total_rejected_shares,
            total_stale_shares,
            stale_ratio,
        }
    }
}

/// Structured report emitted by `kovanica stratum status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StratumStatusReport {
    pub url: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub latency_ms: u64,
    pub worker_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vardiff_enabled: Option<bool>,
    pub summary_computed_locally: bool,
    pub summary: StratumWorkersSummary,
    pub workers: Vec<StratumWorkerSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Validate a Stratum observability URL (`http://` or `https://`), normalize its path
/// to `/workers`, and produce a redacted representation safe for logs and CLI output.
pub fn validate_and_redact_workers_url(raw: &str) -> Result<ValidatedProbeUrl> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("Stratum status URL must not be empty");
    }

    let mut parsed = reqwest::Url::parse(trimmed)
        .with_context(|| "invalid Stratum status URL (expected http:// or https://)")?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => bail!("unsupported URL scheme `{other}` (expected http or https)"),
    }
    if parsed.host_str().is_none() {
        bail!("Stratum status URL must include a host");
    }

    let path = parsed.path().trim_end_matches('/');
    let normalized_path = if path.is_empty() {
        "/workers".to_string()
    } else if path.ends_with("/workers") {
        path.to_string()
    } else if let Some(prefix) = path
        .strip_suffix("/health")
        .or_else(|| path.strip_suffix("/metrics"))
    {
        format!("{prefix}/workers")
    } else {
        format!("{path}/workers")
    };
    parsed.set_path(&normalized_path);

    let request_url = parsed.to_string();
    let redacted_url = redact_parsed_url(&parsed);
    Ok(ValidatedProbeUrl {
        request_url,
        redacted_url,
    })
}

/// Evaluate a parsed `/workers` JSON payload and HTTP status into a [`StratumStatusReport`].
pub fn evaluate_workers_response(
    redacted_url: String,
    http_status: u16,
    latency_ms: u64,
    body: &Value,
) -> StratumStatusReport {
    let mut errors = Vec::new();
    if !(200..300).contains(&http_status) {
        errors.push(format!("unexpected HTTP status {http_status}"));
    }

    let Some(obj) = body.as_object() else {
        errors.push("expected JSON object from /workers endpoint".to_string());
        return StratumStatusReport {
            url: redacted_url,
            ok: false,
            http_status: Some(http_status),
            latency_ms,
            worker_count: 0,
            vardiff_enabled: None,
            summary_computed_locally: true,
            summary: StratumWorkersSummary::default(),
            workers: Vec::new(),
            timestamp: None,
            errors,
        };
    };

    let workers = match obj.get("workers") {
        Some(v) => match serde_json::from_value::<Vec<StratumWorkerSession>>(v.clone()) {
            Ok(list) => list,
            Err(err) => {
                errors.push(format!("invalid `workers` array: {err}"));
                Vec::new()
            }
        },
        None => {
            errors.push("response missing `workers` array".to_string());
            Vec::new()
        }
    };

    let worker_count = obj
        .get("worker_count")
        .or_else(|| obj.get("active_workers"))
        .and_then(Value::as_u64)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(workers.len());

    let vardiff_enabled = obj.get("vardiff_enabled").and_then(Value::as_bool);
    let timestamp = obj.get("timestamp").and_then(Value::as_u64);

    let (summary, summary_computed_locally) = match obj.get("summary") {
        Some(v) if !v.is_null() => match serde_json::from_value::<StratumWorkersSummary>(v.clone())
        {
            Ok(parsed) => (parsed, false),
            Err(err) => {
                errors.push(format!("invalid `summary` object: {err}"));
                (StratumWorkersSummary::from_workers(&workers), true)
            }
        },
        _ => (StratumWorkersSummary::from_workers(&workers), true),
    };

    let ok = errors.is_empty();
    StratumStatusReport {
        url: redacted_url,
        ok,
        http_status: Some(http_status),
        latency_ms,
        worker_count,
        vardiff_enabled,
        summary_computed_locally,
        summary,
        workers,
        timestamp,
        errors,
    }
}

fn format_opt_diff(val: Option<f64>) -> String {
    match val {
        Some(d) => format!("{d:.4}"),
        None => "-".to_string(),
    }
}

fn format_table_string(headers: &[&str], rows: &[Vec<String>]) -> String {
    let columns = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(columns) {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let render = |cells: &[String]| {
        let mut line = String::new();
        for (i, width) in widths.iter().enumerate() {
            let cell = cells.get(i).map(String::as_str).unwrap_or("");
            if i + 1 == columns {
                line.push_str(&format!("{cell:<width$}"));
            } else {
                line.push_str(&format!("{cell:<width$}  "));
            }
        }
        line.trim_end().to_string()
    };

    let mut out = String::new();
    let header: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    let _ = writeln!(out, "{}", render(&header));
    let separator: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    let _ = writeln!(out, "{}", render(&separator));
    for row in rows {
        let _ = writeln!(out, "{}", render(row));
    }
    out
}

/// Format a [`StratumStatusReport`] into a human-readable summary and worker table.
pub fn format_status_report(report: &StratumStatusReport) -> String {
    let mut rows = vec![
        ("Endpoint", report.url.clone()),
        ("Status", if report.ok { "OK" } else { "ERROR" }.to_string()),
        (
            "HTTP Status",
            report
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        ("Latency", format!("{} ms", report.latency_ms)),
        ("Workers", report.worker_count.to_string()),
        (
            "VarDiff",
            report
                .vardiff_enabled
                .map(|b| if b { "enabled" } else { "disabled" }.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Difficulty",
            format!(
                "min={} median={} max={}",
                format_opt_diff(report.summary.min_difficulty),
                format_opt_diff(report.summary.median_difficulty),
                format_opt_diff(report.summary.max_difficulty),
            ),
        ),
        (
            "Shares",
            format!(
                "accepted={} rejected={} stale={}",
                report.summary.total_accepted_shares,
                report.summary.total_rejected_shares,
                report.summary.total_stale_shares,
            ),
        ),
        (
            "Stale Ratio",
            format!("{:.2}%", report.summary.stale_ratio * 100.0),
        ),
    ];
    if report.summary_computed_locally {
        rows.push(("Summary Source", "computed locally (fallback)".to_string()));
    }
    if let Some(ts) = report.timestamp {
        rows.push(("Timestamp", ts.to_string()));
    }

    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in &rows {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }

    out.push('\n');
    if report.workers.is_empty() {
        out.push_str("No active workers.\n");
    } else {
        let headers = [
            "SESSION",
            "WORKER",
            "AUTH",
            "DIFF",
            "ACCEPTED",
            "REJECTED",
            "STALE",
            "CONNECTED",
            "IDLE",
        ];
        let table_rows: Vec<Vec<String>> = report
            .workers
            .iter()
            .map(|w| {
                vec![
                    w.session_id.to_string(),
                    w.worker_name.clone(),
                    if w.authorized { "yes" } else { "no" }.to_string(),
                    format!("{:.4}", w.difficulty),
                    w.shares_accepted.to_string(),
                    w.shares_rejected.to_string(),
                    w.shares_stale.to_string(),
                    format!("{}s", w.connected_secs),
                    format!("{}s", w.idle_secs),
                ]
            })
            .collect();
        out.push_str(&format_table_string(&headers, &table_rows));
    }

    if !report.errors.is_empty() {
        out.push('\n');
        for err in &report.errors {
            let _ = writeln!(out, "ERROR: {err}");
        }
    }

    out
}

/// Fetch `GET <url>/workers` and evaluate the response.
pub async fn fetch_status(args: &StratumStatusArgs) -> Result<StratumStatusReport> {
    if args.timeout_ms == 0 {
        bail!("--timeout-ms must be greater than 0");
    }

    let target = validate_and_redact_workers_url(&args.url)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout_ms))
        .build()
        .context("failed to build HTTP client")?;

    let t0 = Instant::now();
    let resp = match http.get(&target.request_url).send().await {
        Ok(r) => r,
        Err(err) => {
            let latency_ms = t0.elapsed().as_millis() as u64;
            return Ok(StratumStatusReport {
                url: target.redacted_url.clone(),
                ok: false,
                http_status: None,
                latency_ms,
                worker_count: 0,
                vardiff_enabled: None,
                summary_computed_locally: true,
                summary: StratumWorkersSummary::default(),
                workers: Vec::new(),
                timestamp: None,
                errors: vec![format!(
                    "network request to `{}` failed: {}",
                    target.redacted_url,
                    err.without_url()
                )],
            });
        }
    };

    let http_status = resp.status().as_u16();
    let body_res = resp.json::<Value>().await;
    let latency_ms = t0.elapsed().as_millis() as u64;

    match body_res {
        Ok(body) => Ok(evaluate_workers_response(
            target.redacted_url,
            http_status,
            latency_ms,
            &body,
        )),
        Err(err) => Ok(StratumStatusReport {
            url: target.redacted_url.clone(),
            ok: false,
            http_status: Some(http_status),
            latency_ms,
            worker_count: 0,
            vardiff_enabled: None,
            summary_computed_locally: true,
            summary: StratumWorkersSummary::default(),
            workers: Vec::new(),
            timestamp: None,
            errors: vec![format!(
                "invalid JSON response from `{}` (HTTP {http_status}): {}",
                target.redacted_url,
                err.without_url()
            )],
        }),
    }
}

/// CLI entry point for `kovanica stratum status`.
pub async fn run(args: StratumStatusArgs, json_output: bool) -> Result<()> {
    let report = fetch_status(&args).await?;

    if json_output {
        output::print_json(&serde_json::to_value(&report)?)?;
    } else {
        print!("{}", format_status_report(&report));
    }

    if !report.ok {
        return Err(anyhow!(
            "Stratum status check failed for {}: {}",
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
    fn workers_url_normalization_and_credential_redaction() {
        let base = validate_and_redact_workers_url("http://127.0.0.1:9100").unwrap();
        assert_eq!(base.request_url, "http://127.0.0.1:9100/workers");
        assert_eq!(base.redacted_url, "http://127.0.0.1:9100/workers");

        let from_health = validate_and_redact_workers_url("http://127.0.0.1:9100/health").unwrap();
        assert_eq!(from_health.request_url, "http://127.0.0.1:9100/workers");

        let from_metrics =
            validate_and_redact_workers_url("http://127.0.0.1:9100/metrics").unwrap();
        assert_eq!(from_metrics.request_url, "http://127.0.0.1:9100/workers");

        let already_workers =
            validate_and_redact_workers_url("https://pool.example.com/stratum/workers").unwrap();
        assert_eq!(
            already_workers.request_url,
            "https://pool.example.com/stratum/workers"
        );

        let creds = validate_and_redact_workers_url(
            "https://miner:pw123@stratum.kovanica.org:9100/health?api-key=secret_k&token=tok_9&view=full",
        )
        .unwrap();
        assert_eq!(
            creds.request_url,
            "https://miner:pw123@stratum.kovanica.org:9100/workers?api-key=secret_k&token=tok_9&view=full"
        );
        assert!(!creds.redacted_url.contains("miner"));
        assert!(!creds.redacted_url.contains("pw123"));
        assert!(!creds.redacted_url.contains("secret_k"));
        assert!(!creds.redacted_url.contains("tok_9"));
        assert!(creds.redacted_url.contains("REDACTED:REDACTED@"));
        assert!(creds.redacted_url.contains("api-key=REDACTED"));
        assert!(creds.redacted_url.contains("token=REDACTED"));
        assert!(creds.redacted_url.contains("view=full"));

        // Reject invalid schemes and empty URLs without echoing secrets
        let bad_err = validate_and_redact_workers_url("ws://user:pw@127.0.0.1:9100")
            .unwrap_err()
            .to_string();
        assert!(!bad_err.contains("pw"));
        assert!(validate_and_redact_workers_url("").is_err());
        assert!(validate_and_redact_workers_url("not-a-url").is_err());
    }

    #[test]
    fn evaluate_full_workers_response_and_format_table() {
        let body = json!({
            "active_workers": 2,
            "vardiff_enabled": true,
            "summary": {
                "min_difficulty": 1.0,
                "median_difficulty": 2.5,
                "max_difficulty": 4.0,
                "total_accepted_shares": 95,
                "total_rejected_shares": 5,
                "total_stale_shares": 2,
                "stale_ratio": 0.02
            },
            "workers": [
                {
                    "session_id": 1,
                    "worker_name": "rig_01",
                    "authorized": true,
                    "extranonce_subscribed": true,
                    "difficulty": 1.0,
                    "shares_accepted": 45,
                    "shares_rejected": 2,
                    "shares_stale": 1,
                    "connected_secs": 3600,
                    "idle_secs": 4
                },
                {
                    "session_id": 2,
                    "worker_name": "rig_02",
                    "authorized": true,
                    "extranonce_subscribed": false,
                    "difficulty": 4.0,
                    "shares_accepted": 50,
                    "shares_rejected": 3,
                    "shares_stale": 1,
                    "connected_secs": 1800,
                    "idle_secs": 12
                }
            ],
            "timestamp": 1730000000
        });

        let report =
            evaluate_workers_response("http://127.0.0.1:9100/workers".to_string(), 200, 9, &body);

        assert!(report.ok);
        assert_eq!(report.worker_count, 2);
        assert_eq!(report.vardiff_enabled, Some(true));
        assert!(!report.summary_computed_locally);
        assert_eq!(report.summary.min_difficulty, Some(1.0));
        assert_eq!(report.summary.median_difficulty, Some(2.5));
        assert_eq!(report.summary.max_difficulty, Some(4.0));
        assert_eq!(report.summary.total_accepted_shares, 95);
        assert_eq!(report.summary.total_rejected_shares, 5);
        assert_eq!(report.summary.total_stale_shares, 2);
        assert!((report.summary.stale_ratio - 0.02).abs() < 1e-9);
        assert_eq!(report.workers.len(), 2);
        assert_eq!(report.timestamp, Some(1730000000));

        let rendered = format_status_report(&report);
        assert!(rendered.contains("Workers"));
        assert!(rendered.contains("enabled"));
        assert!(rendered.contains("min=1.0000 median=2.5000 max=4.0000"));
        assert!(rendered.contains("accepted=95 rejected=5 stale=2"));
        assert!(rendered.contains("2.00%"));
        assert!(rendered.contains("SESSION"));
        assert!(rendered.contains("rig_01"));
        assert!(rendered.contains("rig_02"));
    }

    #[test]
    fn fallback_summary_computed_when_server_omits_summary() {
        let body = json!({
            "active_workers": 3,
            "vardiff_enabled": false,
            "workers": [
                {
                    "session_id": 1,
                    "worker_name": "a",
                    "authorized": true,
                    "difficulty": 8.0,
                    "shares_accepted": 10,
                    "shares_rejected": 2,
                    "shares_stale": 1
                },
                {
                    "session_id": 2,
                    "worker_name": "b",
                    "authorized": true,
                    "difficulty": 2.0,
                    "shares_accepted": 20,
                    "shares_rejected": 3,
                    "shares_stale": 2
                },
                {
                    "session_id": 3,
                    "worker_name": "c",
                    "authorized": false,
                    "difficulty": 4.0,
                    "shares_accepted": 15,
                    "shares_rejected": 0,
                    "shares_stale": 0
                }
            ]
        });

        let report =
            evaluate_workers_response("http://127.0.0.1:9100/workers".to_string(), 200, 6, &body);

        assert!(report.ok);
        assert!(report.summary_computed_locally);
        assert_eq!(report.worker_count, 3);
        assert_eq!(report.summary.min_difficulty, Some(2.0));
        assert_eq!(report.summary.median_difficulty, Some(4.0));
        assert_eq!(report.summary.max_difficulty, Some(8.0));
        assert_eq!(report.summary.total_accepted_shares, 45);
        assert_eq!(report.summary.total_rejected_shares, 5);
        assert_eq!(report.summary.total_stale_shares, 3);
        assert!((report.summary.stale_ratio - 0.06).abs() < 1e-9);

        let rendered = format_status_report(&report);
        assert!(rendered.contains("computed locally (fallback)"));
    }

    #[test]
    fn empty_workers_and_non_200_responses() {
        let empty = evaluate_workers_response(
            "http://127.0.0.1:9100/workers".to_string(),
            200,
            3,
            &json!({"active_workers": 0, "workers": []}),
        );
        assert!(empty.ok);
        assert_eq!(empty.worker_count, 0);
        assert_eq!(empty.summary.min_difficulty, None);
        assert_eq!(empty.summary.stale_ratio, 0.0);
        assert!(format_status_report(&empty).contains("No active workers."));

        let err_resp = evaluate_workers_response(
            "http://REDACTED@127.0.0.1:9100/workers".to_string(),
            503,
            5,
            &json!({"active_workers": 0, "workers": []}),
        );
        assert!(!err_resp.ok);
        assert!(err_resp
            .errors
            .iter()
            .any(|e| e.contains("unexpected HTTP status 503")));
    }

    #[tokio::test]
    async fn zero_timeout_ms_is_rejected() {
        let err = fetch_status(&StratumStatusArgs {
            url: "http://127.0.0.1:9100".to_string(),
            timeout_ms: 0,
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--timeout-ms"));
    }
}
