//! Read-only transaction inspection subcommands (`kovanica tx receipt`).
//!
//! These commands never sign or submit transactions; they invoke the node's
//! read-only JSON-RPC endpoints (such as `kovanica_getTransactionReceipt`).

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{json, Value};

use crate::contract_inspect::parse_bytes32_hex;
use crate::output;
use crate::rpc::{parse_quantity, RpcClient};

/// Default timeout in seconds when `--wait` is passed to `kovanica tx receipt`.
pub const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 60;

/// Default polling interval in milliseconds when `--wait` is passed to `kovanica tx receipt`.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;

/// Read-only transaction inspection commands (`kovanica tx …`).
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum TxInspectCommand {
    /// Fetch a transaction receipt via `kovanica_getTransactionReceipt`
    Receipt(TxReceiptArgs),
}

/// Arguments for `kovanica tx receipt`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct TxReceiptArgs {
    /// Transaction hash (32-byte hex, with or without `0x` prefix)
    pub tx_hash: String,
    /// Poll until the transaction receipt becomes available or timeout elapses
    #[arg(long, default_value_t = false)]
    pub wait: bool,
    /// Maximum seconds to wait when `--wait` is set
    #[arg(long, default_value_t = DEFAULT_WAIT_TIMEOUT_SECS)]
    pub timeout_secs: u64,
    /// Polling interval in milliseconds when `--wait` is set
    #[arg(long, default_value_t = DEFAULT_POLL_INTERVAL_MS)]
    pub poll_interval_ms: u64,
}

/// Normalized summary of a transaction receipt returned by `kovanica_getTransactionReceipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptSummary {
    pub transaction_hash: String,
    pub status: String,
    pub success: bool,
    pub block_hash: Option<String>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
    pub gas_used: u64,
    pub log_count: usize,
}

/// Validate a transaction hash as a 32-byte hex string (with or without `0x` prefix)
/// and normalize it to lowercase `0x<64 hex chars>`.
pub fn normalize_tx_hash(input: &str) -> Result<String> {
    let bytes = parse_bytes32_hex(input, "transaction hash")?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Extract a normalized [`ReceiptSummary`] from a non-null JSON receipt object.
pub fn summarize_receipt(fallback_tx_hash: &str, receipt: &Value) -> Result<ReceiptSummary> {
    let obj = receipt
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("expected receipt JSON object, got {receipt}"))?;

    let transaction_hash = obj
        .get("transactionHash")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| fallback_tx_hash.to_string());

    let success = if let Some(b) = obj.get("success").and_then(Value::as_bool) {
        b
    } else if let Some(status_val) = obj.get("status") {
        if let Some(s) = status_val.as_str() {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "0x1" | "1" | "success"
            )
        } else if let Some(n) = status_val.as_u64() {
            n == 1
        } else {
            false
        }
    } else {
        false
    };

    let status = if success {
        "success".to_string()
    } else {
        "reverted".to_string()
    };

    let block_hash = obj
        .get("blockHash")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let block_number = match obj.get("blockNumber") {
        Some(v) if !v.is_null() => Some(parse_quantity(v)?),
        _ => None,
    };

    let transaction_index = match obj.get("transactionIndex") {
        Some(v) if !v.is_null() => Some(parse_quantity(v)?),
        _ => None,
    };

    let gas_used = match obj.get("gasUsed") {
        Some(v) if !v.is_null() => parse_quantity(v)?,
        _ => 0,
    };

    let log_count = obj
        .get("logs")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);

    Ok(ReceiptSummary {
        transaction_hash,
        status,
        success,
        block_hash,
        block_number,
        transaction_index,
        gas_used,
        log_count,
    })
}

/// Format a [`ReceiptSummary`] for `--json` output.
pub fn format_receipt_json(summary: &ReceiptSummary) -> Value {
    json!({
        "found": true,
        "transactionHash": summary.transaction_hash,
        "status": summary.status,
        "success": summary.success,
        "blockHash": summary.block_hash,
        "blockNumber": summary.block_number,
        "transactionIndex": summary.transaction_index,
        "gasUsed": summary.gas_used,
        "logCount": summary.log_count,
    })
}

/// Format a [`ReceiptSummary`] into key/value rows for human-readable output.
pub fn format_receipt_rows(summary: &ReceiptSummary) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("Transaction", summary.transaction_hash.clone()),
        ("Status", summary.status.clone()),
        (
            "Block Hash",
            summary
                .block_hash
                .clone()
                .unwrap_or_else(|| "(none)".to_string()),
        ),
    ];
    if let Some(block_number) = summary.block_number {
        rows.push(("Block Number", block_number.to_string()));
    }
    if let Some(tx_index) = summary.transaction_index {
        rows.push(("Tx Index", tx_index.to_string()));
    }
    rows.push(("Gas Used", summary.gas_used.to_string()));
    rows.push(("Logs", summary.log_count.to_string()));
    rows
}

/// Execute `kovanica tx <subcommand>`.
pub async fn run(client: &RpcClient, command: TxInspectCommand, json_output: bool) -> Result<()> {
    match command {
        TxInspectCommand::Receipt(args) => run_receipt(client, args, json_output).await,
    }
}

async fn fetch_receipt(client: &RpcClient, tx_hash: &str) -> Result<Option<Value>> {
    let result = client
        .call("kovanica_getTransactionReceipt", json!([tx_hash]))
        .await?;
    if result.is_null() {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}

/// Fetch a transaction receipt, optionally polling until available or timeout.
pub async fn resolve_receipt(
    client: &RpcClient,
    args: &TxReceiptArgs,
) -> Result<(String, Option<Value>)> {
    let tx_hash = normalize_tx_hash(&args.tx_hash)?;
    if args.wait && args.poll_interval_ms == 0 {
        bail!("--poll-interval-ms must be greater than 0");
    }

    if !args.wait {
        let receipt = fetch_receipt(client, &tx_hash).await?;
        return Ok((tx_hash, receipt));
    }

    let deadline = Instant::now() + Duration::from_secs(args.timeout_secs);
    let interval = Duration::from_millis(args.poll_interval_ms);
    loop {
        if let Some(receipt) = fetch_receipt(client, &tx_hash).await? {
            return Ok((tx_hash, Some(receipt)));
        }
        let now = Instant::now();
        if now >= deadline {
            bail!(
                "timed out after {}s waiting for receipt of {tx_hash}",
                args.timeout_secs
            );
        }
        let sleep_for = interval.min(deadline.saturating_duration_since(now));
        tokio::time::sleep(sleep_for).await;
    }
}

async fn run_receipt(client: &RpcClient, args: TxReceiptArgs, json_output: bool) -> Result<()> {
    let (tx_hash, maybe_receipt) = resolve_receipt(client, &args).await?;

    let Some(receipt) = maybe_receipt else {
        if json_output {
            return output::print_json(&json!({
                "found": false,
                "transactionHash": tx_hash,
                "status": "pending",
                "receipt": Value::Null,
            }));
        }
        output::print_kv(&[
            ("Transaction", tx_hash),
            ("Status", "not found (pending or unknown)".to_string()),
        ]);
        return Ok(());
    };

    let summary = summarize_receipt(&tx_hash, &receipt)?;
    if json_output {
        return output::print_json(&format_receipt_json(&summary));
    }
    output::print_kv(&format_receipt_rows(&summary));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_tx_hash_accepts_prefixed_and_unprefixed_32_bytes() {
        let raw = "AB".repeat(32);
        let expected = format!("0x{}", "ab".repeat(32));
        assert_eq!(normalize_tx_hash(&raw).unwrap(), expected);
        assert_eq!(normalize_tx_hash(&format!("0x{raw}")).unwrap(), expected);
        assert_eq!(normalize_tx_hash(&format!("0X{raw}")).unwrap(), expected);
        assert_eq!(
            normalize_tx_hash(&format!("  0x{raw}  ")).unwrap(),
            expected
        );
    }

    #[test]
    fn normalize_tx_hash_rejects_invalid_inputs() {
        assert!(normalize_tx_hash("").is_err());
        assert!(normalize_tx_hash("0x").is_err());
        assert!(normalize_tx_hash("0x1234").is_err());
        assert!(normalize_tx_hash(&"zz".repeat(32)).is_err());
        assert!(normalize_tx_hash(&"aa".repeat(31)).is_err());
        assert!(normalize_tx_hash(&"aa".repeat(33)).is_err());
    }

    #[test]
    fn summarize_receipt_formats_success_and_reverted_with_logs() {
        let tx_hash = format!("0x{}", "11".repeat(32));
        let block_hash = format!("0x{}", "22".repeat(32));

        let ok_receipt = json!({
            "transactionHash": tx_hash,
            "blockHash": block_hash,
            "blockNumber": "0x2a",
            "transactionIndex": "0x1",
            "status": "0x1",
            "success": true,
            "gasUsed": "0x5208",
            "logs": [
                {"topic": "0x01"},
                {"topic": "0x02"}
            ]
        });
        let summary = summarize_receipt(&tx_hash, &ok_receipt).unwrap();
        assert_eq!(summary.transaction_hash, tx_hash);
        assert_eq!(summary.status, "success");
        assert!(summary.success);
        assert_eq!(summary.block_hash.as_deref(), Some(block_hash.as_str()));
        assert_eq!(summary.block_number, Some(42));
        assert_eq!(summary.transaction_index, Some(1));
        assert_eq!(summary.gas_used, 21_000);
        assert_eq!(summary.log_count, 2);

        let json_out = format_receipt_json(&summary);
        assert_eq!(json_out["found"], true);
        assert_eq!(json_out["status"], "success");
        assert_eq!(json_out["blockHash"], block_hash);
        assert_eq!(json_out["gasUsed"], 21_000);
        assert_eq!(json_out["logCount"], 2);

        let rows = format_receipt_rows(&summary);
        assert!(rows.iter().any(|(k, v)| *k == "Status" && v == "success"));
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Block Hash" && v == &block_hash));
        assert!(rows.iter().any(|(k, v)| *k == "Gas Used" && v == "21000"));
        assert!(rows.iter().any(|(k, v)| *k == "Logs" && v == "2"));

        // Reverted receipt without explicit `logs` array or `success` bool (derived from `status: "0x0"`).
        let reverted_receipt = json!({
            "transactionHash": tx_hash,
            "blockHash": block_hash,
            "blockNumber": 100,
            "transactionIndex": null,
            "status": "0x0",
            "gasUsed": "0x186a0"
        });
        let reverted = summarize_receipt(&tx_hash, &reverted_receipt).unwrap();
        assert_eq!(reverted.status, "reverted");
        assert!(!reverted.success);
        assert_eq!(reverted.block_number, Some(100));
        assert_eq!(reverted.transaction_index, None);
        assert_eq!(reverted.gas_used, 100_000);
        assert_eq!(reverted.log_count, 0);
    }

    #[tokio::test]
    async fn resolve_receipt_polls_until_non_null_when_wait_is_enabled() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let tx_hash = format!("0x{}", "ab".repeat(32));
        let block_hash = format!("0x{}", "cd".repeat(32));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tx_hash_srv = tx_hash.clone();
        let block_hash_srv = block_hash.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await.unwrap();
                let body = if attempt == 0 {
                    r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string()
                } else {
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "transactionHash": tx_hash_srv,
                            "blockHash": block_hash_srv,
                            "blockNumber": "0x5",
                            "transactionIndex": "0x0",
                            "status": "0x1",
                            "success": true,
                            "gasUsed": "0x0"
                        }
                    })
                    .to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client = RpcClient::new(format!("http://{addr}"));
        let (normalized, receipt) = resolve_receipt(
            &client,
            &TxReceiptArgs {
                tx_hash: "ab".repeat(32),
                wait: true,
                timeout_secs: 5,
                poll_interval_ms: 20,
            },
        )
        .await
        .unwrap();

        assert_eq!(normalized, tx_hash);
        let summary = summarize_receipt(&normalized, &receipt.unwrap()).unwrap();
        assert_eq!(summary.status, "success");
        assert_eq!(summary.block_hash.as_deref(), Some(block_hash.as_str()));
        assert_eq!(summary.block_number, Some(5));

        server.await.unwrap();
    }
}
