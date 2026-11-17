//! Integration test for the Stratum V1 mining client (`kovanica miner run --stratum`).
//!
//! Spawns a mock Stratum V1 TCP pool server, connects the `StratumMiner` client,
//! completes the Stratum handshake (`mining.subscribe` and `mining.authorize`),
//! receives difficulty and job notifications, computes PoW shares, verifies share submission,
//! and ensures clean graceful shutdown.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use kovanica_cli::stratum_client::StratumMiner;
use kovanica_types::signing::chain_id::HYBRID_TESTNET;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Spawn a mock Stratum V1 TCP server for testing client handshakes and share reception.
async fn spawn_mock_stratum_pool(
    server_shutdown: Arc<AtomicBool>,
) -> (String, Arc<AtomicU64>, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");

    let auth_count = Arc::new(AtomicU64::new(0));
    let submit_count = Arc::new(AtomicU64::new(0));

    let auth_clone = auth_count.clone();
    let submit_clone = submit_count.clone();

    tokio::spawn(async move {
        while !server_shutdown.load(Ordering::Relaxed) {
            let accept_res = tokio::select! {
                res = listener.accept() => res,
                _ = tokio::time::sleep(Duration::from_millis(50)) => continue,
            };

            let Ok((socket, _)) = accept_res else {
                continue;
            };

            let auth = auth_clone.clone();
            let sub = submit_clone.clone();

            tokio::spawn(async move {
                let (read_half, mut write_half) = socket.into_split();
                let mut reader = BufReader::new(read_half);
                let mut line = String::new();

                while let Ok(n) = reader.read_line(&mut line).await {
                    if n == 0 {
                        break;
                    }

                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        line.clear();
                        continue;
                    }

                    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
                        line.clear();
                        continue;
                    };

                    let req_id = val.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    let method = val
                        .get("method")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();

                    match method {
                        "mining.subscribe" => {
                            let resp = json!({
                                "id": req_id,
                                "result": [
                                    [["mining.set_difficulty", "sub_diff"], ["mining.notify", "sub_notify"]],
                                    "01a4b8",
                                    4
                                ],
                                "error": null
                            });
                            let _ = write_half.write_all(format!("{resp}\n").as_bytes()).await;
                            let _ = write_half.flush().await;
                        }
                        "mining.authorize" => {
                            auth.fetch_add(1, Ordering::SeqCst);
                            let resp = json!({
                                "id": req_id,
                                "result": true,
                                "error": null
                            });
                            let _ = write_half.write_all(format!("{resp}\n").as_bytes()).await;
                            let _ = write_half.flush().await;

                            // Send set_difficulty (easy target for instant test share solving)
                            let set_diff = json!({
                                "id": Value::Null,
                                "method": "mining.set_difficulty",
                                "params": [0.001]
                            });
                            let _ = write_half
                                .write_all(format!("{set_diff}\n").as_bytes())
                                .await;
                            let _ = write_half.flush().await;

                            // Send notify job
                            let dummy_prev = hex::encode([0x33u8; 32]);
                            let notify = json!({
                                "id": Value::Null,
                                "method": "mining.notify",
                                "params": [
                                    "job_42",
                                    dummy_prev,
                                    "01000000",
                                    "00000000",
                                    [],
                                    "00000001",
                                    "207fffff",
                                    "64000000",
                                    true
                                ]
                            });
                            let _ = write_half.write_all(format!("{notify}\n").as_bytes()).await;
                            let _ = write_half.flush().await;
                        }
                        "mining.submit" => {
                            sub.fetch_add(1, Ordering::SeqCst);
                            let resp = json!({
                                "id": req_id,
                                "result": true,
                                "error": null
                            });
                            let _ = write_half.write_all(format!("{resp}\n").as_bytes()).await;
                            let _ = write_half.flush().await;
                        }
                        _ => {}
                    }

                    line.clear();
                }
            });
        }
    });

    (endpoint, auth_count, submit_count)
}

#[tokio::test]
async fn stratum_miner_completes_handshake_and_submits_shares() {
    let server_shutdown = Arc::new(AtomicBool::new(false));
    let (endpoint, auth_count, submit_count) =
        spawn_mock_stratum_pool(server_shutdown.clone()).await;

    // Use a canonical PRO-21 testnet address
    let test_address =
        "kvnc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqvkmj3dag".to_string();
    let worker_name = "test_rig1".to_string();

    let miner = Arc::new(StratumMiner::new(
        endpoint,
        test_address,
        worker_name,
        "x".to_string(),
        HYBRID_TESTNET,
        2, // 2 worker threads
    ));

    let miner_handle = {
        let miner_clone = miner.clone();
        tokio::spawn(async move {
            let _ = miner_clone.run().await;
        })
    };

    // Wait until at least 1 share has been submitted and accepted
    let start = std::time::Instant::now();
    let mut success = false;
    while start.elapsed() < Duration::from_secs(5) {
        if submit_count.load(Ordering::SeqCst) > 0 {
            success = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Stop miner and server
    miner.stop();
    server_shutdown.store(true, Ordering::SeqCst);
    let _ = tokio::time::timeout(Duration::from_secs(3), miner_handle).await;

    assert!(
        auth_count.load(Ordering::SeqCst) > 0,
        "worker should have been authorized"
    );
    assert!(
        success,
        "worker should have solved and submitted at least 1 share"
    );
    assert!(
        miner.stats().blocks_found() > 0,
        "stats should reflect found shares"
    );
    assert!(
        miner.stats().blocks_accepted() > 0,
        "stats should reflect accepted shares"
    );
}
