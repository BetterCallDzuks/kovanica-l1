//! End-to-end integration tests for `kovanica-stratum`.
//!
//! Simulates real TCP client handshakes against the `StratumGateway`:
//! - `mining.subscribe` -> Extranonce1 and extranonce2_size allocation.
//! - `mining.authorize` -> PRO-21 address validation and difficulty notification.
//! - `mining.notify` -> Job broadcasting to active subscribed miners.
//! - `mining.submit` -> Share validation, duplicate detection, and low difficulty rejection.
//! - Error cases: unauthorized submissions, malformed JSON, and unknown jobs.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use kovanica_crypto::{generate_keypair, KovanicaHasher};

// Global logging setup
static INIT_LOG: Once = Once::new();

fn init_test_logging() {
    INIT_LOG.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });
}

use kovanica_stratum::config::StratumConfig;
use kovanica_stratum::gateway::StratumGateway;
use kovanica_stratum::{KOVANICA_STRATUM_ALGORITHM, KOVANICA_STRATUM_CAPABILITY};
use kovanica_types::block::{check_pow_hash_meets_target, BlockHeader};
use kovanica_types::signing::chain_id::HYBRID_TESTNET;
use kovanica_types::{Address, Hash};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Helper to start a test gateway on an ephemeral local port.
async fn start_test_gateway(initial_difficulty: f64) -> (Arc<StratumGateway>, SocketAddr) {
    init_test_logging();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("must bind ephemeral listener");
    let local_addr = listener.local_addr().expect("must get local addr");

    let config = StratumConfig {
        listen_addr: local_addr,
        difficulty: initial_difficulty,
        chain_id: HYBRID_TESTNET,
        // Point the poller at a closed port so tests never depend on a live node or receive an
        // unsolicited `mining.notify` before the test injects its own job.
        rpc_url: "http://127.0.0.1:1/rpc".to_string(),
        // Set a very long poll interval so the test doesn't log unneeded upstream errors
        poll_interval: Duration::from_secs(3600),
        ..Default::default()
    };

    let gateway = Arc::new(StratumGateway::new(config).expect("gateway creation failed"));
    let gw_clone = Arc::clone(&gateway);

    let handle = tokio::spawn(async move {
        let result = gw_clone.run_with_listener(listener).await;
        eprintln!("Gateway run_with_listener completed with: {:?}", result);
    });

    // Wait a bit more for the gateway to fully start
    tokio::time::sleep(Duration::from_millis(500)).await;

    let handle_finished = handle.is_finished();
    if handle_finished {
        eprintln!("WARNING: Gateway task finished early!");
    } else {
        eprintln!("Gateway task is running");
    }

    // Brief yield to ensure server loop is ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Check if gateway task is still running
    if handle.is_finished() {
        eprintln!("WARNING: Gateway task finished early!");
    } else {
        eprintln!("Gateway task is running");
    }

    (gateway, local_addr)
}

/// Helper client connection with buffered I/O.
struct TestClient {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl TestClient {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr)
            .await
            .expect("client must connect to stratum gateway");
        let (read_half, write_half) = stream.into_split();
        Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        }
    }

    async fn send_line(&mut self, line: &str) {
        self.writer
            .write_all(format!("{}\n", line.trim()).as_bytes())
            .await
            .expect("must write to server");
        self.writer.flush().await.expect("must flush to server");
    }

    async fn read_json(&mut self) -> Value {
        let mut line = String::new();
        timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
            .await
            .expect("timed out reading from server")
            .expect("I/O error reading line");
        serde_json::from_str(&line).expect("must parse valid JSON response")
    }
}

/// Create a dummy candidate block header for job testing.
fn create_test_header(round: u64, target_bits: u32) -> BlockHeader {
    let (_sk, pk) = generate_keypair();
    let payout = Address(pk.0);

    BlockHeader::new(
        HYBRID_TESTNET,
        round,
        0,
        vec![],
        Hash([0x42; 32]),
        1731800000000,
        target_bits,
        0,
    )
    .with_payout(payout)
}

/// Find a nonce that satisfies the template's real network target, so the gateway will forward
/// the solved header upstream instead of only accepting it as a share.
fn find_network_solution(header: &BlockHeader, extranonce2: u32) -> u64 {
    let mut candidate = header.clone();
    let mut hasher = KovanicaHasher::new();
    for nonce in 0..100_000u64 {
        let full_nonce = ((extranonce2 as u64) << 32) | nonce;
        candidate.nonce = full_nonce;
        let pow_hash = hasher.hash(&candidate.preimage());
        if check_pow_hash_meets_target(&pow_hash, candidate.target_bits) {
            return full_nonce;
        }
    }
    panic!("no network solution found in nonce range");
}

#[tokio::test]
async fn test_full_stratum_handshake_and_share_submission() {
    // Start gateway with 0.0 difficulty so any nonce succeeds for fast deterministic testing
    let (gateway, addr) = start_test_gateway(0.0).await;
    let mut client = TestClient::connect(addr).await;

    // 1. mining.subscribe
    let subscribe_req = json!({
        "id": 1,
        "method": "mining.subscribe",
        "params": ["TestMiner/1.0"]
    });
    client.send_line(&subscribe_req.to_string()).await;

    let sub_resp = client.read_json().await;
    assert_eq!(sub_resp["id"], 1);
    assert!(sub_resp["error"].is_null());

    let result = sub_resp["result"].as_array().expect("result array");
    assert_eq!(result.len(), 4);
    let extranonce1 = result[1].as_str().expect("extranonce1 hex");
    let en2_size = result[2].as_u64().expect("extranonce2 size");
    assert!(!extranonce1.is_empty());
    assert_eq!(en2_size, 4);
    assert_eq!(result[3]["algorithm"], KOVANICA_STRATUM_ALGORITHM);
    assert_eq!(result[3]["profile"], KOVANICA_STRATUM_CAPABILITY);
    assert_eq!(result[3]["version"], 1);

    // 2. mining.authorize with invalid address syntax (should fail)
    let invalid_auth_req = json!({
        "id": 2,
        "method": "mining.authorize",
        "params": ["invalid_address_format.worker1", "x"]
    });
    client.send_line(&invalid_auth_req.to_string()).await;

    let invalid_auth_resp = client.read_json().await;
    assert_eq!(invalid_auth_resp["id"], 2);
    assert!(!invalid_auth_resp["error"].is_null());
    assert_eq!(invalid_auth_resp["error"][0], 24);

    // 3. mining.authorize with canonical PRO-21 address
    let (_sk, pk) = generate_keypair();
    let valid_addr = Address(pk.0);
    let valid_addr_str = valid_addr.encode();
    let username = format!("{}.rig_01", valid_addr_str);

    let auth_req = json!({
        "id": 3,
        "method": "mining.authorize",
        "params": [username, "x"]
    });
    client.send_line(&auth_req.to_string()).await;

    // Expect auth response (result: true)
    let auth_resp = client.read_json().await;
    assert_eq!(auth_resp["id"], 3);
    assert_eq!(auth_resp["result"], true);
    assert!(auth_resp["error"].is_null());

    // Expect mining.set_difficulty notification
    let set_diff_msg = client.read_json().await;
    assert_eq!(set_diff_msg["method"], "mining.set_difficulty");
    let diff_val = set_diff_msg["params"][0].as_f64().expect("difficulty f64");
    assert!((diff_val - 0.0).abs() < 1e-6);

    // 4. Inject candidate block template and broadcast
    let test_header = create_test_header(100, 0x207fffff);
    let job = gateway.job_manager().add_template(test_header);
    gateway.broadcast_notify(&job);

    // Client should receive mining.notify
    let notify_msg = client.read_json().await;
    assert_eq!(notify_msg["method"], "mining.notify");
    let notify_params = notify_msg["params"].as_array().expect("notify params");
    assert_eq!(notify_params.len(), 9);
    let broadcast_job_id = notify_params[0].as_str().expect("job_id");
    assert_eq!(broadcast_job_id, job.job_id);

    // 5. Submit valid share
    let extranonce2 = "00000001";
    let nonce = "00000042";
    let submit_req = json!({
        "id": 4,
        "method": "mining.submit",
        "params": [username, broadcast_job_id, extranonce2, nonce]
    });
    client.send_line(&submit_req.to_string()).await;

    let submit_resp = client.read_json().await;
    assert_eq!(submit_resp["id"], 4);
    assert_eq!(submit_resp["result"], true);
    assert!(submit_resp["error"].is_null());

    // 6. Submit duplicate share (should be rejected with code 22)
    let dup_submit_req = json!({
        "id": 5,
        "method": "mining.submit",
        "params": [username, broadcast_job_id, extranonce2, nonce]
    });
    client.send_line(&dup_submit_req.to_string()).await;

    let dup_resp = client.read_json().await;
    assert_eq!(dup_resp["id"], 5);
    assert!(!dup_resp["error"].is_null());
    assert_eq!(dup_resp["error"][0], 22); // Duplicate share

    // 7. Submit to unknown job (should be rejected with code 21)
    let unknown_job_req = json!({
        "id": 6,
        "method": "mining.submit",
        "params": [username, "job_deadbeef", extranonce2, "00000099"]
    });
    client.send_line(&unknown_job_req.to_string()).await;

    let unknown_resp = client.read_json().await;
    assert_eq!(unknown_resp["id"], 6);
    assert!(!unknown_resp["error"].is_null());
    assert_eq!(unknown_resp["error"][0], 21); // Job not found

    gateway.shutdown();
}

#[tokio::test]
async fn test_stratum_unauthorized_submit_rejected() {
    let (gateway, addr) = start_test_gateway(1.0).await;
    let mut client = TestClient::connect(addr).await;

    // Attempt to submit without authorization
    let submit_req = json!({
        "id": 1,
        "method": "mining.submit",
        "params": ["worker", "job_1", "00000001", "00000001"]
    });
    client.send_line(&submit_req.to_string()).await;

    let resp = client.read_json().await;
    assert_eq!(resp["id"], 1);
    assert!(!resp["error"].is_null());
    assert_eq!(resp["error"][0], 24); // Unauthorized

    gateway.shutdown();
}

#[tokio::test]
async fn test_stratum_low_difficulty_share_rejected() {
    // Start gateway with astronomical difficulty so shares are rejected
    let (gateway, addr) = start_test_gateway(1_000_000_000.0).await;
    let mut client = TestClient::connect(addr).await;

    // Subscribe
    client
        .send_line(&json!({"id": 1, "method": "mining.subscribe", "params": []}).to_string())
        .await;
    let _ = client.read_json().await;

    // Authorize
    let (_sk, pk) = generate_keypair();
    let addr_str = Address(pk.0).encode();
    client
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [addr_str, "x"]}).to_string(),
        )
        .await;
    let _ = client.read_json().await; // auth result
    let _ = client.read_json().await; // set_difficulty

    // Inject job
    let test_header = create_test_header(1, 0x1d00ffff);
    let job = gateway.job_manager().add_template(test_header);

    // Submit arbitrary share -> target at 1B difficulty requires ~30 leading zero bits
    let submit_req = json!({
        "id": 3,
        "method": "mining.submit",
        "params": [addr_str, job.job_id, "00000001", "00000001"]
    });
    client.send_line(&submit_req.to_string()).await;

    let submit_resp = client.read_json().await;
    assert_eq!(submit_resp["id"], 3);
    assert!(!submit_resp["error"].is_null());
    assert_eq!(submit_resp["error"][0], 23); // Low difficulty share

    gateway.shutdown();
}

#[tokio::test]
async fn test_multiple_subscribers_unique_extranonce1() {
    let (gateway, addr) = start_test_gateway(1.0).await;

    let mut client1 = TestClient::connect(addr).await;
    let mut client2 = TestClient::connect(addr).await;

    client1
        .send_line(&json!({"id": 1, "method": "mining.subscribe", "params": []}).to_string())
        .await;
    let resp1 = client1.read_json().await;
    let en1_1 = resp1["result"][1]
        .as_str()
        .expect("extranonce1 for client 1");

    client2
        .send_line(&json!({"id": 1, "method": "mining.subscribe", "params": []}).to_string())
        .await;
    let resp2 = client2.read_json().await;
    let en1_2 = resp2["result"][1]
        .as_str()
        .expect("extranonce1 for client 2");

    assert_ne!(
        en1_1, en1_2,
        "each subscriber must receive unique extranonce1"
    );

    gateway.shutdown();
}

/// Minimal JSON-RPC node stub that serves one work template and records submitted headers.
async fn spawn_mock_node(header: BlockHeader) -> (String, Arc<Mutex<Vec<BlockHeader>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock node must bind ephemeral listener");
    let addr = listener.local_addr().expect("mock node local addr");
    let submitted = Arc::new(Mutex::new(Vec::new()));
    let submitted_srv = Arc::clone(&submitted);

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let header = header.clone();
            let submitted = Arc::clone(&submitted_srv);

            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end = loop {
                    let Ok(n) = socket.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };

                let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_len = header_text
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        if key.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + content_len {
                    let Ok(n) = socket.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                let req: Value =
                    match serde_json::from_slice(&buf[header_end..header_end + content_len]) {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                let method = req["method"].as_str().unwrap_or("");

                let result = match method {
                    "kovanica_getWork" => {
                        let mut work =
                            serde_json::to_value(&header).expect("header must serialize");
                        let obj = work
                            .as_object_mut()
                            .expect("header must serialize to object");
                        obj.insert("chain_id".into(), json!(HYBRID_TESTNET));
                        obj.insert("round".into(), json!(header.round));
                        obj.insert("author".into(), json!(header.author));
                        obj.insert("parents".into(), json!([]));
                        obj.insert("parent_refs".into(), json!([]));
                        obj.insert(
                            "merkle_root".into(),
                            json!(hex::encode(header.merkle_root.0)),
                        );
                        obj.insert("timestamp".into(), json!(header.timestamp));
                        obj.insert(
                            "target_bits".into(),
                            json!(format!("0x{:08x}", header.target_bits)),
                        );
                        obj.insert(
                            "payout_address".into(),
                            json!(header.payout.expect("test header has payout").encode()),
                        );
                        obj.insert("header".into(), serde_json::to_value(&header).unwrap());
                        work
                    }
                    "kovanica_submitWork" => {
                        if let Ok(solved) =
                            serde_json::from_value::<BlockHeader>(req["params"]["header"].clone())
                        {
                            submitted
                                .lock()
                                .expect("lock submitted headers")
                                .push(solved);
                        }
                        json!({ "accepted": true })
                    }
                    _ => Value::Null,
                };

                let resp = json!({ "jsonrpc": "2.0", "id": 1, "result": result });
                let body = serde_json::to_vec(&resp).expect("response must serialize");
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
        }
    });

    (format!("http://{addr}/rpc"), submitted)
}

#[tokio::test]
async fn test_gateway_and_builtin_client_hash_and_submit_same_template() {
    let (_sk, pk) = generate_keypair();
    let worker_payout = Address(pk.0);
    let header = create_test_header(4242, 0x207fffff).with_payout(worker_payout);
    let (rpc_url, submitted) = spawn_mock_node(header.clone()).await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("must bind ephemeral listener");
    let addr = listener.local_addr().expect("must get local addr");
    let config = StratumConfig {
        listen_addr: addr,
        rpc_url,
        difficulty: 0.0,
        poll_interval: Duration::from_millis(20),
        ..Default::default()
    };
    let gateway = Arc::new(StratumGateway::new(config).expect("gateway creation failed"));
    let gw_clone = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = gw_clone.run_with_listener(listener).await;
    });

    let mut client = TestClient::connect(addr).await;
    client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["kovanica-miner/test"]})
                .to_string(),
        )
        .await;
    let sub_resp = client.read_json().await;
    let sub_result = sub_resp["result"].as_array().expect("subscribe result");
    assert_eq!(sub_result[3]["profile"], KOVANICA_STRATUM_CAPABILITY);

    let username = format!("{}.rig_01", worker_payout.encode());
    client
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [username.clone(), "x"]})
                .to_string(),
        )
        .await;
    let _ = client.read_json().await; // auth result
    let _ = client.read_json().await; // set_difficulty

    // Wait for the poller to deliver a job from the mock node.
    let notify = loop {
        let mut line = String::new();
        timeout(Duration::from_secs(5), client.reader.read_line(&mut line))
            .await
            .expect("timed out waiting for mining.notify")
            .expect("notify I/O");
        let value: Value = serde_json::from_str(&line).expect("notify must be JSON");
        if value["method"].as_str() == Some("mining.notify") {
            break value;
        }
    };

    let params = notify["params"].as_array().expect("notify params");
    let job_id = params[0].as_str().expect("job id");
    let coinb1 = params[2].as_str().expect("coinb1 preimage prefix");
    let ntime = params[7].as_str().expect("ntime");
    let prefix = hex::decode(coinb1).expect("coinb1 must be hex");
    assert!(
        prefix.len() > 32,
        "coinb1 must carry the Kovanica preimage prefix"
    );

    // This mirrors the fixed built-in client: append an 8-byte nonce slot and submit the
    // (extranonce2 << 32) | nonce value that the gateway will write back into the header.
    let extranonce2 = "00000001";
    let full_nonce = find_network_solution(&header, 1);
    client
        .send_line(
            &json!({
                "id": 3,
                "method": "mining.submit",
                "params": [username, job_id, extranonce2, ntime, format!("{full_nonce:016x}")]
            })
            .to_string(),
        )
        .await;
    let submit_resp = client.read_json().await;
    assert_eq!(submit_resp["result"], true, "share must be accepted");

    // Duplicate share and stale/unknown job must be rejected with the documented codes.
    let duplicate_params = json!([
        username,
        job_id,
        extranonce2,
        ntime,
        format!("{full_nonce:016x}")
    ]);
    client
        .send_line(
            &json!({"id": 4, "method": "mining.submit", "params": duplicate_params}).to_string(),
        )
        .await;
    let duplicate_resp = client.read_json().await;
    assert_eq!(
        duplicate_resp["error"][0], 22,
        "duplicate share must be rejected"
    );

    let stale_params = json!([
        username,
        "job_stale",
        extranonce2,
        ntime,
        format!("{full_nonce:016x}")
    ]);
    client
        .send_line(&json!({"id": 5, "method": "mining.submit", "params": stale_params}).to_string())
        .await;
    let stale_resp = client.read_json().await;
    assert_eq!(stale_resp["error"][0], 21, "unknown job must be rejected");

    // The upstream node must receive the reconstructed header with the worker payout and the
    // same full nonce the miner hashed.
    let recorded = timeout(Duration::from_secs(5), async {
        loop {
            let found = submitted
                .lock()
                .expect("lock submitted headers")
                .first()
                .cloned();
            if let Some(header) = found {
                return header;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("upstream submitWork must be called");
    assert_eq!(recorded.nonce, full_nonce);
    assert_eq!(recorded.payout, Some(worker_payout));
    assert_eq!(recorded.target_bits, header.target_bits);

    // The simulator must have produced a real KovanicaHash solution over the reconstructed
    // preimage, not a SHA-256 or otherwise fabricated share.
    let mut hasher = KovanicaHasher::new();
    let pow_hash = hasher.hash(&recorded.preimage());
    assert_eq!(recorded.pow_hash, Some(pow_hash));
    assert!(
        check_pow_hash_meets_target(&pow_hash, recorded.target_bits),
        "submitted header must satisfy the real network target"
    );

    gateway.shutdown();
}

#[tokio::test]
async fn test_observability_metrics_and_health_endpoints() {
    let (gateway, stratum_addr) = start_test_gateway(0.0).await;

    // Seed a job so we can submit a valid share and a stale share
    let job = gateway
        .job_manager()
        .add_template(create_test_header(50, 0x207f_ffff));

    // Start observability HTTP server on ephemeral port
    let obs_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observability listener");
    let obs_addr = obs_listener.local_addr().expect("observability local addr");
    let obs_gateway = gateway.clone();
    tokio::spawn(async move {
        let _ = obs_gateway.serve_observability(obs_listener).await;
    });

    let http = reqwest::Client::new();

    // 1. Check /health before connecting
    let health_resp = http
        .get(format!("http://{obs_addr}/health"))
        .send()
        .await
        .expect("GET /health");
    assert_eq!(health_resp.status(), 200);
    let health_json: Value = health_resp.json().await.expect("parse health JSON");
    assert_eq!(health_json["status"], "healthy");
    assert_eq!(health_json["active_connections"], 0);
    assert_eq!(health_json["current_job_id"], job.job_id);

    // 2. Connect a miner, subscribe, authorize, submit 1 valid share + 1 stale share
    let mut client = TestClient::connect(stratum_addr).await;
    client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["obs-miner/1.0"]})
                .to_string(),
        )
        .await;
    let _ = client.read_json().await;

    let worker_addr = Address([0x33; 32]);
    let username = format!("{worker_addr}.obsrig");
    client
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [username, "x"]}).to_string(),
        )
        .await;
    let _ = client.read_json().await; // authorize ok
    let _ = client.read_json().await; // set_difficulty
    let _ = client.read_json().await; // notify

    // Valid share (difficulty 0.0 accepts any hash)
    client
        .send_line(
            &json!({"id": 3, "method": "mining.submit", "params": [username, job.job_id, "00000001", "00000001"]})
                .to_string(),
        )
        .await;
    let accept_resp = client.read_json().await;
    assert_eq!(accept_resp["result"], true);

    // Stale share (unknown job)
    client
        .send_line(
            &json!({"id": 4, "method": "mining.submit", "params": [username, "nonexistent_job", "00000001", "00000002"]})
                .to_string(),
        )
        .await;
    let stale_resp = client.read_json().await;
    assert_eq!(stale_resp["error"][0], 21);

    // 3. Scrape /metrics while connected
    let metrics_resp = http
        .get(format!("http://{obs_addr}/metrics"))
        .send()
        .await
        .expect("GET /metrics");
    assert_eq!(metrics_resp.status(), 200);
    let body = metrics_resp.text().await.expect("read metrics body");

    assert!(
        body.contains("stratum_active_connections 1"),
        "body:\n{body}"
    );
    assert!(
        body.contains("stratum_connections_per_ip{ip=\"127.0.0.1\"} 1"),
        "body:\n{body}"
    );
    assert!(
        body.contains("stratum_shares_submitted_total 2"),
        "body:\n{body}"
    );
    assert!(
        body.contains("stratum_shares_accepted_total 1"),
        "body:\n{body}"
    );
    assert!(
        body.contains("stratum_shares_rejected_total 1"),
        "body:\n{body}"
    );
    assert!(
        body.contains("stratum_shares_rejected_stale_total 1"),
        "body:\n{body}"
    );
    assert!(
        body.contains("stratum_shares_by_difficulty_bucket_total{bucket=\"<1\"} 2"),
        "body:\n{body}"
    );
    assert!(
        body.contains("stratum_worker_hashrate{worker=\"obsrig\"}"),
        "body:\n{body}"
    );
    assert!(body.contains("stratum_connection_rate_limit_hits_total"));
    assert!(body.contains("stratum_request_rate_limit_hits_total"));
    assert!(body.contains("stratum_rpc_getwork_latency_seconds"));
    assert!(body.contains("stratum_rpc_submitwork_latency_seconds"));
    assert!(body.contains("stratum_job_broadcast_latency_seconds"));
    assert!(body.contains("stratum_tls_handshake_success_total"));
    assert!(body.contains("stratum_tls_handshake_failure_total"));
    assert!(body.contains("stratum_uptime_seconds"));

    // 4. Disconnect and verify active_connections returns to 0
    drop(client);
    timeout(Duration::from_secs(2), async {
        loop {
            if gateway.metrics().active_connections.get() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("active_connections must decrement to 0 after disconnect");

    gateway.shutdown();
}

#[tokio::test]
async fn test_stratum_oversized_line_disconnects_cleanly() {
    let (gateway, addr) = start_test_gateway(1.0).await;
    let mut client = TestClient::connect(addr).await;

    // Send a 6 KiB line exceeding MAX_STRATUM_LINE_BYTES (4096).
    let oversized = "a".repeat(6 * 1024);
    client.send_line(&oversized).await;

    // Gateway must close the connection cleanly (EOF or error on read) and decrement active_connections.
    let mut buf = String::new();
    let read_res = timeout(Duration::from_secs(2), client.reader.read_line(&mut buf))
        .await
        .expect("gateway must close oversized-line client promptly");
    assert!(
        matches!(read_res, Ok(0) | Err(_)),
        "expected EOF or disconnect, got {read_res:?} ({buf:?})"
    );

    timeout(Duration::from_secs(2), async {
        loop {
            if gateway.metrics().active_connections.get() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("active_connections must return to 0 after oversized-line disconnect");

    gateway.shutdown();
}

#[tokio::test]
async fn test_stratum_submit_validates_extranonce2_and_ntime() {
    let (gateway, addr) = start_test_gateway(0.0).await;
    let mut client = TestClient::connect(addr).await;

    // Subscribe & authorize
    client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["test/1.0"]}).to_string(),
        )
        .await;
    let _ = client.read_json().await;

    let (_sk, pk) = generate_keypair();
    let username = format!("{}.valrig", Address(pk.0).encode());
    client
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [username.clone(), "x"]})
                .to_string(),
        )
        .await;
    let _ = client.read_json().await; // authorize ok
    let _ = client.read_json().await; // set_difficulty

    let test_header = create_test_header(77, 0x207fffff);
    let job_ts = test_header.timestamp;
    let job = gateway.job_manager().add_template(test_header);
    gateway.broadcast_notify(&job);
    let notify = client.read_json().await;
    let ntime_hex = notify["params"][7]
        .as_str()
        .expect("notify must include ntime")
        .to_string();

    // 1. Short extranonce2 -> code 25
    client
        .send_line(
            &json!({
                "id": 10,
                "method": "mining.submit",
                "params": [username, job.job_id, "0001", ntime_hex, "00000001"]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 10);
    assert_eq!(resp["error"][0], 25);

    // 2. Oversized extranonce2 -> code 25
    client
        .send_line(
            &json!({
                "id": 11,
                "method": "mining.submit",
                "params": [username, job.job_id, "0000000001", ntime_hex, "00000001"]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 11);
    assert_eq!(resp["error"][0], 25);

    // 3. Non-hex extranonce2 -> code 25
    client
        .send_line(
            &json!({
                "id": 12,
                "method": "mining.submit",
                "params": [username, job.job_id, "zzzzzzzz", ntime_hex, "00000001"]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 12);
    assert_eq!(resp["error"][0], 25);

    // 4. Malformed ntime -> code 25
    client
        .send_line(
            &json!({
                "id": 13,
                "method": "mining.submit",
                "params": [username, job.job_id, "00000001", "not_hex!", "00000001"]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 13);
    assert_eq!(resp["error"][0], 25);

    // 5. Out-of-range past ntime -> code 25
    client
        .send_line(
            &json!({
                "id": 14,
                "method": "mining.submit",
                "params": [username, job.job_id, "00000001", format!("{:08x}", job_ts - 1), "00000001"]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 14);
    assert_eq!(resp["error"][0], 25);

    // 6. Out-of-range future ntime -> code 25
    client
        .send_line(
            &json!({
                "id": 15,
                "method": "mining.submit",
                "params": [
                    username,
                    job.job_id,
                    "00000001",
                    format!("{:08x}", job_ts + kovanica_stratum::MAX_NTIME_DRIFT_MS + 1),
                    "00000001"
                ]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 15);
    assert_eq!(resp["error"][0], 25);

    // 7. Valid extranonce2 + valid ntime -> accepted
    client
        .send_line(
            &json!({
                "id": 16,
                "method": "mining.submit",
                "params": [username, job.job_id, "0000000A", ntime_hex, "00000001"]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 16);
    assert_eq!(resp["result"], true);
    assert!(resp["error"].is_null());

    // 8. Same share with lowercase extranonce2 must be caught as duplicate (code 22)
    client
        .send_line(
            &json!({
                "id": 17,
                "method": "mining.submit",
                "params": [username, job.job_id, "0000000a", ntime_hex, "00000001"]
            })
            .to_string(),
        )
        .await;
    let resp = client.read_json().await;
    assert_eq!(resp["id"], 17);
    assert_eq!(resp["error"][0], 22);

    gateway.shutdown();
}

#[tokio::test]
async fn test_tls_stratum_e2e_handshake_notify_and_submit() {
    init_test_logging();

    // 1. Generate ephemeral self-signed certificate for localhost / 127.0.0.1
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("generate ephemeral self-signed cert");
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let cert_der = certified.cert.der().clone();

    let tmp_dir = tempfile::tempdir().expect("tempdir for TLS cert/key");
    let cert_path = tmp_dir.path().join("stratum_cert.pem");
    let key_path = tmp_dir.path().join("stratum_key.pem");
    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert PEM");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write key PEM");

    // 2. Start StratumGateway with TLS enabled
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral TLS listener");
    let local_addr = listener.local_addr().expect("local addr");

    let config = StratumConfig {
        listen_addr: local_addr,
        difficulty: 0.0,
        chain_id: HYBRID_TESTNET,
        rpc_url: "http://127.0.0.1:1/rpc".to_string(),
        poll_interval: Duration::from_secs(3600),
        tls: true,
        tls_cert: Some(cert_path),
        tls_key: Some(key_path),
        ..Default::default()
    };
    config.validate().expect("TLS config must validate");

    let gateway = Arc::new(StratumGateway::new(config).expect("TLS gateway creation failed"));
    let gw_clone = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = gw_clone.run_with_listener(listener).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Connect TLS client trusting the ephemeral certificate
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(cert_der)
        .expect("add ephemeral cert to root store");
    let mut client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"stratum".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

    let tcp_stream = TcpStream::connect(local_addr)
        .await
        .expect("connect TCP to TLS gateway");
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost").expect("valid SNI server name");
    let tls_stream = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .expect("TLS handshake timed out")
    .expect("TLS handshake failed");

    let (read_half, mut write_half) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(read_half);

    async fn send_tls_json(
        writer: &mut tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
        val: Value,
    ) {
        writer
            .write_all(format!("{val}\n").as_bytes())
            .await
            .expect("write over TLS");
        writer.flush().await.expect("flush over TLS");
    }

    async fn read_tls_json(
        reader: &mut BufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    ) -> Value {
        let mut line = String::new();
        timeout(Duration::from_secs(3), reader.read_line(&mut line))
            .await
            .expect("timed out reading TLS line")
            .expect("TLS read error");
        serde_json::from_str(&line).expect("valid JSON over TLS")
    }

    // 4. mining.subscribe over TLS
    send_tls_json(
        &mut write_half,
        json!({"id": 1, "method": "mining.subscribe", "params": ["TlsTestMiner/1.0"]}),
    )
    .await;
    let sub_resp = read_tls_json(&mut reader).await;
    assert_eq!(sub_resp["id"], 1);
    assert!(sub_resp["error"].is_null());
    assert_eq!(sub_resp["result"][2], 4);
    assert_eq!(
        sub_resp["result"][3]["profile"],
        KOVANICA_STRATUM_CAPABILITY
    );

    // 5. mining.authorize over TLS
    let (_sk, pk) = generate_keypair();
    let username = format!("{}.tls_rig", Address(pk.0).encode());
    send_tls_json(
        &mut write_half,
        json!({"id": 2, "method": "mining.authorize", "params": [username.clone(), "x"]}),
    )
    .await;
    let auth_resp = read_tls_json(&mut reader).await;
    assert_eq!(auth_resp["id"], 2);
    assert_eq!(auth_resp["result"], true);

    let diff_notif = read_tls_json(&mut reader).await;
    assert_eq!(diff_notif["method"], "mining.set_difficulty");

    // 6. Inject job and receive mining.notify over TLS
    let header = create_test_header(314, 0x207fffff);
    let job_ts = header.timestamp;
    let job = gateway.job_manager().add_template(header);
    gateway.broadcast_notify(&job);

    let notify = read_tls_json(&mut reader).await;
    assert_eq!(notify["method"], "mining.notify");
    assert_eq!(notify["params"][0], job.job_id);
    let ntime_hex = notify["params"][7]
        .as_str()
        .expect("notify ntime")
        .to_string();

    // 7. Invalid extranonce2 over TLS -> error code 25
    send_tls_json(
        &mut write_half,
        json!({
            "id": 3,
            "method": "mining.submit",
            "params": [username.clone(), job.job_id, "bad_en2", ntime_hex.clone(), "00000001"]
        }),
    )
    .await;
    let bad_en2_resp = read_tls_json(&mut reader).await;
    assert_eq!(bad_en2_resp["id"], 3);
    assert_eq!(bad_en2_resp["error"][0], 25);

    // 8. Out-of-range ntime over TLS -> error code 25
    send_tls_json(
        &mut write_half,
        json!({
            "id": 4,
            "method": "mining.submit",
            "params": [
                username.clone(),
                job.job_id,
                "00000001",
                format!("{:08x}", job_ts + kovanica_stratum::MAX_NTIME_DRIFT_MS + 10),
                "00000001"
            ]
        }),
    )
    .await;
    let bad_ntime_resp = read_tls_json(&mut reader).await;
    assert_eq!(bad_ntime_resp["id"], 4);
    assert_eq!(bad_ntime_resp["error"][0], 25);

    // 9. Valid mining.submit over TLS -> accepted
    send_tls_json(
        &mut write_half,
        json!({
            "id": 5,
            "method": "mining.submit",
            "params": [username.clone(), job.job_id, "00000001", ntime_hex.clone(), "00000042"]
        }),
    )
    .await;
    let ok_resp = read_tls_json(&mut reader).await;
    assert_eq!(ok_resp["id"], 5);
    assert_eq!(ok_resp["result"], true);
    assert!(ok_resp["error"].is_null());

    // 10. Duplicate submit over TLS -> error code 22
    send_tls_json(
        &mut write_half,
        json!({
            "id": 6,
            "method": "mining.submit",
            "params": [username, job.job_id, "00000001", ntime_hex, "00000042"]
        }),
    )
    .await;
    let dup_resp = read_tls_json(&mut reader).await;
    assert_eq!(dup_resp["id"], 6);
    assert_eq!(dup_resp["error"][0], 22);

    assert_eq!(gateway.metrics().tls_handshake_success.get(), 1);
    assert_eq!(gateway.metrics().tls_handshake_failure.get(), 0);

    gateway.shutdown();
}

#[tokio::test]
async fn test_vardiff_e2e_retargeting_and_expanded_prometheus_metrics() {
    init_test_logging();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral listener");
    let stratum_addr = listener.local_addr().expect("stratum local addr");

    // Initial difficulty 1e-10 yields target [0xff; 32] so every share is accepted immediately,
    // allowing fast deterministic verification of VarDiff ramp-up and `mining.set_difficulty`.
    let initial_diff = 1e-10;
    let max_diff = 1e-6;
    let config = StratumConfig {
        listen_addr: stratum_addr,
        difficulty: initial_diff,
        chain_id: HYBRID_TESTNET,
        rpc_url: "http://127.0.0.1:1/rpc".to_string(),
        poll_interval: Duration::from_secs(3600),
        vardiff_enabled: true,
        vardiff_min_difficulty: initial_diff,
        vardiff_max_difficulty: max_diff,
        vardiff_target_share_secs: 30.0,
        vardiff_retarget_interval_secs: 60,
        vardiff_variance_percent: 20.0,
        ..Default::default()
    };
    config.validate().expect("VarDiff config must validate");

    let gateway = Arc::new(StratumGateway::new(config).expect("gateway creation failed"));
    let gw_clone = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = gw_clone.run_with_listener(listener).await;
    });

    // Start observability HTTP server
    let obs_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observability listener");
    let obs_addr = obs_listener.local_addr().expect("observability local addr");
    let obs_gw = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = obs_gw.serve_observability(obs_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let job = gateway
        .job_manager()
        .add_template(create_test_header(99, 0x207f_ffff));

    let mut client = TestClient::connect(stratum_addr).await;

    // 1. Subscribe & authorize
    client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["vardiff-miner/1.0"]})
                .to_string(),
        )
        .await;
    let _ = client.read_json().await;

    let (_sk, pk) = generate_keypair();
    let username = format!("{}.vardiff_rig", Address(pk.0).encode());
    client
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [username.clone(), "x"]})
                .to_string(),
        )
        .await;
    let auth_resp = client.read_json().await;
    assert_eq!(auth_resp["result"], true);

    let init_diff_notif = client.read_json().await;
    assert_eq!(init_diff_notif["method"], "mining.set_difficulty");
    let init_diff_sent = init_diff_notif["params"][0].as_f64().expect("initial diff");
    assert!((init_diff_sent - initial_diff).abs() < 1e-18);

    let notify_msg = client.read_json().await;
    assert_eq!(notify_msg["method"], "mining.notify");

    // 2. Submit 5 valid shares rapidly -> triggers VarDiff ramp-up on the 5th share
    // (5 shares in 60s = 12s/share vs 30s target => ratio 2.5 => new_diff = 2.5e-10)
    for idx in 1..=5u64 {
        let nonce_hex = format!("{idx:08x}");
        client
            .send_line(
                &json!({
                    "id": 10 + idx,
                    "method": "mining.submit",
                    "params": [username, job.job_id, "00000001", nonce_hex]
                })
                .to_string(),
            )
            .await;
        let resp = client.read_json().await;
        assert_eq!(resp["id"], 10 + idx);
        assert_eq!(resp["result"], true);
    }

    // 3. Expect server-pushed mining.set_difficulty with increased bounded difficulty
    let retarget_notif = client.read_json().await;
    assert_eq!(retarget_notif["method"], "mining.set_difficulty");
    let retargeted_diff = retarget_notif["params"][0]
        .as_f64()
        .expect("retargeted difficulty f64");
    assert!(
        retargeted_diff > initial_diff && retargeted_diff <= max_diff,
        "expected retargeted diff in ({initial_diff}, {max_diff}], got {retargeted_diff}"
    );

    // 4. Submit one duplicate share and one stale share to verify per-reason metrics
    client
        .send_line(
            &json!({
                "id": 20,
                "method": "mining.submit",
                "params": [username, job.job_id, "00000001", "00000001"]
            })
            .to_string(),
        )
        .await;
    let dup_resp = client.read_json().await;
    assert_eq!(dup_resp["error"][0], 22);

    client
        .send_line(
            &json!({
                "id": 21,
                "method": "mining.submit",
                "params": [username, "stale_job_id", "00000001", "00000099"]
            })
            .to_string(),
        )
        .await;
    let stale_resp = client.read_json().await;
    assert_eq!(stale_resp["error"][0], 21);

    // 5. Scrape /metrics and verify VarDiff + per-reason rejection + TLS handshake metrics
    let http = reqwest::Client::new();
    let metrics_body = http
        .get(format!("http://{obs_addr}/metrics"))
        .send()
        .await
        .expect("GET /metrics")
        .text()
        .await
        .expect("read /metrics body");

    assert!(
        metrics_body.contains("stratum_vardiff_retargets_total 1"),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_vardiff_retargets_by_direction_total{direction=\"up\"} 1"),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_shares_rejected_by_reason_total{reason=\"duplicate\"} 1"),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_shares_rejected_by_reason_total{reason=\"stale\"} 1"),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_tls_handshakes_total{result=\"success\"} 0"),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_tls_handshakes_total{result=\"failure\"} 0"),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_worker_difficulty_avg "),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_worker_difficulty_min "),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_worker_difficulty_max "),
        "body:\n{metrics_body}"
    );
    assert!(
        (gateway.metrics().worker_difficulty_avg.get() - retargeted_diff).abs() < 1e-18,
        "worker_difficulty_avg gauge must match retargeted difficulty"
    );

    gateway.shutdown();
}

#[tokio::test]
async fn test_per_ip_invalid_share_rate_limit_temporary_ban_and_expiry_e2e() {
    init_test_logging();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral listener");
    let stratum_addr = listener.local_addr().expect("stratum local addr");

    // Configure gateway with ban_threshold_invalid_shares = 3 and ban_duration_secs = 1
    let config = StratumConfig {
        listen_addr: stratum_addr,
        difficulty: 0.0,
        chain_id: HYBRID_TESTNET,
        rpc_url: "http://127.0.0.1:1/rpc".to_string(),
        poll_interval: Duration::from_secs(3600),
        ban_threshold_invalid_shares: 3,
        ban_duration_secs: 1,
        ..Default::default()
    };
    config.validate().expect("ban config must validate");

    let gateway = Arc::new(StratumGateway::new(config).expect("gateway creation failed"));
    let gw_clone = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = gw_clone.run_with_listener(listener).await;
    });

    // Start observability HTTP server to verify Prometheus ban metrics
    let obs_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observability listener");
    let obs_addr = obs_listener.local_addr().expect("observability local addr");
    let obs_gw = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = obs_gw.serve_observability(obs_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let job = gateway
        .job_manager()
        .add_template(create_test_header(303, 0x207f_ffff));

    // 1. Connect client, subscribe, and authorize
    let mut client = TestClient::connect(stratum_addr).await;
    client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["misbehaving-miner/1.0"]})
                .to_string(),
        )
        .await;
    let _ = client.read_json().await;

    let (_sk, pk) = generate_keypair();
    let username = format!("{}.bad_rig", Address(pk.0).encode());
    client
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [username.clone(), "x"]})
                .to_string(),
        )
        .await;
    let _ = client.read_json().await; // auth result
    let _ = client.read_json().await; // set_difficulty
    let _ = client.read_json().await; // notify

    // 2. Submit 1st invalid share (stale job) -> rejected with 21, connection stays open
    client
        .send_line(
            &json!({
                "id": 10,
                "method": "mining.submit",
                "params": [username, "stale_job_1", "00000001", "00000001"]
            })
            .to_string(),
        )
        .await;
    let r1 = client.read_json().await;
    assert_eq!(r1["error"][0], 21);
    assert_eq!(gateway.metrics().ip_bans.get(), 0);
    assert_eq!(gateway.metrics().banned_ips_active.get(), 0);

    // 3. Submit 2nd invalid share (invalid extranonce2) -> rejected with 25, connection stays open
    client
        .send_line(
            &json!({
                "id": 11,
                "method": "mining.submit",
                "params": [username, job.job_id, "bad_hex", "00000002"]
            })
            .to_string(),
        )
        .await;
    let r2 = client.read_json().await;
    assert_eq!(r2["error"][0], 25);
    assert_eq!(gateway.metrics().ip_bans.get(), 0);

    // 4. Submit 3rd invalid share (stale job) -> reaches threshold (3), triggers ban and closes connection
    client
        .send_line(
            &json!({
                "id": 12,
                "method": "mining.submit",
                "params": [username, "stale_job_3", "00000001", "00000003"]
            })
            .to_string(),
        )
        .await;
    let r3 = client.read_json().await;
    assert_eq!(r3["error"][0], 21);

    // Active misbehaving connection must now be closed by the gateway
    let mut eof_buf = String::new();
    let eof_res = timeout(
        Duration::from_secs(2),
        client.reader.read_line(&mut eof_buf),
    )
    .await
    .expect("gateway must close connection after crossing ban threshold");
    assert!(
        matches!(eof_res, Ok(0) | Err(_)),
        "expected EOF on banned active connection, got {eof_res:?}"
    );

    assert_eq!(gateway.metrics().ip_bans.get(), 1);
    assert_eq!(gateway.metrics().banned_ips_active.get(), 1);

    // Verify Prometheus /metrics endpoint exposes stratum_ip_bans_total and stratum_banned_ips_active
    let http = reqwest::Client::new();
    let metrics_body = http
        .get(format!("http://{obs_addr}/metrics"))
        .send()
        .await
        .expect("GET /metrics")
        .text()
        .await
        .expect("read /metrics body");
    assert!(
        metrics_body.contains("stratum_ip_bans_total 1"),
        "body:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_banned_ips_active 1"),
        "body:\n{metrics_body}"
    );

    // 5. Attempt to reconnect while ban is active -> immediately dropped by gateway
    let mut banned_reconnect = TestClient::connect(stratum_addr).await;
    let _ = banned_reconnect
        .writer
        .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"reconnect/1.0\"]}\n")
        .await;
    let _ = banned_reconnect.writer.flush().await;
    let mut reconnect_buf = String::new();
    let reconnect_res = timeout(
        Duration::from_secs(2),
        banned_reconnect.reader.read_line(&mut reconnect_buf),
    )
    .await
    .expect("banned reconnect must be closed immediately");
    assert!(
        matches!(reconnect_res, Ok(0) | Err(_)),
        "banned IP must not receive a Stratum response on reconnect, got {reconnect_res:?} ({reconnect_buf:?})"
    );

    // 6. Wait for ban duration (1s) to expire and verify client can reconnect and subscribe cleanly
    tokio::time::sleep(Duration::from_millis(1_150)).await;
    let mut clean_client = TestClient::connect(stratum_addr).await;
    clean_client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["recovered-miner/1.0"]})
                .to_string(),
        )
        .await;
    let sub_resp = clean_client.read_json().await;
    assert_eq!(sub_resp["id"], 1);
    assert!(sub_resp["error"].is_null());
    assert_eq!(gateway.metrics().banned_ips_active.get(), 0);

    gateway.shutdown();
}

#[tokio::test]
async fn test_observability_workers_endpoint_e2e() {
    let (gateway, stratum_addr) = start_test_gateway(0.0).await;

    let job = gateway
        .job_manager()
        .add_template(create_test_header(88, 0x207f_ffff));

    // Start observability HTTP server on ephemeral port
    let obs_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observability listener");
    let obs_addr = obs_listener.local_addr().expect("observability local addr");
    let obs_gateway = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = obs_gateway.serve_observability(obs_listener).await;
    });

    let http = reqwest::Client::new();

    // 1. Query GET /workers before any miner connects
    let init_resp = http
        .get(format!("http://{obs_addr}/workers"))
        .send()
        .await
        .expect("GET /workers initial");
    assert_eq!(init_resp.status(), 200);
    let init_json: Value = init_resp.json().await.expect("parse initial /workers JSON");
    assert_eq!(init_json["active_workers"], 0);
    assert_eq!(init_json["vardiff_enabled"], false);
    assert_eq!(
        init_json["workers"]
            .as_array()
            .expect("workers array")
            .len(),
        0
    );
    assert!(init_json["timestamp"].as_u64().expect("timestamp u64") > 0);

    // 2. Connect worker 1, subscribe, and authorize
    let mut client1 = TestClient::connect(stratum_addr).await;
    client1
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["workers-e2e/1.0"]})
                .to_string(),
        )
        .await;
    let _ = client1.read_json().await;

    let (_sk1, pk1) = generate_keypair();
    let addr1_str = Address(pk1.0).encode();
    let username1 = format!("{addr1_str}.rig_01");
    client1
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [username1.clone(), "secret_pw"]})
                .to_string(),
        )
        .await;
    let _ = client1.read_json().await; // authorize ok
    let _ = client1.read_json().await; // set_difficulty
    let _ = client1.read_json().await; // notify

    // Verify GET /workers lists the authorized worker with 0 shares and no sensitive fields
    let after_auth_resp = http
        .get(format!("http://{obs_addr}/workers"))
        .send()
        .await
        .expect("GET /workers after authorize");
    assert_eq!(after_auth_resp.status(), 200);
    let after_auth_text = after_auth_resp.text().await.expect("read /workers body");
    assert!(
        !after_auth_text.contains("127.0.0.1"),
        "/workers must never expose client IP: {after_auth_text}"
    );
    assert!(
        !after_auth_text.contains(&addr1_str),
        "/workers must not expose payout address: {after_auth_text}"
    );
    assert!(
        !after_auth_text.contains("secret_pw"),
        "/workers must never expose password: {after_auth_text}"
    );

    let after_auth_json: Value =
        serde_json::from_str(&after_auth_text).expect("parse /workers JSON");
    assert_eq!(after_auth_json["active_workers"], 1);
    assert_eq!(after_auth_json["vardiff_enabled"], false);
    let w0 = &after_auth_json["workers"][0];
    assert_eq!(w0["session_id"], 1);
    assert_eq!(w0["worker_name"], "rig_01");
    assert_eq!(w0["authorized"], true);
    assert_eq!(w0["extranonce_subscribed"], false);
    assert_eq!(w0["difficulty"], 0.0);
    assert_eq!(w0["shares_accepted"], 0);
    assert_eq!(w0["shares_rejected"], 0);
    assert!(w0["connected_secs"].as_u64().is_some());
    assert!(w0["idle_secs"].as_u64().is_some());

    // 3. Submit 2 valid shares and 1 duplicate share + 1 stale share
    client1
        .send_line(
            &json!({"id": 3, "method": "mining.submit", "params": [username1.clone(), job.job_id, "00000001", "00000001"]})
                .to_string(),
        )
        .await;
    assert_eq!(client1.read_json().await["result"], true);

    client1
        .send_line(
            &json!({"id": 4, "method": "mining.submit", "params": [username1.clone(), job.job_id, "00000001", "00000002"]})
                .to_string(),
        )
        .await;
    assert_eq!(client1.read_json().await["result"], true);

    // Duplicate share -> rejected (22)
    client1
        .send_line(
            &json!({"id": 5, "method": "mining.submit", "params": [username1.clone(), job.job_id, "00000001", "00000001"]})
                .to_string(),
        )
        .await;
    assert_eq!(client1.read_json().await["error"][0], 22);

    // Stale share -> rejected (21)
    client1
        .send_line(
            &json!({"id": 6, "method": "mining.submit", "params": [username1, "unknown_job", "00000001", "00000003"]})
                .to_string(),
        )
        .await;
    assert_eq!(client1.read_json().await["error"][0], 21);

    // 4. Verify GET /workers reports updated share counters (2 accepted, 2 rejected)
    let after_submit_json: Value = http
        .get(format!("http://{obs_addr}/workers"))
        .send()
        .await
        .expect("GET /workers after submit")
        .json()
        .await
        .expect("parse /workers JSON after submit");
    assert_eq!(after_submit_json["active_workers"], 1);
    let w0_updated = &after_submit_json["workers"][0];
    assert_eq!(w0_updated["session_id"], 1);
    assert_eq!(w0_updated["worker_name"], "rig_01");
    assert_eq!(w0_updated["authorized"], true);
    assert_eq!(w0_updated["shares_accepted"], 2);
    assert_eq!(w0_updated["shares_rejected"], 2);

    // 5. Disconnect worker and verify GET /workers returns to 0 active workers
    drop(client1);
    timeout(Duration::from_secs(2), async {
        loop {
            let snap: Value = http
                .get(format!("http://{obs_addr}/workers"))
                .send()
                .await
                .expect("GET /workers after disconnect")
                .json()
                .await
                .expect("parse /workers JSON");
            if snap["active_workers"] == 0 {
                assert_eq!(snap["workers"].as_array().unwrap().len(), 0);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("/workers active_workers must decrement to 0 after disconnect");

    gateway.shutdown();
}

#[tokio::test]
async fn test_extranonce_subscribe_and_set_extranonce_e2e() {
    let (gateway, stratum_addr) = start_test_gateway(0.0).await;

    // Start observability HTTP server on ephemeral port
    let obs_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observability listener");
    let obs_addr = obs_listener.local_addr().expect("observability local addr");
    let obs_gateway = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = obs_gateway.serve_observability(obs_listener).await;
    });

    let http = reqwest::Client::new();
    let mut client = TestClient::connect(stratum_addr).await;

    // 1. mining.subscribe
    client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["NiceHash/1.0.0"]})
                .to_string(),
        )
        .await;
    let sub_resp = client.read_json().await;
    assert_eq!(sub_resp["id"], 1);
    assert!(sub_resp["error"].is_null());
    let initial_en1 = sub_resp["result"][1]
        .as_str()
        .expect("initial extranonce1")
        .to_string();
    assert_eq!(initial_en1, "00000001");

    // 2. Verify /workers initially shows extranonce_subscribed: false
    let workers_before: Value = http
        .get(format!("http://{obs_addr}/workers"))
        .send()
        .await
        .expect("GET /workers before extranonce.subscribe")
        .json()
        .await
        .expect("parse /workers JSON");
    assert_eq!(workers_before["active_workers"], 1);
    assert_eq!(workers_before["workers"][0]["extranonce_subscribed"], false);

    // Verify rotating extranonce before subscription returns None and pushes nothing
    assert!(gateway
        .set_session_extranonce("sess_00000001", "00000099")
        .is_none());

    // 3. Send mining.extranonce.subscribe
    client
        .send_line(
            &json!({"id": 2, "method": "mining.extranonce.subscribe", "params": []}).to_string(),
        )
        .await;
    let en_sub_resp = client.read_json().await;
    assert_eq!(en_sub_resp["id"], 2);
    assert_eq!(en_sub_resp["result"], true);
    assert!(en_sub_resp["error"].is_null());

    // 4. Verify /workers updates to extranonce_subscribed: true
    let workers_after: Value = http
        .get(format!("http://{obs_addr}/workers"))
        .send()
        .await
        .expect("GET /workers after extranonce.subscribe")
        .json()
        .await
        .expect("parse /workers JSON");
    assert_eq!(workers_after["active_workers"], 1);
    assert_eq!(workers_after["workers"][0]["extranonce_subscribed"], true);

    // 5. Verify /metrics increments stratum_extranonce_subscriptions_total
    let metrics_body = http
        .get(format!("http://{obs_addr}/metrics"))
        .send()
        .await
        .expect("GET /metrics")
        .text()
        .await
        .expect("read /metrics body");
    assert!(
        metrics_body.contains("stratum_extranonce_subscriptions_total 1"),
        "expected stratum_extranonce_subscriptions_total 1 in:\n{metrics_body}"
    );

    // 6. Trigger mining.set_extranonce via StratumGateway helper and verify client receives notification
    let pushed_notif = gateway
        .set_session_extranonce("sess_00000001", "deadbeef")
        .expect("must format and push mining.set_extranonce when subscribed");
    assert_eq!(pushed_notif.id, Value::Null);
    assert_eq!(pushed_notif.method, "mining.set_extranonce");
    assert_eq!(pushed_notif.params, json!(["deadbeef", 4]));

    let client_notif = client.read_json().await;
    assert!(client_notif["id"].is_null());
    assert_eq!(client_notif["method"], "mining.set_extranonce");
    assert_eq!(client_notif["params"], json!(["deadbeef", 4]));

    // 7. Also verify rotate_session_extranonce allocates a fresh extranonce1 and notifies client
    let rotated_notif = gateway
        .rotate_session_extranonce("sess_00000001")
        .expect("must rotate extranonce1 for subscribed session");
    let client_rotated = client.read_json().await;
    assert!(client_rotated["id"].is_null());
    assert_eq!(client_rotated["method"], "mining.set_extranonce");
    assert_eq!(client_rotated["params"], rotated_notif.params);
    assert_eq!(client_rotated["params"][0], "00000002");
    assert_eq!(client_rotated["params"][1], 4);

    gateway.shutdown();
}

#[tokio::test]
async fn test_mining_ping_keepalive_and_idle_session_timeout_eviction_e2e() {
    init_test_logging();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral listener");
    let stratum_addr = listener.local_addr().expect("stratum local addr");

    // Configure gateway with a 2-second session idle timeout for deterministic E2E testing
    let config = StratumConfig {
        listen_addr: stratum_addr,
        difficulty: 0.0,
        chain_id: HYBRID_TESTNET,
        rpc_url: "http://127.0.0.1:1/rpc".to_string(),
        poll_interval: Duration::from_secs(3600),
        session_idle_timeout_secs: 2,
        ..Default::default()
    };
    config
        .validate()
        .expect("idle timeout config must validate");

    let gateway = Arc::new(StratumGateway::new(config).expect("gateway creation failed"));
    let gw_clone = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = gw_clone.run_with_listener(listener).await;
    });

    // Start observability HTTP server on ephemeral port
    let obs_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observability listener");
    let obs_addr = obs_listener.local_addr().expect("observability local addr");
    let obs_gateway = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = obs_gateway.serve_observability(obs_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let http = reqwest::Client::new();
    let mut client = TestClient::connect(stratum_addr).await;

    // 1. Subscribe and authorize worker
    client
        .send_line(
            &json!({"id": 1, "method": "mining.subscribe", "params": ["ping-test/1.0"]})
                .to_string(),
        )
        .await;
    let sub_resp = client.read_json().await;
    assert_eq!(sub_resp["id"], 1);
    assert!(sub_resp["error"].is_null());

    let (_sk, pk) = generate_keypair();
    let username = format!("{}.ping_rig", Address(pk.0).encode());
    client
        .send_line(
            &json!({"id": 2, "method": "mining.authorize", "params": [username, "x"]}).to_string(),
        )
        .await;
    let auth_resp = client.read_json().await;
    assert_eq!(auth_resp["id"], 2);
    assert_eq!(auth_resp["result"], true);
    let _ = client.read_json().await; // mining.set_difficulty

    // 2. Wait ~1.1s (less than 2s timeout) so idle_secs advances to >= 1
    tokio::time::sleep(Duration::from_millis(1_150)).await;
    let workers_idle: Value = http
        .get(format!("http://{obs_addr}/workers"))
        .send()
        .await
        .expect("GET /workers while idle")
        .json()
        .await
        .expect("parse /workers JSON");
    assert_eq!(workers_idle["active_workers"], 1);
    let idle_before_ping = workers_idle["workers"][0]["idle_secs"]
        .as_u64()
        .expect("idle_secs u64");
    assert!(
        idle_before_ping >= 1,
        "expected idle_secs >= 1 before ping, got {idle_before_ping}"
    );

    // 3. Send mining.ping -> must reply with result: "pong", error: null, reset idle_secs to 0,
    // and increment stratum_pings_total
    client
        .send_line(&json!({"id": 3, "method": "mining.ping", "params": []}).to_string())
        .await;
    let ping_resp = client.read_json().await;
    assert_eq!(ping_resp["id"], 3);
    assert_eq!(ping_resp["result"], "pong");
    assert!(ping_resp["error"].is_null());

    let workers_after_ping: Value = http
        .get(format!("http://{obs_addr}/workers"))
        .send()
        .await
        .expect("GET /workers after ping")
        .json()
        .await
        .expect("parse /workers JSON after ping");
    assert_eq!(workers_after_ping["active_workers"], 1);
    assert_eq!(
        workers_after_ping["workers"][0]["idle_secs"], 0,
        "mining.ping must reset worker idle_secs to 0"
    );
    assert_eq!(gateway.metrics().pings.get(), 1);
    assert_eq!(gateway.metrics().idle_evictions.get(), 0);

    // 4. Stop sending messages and wait for the 2-second idle timeout to evict the session
    let mut eof_buf = String::new();
    let eof_res = timeout(
        Duration::from_secs(4),
        client.reader.read_line(&mut eof_buf),
    )
    .await
    .expect("idle worker connection must be closed after session_idle_timeout_secs");
    assert!(
        matches!(eof_res, Ok(0) | Err(_)),
        "expected EOF on evicted idle connection, got {eof_res:?} ({eof_buf:?})"
    );

    // 5. Verify /workers drops to 0 active workers and /metrics increments stratum_idle_evictions_total
    timeout(Duration::from_secs(2), async {
        loop {
            let snap: Value = http
                .get(format!("http://{obs_addr}/workers"))
                .send()
                .await
                .expect("GET /workers after eviction")
                .json()
                .await
                .expect("parse /workers JSON");
            if snap["active_workers"] == 0 && gateway.metrics().idle_evictions.get() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("evicted idle worker must be removed from /workers and increment idle_evictions");

    let metrics_body = http
        .get(format!("http://{obs_addr}/metrics"))
        .send()
        .await
        .expect("GET /metrics")
        .text()
        .await
        .expect("read /metrics body");
    assert!(
        metrics_body.contains("stratum_pings_total 1"),
        "expected stratum_pings_total 1 in:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("stratum_idle_evictions_total 1"),
        "expected stratum_idle_evictions_total 1 in:\n{metrics_body}"
    );

    gateway.shutdown();
}

#[tokio::test]
async fn test_graceful_drain_client_reconnect_health_metrics_and_reject_new_connections_e2e() {
    let (gateway, stratum_addr) = start_test_gateway(0.0).await;

    // Start observability HTTP server on ephemeral port
    let obs_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observability listener");
    let obs_addr = obs_listener.local_addr().expect("observability local addr");
    let obs_gateway = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = obs_gateway.serve_observability(obs_listener).await;
    });

    tokio::time::sleep(Duration::from_millis(80)).await;
    let http = reqwest::Client::new();

    // 1. Verify /health starts as "healthy"
    let health_before: Value = http
        .get(format!("http://{obs_addr}/health"))
        .send()
        .await
        .expect("GET /health before drain")
        .json()
        .await
        .expect("parse /health JSON");
    assert_eq!(health_before["status"], "healthy");
    assert!(!gateway.is_draining());

    // 2. Connect and subscribe/authorize two workers
    let mut client1 = TestClient::connect(stratum_addr).await;
    let mut client2 = TestClient::connect(stratum_addr).await;

    for (idx, client) in [&mut client1, &mut client2].into_iter().enumerate() {
        client
            .send_line(
                &json!({"id": 1, "method": "mining.subscribe", "params": [format!("drain-miner/{idx}")]})
                    .to_string(),
            )
            .await;
        let sub_resp = client.read_json().await;
        assert_eq!(sub_resp["id"], 1);
        assert!(sub_resp["error"].is_null());

        let (_sk, pk) = generate_keypair();
        let username = format!("{}.drain_rig_{idx}", Address(pk.0).encode());
        client
            .send_line(
                &json!({"id": 2, "method": "mining.authorize", "params": [username, "x"]})
                    .to_string(),
            )
            .await;
        let auth_resp = client.read_json().await;
        assert_eq!(auth_resp["id"], 2);
        assert_eq!(auth_resp["result"], true);
        let _ = client.read_json().await; // mining.set_difficulty
    }

    assert_eq!(gateway.metrics().active_connections.get(), 2);

    // 3. Initiate graceful drain with target host, port, and wait time
    let notified = gateway.begin_graceful_drain(Some("pool2.kovanica.online"), Some(3334), 5);
    assert_eq!(notified, 2);
    assert!(gateway.is_draining());

    // 4. Both connected workers must receive the standard Stratum client.reconnect notification
    for client in [&mut client1, &mut client2] {
        let notif = client.read_json().await;
        assert!(notif["id"].is_null());
        assert_eq!(notif["method"], "client.reconnect");
        assert_eq!(notif["params"], json!(["pool2.kovanica.online", 3334, 5]));
    }

    // 5. /health must now report "status": "draining"
    let health_draining: Value = http
        .get(format!("http://{obs_addr}/health"))
        .send()
        .await
        .expect("GET /health while draining")
        .json()
        .await
        .expect("parse /health JSON while draining");
    assert_eq!(health_draining["status"], "draining");

    // 6. /metrics must increment stratum_graceful_drains_total
    let metrics_body = http
        .get(format!("http://{obs_addr}/metrics"))
        .send()
        .await
        .expect("GET /metrics while draining")
        .text()
        .await
        .expect("read /metrics body");
    assert!(
        metrics_body.contains("stratum_graceful_drains_total 1"),
        "expected stratum_graceful_drains_total 1 in:\n{metrics_body}"
    );

    // 7. New connections must be rejected cleanly while draining
    let mut rejected_client = TestClient::connect(stratum_addr).await;
    let mut eof_buf = String::new();
    let read_res = timeout(
        Duration::from_secs(2),
        rejected_client.reader.read_line(&mut eof_buf),
    )
    .await
    .expect("draining gateway must close rejected connection promptly");
    assert!(
        matches!(read_res, Ok(0) | Err(_)),
        "expected EOF or connection reset for rejected connection during drain, got {read_res:?} ({eof_buf:?})"
    );
    assert_eq!(
        gateway.metrics().active_connections.get(),
        2,
        "rejected connection during drain must not increment active_connections"
    );

    // 8. Existing workers disconnect cleanly
    drop(client1);
    drop(client2);
    timeout(Duration::from_secs(2), async {
        loop {
            if gateway.metrics().active_connections.get() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("active_connections must return to 0 after workers disconnect");

    gateway.shutdown();
}
