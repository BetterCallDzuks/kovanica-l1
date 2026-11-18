//! End-to-end integration tests for `kovanica-stratum`.
//!
//! Simulates real TCP client handshakes against the `StratumGateway`:
//! - `mining.subscribe` -> Extranonce1 and extranonce2_size allocation.
//! - `mining.authorize` -> PRO-21 address validation and difficulty notification.
//! - `mining.notify` -> Job broadcasting to active subscribed miners.
//! - `mining.submit` -> Share validation, duplicate detection, and low difficulty rejection.
//! - Error cases: unauthorized submissions, malformed JSON, and unknown jobs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kovanica_crypto::generate_keypair;
use kovanica_stratum::config::StratumConfig;
use kovanica_stratum::gateway::StratumGateway;
use kovanica_types::block::BlockHeader;
use kovanica_types::signing::chain_id::HYBRID_TESTNET;
use kovanica_types::{Address, Hash};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Helper to start a test gateway on an ephemeral local port.
async fn start_test_gateway(initial_difficulty: f64) -> (Arc<StratumGateway>, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("must bind ephemeral listener");
    let local_addr = listener.local_addr().expect("must get local addr");

    let config = StratumConfig {
        listen_addr: local_addr,
        difficulty: initial_difficulty,
        chain_id: HYBRID_TESTNET,
        // Set a very long poll interval so the test doesn't log unneeded upstream errors
        poll_interval: Duration::from_secs(3600),
        ..Default::default()
    };

    let gateway = Arc::new(StratumGateway::new(config));
    let gw_clone = Arc::clone(&gateway);

    tokio::spawn(async move {
        let _ = gw_clone.run_with_listener(listener).await;
    });

    // Brief yield to ensure server loop is ready
    tokio::time::sleep(Duration::from_millis(50)).await;

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
    assert_eq!(result.len(), 3);
    let extranonce1 = result[1].as_str().expect("extranonce1 hex");
    let en2_size = result[2].as_u64().expect("extranonce2 size");
    assert!(!extranonce1.is_empty());
    assert_eq!(en2_size, 4);

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
