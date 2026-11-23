//! End-to-end WebSocket subscription tests.
//!
//! These spin up a real [`RpcServer`], connect with a `tokio-tungstenite`
//! client, subscribe, and assert that node events published on the
//! [`EventBus`] arrive as `kovanica_subscription` notifications.

use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use kovanica_consensus::{AuthorityInfo, CommitteeInfo};
use kovanica_dag::DagStore;
use kovanica_mempool::{Mempool, MempoolConfig};
use kovanica_rpc::{AuthConfig, EventBus, RateLimitConfig, RateLimiterState, RpcServer, RpcState};
use kovanica_staking::{StakingState, MIN_VALIDATOR_STAKE};
use kovanica_storage::Storage;
use kovanica_types::{crypto::PublicKey, Address, Hash, Signature, StatementBlock};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn test_state(storage: Arc<Storage>, events: EventBus) -> RpcState {
    let authority = AuthorityInfo {
        index: 0,
        stake: MIN_VALIDATOR_STAKE,
        public_key: PublicKey([7u8; 32]),
        vrf_public_key: None,
        address: Address([9u8; 32]),
        network_address: "127.0.0.1:9000".to_string(),
    };
    RpcState {
        health: kovanica_rpc::NodeHealth::new(),
        consensus_store: Arc::new(DagStore::from_storage(storage.clone())),
        mempool: Arc::new(Mempool::new(
            MempoolConfig::default(),
            storage.clone(),
            kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::DEVNET),
        )),
        storage,
        staking: Arc::new(RwLock::new(StakingState::new())),
        committee: Arc::new(RwLock::new(
            CommitteeInfo::try_new(0, vec![authority]).expect("valid committee"),
        )),
        peer_count: Arc::new(AtomicUsize::new(0)),
        events,
        rate_limiter: Arc::new(RateLimiterState::new(RateLimitConfig::default())),
        auth_config: Arc::new(AuthConfig::default()),
        tx_gossip: None,
        sync_status: None,
        block_gossip: None,
        block_submission: None,
        mining_enabled: false,
        mining_threads: 0,
        bootstrap_addresses: Vec::new(),
    }
}

/// Start a server on an ephemeral port and return its handle and address.
async fn start_server() -> (
    tokio::task::JoinHandle<()>,
    SocketAddr,
    EventBus,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::new(dir.path().join("state.db")).expect("storage"));
    let events = EventBus::new();
    let state = test_state(storage, events.clone());
    let addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let server = RpcServer::new(addr, state, None, None).await;
    let handle = server.start().await.expect("start rpc server");
    (handle, addr, events, dir)
}

/// Connect to `/ws`, retrying briefly while the accept loop warms up.
async fn connect(url: &str) -> Ws {
    for _ in 0..50 {
        match connect_async(url).await {
            Ok((ws, _response)) => return ws,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("could not connect to {url}");
}

/// Read the next text frame and parse it as JSON (5s timeout).
async fn next_json(ws: &mut Ws) -> Value {
    let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for a websocket frame")
        .expect("websocket closed unexpectedly")
        .expect("websocket error");
    let text = message.into_text().expect("expected a text frame");
    serde_json::from_str(&text).expect("frame is valid JSON")
}

async fn send_json(ws: &mut Ws, value: Value) {
    ws.send(Message::Text(value.to_string()))
        .await
        .expect("send json frame");
}

#[tokio::test]
async fn websocket_receives_new_head_notification() {
    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["newHeads"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    let block = StatementBlock {
        author: 0,
        round: 7,
        parents: Vec::new(),
        transactions: Vec::new(),
        statements: Vec::new(),
        signature: Signature([0u8; 64]),
        digest: Hash([0x42; 32]),
        merkle_root: Default::default(),
    };
    events.publish_new_head(&block);

    let notification = next_json(&mut ws).await;
    assert_eq!(notification["method"], json!("kovanica_subscription"));
    assert_eq!(notification["params"]["subscription"], json!("0x1"));
    assert_eq!(
        notification["params"]["result"]["hash"],
        json!(format!("0x{}", hex::encode(block.digest.0)))
    );
    assert_eq!(notification["params"]["result"]["number"], json!("0x7"));

    handle.abort();
}

#[tokio::test]
async fn websocket_unsubscribe_stops_notifications() {
    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["pendingTransactions"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 2, "method": "unsubscribe", "params": ["0x1"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!(true));

    let tx = sample_transaction();
    events.publish_pending_transaction(&tx);

    // No frame should arrive after unsubscribing.
    let quiet = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        quiet.is_err(),
        "received unexpected frame after unsubscribe"
    );

    // Re-subscribing resumes delivery.
    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 3, "method": "subscribe", "params": ["pendingTransactions"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x2"));

    events.publish_pending_transaction(&tx);
    let notification = next_json(&mut ws).await;
    assert_eq!(notification["params"]["subscription"], json!("0x2"));
    assert_eq!(
        notification["params"]["result"]["hash"],
        json!(format!("0x{}", hex::encode([0x01u8; 32])))
    );

    handle.abort();
}

#[tokio::test]
async fn websocket_receives_committed_leader_notification() {
    use kovanica_types::CommittedSubDag;

    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["newCommittedLeader"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    let leader = StatementBlock {
        author: 0,
        round: 4,
        parents: Vec::new(),
        transactions: Vec::new(),
        statements: Vec::new(),
        signature: Signature([0u8; 64]),
        digest: Hash([0x24; 32]),
        merkle_root: Default::default(),
    };
    let subdag = CommittedSubDag {
        blocks: vec![leader.clone()],
        leader,
        leader_round: 4,
        leader_author: 0,
        non_blue: Vec::new(),
    };
    events.publish_committed_leader(&subdag);

    let notification = next_json(&mut ws).await;
    assert_eq!(notification["params"]["subscription"], json!("0x1"));
    assert_eq!(
        notification["params"]["result"]["leader"]["hash"],
        json!(format!("0x{}", hex::encode([0x24u8; 32])))
    );
    assert_eq!(notification["params"]["result"]["leaderRound"], json!(4));
    assert_eq!(notification["params"]["result"]["leaderAuthor"], json!(0));

    handle.abort();
}

#[tokio::test]
async fn websocket_receives_logs_notification() {
    use kovanica_execution::TransactionReceipt;

    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["logs"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    let receipt = TransactionReceipt {
        tx_hash: Hash([0x33; 32]),
        success: true,
        gas_used: 21_000,
        events: Vec::new(),
        error: None,
    };
    events.publish_logs(std::slice::from_ref(&receipt));

    let notification = next_json(&mut ws).await;
    assert_eq!(notification["params"]["subscription"], json!("0x1"));
    assert_eq!(notification["params"]["result"][0]["success"], json!(true));
    assert_eq!(
        notification["params"]["result"][0]["gas_used"],
        json!(21_000)
    );

    handle.abort();
}

#[tokio::test]
async fn websocket_eth_subscribe_logs_with_filter() {
    use kovanica_execution::{ContractEvent, TransactionReceipt};

    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    let target_contract = Address([0x77; 32]);
    let other_contract = Address([0x88; 32]);
    let topic_transfer = b"Transfer".to_vec();
    let topic_approval = b"Approval".to_vec();

    // eth_subscribe with address filter and topic filter
    send_json(
        &mut ws,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_subscribe",
            "params": [
                "logs",
                {
                    "address": format!("0x{}", hex::encode(target_contract.0)),
                    "topics": [format!("0x{}", hex::encode(&topic_transfer))]
                }
            ]
        }),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    // 1. Publish receipt from other contract (should NOT be received)
    let non_matching_receipt_1 = TransactionReceipt {
        tx_hash: Hash([0x01; 32]),
        success: true,
        gas_used: 25_000,
        events: vec![ContractEvent {
            address: other_contract,
            topic: topic_transfer.clone(),
            data: vec![1, 2, 3],
        }],
        error: None,
    };
    events.publish_logs(std::slice::from_ref(&non_matching_receipt_1));

    // 2. Publish receipt from target contract but wrong topic (should NOT be received)
    let non_matching_receipt_2 = TransactionReceipt {
        tx_hash: Hash([0x02; 32]),
        success: true,
        gas_used: 25_000,
        events: vec![ContractEvent {
            address: target_contract,
            topic: topic_approval,
            data: vec![4, 5, 6],
        }],
        error: None,
    };
    events.publish_logs(std::slice::from_ref(&non_matching_receipt_2));

    // Verify no frame arrived for non-matching receipts
    let quiet = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        quiet.is_err(),
        "received unexpected frame for non-matching receipts"
    );

    // 3. Publish matching receipt
    let matching_receipt = TransactionReceipt {
        tx_hash: Hash([0x03; 32]),
        success: true,
        gas_used: 30_000,
        events: vec![ContractEvent {
            address: target_contract,
            topic: topic_transfer.clone(),
            data: vec![7, 8, 9],
        }],
        error: None,
    };
    events.publish_logs(std::slice::from_ref(&matching_receipt));

    let notification = next_json(&mut ws).await;
    assert_eq!(notification["method"], json!("eth_subscription"));
    assert_eq!(notification["params"]["subscription"], json!("0x1"));
    assert_eq!(notification["params"]["result"][0]["success"], json!(true));
    assert_eq!(
        notification["params"]["result"][0]["gas_used"],
        json!(30_000)
    );

    // Unsubscribe with eth_unsubscribe
    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 2, "method": "eth_unsubscribe", "params": ["0x1"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!(true));

    events.publish_logs(std::slice::from_ref(&matching_receipt));
    let quiet_after_unsub = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        quiet_after_unsub.is_err(),
        "received unexpected frame after eth_unsubscribe"
    );

    handle.abort();
}

async fn fetch_metrics(addr: SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = TcpStream::connect(addr).await.expect("connect to /metrics");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write GET /metrics");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read /metrics");
    String::from_utf8(buf).expect("metrics response utf8")
}

fn parse_metric_u64(metrics_text: &str, name: &str) -> u64 {
    let prefix = format!("{name} ");
    metrics_text
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|val| val.trim().parse::<u64>().ok())
        .unwrap_or_else(|| panic!("metric `{name}` not found in /metrics:\n{metrics_text}"))
}

#[tokio::test]
async fn websocket_enforces_per_ip_cap_releases_slots_and_exposes_metrics() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::new(dir.path().join("state.db")).expect("storage"));
    let events = EventBus::new();
    let state = test_state(storage, events.clone());
    let addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let server = RpcServer::new(
        addr,
        state,
        Some(RateLimitConfig::from_requests_per_minute(0)),
        None,
    )
    .await
    .with_max_ws_connections_per_ip(2);
    let ws_limiter = server.ws_limiter();
    let handle = server.start().await.expect("start rpc server");

    let url = format!("ws://{addr}/ws");

    // 1. Open 2 connections (reaches cap = 2).
    let mut ws1 = connect(&url).await;
    let ws2 = connect(&url).await;
    assert_eq!(ws_limiter.total_active(), 2);

    let rejected_before = parse_metric_u64(
        &fetch_metrics(addr).await,
        "rpc_ws_rejected_connections_total",
    );

    // 2. 3rd concurrent connection from the same IP is rejected with HTTP 429.
    let err = connect_async(&url)
        .await
        .expect_err("3rd concurrent WebSocket from same IP must be rejected");
    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(
                resp.status(),
                tokio_tungstenite::tungstenite::http::StatusCode::TOO_MANY_REQUESTS,
                "expected 429 Too Many Requests on per-IP WS cap overflow"
            );
        }
        other => panic!("expected HTTP 429 rejection, got: {other:?}"),
    }

    // 3. Trigger broadcast lag on ws1 by publishing > CHANNEL_CAPACITY (1024) events
    //    synchronously without yielding so the subscriber channel wraps around.
    send_json(
        &mut ws1,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["newHeads"]}),
    )
    .await;
    let sub_resp = next_json(&mut ws1).await;
    assert_eq!(sub_resp["result"], json!("0x1"));

    let lagged_before =
        parse_metric_u64(&fetch_metrics(addr).await, "rpc_ws_lagged_messages_total");

    let block = StatementBlock {
        author: 0,
        round: 1,
        parents: Vec::new(),
        transactions: Vec::new(),
        statements: Vec::new(),
        signature: Signature([0u8; 64]),
        digest: Hash([0x55; 32]),
        merkle_root: Default::default(),
    };
    for _ in 0..1100 {
        events.publish_new_head(&block);
    }

    // Wait briefly for serve_connection to observe RecvError::Lagged.
    let mut lagged_after = lagged_before;
    for _ in 0..25 {
        lagged_after = parse_metric_u64(&fetch_metrics(addr).await, "rpc_ws_lagged_messages_total");
        if lagged_after > lagged_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        lagged_after > lagged_before,
        "expected rpc_ws_lagged_messages_total to increment after broadcast overflow ({lagged_before} -> {lagged_after})"
    );

    // Verify /metrics exposes all three WS metrics before any # EOF marker.
    let metrics_body = fetch_metrics(addr).await;
    let active_now = parse_metric_u64(&metrics_body, "rpc_ws_active_connections");
    let rejected_after = parse_metric_u64(&metrics_body, "rpc_ws_rejected_connections_total");
    assert!(
        active_now >= 2,
        "expected rpc_ws_active_connections >= 2 while two sockets are open, got {active_now}"
    );
    assert!(
        rejected_after > rejected_before,
        "expected rpc_ws_rejected_connections_total to increment ({rejected_before} -> {rejected_after})"
    );
    if let Some(eof_pos) = metrics_body.find("# EOF") {
        assert!(
            metrics_body.find("rpc_ws_active_connections").unwrap() < eof_pos
                && metrics_body
                    .find("rpc_ws_rejected_connections_total")
                    .unwrap()
                    < eof_pos
                && metrics_body.find("rpc_ws_lagged_messages_total").unwrap() < eof_pos,
            "WS metrics must appear before # EOF"
        );
    }

    // 4. Closing ws2 releases its RAII slot so a replacement connection succeeds.
    drop(ws2);
    for _ in 0..50 {
        if ws_limiter.total_active() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        ws_limiter.total_active(),
        1,
        "dropping ws2 must release its per-IP slot"
    );

    let ws3 = connect(&url).await;
    assert_eq!(ws_limiter.total_active(), 2);

    drop(ws1);
    drop(ws3);
    for _ in 0..50 {
        if ws_limiter.total_active() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        ws_limiter.total_active(),
        0,
        "dropping all sockets must release all slots"
    );

    handle.abort();
}

fn sample_transaction() -> kovanica_types::Transaction {
    use kovanica_types::{Transaction, TransactionKind};

    Transaction {
        sender: Address([0x11; 32]),
        nonce: 0,
        kind: TransactionKind::Transfer {
            to: Address([0x33; 32]),
            amount: 1,
        },
        fee: 1,
        signature: Signature([0u8; 64]),
        hash: Hash([0x01; 32]),
    }
}
