//! WebSocket subscription support for the Kovanica JSON-RPC server.
//!
//! The RPC server exposes a WebSocket endpoint (`GET /ws`) alongside the
//! existing HTTP `POST /rpc` endpoint. Clients open a socket, issue
//! `subscribe` / `unsubscribe` JSON-RPC requests and receive push
//! notifications for node events.
//!
//! # Supported subscriptions
//!
//! | Method                     | Emitted when                                            |
//! |----------------------------|---------------------------------------------------------|
//! | `newHeads`                 | A new block is produced or accepted by the node.        |
//! | `newCommittedLeader`       | Consensus commits a leader sub-DAG.                     |
//! | `pendingTransactions`      | A transaction enters the mempool.                       |
//! | `logs`                     | Transaction execution logs (receipts) emitted per committed sub-DAG. |
//! | `newSealedHeader`          | A committed-leader header was stored, or a matching seal arrived. |
//!
//! Transaction execution logs (`logs`) are emitted for each committed sub-DAG
//! and contain the transaction receipts (status, gas used, logs, etc.).
//!
//! # Wire protocol
//!
//! Subscribe request (params may be a bare string or a single-element array):
//!
//! ```json
//! {"jsonrpc":"2.0","id":1,"method":"subscribe","params":["newHeads"]}
//! ```
//!
//! Success response (`result` is a hex quantity string):
//!
//! ```json
//! {"jsonrpc":"2.0","id":1,"result":"0x1"}
//! ```
//!
//! Notifications use the standard subscription envelope:
//!
//! ```json
//! {"jsonrpc":"2.0","method":"kovanica_subscription",
//!  "params":{"subscription":"0x1","result":{ ... }}}
//! ```
//!
//! Unsubscribe accepts the id returned by `subscribe` (hex string or number):
//!
//! ```json
//! {"jsonrpc":"2.0","id":2,"method":"unsubscribe","params":["0x1"]}
//! ```
//!
//! Subscription ids are scoped to a single WebSocket connection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::chain_methods::{block_to_json, transaction_to_json};
use crate::rpc_middleware::normalize_bucket_ip;
use crate::{JsonRpcErrorObject, JsonRpcRequest, JsonRpcResponse, RpcError};
use kovanica_execution::TransactionReceipt;
use kovanica_types::{
    Address, CommitSeal, CommittedSubDag, LeaderHeader, StatementBlock, Transaction,
};

/// Capacity of each broadcast channel. Slow consumers that fall further than
/// this behind simply drop missed notifications (a `Lagged` receive error is
/// treated as "no event" and counted in `rpc_ws_lagged_messages_total`) rather
/// than stalling the publisher.
const CHANNEL_CAPACITY: usize = 1024;

/// Default maximum concurrent WebSocket connections allowed per client IP
/// (IPv6 clients are grouped by `/64`, matching HTTP rate limiting).
pub const DEFAULT_MAX_WS_CONNECTIONS_PER_IP: usize = 16;

/// Process-wide WebSocket telemetry metrics (exported on `/metrics`).
static RPC_WS_ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static RPC_WS_REJECTED_CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static RPC_WS_LAGGED_MESSAGES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Current number of active WebSocket subscription connections.
pub fn rpc_ws_active_connections() -> u64 {
    RPC_WS_ACTIVE_CONNECTIONS.load(Ordering::Relaxed)
}

/// Total number of WebSocket connection attempts rejected due to the per-IP cap.
pub fn rpc_ws_rejected_connections_total() -> u64 {
    RPC_WS_REJECTED_CONNECTIONS_TOTAL.load(Ordering::Relaxed)
}

/// Total number of WebSocket broadcast notifications dropped due to slow consumers.
pub fn rpc_ws_lagged_messages_total() -> u64 {
    RPC_WS_LAGGED_MESSAGES_TOTAL.load(Ordering::Relaxed)
}

fn record_ws_lagged_messages(skipped: u64) {
    RPC_WS_LAGGED_MESSAGES_TOTAL.fetch_add(skipped, Ordering::Relaxed);
}

/// Error returned when a client IP exceeds its concurrent WebSocket connection cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsConnectionLimitExceeded {
    pub max_per_ip: usize,
}

impl std::fmt::Display for WsConnectionLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WebSocket per-IP connection limit ({}) exceeded",
            self.max_per_ip
        )
    }
}

impl std::error::Error for WsConnectionLimitExceeded {}

/// Bounded per-IP concurrent WebSocket connection tracker.
///
/// IPv6 addresses are normalized to their `/64` prefix so rotating host bits
/// within an allocation cannot bypass the per-IP cap. Slots are released
/// automatically when the returned [`WsConnectionGuard`] is dropped.
#[derive(Debug)]
pub struct WsConnectionLimiter {
    max_per_ip: usize,
    active: Mutex<HashMap<IpAddr, usize>>,
}

impl Default for WsConnectionLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_WS_CONNECTIONS_PER_IP)
    }
}

impl WsConnectionLimiter {
    /// Create a limiter permitting at most `max_per_ip` concurrent WebSocket
    /// connections per client IP (`0` rejects all connections fail-closed).
    pub fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Configured maximum concurrent connections per client IP.
    pub fn max_per_ip(&self) -> usize {
        self.max_per_ip
    }

    /// Attempt to reserve a WebSocket connection slot for `ip`.
    ///
    /// On success, increments both the per-IP counter and the process-wide
    /// `rpc_ws_active_connections` gauge, returning an RAII [`WsConnectionGuard`]
    /// that releases both on [`Drop`]. On failure, increments
    /// `rpc_ws_rejected_connections_total` and returns
    /// [`WsConnectionLimitExceeded`].
    pub fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> Result<WsConnectionGuard, WsConnectionLimitExceeded> {
        let bucket_ip = normalize_bucket_ip(ip);
        let mut active = self.active.lock();
        let current = active.get(&bucket_ip).copied().unwrap_or(0);
        if current >= self.max_per_ip {
            RPC_WS_REJECTED_CONNECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(WsConnectionLimitExceeded {
                max_per_ip: self.max_per_ip,
            });
        }
        active.insert(bucket_ip, current + 1);
        drop(active);

        RPC_WS_ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Ok(WsConnectionGuard {
            limiter: Arc::clone(self),
            bucket_ip,
        })
    }

    /// Current active WebSocket connections tracked for `ip` by this limiter.
    pub fn active_for(&self, ip: IpAddr) -> usize {
        let bucket_ip = normalize_bucket_ip(ip);
        self.active.lock().get(&bucket_ip).copied().unwrap_or(0)
    }

    /// Total active WebSocket connections across all IPs tracked by this limiter.
    pub fn total_active(&self) -> usize {
        self.active.lock().values().sum()
    }

    /// Number of distinct IP buckets currently holding at least one connection.
    pub fn tracked_ips(&self) -> usize {
        self.active.lock().len()
    }

    fn release(&self, bucket_ip: IpAddr) {
        let mut active = self.active.lock();
        if let Some(count) = active.get_mut(&bucket_ip) {
            if *count <= 1 {
                active.remove(&bucket_ip);
            } else {
                *count -= 1;
            }
        }
        drop(active);
        RPC_WS_ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard holding one per-IP WebSocket connection slot.
///
/// Automatically decrements the per-IP count and `rpc_ws_active_connections`
/// when dropped (e.g. when the socket closes or the upgrade is aborted).
#[derive(Debug)]
pub struct WsConnectionGuard {
    limiter: Arc<WsConnectionLimiter>,
    bucket_ip: IpAddr,
}

impl Drop for WsConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release(self.bucket_ip);
    }
}

/// The set of events a client can subscribe to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubscriptionKind {
    /// A new block was produced or accepted into the DAG.
    NewHeads,
    /// Consensus committed a leader sub-DAG.
    NewCommittedLeader,
    /// A transaction entered the mempool.
    PendingTransactions,
    /// Transaction execution logs (receipts) emitted per committed sub-DAG.
    Logs,
    /// A locally executed leader header, with the seals stored for it.
    NewSealedHeader,
}

impl SubscriptionKind {
    /// Canonical wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            SubscriptionKind::NewHeads => "newHeads",
            SubscriptionKind::NewCommittedLeader => "newCommittedLeader",
            SubscriptionKind::PendingTransactions => "pendingTransactions",
            SubscriptionKind::Logs => "logs",
            SubscriptionKind::NewSealedHeader => "newSealedHeader",
        }
    }

    /// Parse a subscription name, accepting a few common snake_case aliases.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "newHeads" | "new_heads" => Ok(SubscriptionKind::NewHeads),
            "newCommittedLeader" | "new_committed_leader" => {
                Ok(SubscriptionKind::NewCommittedLeader)
            }
            "pendingTransactions" | "pending_transactions" => {
                Ok(SubscriptionKind::PendingTransactions)
            }
            "logs" => Ok(SubscriptionKind::Logs),
            "newSealedHeader" | "new_sealed_header" => Ok(SubscriptionKind::NewSealedHeader),
            other => Err(format!("unsupported subscription: {other}")),
        }
    }
}

/// Fan-out bus connecting node event sources to WebSocket subscribers.
///
/// Cheap to clone; all clones share the same channels.
#[derive(Clone)]
pub struct EventBus {
    new_heads: broadcast::Sender<Value>,
    committed_leaders: broadcast::Sender<Value>,
    pending_transactions: broadcast::Sender<Value>,
    logs: broadcast::Sender<Value>,
    sealed_headers: broadcast::Sender<Value>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create a new bus with empty channels.
    pub fn new() -> Self {
        let (new_heads, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (committed_leaders, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (pending_transactions, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (logs, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (sealed_headers, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            new_heads,
            committed_leaders,
            pending_transactions,
            logs,
            sealed_headers,
        }
    }

    /// Subscribe to the raw event stream for `kind`.
    pub fn subscribe_receiver(&self, kind: SubscriptionKind) -> broadcast::Receiver<Value> {
        match kind {
            SubscriptionKind::NewHeads => self.new_heads.subscribe(),
            SubscriptionKind::NewCommittedLeader => self.committed_leaders.subscribe(),
            SubscriptionKind::PendingTransactions => self.pending_transactions.subscribe(),
            SubscriptionKind::Logs => self.logs.subscribe(),
            SubscriptionKind::NewSealedHeader => self.sealed_headers.subscribe(),
        }
    }

    /// Returns `true` when at least one subscriber (such as an attached
    /// indexer or WebSocket block/log listener) is actively subscribed to
    /// `logs`, `newCommittedLeader`, or `newHeads` events.
    pub fn has_indexer_subscriber(&self) -> bool {
        self.logs.receiver_count() > 0
            || self.committed_leaders.receiver_count() > 0
            || self.new_heads.receiver_count() > 0
    }

    /// Broadcast a newly produced/accepted block. No-op if nobody listens.
    pub fn publish_new_head(&self, block: &StatementBlock) {
        let _ = self.new_heads.send(block_to_json(block));
    }

    /// Broadcast a committed leader sub-DAG. No-op if nobody listens.
    pub fn publish_committed_leader(&self, subdag: &CommittedSubDag) {
        let payload = json!({
            "leader": block_to_json(&subdag.leader),
            "leaderRound": subdag.leader_round,
            "leaderAuthor": subdag.leader_author,
            "blocks": subdag
                .blocks
                .iter()
                .map(block_to_json)
                .collect::<Vec<Value>>(),
        });
        let _ = self.committed_leaders.send(payload);
    }

    /// Broadcast a mempool admission. No-op if nobody listens.
    pub fn publish_pending_transaction(&self, tx: &Transaction) {
        let _ = self.pending_transactions.send(transaction_to_json(tx));
    }

    /// Broadcast a transaction execution log. No-op if nobody listens.
    pub fn publish_logs(&self, receipts: &[TransactionReceipt]) {
        let _ = self.logs.send(json!(receipts));
    }

    /// Broadcast a leader header and the seals stored for its height.
    ///
    /// No-op if nobody listens. Consensus does not wait on this event.
    pub fn publish_sealed_header(&self, header: &LeaderHeader, seals: &[CommitSeal]) {
        let _ = self
            .sealed_headers
            .send(crate::chain_methods::sealed_header_json(header, seals));
    }
}

/// Optional filter for `logs` subscriptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFilter {
    /// Addresses to filter by (or None for any address).
    pub addresses: Option<Vec<Address>>,
    /// Topics to filter by (per-position alternatives, per Ethereum / kovanica spec).
    pub topics: Vec<Option<Vec<Vec<u8>>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveSubscription {
    kind: SubscriptionKind,
    is_eth: bool,
    log_filter: Option<LogFilter>,
}

/// Per-connection subscription registry.
struct Connection {
    chain_id: u64,
    next_id: u64,
    subscriptions: HashMap<u64, ActiveSubscription>,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new(3)
    }
}

impl Connection {
    fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            next_id: 1,
            subscriptions: HashMap::new(),
        }
    }

    /// Handle a single inbound JSON-RPC frame, returning the response text.
    fn handle_request(&mut self, text: &str) -> String {
        let request: JsonRpcRequest = match serde_json::from_str(text) {
            Ok(request) => request,
            Err(e) => return error_response(Value::Null, RpcError::ParseError(e.to_string())),
        };

        if request.jsonrpc != "2.0" {
            return error_response(
                request.id.unwrap_or(Value::Null),
                RpcError::InvalidRequest("Invalid JSON-RPC version".into()),
            );
        }

        let id = request.id.clone().unwrap_or(Value::Null);

        match request.method.as_str() {
            "subscribe" | "kovanica_subscribe" => match self.subscribe(request.params, false) {
                Ok(subscription_id) => success_response(id, Value::String(subscription_id)),
                Err(e) => error_response(id, e),
            },
            "eth_subscribe" => match self.subscribe(request.params, true) {
                Ok(subscription_id) => success_response(id, Value::String(subscription_id)),
                Err(e) => error_response(id, e),
            },
            "unsubscribe" | "kovanica_unsubscribe" | "eth_unsubscribe" => {
                match self.unsubscribe(request.params) {
                    Ok(removed) => success_response(id, Value::Bool(removed)),
                    Err(e) => error_response(id, e),
                }
            }
            other => error_response(id, RpcError::MethodNotFound(other.to_string())),
        }
    }

    fn subscribe(&mut self, params: Option<Value>, is_eth: bool) -> Result<String, RpcError> {
        const MAX_SUBSCRIPTIONS_PER_CONN: usize = 32;
        if self.subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_CONN {
            return Err(RpcError::InvalidRequest(format!(
                "maximum active subscriptions per WebSocket connection ({MAX_SUBSCRIPTIONS_PER_CONN}) reached"
            )));
        }

        let (name, filter_obj) = parse_subscribe_params(params)?;

        let kind = SubscriptionKind::parse(&name)
            .map_err(|e| RpcError::InvalidParams(format!("subscribe: {e}")))?;

        let log_filter = if kind == SubscriptionKind::Logs {
            if let Some(ref obj) = filter_obj {
                if !obj.is_null() && obj.is_object() {
                    let addresses = crate::chain_methods::parse_address_filter(
                        obj.get("address"),
                        self.chain_id,
                    )?;
                    let topics = crate::chain_methods::parse_topics_filter(obj.get("topics"))?;
                    Some(LogFilter { addresses, topics })
                } else if !obj.is_null() {
                    return Err(RpcError::InvalidParams(
                        "subscribe: logs filter must be an object".into(),
                    ));
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let subscription_id = self.next_id;
        self.next_id += 1;
        self.subscriptions.insert(
            subscription_id,
            ActiveSubscription {
                kind,
                is_eth,
                log_filter,
            },
        );

        Ok(format!("0x{subscription_id:x}"))
    }

    fn unsubscribe(&mut self, params: Option<Value>) -> Result<bool, RpcError> {
        let subscription_id = first_param(params)
            .and_then(parse_subscription_id)
            .ok_or_else(|| {
                RpcError::InvalidParams("unsubscribe: expected a subscription id".into())
            })?;

        Ok(self.subscriptions.remove(&subscription_id).is_some())
    }
}

fn parse_subscribe_params(params: Option<Value>) -> Result<(String, Option<Value>), RpcError> {
    match params {
        Some(Value::Array(mut values)) => {
            if values.is_empty() {
                return Err(RpcError::InvalidParams(
                    "subscribe: expected a subscription name".into(),
                ));
            }
            let name_val = values.remove(0);
            let name = name_val
                .as_str()
                .ok_or_else(|| {
                    RpcError::InvalidParams("subscribe: expected a subscription name string".into())
                })?
                .to_string();
            let filter = values.into_iter().next();
            Ok((name, filter))
        }
        Some(Value::String(name)) => Ok((name, None)),
        _ => Err(RpcError::InvalidParams(
            "subscribe: expected a subscription name".into(),
        )),
    }
}

/// Extract the first parameter, flattening a single-element array.
fn first_param(params: Option<Value>) -> Option<Value> {
    match params {
        Some(Value::Array(values)) => values.into_iter().next(),
        Some(Value::Null) | None => None,
        Some(value) => Some(value),
    }
}

/// Parse a subscription id given as a hex string, decimal string or number.
fn parse_subscription_id(value: Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => {
            let raw = raw.trim();
            match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => raw.parse::<u64>().ok(),
            }
        }
        _ => None,
    }
}

fn success_response(id: Value, result: Value) -> String {
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(result),
        error: None,
        id: Some(id),
    };
    serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
}

fn error_response(id: Value, error: RpcError) -> String {
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(JsonRpcErrorObject {
            code: error.code(),
            message: error.to_string(),
            data: None,
        }),
        id: Some(id),
    };
    serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
}

/// Filter a logs event (array of TransactionReceipts) according to a LogFilter.
/// Returns None if no receipts match.
fn filter_logs_event(event: &Value, filter: &LogFilter, chain_id: u64) -> Option<Value> {
    let receipts = event.as_array()?;
    let mut matching_receipts = Vec::new();

    for receipt in receipts {
        let events = receipt.get("events").and_then(|e| e.as_array());
        let mut matched = false;

        if let Some(events_arr) = events {
            for ev in events_arr {
                // Address filter
                if let Some(ref addrs) = filter.addresses {
                    let ev_addr = if let Some(arr) = ev.get("address").and_then(|a| a.as_array()) {
                        if arr.len() == 32 {
                            let mut bytes = [0u8; 32];
                            for (i, b) in arr.iter().enumerate() {
                                bytes[i] = b.as_u64().unwrap_or(0) as u8;
                            }
                            Some(Address(bytes))
                        } else {
                            None
                        }
                    } else if let Some(a_str) = ev.get("address").and_then(|a| a.as_str()) {
                        Address::parse_for_chain(a_str, chain_id).ok().or_else(|| {
                            addrs
                                .iter()
                                .find(|a| {
                                    a.to_string() == a_str
                                        || a.encode() == a_str
                                        || a.to_hex() == a_str
                                })
                                .copied()
                        })
                    } else {
                        None
                    };

                    match ev_addr {
                        Some(addr) if addrs.contains(&addr) => {}
                        _ => continue,
                    }
                }

                // Topic filter
                let topic_bytes: Vec<u8> =
                    if let Some(arr) = ev.get("topic").and_then(|t| t.as_array()) {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|b| b as u8))
                            .collect()
                    } else if let Some(s) = ev.get("topic").and_then(|t| t.as_str()) {
                        let clean = s
                            .strip_prefix("0x")
                            .or_else(|| s.strip_prefix("0X"))
                            .unwrap_or(s);
                        hex::decode(clean).unwrap_or_else(|_| s.as_bytes().to_vec())
                    } else {
                        Vec::new()
                    };

                if crate::chain_methods::topics_match(&filter.topics, &topic_bytes) {
                    matched = true;
                    break;
                }
            }
        }

        if matched {
            matching_receipts.push(receipt.clone());
        }
    }

    if matching_receipts.is_empty() {
        None
    } else {
        Some(Value::Array(matching_receipts))
    }
}

/// All notification frames owed to `connection` for an event of `kind`.
///
/// Returns an empty vector when the receiver lagged / closed or when the
/// connection has no matching subscriptions.
fn notifications_for(
    connection: &Connection,
    kind: SubscriptionKind,
    received: Result<Value, broadcast::error::RecvError>,
) -> Vec<Value> {
    let event = match received {
        Ok(event) => event,
        Err(broadcast::error::RecvError::Lagged(skipped)) => {
            record_ws_lagged_messages(skipped);
            tracing::warn!(
                subscription = kind.as_str(),
                skipped,
                "WebSocket subscriber lagged behind event bus; dropped missed notifications"
            );
            return Vec::new();
        }
        Err(broadcast::error::RecvError::Closed) => {
            return Vec::new();
        }
    };

    let mut ids: Vec<u64> = connection
        .subscriptions
        .iter()
        .filter(|(_, sub)| sub.kind == kind)
        .map(|(id, _)| *id)
        .collect();
    ids.sort_unstable();

    ids.into_iter()
        .filter_map(|id| {
            let sub = connection.subscriptions.get(&id)?;
            let method = if sub.is_eth {
                "eth_subscription"
            } else {
                "kovanica_subscription"
            };

            let payload = if kind == SubscriptionKind::Logs {
                if let Some(ref filter) = sub.log_filter {
                    filter_logs_event(&event, filter, connection.chain_id)?
                } else {
                    event.clone()
                }
            } else {
                event.clone()
            };

            Some(json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": {
                    "subscription": format!("0x{id:x}"),
                    "result": payload,
                }
            }))
        })
        .collect()
}

/// Drive a single upgraded WebSocket connection until the peer disconnects.
pub async fn serve_connection(socket: axum::extract::ws::WebSocket, state: crate::RpcState) {
    use axum::extract::ws::Message;
    use futures::{SinkExt, StreamExt};

    let chain_id = state.mempool.signing_context().chain_id;
    let mut connection = Connection::new(chain_id);
    let mut new_heads = state.events.subscribe_receiver(SubscriptionKind::NewHeads);
    let mut committed_leaders = state
        .events
        .subscribe_receiver(SubscriptionKind::NewCommittedLeader);
    let mut pending = state
        .events
        .subscribe_receiver(SubscriptionKind::PendingTransactions);
    let mut logs = state.events.subscribe_receiver(SubscriptionKind::Logs);
    let mut sealed_headers = state
        .events
        .subscribe_receiver(SubscriptionKind::NewSealedHeader);

    let (mut sender, mut receiver) = socket.split();

    loop {
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let response = connection.handle_request(&text);
                        if sender
                            .send(Message::Text(response))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sender
                            .send(Message::Pong(payload))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            event = new_heads.recv() => {
                let frames = notifications_for(&connection, SubscriptionKind::NewHeads, event);
                if send_frames(&mut sender, frames).await.is_err() {
                    break;
                }
            }
            event = committed_leaders.recv() => {
                let frames = notifications_for(&connection, SubscriptionKind::NewCommittedLeader, event);
                if send_frames(&mut sender, frames).await.is_err() {
                    break;
                }
            }
            event = pending.recv() => {
                let frames = notifications_for(&connection, SubscriptionKind::PendingTransactions, event);
                if send_frames(&mut sender, frames).await.is_err() {
                    break;
                }
            }
            event = logs.recv() => {
                let frames = notifications_for(&connection, SubscriptionKind::Logs, event);
                if send_frames(&mut sender, frames).await.is_err() {
                    break;
                }
            }
            event = sealed_headers.recv() => {
                let frames = notifications_for(&connection, SubscriptionKind::NewSealedHeader, event);
                if send_frames(&mut sender, frames).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn send_frames<S>(sender: &mut S, frames: Vec<Value>) -> Result<(), ()>
where
    S: futures::Sink<axum::extract::ws::Message, Error = axum::Error> + Unpin,
{
    use futures::SinkExt;
    for frame in frames {
        sender
            .send(axum::extract::ws::Message::Text(frame.to_string()))
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(connection: &mut Connection, value: Value) -> Value {
        let raw = serde_json::to_string(&value).expect("serialise request");
        let response = connection.handle_request(&raw);
        serde_json::from_str(&response).expect("parse response")
    }

    #[test]
    fn parses_canonical_and_alias_subscription_names() {
        assert_eq!(
            SubscriptionKind::parse("newHeads").unwrap(),
            SubscriptionKind::NewHeads
        );
        assert_eq!(
            SubscriptionKind::parse("new_committed_leader").unwrap(),
            SubscriptionKind::NewCommittedLeader
        );
        assert_eq!(
            SubscriptionKind::parse("pendingTransactions").unwrap(),
            SubscriptionKind::PendingTransactions
        );
        assert_eq!(
            SubscriptionKind::parse("logs").unwrap(),
            SubscriptionKind::Logs
        );
        assert_eq!(
            SubscriptionKind::parse("newSealedHeader").unwrap(),
            SubscriptionKind::NewSealedHeader
        );
        assert!(SubscriptionKind::parse("blocks").is_err());
    }

    #[test]
    fn subscribe_returns_hex_id_and_unsubscribe_removes_it() {
        let mut connection = Connection::default();
        let response = request(
            &mut connection,
            json!({"jsonrpc":"2.0","id":1,"method":"subscribe","params":["newHeads"]}),
        );
        assert_eq!(response["result"], json!("0x1"));

        let response = request(
            &mut connection,
            json!({"jsonrpc":"2.0","id":2,"method":"unsubscribe","params":["0x1"]}),
        );
        assert_eq!(response["result"], json!(true));

        // Unsubscribing twice reports the subscription no longer exists.
        let response = request(
            &mut connection,
            json!({"jsonrpc":"2.0","id":3,"method":"unsubscribe","params":["0x1"]}),
        );
        assert_eq!(response["result"], json!(false));
    }

    #[test]
    fn subscribe_accepts_bare_string_param_variant() {
        let mut connection = Connection::default();
        let response = request(
            &mut connection,
            json!({"jsonrpc":"2.0","id":1,"method":"subscribe","params":"newCommittedLeader"}),
        );
        assert_eq!(response["result"], json!("0x1"));
    }

    #[test]
    fn unknown_subscription_is_an_invalid_params_error() {
        let mut connection = Connection::default();
        let response = request(
            &mut connection,
            json!({"jsonrpc":"2.0","id":1,"method":"subscribe","params":["nope"]}),
        );
        assert_eq!(response["error"]["code"], json!(-32602));
    }

    #[test]
    fn notifications_only_reach_matching_subscriptions() {
        let mut connection = Connection::default();
        request(
            &mut connection,
            json!({"jsonrpc":"2.0","id":1,"method":"subscribe","params":["newHeads"]}),
        );
        request(
            &mut connection,
            json!({"jsonrpc":"2.0","id":2,"method":"subscribe","params":["pendingTransactions"]}),
        );

        let event = json!({"hash": "0xabc"});
        let frames = notifications_for(&connection, SubscriptionKind::NewHeads, Ok(event.clone()));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["method"], json!("kovanica_subscription"));
        assert_eq!(frames[0]["params"]["subscription"], json!("0x1"));
        assert_eq!(frames[0]["params"]["result"], event);

        // A lagged receiver yields no frames rather than an error.
        let frames = notifications_for(
            &connection,
            SubscriptionKind::NewHeads,
            Err(broadcast::error::RecvError::Lagged(3)),
        );
        assert!(frames.is_empty());
    }

    #[test]
    fn eth_subscribe_and_unsubscribe_with_filter() {
        let mut connection = Connection::new(3);
        let response = request(
            &mut connection,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_subscribe",
                "params": ["logs", {
                    "topics": ["transfer"]
                }]
            }),
        );
        assert_eq!(response["result"], json!("0x1"));

        // Event matching topic "transfer"
        let matching_event = json!([{
            "tx_hash": "0x1111",
            "success": true,
            "gas_used": 21000,
            "error": null,
            "events": [{
                "address": "kvnc1111111111111111111111111111111111111111111111111111111111dag",
                "topic": b"transfer".to_vec(),
                "data": [1, 2, 3]
            }]
        }]);

        let frames = notifications_for(&connection, SubscriptionKind::Logs, Ok(matching_event));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["method"], json!("eth_subscription"));
        assert_eq!(frames[0]["params"]["subscription"], json!("0x1"));
        assert_eq!(frames[0]["params"]["result"][0]["gas_used"], json!(21000));

        // Event with non-matching topic "approval"
        let non_matching_event = json!([{
            "tx_hash": "0x2222",
            "success": true,
            "gas_used": 21000,
            "error": null,
            "events": [{
                "address": "kvnc1111111111111111111111111111111111111111111111111111111111dag",
                "topic": b"approval".to_vec(),
                "data": [1, 2, 3]
            }]
        }]);

        let frames = notifications_for(&connection, SubscriptionKind::Logs, Ok(non_matching_event));
        assert!(
            frames.is_empty(),
            "filtered subscriber should not receive non-matching event"
        );

        // eth_unsubscribe
        let response = request(
            &mut connection,
            json!({"jsonrpc": "2.0", "id": 2, "method": "eth_unsubscribe", "params": ["0x1"]}),
        );
        assert_eq!(response["result"], json!(true));
    }

    #[test]
    fn subscribe_enforces_per_connection_cap() {
        let mut connection = Connection::new(3);
        for i in 1..=32 {
            let resp = request(
                &mut connection,
                json!({"jsonrpc": "2.0", "id": i, "method": "subscribe", "params": ["newHeads"]}),
            );
            assert!(
                resp["error"].is_null(),
                "subscription {i} should succeed: {resp}"
            );
        }
        let overflow = request(
            &mut connection,
            json!({"jsonrpc": "2.0", "id": 33, "method": "subscribe", "params": ["newHeads"]}),
        );
        assert!(
            !overflow["error"].is_null(),
            "33rd subscription must be rejected"
        );
        assert_eq!(overflow["error"]["code"], json!(-32600));
    }

    #[test]
    fn ws_connection_limiter_enforces_cap_and_releases_on_drop() {
        let limiter = Arc::new(WsConnectionLimiter::new(2));
        let ip: IpAddr = "198.51.100.10".parse().unwrap();

        let rejected_before = rpc_ws_rejected_connections_total();

        let g1 = limiter.try_acquire(ip).expect("1st connection allowed");
        let g2 = limiter.try_acquire(ip).expect("2nd connection allowed");
        assert_eq!(limiter.active_for(ip), 2);
        assert_eq!(limiter.total_active(), 2);
        assert_eq!(limiter.tracked_ips(), 1);

        let err = limiter
            .try_acquire(ip)
            .expect_err("3rd connection must be rejected");
        assert_eq!(err, WsConnectionLimitExceeded { max_per_ip: 2 });
        assert!(rpc_ws_rejected_connections_total() > rejected_before);
        assert_eq!(limiter.active_for(ip), 2);

        // Dropping one guard frees its slot cleanly.
        drop(g1);
        assert_eq!(limiter.active_for(ip), 1);
        assert_eq!(limiter.total_active(), 1);

        let g3 = limiter
            .try_acquire(ip)
            .expect("slot released after drop must be reusable");
        assert_eq!(limiter.active_for(ip), 2);

        // Dropping all guards cleans up the map entry completely.
        drop(g2);
        drop(g3);
        assert_eq!(limiter.active_for(ip), 0);
        assert_eq!(limiter.total_active(), 0);
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn ws_connection_limiter_isolates_distinct_ips_and_groups_ipv6_slash64() {
        let limiter = Arc::new(WsConnectionLimiter::new(1));
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        let v6_a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let v6_b: IpAddr = "2001:db8:abcd:1234::9999".parse().unwrap();
        let v6_other: IpAddr = "2001:db8:abcd:5678::1".parse().unwrap();

        let _ga = limiter.try_acquire(ip_a).expect("ip_a allowed");
        assert!(
            limiter.try_acquire(ip_a).is_err(),
            "ip_a reached its cap of 1"
        );
        let _gb = limiter
            .try_acquire(ip_b)
            .expect("ip_b has an independent cap");

        let _gv6 = limiter.try_acquire(v6_a).expect("v6_a allowed");
        assert!(
            limiter.try_acquire(v6_b).is_err(),
            "same IPv6 /64 must share connection cap"
        );
        let _gv6_other = limiter
            .try_acquire(v6_other)
            .expect("different IPv6 /64 has independent cap");
        assert_eq!(limiter.total_active(), 4);
        assert_eq!(limiter.tracked_ips(), 4);
    }

    #[test]
    fn lagged_broadcast_increments_lag_metric() {
        let connection = Connection::default();
        let before = rpc_ws_lagged_messages_total();
        let frames = notifications_for(
            &connection,
            SubscriptionKind::NewHeads,
            Err(broadcast::error::RecvError::Lagged(7)),
        );
        assert!(frames.is_empty());
        assert!(
            rpc_ws_lagged_messages_total() >= before + 7,
            "lagged counter should increase by skipped count"
        );
    }
}
