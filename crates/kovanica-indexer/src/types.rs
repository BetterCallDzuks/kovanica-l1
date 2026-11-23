//! Shared types for the indexer.

use kovanica_types::Address;
use serde::{Deserialize, Serialize};

/// One indexed log/event entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedEvent {
    /// Monotonic id assigned by the store.
    pub id: u64,
    /// Committed-leader height the event came from.
    pub height: u64,
    /// Transaction hash (hex-encoded in JSON).
    pub tx_hash: [u8; 32],
    /// Position of the transaction within the block.
    pub tx_index: u64,
    /// Position of the log within the transaction.
    pub log_index: u64,
    /// Emitting address.
    pub address: Address,
    /// Event topic bytes.
    pub topic: Vec<u8>,
    /// Event payload.
    pub data: Vec<u8>,
    /// Whether the originating transaction succeeded.
    pub success: bool,
}

/// Query filter for logs.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LogFilter {
    pub from_height: Option<u64>,
    pub to_height: Option<u64>,
    pub address: Option<String>,
    pub topic: Option<String>,
    pub limit: Option<usize>,
}

/// Indexer status.
#[derive(Debug, Clone, Serialize)]
pub struct IndexerStatus {
    pub latest_indexed_height: u64,
    pub latest_node_height: u64,
    pub event_count: u64,
}

/// Classify indexer sync lag relative to the node head height.
///
/// - `"synced"` when lag <= 2
/// - `"lagging"` when lag <= 50
/// - `"stalled"` when lag > 50
pub fn classify_sync_lag(indexed_height: u64, node_head_height: u64) -> &'static str {
    let lag = node_head_height.saturating_sub(indexed_height);
    if lag <= 2 {
        "synced"
    } else if lag <= 50 {
        "lagging"
    } else {
        "stalled"
    }
}

/// Structured readiness and sync-lag health payload returned by `/health`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexerHealth {
    pub status: String,
    pub indexed_height: u64,
    pub node_head_height: u64,
    pub lag_blocks: u64,
    pub sync_state: String,
    pub event_count: u64,
}

/// Point-in-time snapshot of lock-free indexer telemetry counters and gauges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexerMetricsSnapshot {
    pub indexed_height: u64,
    pub node_head_height: u64,
    pub lag_blocks: u64,
    pub blocks_processed_total: u64,
}

/// WS subscription filter.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsFilter {
    pub address: Option<String>,
    pub topics: Option<Vec<String>>,
}
