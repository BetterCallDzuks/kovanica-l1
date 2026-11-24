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
    pub integrity_checks_total: u64,
    pub integrity_check_failures_total: u64,
    pub integrity_last_ok: u64,
    pub integrity_last_issues: u64,
    pub integrity_last_checked_at_ms: u64,
    pub prune_dry_runs_total: u64,
    pub prune_dry_run_prunable_heights: u64,
    pub prune_dry_run_prunable_events: u64,
    pub prune_dry_run_prunable_txs: u64,
    pub prune_dry_run_prunable_bytes: u64,
}

/// Result of running a read-only structural integrity check on `IndexerStore`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreIntegrityReport {
    /// True iff no structural, deserialization, or cross-index issues were found.
    pub ok: bool,
    /// Unix timestamp in milliseconds when the check completed.
    pub checked_at_ms: u64,
    /// Storage backend identifier (e.g. `"redb"`).
    pub backend: String,
    /// Latest indexed height recorded in metadata.
    pub latest_indexed_height: u64,
    /// Next monotonic event ID recorded in metadata (0 if unset).
    pub next_id: u64,
    /// Number of rows in `idx_events`.
    pub event_count: u64,
    /// Number of height buckets in `idx_heights`.
    pub height_bucket_count: u64,
    /// Number of address buckets in `idx_by_addr`.
    pub address_bucket_count: u64,
    /// Number of topic buckets in `idx_by_topic`.
    pub topic_bucket_count: u64,
    /// Human-readable descriptions of any detected issues (empty when `ok == true`).
    pub issues: Vec<String>,
}

/// Read-only estimate of indexed data eligible for pruning under a height retention window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruneDryRunReport {
    /// Unix timestamp in milliseconds when the dry-run completed.
    pub checked_at_ms: u64,
    /// Requested number of recent heights to retain.
    pub keep_heights: u64,
    /// Latest indexed height recorded in store metadata.
    pub latest_indexed_height: u64,
    /// Heights strictly below `cutoff_height` would be pruned.
    pub cutoff_height: u64,
    /// Number of height buckets that would be pruned.
    pub prunable_heights: u64,
    /// Number of indexed events/logs that would be pruned.
    pub prunable_events: u64,
    /// Number of distinct `(height, tx_hash)` transactions represented in prunable events.
    pub prunable_txs: u64,
    /// Estimated serialized bytes across event and height tables that would be pruned.
    pub prunable_bytes: u64,
    /// Number of height buckets that would be retained.
    pub retained_heights: u64,
    /// Number of indexed events/logs that would be retained.
    pub retained_events: u64,
    /// Always `false` for dry-run checks, confirming the store was not mutated.
    pub mutated: bool,
}

/// WS subscription filter.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsFilter {
    pub address: Option<String>,
    pub topics: Option<Vec<String>>,
}
