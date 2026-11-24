//! Indexer orchestration: sync loop + broadcast + lock-free lag telemetry.

use crate::node_reader::{NodeReader, NodeReaderError};
use crate::store::{IndexerStore, StoreError};
pub use crate::types::classify_sync_lag;
use crate::types::{
    IndexedEvent, IndexerHealth, IndexerMetricsSnapshot, IndexerStatus, PruneDryRunReport,
    StoreIntegrityReport,
};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::info;

/// Lock-free telemetry for indexer sync lag, block throughput, store integrity, and prune dry-runs.
#[derive(Debug, Default)]
pub struct IndexerMetrics {
    indexed_height: AtomicU64,
    node_head_height: AtomicU64,
    blocks_processed_total: AtomicU64,
    integrity_checks_total: AtomicU64,
    integrity_check_failures_total: AtomicU64,
    integrity_last_ok: AtomicU64,
    integrity_last_issues: AtomicU64,
    integrity_last_checked_at_ms: AtomicU64,
    prune_dry_runs_total: AtomicU64,
    prune_dry_run_prunable_heights: AtomicU64,
    prune_dry_run_prunable_events: AtomicU64,
    prune_dry_run_prunable_txs: AtomicU64,
    prune_dry_run_prunable_bytes: AtomicU64,
}

impl IndexerMetrics {
    pub fn new(initial_indexed_height: u64) -> Self {
        Self {
            indexed_height: AtomicU64::new(initial_indexed_height),
            node_head_height: AtomicU64::new(0),
            blocks_processed_total: AtomicU64::new(0),
            integrity_checks_total: AtomicU64::new(0),
            integrity_check_failures_total: AtomicU64::new(0),
            integrity_last_ok: AtomicU64::new(0),
            integrity_last_issues: AtomicU64::new(0),
            integrity_last_checked_at_ms: AtomicU64::new(0),
            prune_dry_runs_total: AtomicU64::new(0),
            prune_dry_run_prunable_heights: AtomicU64::new(0),
            prune_dry_run_prunable_events: AtomicU64::new(0),
            prune_dry_run_prunable_txs: AtomicU64::new(0),
            prune_dry_run_prunable_bytes: AtomicU64::new(0),
        }
    }

    pub fn set_indexed_height(&self, height: u64) {
        self.indexed_height.store(height, Ordering::Relaxed);
    }

    pub fn set_node_head_height(&self, height: u64) {
        self.node_head_height.store(height, Ordering::Relaxed);
    }

    pub fn inc_blocks_processed(&self, count: u64) {
        if count > 0 {
            self.blocks_processed_total
                .fetch_add(count, Ordering::Relaxed);
        }
    }

    /// Record the outcome of a store integrity check.
    pub fn record_integrity_report(&self, report: &StoreIntegrityReport) {
        self.integrity_checks_total.fetch_add(1, Ordering::Relaxed);
        if !report.ok {
            self.integrity_check_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
        self.integrity_last_ok
            .store(u64::from(report.ok), Ordering::Relaxed);
        self.integrity_last_issues
            .store(report.issues.len() as u64, Ordering::Relaxed);
        self.integrity_last_checked_at_ms
            .store(report.checked_at_ms, Ordering::Relaxed);
    }

    /// Record the candidate counts from a read-only prune dry-run.
    pub fn record_prune_dry_run(&self, report: &PruneDryRunReport) {
        self.prune_dry_runs_total.fetch_add(1, Ordering::Relaxed);
        self.prune_dry_run_prunable_heights
            .store(report.prunable_heights, Ordering::Relaxed);
        self.prune_dry_run_prunable_events
            .store(report.prunable_events, Ordering::Relaxed);
        self.prune_dry_run_prunable_txs
            .store(report.prunable_txs, Ordering::Relaxed);
        self.prune_dry_run_prunable_bytes
            .store(report.prunable_bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> IndexerMetricsSnapshot {
        let indexed_height = self.indexed_height.load(Ordering::Relaxed);
        let node_head_height = self.node_head_height.load(Ordering::Relaxed);
        let lag_blocks = node_head_height.saturating_sub(indexed_height);
        let blocks_processed_total = self.blocks_processed_total.load(Ordering::Relaxed);
        IndexerMetricsSnapshot {
            indexed_height,
            node_head_height,
            lag_blocks,
            blocks_processed_total,
            integrity_checks_total: self.integrity_checks_total.load(Ordering::Relaxed),
            integrity_check_failures_total: self
                .integrity_check_failures_total
                .load(Ordering::Relaxed),
            integrity_last_ok: self.integrity_last_ok.load(Ordering::Relaxed),
            integrity_last_issues: self.integrity_last_issues.load(Ordering::Relaxed),
            integrity_last_checked_at_ms: self.integrity_last_checked_at_ms.load(Ordering::Relaxed),
            prune_dry_runs_total: self.prune_dry_runs_total.load(Ordering::Relaxed),
            prune_dry_run_prunable_heights: self
                .prune_dry_run_prunable_heights
                .load(Ordering::Relaxed),
            prune_dry_run_prunable_events: self
                .prune_dry_run_prunable_events
                .load(Ordering::Relaxed),
            prune_dry_run_prunable_txs: self.prune_dry_run_prunable_txs.load(Ordering::Relaxed),
            prune_dry_run_prunable_bytes: self.prune_dry_run_prunable_bytes.load(Ordering::Relaxed),
        }
    }

    /// Render indexer metrics in OpenMetrics text exposition format.
    pub fn render_openmetrics(&self) -> String {
        let snap = self.snapshot();
        let mut out = String::with_capacity(1536);
        let _ = writeln!(
            out,
            "# HELP indexer_indexed_height Latest block height indexed by kovanica-indexer.\n\
             # TYPE indexer_indexed_height gauge\n\
             indexer_indexed_height {}\n\
             # HELP indexer_node_head_height Latest block height observed from the L1 node.\n\
             # TYPE indexer_node_head_height gauge\n\
             indexer_node_head_height {}\n\
             # HELP indexer_lag_blocks Number of blocks the indexer is behind the L1 node head.\n\
             # TYPE indexer_lag_blocks gauge\n\
             indexer_lag_blocks {}\n\
             # HELP indexer_blocks_processed_total Total number of blocks processed by kovanica-indexer.\n\
             # TYPE indexer_blocks_processed_total counter\n\
             indexer_blocks_processed_total {}\n\
             # HELP indexer_store_integrity_checks_total Total number of store integrity checks executed.\n\
             # TYPE indexer_store_integrity_checks_total counter\n\
             indexer_store_integrity_checks_total {}\n\
             # HELP indexer_store_integrity_check_failures_total Total number of store integrity checks that reported issues.\n\
             # TYPE indexer_store_integrity_check_failures_total counter\n\
             indexer_store_integrity_check_failures_total {}\n\
             # HELP indexer_store_integrity_ok Result of the most recent store integrity check (1 = ok, 0 = failed or unchecked).\n\
             # TYPE indexer_store_integrity_ok gauge\n\
             indexer_store_integrity_ok {}\n\
             # HELP indexer_store_integrity_issues Number of issues found by the most recent store integrity check.\n\
             # TYPE indexer_store_integrity_issues gauge\n\
             indexer_store_integrity_issues {}\n\
             # HELP indexer_store_integrity_last_checked_timestamp_ms Unix timestamp in milliseconds of the most recent store integrity check.\n\
             # TYPE indexer_store_integrity_last_checked_timestamp_ms gauge\n\
             indexer_store_integrity_last_checked_timestamp_ms {}\n\
             # HELP indexer_prune_dry_runs_total Total number of read-only prune dry-run evaluations executed.\n\
             # TYPE indexer_prune_dry_runs_total counter\n\
             indexer_prune_dry_runs_total {}\n\
             # HELP indexer_prune_dry_run_prunable_heights Number of height buckets eligible for pruning in the latest dry-run.\n\
             # TYPE indexer_prune_dry_run_prunable_heights gauge\n\
             indexer_prune_dry_run_prunable_heights {}\n\
             # HELP indexer_prune_dry_run_prunable_events Number of events eligible for pruning in the latest dry-run.\n\
             # TYPE indexer_prune_dry_run_prunable_events gauge\n\
             indexer_prune_dry_run_prunable_events {}\n\
             # HELP indexer_prune_dry_run_prunable_txs Number of distinct transactions eligible for pruning in the latest dry-run.\n\
             # TYPE indexer_prune_dry_run_prunable_txs gauge\n\
             indexer_prune_dry_run_prunable_txs {}\n\
             # HELP indexer_prune_dry_run_prunable_bytes Estimated serialized bytes eligible for pruning in the latest dry-run.\n\
             # TYPE indexer_prune_dry_run_prunable_bytes gauge\n\
             indexer_prune_dry_run_prunable_bytes {}\n\
             # EOF",
            snap.indexed_height,
            snap.node_head_height,
            snap.lag_blocks,
            snap.blocks_processed_total,
            snap.integrity_checks_total,
            snap.integrity_check_failures_total,
            snap.integrity_last_ok,
            snap.integrity_last_issues,
            snap.integrity_last_checked_at_ms,
            snap.prune_dry_runs_total,
            snap.prune_dry_run_prunable_heights,
            snap.prune_dry_run_prunable_events,
            snap.prune_dry_run_prunable_txs,
            snap.prune_dry_run_prunable_bytes,
        );
        out
    }
}

pub struct Indexer {
    pub store: Arc<IndexerStore>,
    pub node: Arc<dyn NodeReader>,
    pub tx: broadcast::Sender<IndexedEvent>,
    pub latest_node_height: Arc<RwLock<u64>>,
    pub metrics: Arc<IndexerMetrics>,
}

impl Indexer {
    pub fn new(store: Arc<IndexerStore>, node: Arc<dyn NodeReader>) -> Self {
        let (tx, _) = broadcast::channel(1024);
        let initial_indexed = store.latest_indexed_height();
        Self {
            store,
            node,
            tx,
            latest_node_height: Arc::new(RwLock::new(0)),
            metrics: Arc::new(IndexerMetrics::new(initial_indexed)),
        }
    }

    pub async fn sync_once(&self) -> Result<usize, NodeReaderError> {
        let latest = self.node.latest_height().await?;
        *self.latest_node_height.write().await = latest;
        self.metrics.set_node_head_height(latest);
        let current = self.store.latest_indexed_height();
        self.metrics.set_indexed_height(current);
        if latest <= current {
            return Ok(0);
        }
        let from = current + 1;
        let to = latest;
        let batches = self.node.receipts_in_range(from, to).await?;
        let mut total = 0;
        for (height, receipts) in batches {
            let mut events = self.node.receipts_to_events(height, &receipts);
            if events.is_empty() {
                // still advance height
                self.store.set_latest_indexed_height(height).ok();
                self.metrics.set_indexed_height(height);
                continue;
            }
            self.store
                .insert_events(&mut events)
                .map_err(|e| NodeReaderError::Store(e.to_string()))?;
            total += events.len();
            for ev in events {
                let _ = self.tx.send(ev);
            }
            self.store.set_latest_indexed_height(height).ok();
            self.metrics.set_indexed_height(height);
        }
        // ensure latest height advanced even if no receipts rows
        self.store.set_latest_indexed_height(to).ok();
        self.metrics.set_indexed_height(to);
        self.metrics
            .inc_blocks_processed(to.saturating_sub(current));
        info!("indexed {} events up to height {}", total, to);
        Ok(total)
    }

    pub async fn status(&self) -> IndexerStatus {
        let snap = self.metrics.snapshot();
        IndexerStatus {
            latest_indexed_height: self.store.latest_indexed_height(),
            latest_node_height: snap.node_head_height,
            event_count: self.store.event_count(),
        }
    }

    pub fn health(&self) -> IndexerHealth {
        let snap = self.metrics.snapshot();
        IndexerHealth {
            status: "ok".to_string(),
            indexed_height: snap.indexed_height,
            node_head_height: snap.node_head_height,
            lag_blocks: snap.lag_blocks,
            sync_state: classify_sync_lag(snap.indexed_height, snap.node_head_height).to_string(),
            event_count: self.store.event_count(),
        }
    }

    /// Execute a read-only store integrity check and record the result in indexer metrics.
    pub fn check_store_integrity(&self) -> Result<StoreIntegrityReport, StoreError> {
        let report = self.store.integrity_check()?;
        self.metrics.record_integrity_report(&report);
        Ok(report)
    }

    /// Execute a read-only prune dry-run and record the candidate counts in indexer metrics.
    pub fn prune_dry_run(&self, keep_heights: u64) -> Result<PruneDryRunReport, StoreError> {
        let report = self.store.prune_dry_run(keep_heights)?;
        self.metrics.record_prune_dry_run(&report);
        Ok(report)
    }
}
