//! Indexer orchestration: sync loop + broadcast + lock-free lag telemetry.

use crate::node_reader::{NodeReader, NodeReaderError};
use crate::store::IndexerStore;
pub use crate::types::classify_sync_lag;
use crate::types::{IndexedEvent, IndexerHealth, IndexerMetricsSnapshot, IndexerStatus};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::info;

/// Lock-free telemetry for indexer sync lag and block throughput.
#[derive(Debug, Default)]
pub struct IndexerMetrics {
    indexed_height: AtomicU64,
    node_head_height: AtomicU64,
    blocks_processed_total: AtomicU64,
}

impl IndexerMetrics {
    pub fn new(initial_indexed_height: u64) -> Self {
        Self {
            indexed_height: AtomicU64::new(initial_indexed_height),
            node_head_height: AtomicU64::new(0),
            blocks_processed_total: AtomicU64::new(0),
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
        }
    }

    /// Render indexer metrics in OpenMetrics text exposition format.
    pub fn render_openmetrics(&self) -> String {
        let snap = self.snapshot();
        let mut out = String::with_capacity(512);
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
             # EOF",
            snap.indexed_height,
            snap.node_head_height,
            snap.lag_blocks,
            snap.blocks_processed_total,
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
}
