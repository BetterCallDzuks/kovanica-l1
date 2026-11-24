//! HTTP + WebSocket server for the indexer.

use crate::indexer::Indexer;
use crate::types::{
    IndexedEvent, IndexerHealth, LogFilter, PruneDryRunReport, StoreIntegrityReport, WsFilter,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

#[derive(Debug, Deserialize, Default)]
pub struct HttpFilter {
    #[serde(alias = "fromBlock", alias = "from_height", alias = "from")]
    pub from_height: Option<u64>,
    #[serde(alias = "toBlock", alias = "to_height", alias = "to")]
    pub to_height: Option<u64>,
    pub address: Option<String>,
    pub topic: Option<String>,
    pub limit: Option<usize>,
}

impl From<HttpFilter> for LogFilter {
    fn from(f: HttpFilter) -> Self {
        LogFilter {
            from_height: f.from_height,
            to_height: f.to_height,
            address: f.address,
            topic: f.topic,
            limit: f.limit,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PruneDryRunQuery {
    #[serde(alias = "retention")]
    pub keep_heights: u64,
}

pub fn router(indexer: Arc<Indexer>) -> Router {
    Router::new()
        .route("/logs", get(handle_logs))
        .route("/events", get(handle_logs))
        .route("/contracts/:address/logs", get(handle_contract_logs))
        .route("/contracts/:address/events", get(handle_contract_logs))
        .route("/status", get(handle_status))
        .route("/health", get(handle_health))
        .route("/integrity", get(handle_integrity))
        .route("/prune/dry-run", get(handle_prune_dry_run))
        .route("/metrics", get(handle_metrics))
        .route("/ws", get(handle_ws))
        .with_state(indexer)
}

async fn handle_logs(
    State(idx): State<Arc<Indexer>>,
    Query(f): Query<HttpFilter>,
) -> Result<Json<Vec<IndexedEvent>>, StatusCode> {
    let filter: LogFilter = f.into();
    let events = idx
        .store
        .query(&filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(events))
}

async fn handle_contract_logs(
    State(idx): State<Arc<Indexer>>,
    Path(address): Path<String>,
    Query(f): Query<HttpFilter>,
) -> Result<Json<Vec<IndexedEvent>>, StatusCode> {
    let mut filter: LogFilter = f.into();
    filter.address = Some(address);
    let events = idx
        .store
        .query(&filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(events))
}

async fn handle_status(State(idx): State<Arc<Indexer>>) -> Json<crate::types::IndexerStatus> {
    Json(idx.status().await)
}

async fn handle_health(State(idx): State<Arc<Indexer>>) -> Json<IndexerHealth> {
    Json(idx.health())
}

async fn handle_integrity(
    State(idx): State<Arc<Indexer>>,
) -> Result<(StatusCode, Json<StoreIntegrityReport>), StatusCode> {
    let report = idx
        .check_store_integrity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let status = if report.ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Ok((status, Json(report)))
}

async fn handle_prune_dry_run(
    State(idx): State<Arc<Indexer>>,
    Query(q): Query<PruneDryRunQuery>,
) -> Result<Json<PruneDryRunReport>, StatusCode> {
    let report = idx
        .prune_dry_run(q.keep_heights)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(report))
}

async fn handle_metrics(State(idx): State<Arc<Indexer>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)],
        idx.metrics.render_openmetrics(),
    )
}

async fn handle_ws(ws: WebSocketUpgrade, State(idx): State<Arc<Indexer>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_loop(socket, idx))
}

async fn ws_loop(mut socket: WebSocket, idx: Arc<Indexer>) {
    let mut rx = idx.tx.subscribe();
    let mut filter: WsFilter = WsFilter::default();

    // read initial filter (optional) with timeout
    // We'll just loop handling incoming messages and broadcast.
    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(sub) = v.get("subscribe") {
                                if let Ok(f) = serde_json::from_value::<WsFilter>(sub.clone()) {
                                    filter = f;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            ev = rx.recv() => {
                match ev {
                    Ok(event) => {
                        if !matches_filter(&filter, &event) { continue; }
                        let json = serde_json::to_string(&event).unwrap_or_default();
                        if socket.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        }
    }
}

fn matches_filter(filter: &WsFilter, event: &IndexedEvent) -> bool {
    if let Some(addr) = &filter.address {
        if addr != &event.address.to_string() && addr != &hex::encode(event.address.0) {
            return false;
        }
    }
    if let Some(topics) = &filter.topics {
        let topic_str = String::from_utf8_lossy(&event.topic).to_string();
        let topic_hex = format!("0x{}", hex::encode(&event.topic));
        let ok = topics
            .iter()
            .any(|t| t == &topic_str || t == &topic_hex || t.as_bytes() == event.topic);
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_reader::{NodeReader, NodeReaderError};
    use crate::store::IndexerStore;
    use crate::types::classify_sync_lag;
    use async_trait::async_trait;
    use kovanica_execution::TransactionReceipt;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::TcpListener;

    struct StubNodeReader {
        head: AtomicU64,
    }

    impl StubNodeReader {
        fn new(head: u64) -> Self {
            Self {
                head: AtomicU64::new(head),
            }
        }
    }

    #[async_trait]
    impl NodeReader for StubNodeReader {
        async fn latest_height(&self) -> Result<u64, NodeReaderError> {
            Ok(self.head.load(Ordering::Relaxed))
        }

        async fn receipts_in_range(
            &self,
            _from: u64,
            _to: u64,
        ) -> Result<Vec<(u64, Vec<TransactionReceipt>)>, NodeReaderError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn classify_sync_lag_boundaries() {
        // synced: lag <= 2 (including ahead of node head via saturating_sub)
        assert_eq!(classify_sync_lag(100, 100), "synced");
        assert_eq!(classify_sync_lag(105, 100), "synced");
        assert_eq!(classify_sync_lag(99, 100), "synced");
        assert_eq!(classify_sync_lag(98, 100), "synced");

        // lagging: 3 <= lag <= 50
        assert_eq!(classify_sync_lag(97, 100), "lagging");
        assert_eq!(classify_sync_lag(75, 100), "lagging");
        assert_eq!(classify_sync_lag(50, 100), "lagging");

        // stalled: lag > 50
        assert_eq!(classify_sync_lag(49, 100), "stalled");
        assert_eq!(classify_sync_lag(0, 1000), "stalled");
    }

    #[tokio::test]
    async fn metrics_endpoint_openmetrics_format_and_updates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(IndexerStore::new(dir.path().join("indexer.redb")).unwrap());
        let reader = Arc::new(StubNodeReader::new(5));
        let indexer = Arc::new(Indexer::new(store, reader.clone()));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(indexer.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Before sync, simulate lagging state directly via lock-free metrics.
        indexer.metrics.set_node_head_height(10);
        indexer.metrics.set_indexed_height(2);

        let url = format!("http://{addr}/metrics");
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("openmetrics-text"),
            "unexpected content-type: {content_type}"
        );
        let body = resp.text().await.unwrap();
        assert!(body.ends_with("# EOF\n"), "missing trailing # EOF\\n");

        // Verify zero duplicate # TYPE headers and all four metrics exist before # EOF.
        let eof_pos = body.find("# EOF\n").unwrap();
        let mut seen_types = HashSet::new();
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let metric_name = rest.split_whitespace().next().unwrap();
                assert!(
                    seen_types.insert(metric_name.to_string()),
                    "duplicate # TYPE header for {metric_name}"
                );
            }
        }
        for expected in [
            "indexer_indexed_height",
            "indexer_node_head_height",
            "indexer_lag_blocks",
            "indexer_blocks_processed_total",
        ] {
            assert!(
                seen_types.contains(expected),
                "missing # TYPE for {expected}"
            );
            let pos = body.find(expected).unwrap();
            assert!(pos < eof_pos, "{expected} must appear before # EOF");
        }
        assert!(body.contains("indexer_indexed_height 2\n"));
        assert!(body.contains("indexer_node_head_height 10\n"));
        assert!(body.contains("indexer_lag_blocks 8\n"));
        assert!(body.contains("indexer_blocks_processed_total 0\n"));

        // Perform a real sync up to height 5, then advance node head to 12 and sync again.
        indexer.sync_once().await.unwrap();
        let body_after_first = reqwest::get(&url).await.unwrap().text().await.unwrap();
        assert!(body_after_first.contains("indexer_indexed_height 5\n"));
        assert!(body_after_first.contains("indexer_node_head_height 5\n"));
        assert!(body_after_first.contains("indexer_lag_blocks 0\n"));
        assert!(body_after_first.contains("indexer_blocks_processed_total 5\n"));

        reader.head.store(12, Ordering::Relaxed);
        indexer.sync_once().await.unwrap();
        let body_after_second = reqwest::get(&url).await.unwrap().text().await.unwrap();
        assert!(body_after_second.contains("indexer_indexed_height 12\n"));
        assert!(body_after_second.contains("indexer_node_head_height 12\n"));
        assert!(body_after_second.contains("indexer_lag_blocks 0\n"));
        assert!(body_after_second.contains("indexer_blocks_processed_total 12\n"));
    }

    #[tokio::test]
    async fn health_endpoint_reports_sync_state_and_lag_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(IndexerStore::new(dir.path().join("indexer.redb")).unwrap());
        let reader = Arc::new(StubNodeReader::new(20));
        let indexer = Arc::new(Indexer::new(store, reader));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(indexer.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/health");

        // Synced after sync_once (20 / 20 -> lag 0).
        indexer.sync_once().await.unwrap();
        let synced: IndexerHealth = reqwest::get(&url).await.unwrap().json().await.unwrap();
        assert_eq!(synced.status, "ok");
        assert_eq!(synced.indexed_height, 20);
        assert_eq!(synced.node_head_height, 20);
        assert_eq!(synced.lag_blocks, 0);
        assert_eq!(synced.sync_state, "synced");

        // Lagging (20 / 45 -> lag 25).
        indexer.metrics.set_node_head_height(45);
        let lagging: IndexerHealth = reqwest::get(&url).await.unwrap().json().await.unwrap();
        assert_eq!(lagging.indexed_height, 20);
        assert_eq!(lagging.node_head_height, 45);
        assert_eq!(lagging.lag_blocks, 25);
        assert_eq!(lagging.sync_state, "lagging");

        // Stalled (20 / 100 -> lag 80).
        indexer.metrics.set_node_head_height(100);
        let stalled: IndexerHealth = reqwest::get(&url).await.unwrap().json().await.unwrap();
        assert_eq!(stalled.indexed_height, 20);
        assert_eq!(stalled.node_head_height, 100);
        assert_eq!(stalled.lag_blocks, 80);
        assert_eq!(stalled.sync_state, "stalled");
    }

    #[tokio::test]
    async fn integrity_and_prune_dry_run_endpoints_record_openmetrics() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(IndexerStore::new(dir.path().join("indexer.redb")).unwrap());
        let mut events = vec![
            IndexedEvent {
                id: 0,
                height: 1,
                tx_hash: [1u8; 32],
                tx_index: 0,
                log_index: 0,
                address: kovanica_types::Address([2u8; 32]),
                topic: b"transfer".to_vec(),
                data: vec![1, 2, 3],
                success: true,
            },
            IndexedEvent {
                id: 0,
                height: 2,
                tx_hash: [2u8; 32],
                tx_index: 0,
                log_index: 0,
                address: kovanica_types::Address([2u8; 32]),
                topic: b"transfer".to_vec(),
                data: vec![4, 5, 6],
                success: true,
            },
            IndexedEvent {
                id: 0,
                height: 3,
                tx_hash: [3u8; 32],
                tx_index: 0,
                log_index: 0,
                address: kovanica_types::Address([3u8; 32]),
                topic: b"mint".to_vec(),
                data: vec![7, 8, 9],
                success: true,
            },
        ];
        store.insert_events(&mut events).unwrap();
        store.set_latest_indexed_height(3).unwrap();

        let reader = Arc::new(StubNodeReader::new(3));
        let indexer = Arc::new(Indexer::new(store.clone(), reader));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(indexer.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Call GET /integrity
        let integrity_resp = reqwest::get(format!("http://{addr}/integrity"))
            .await
            .unwrap();
        assert_eq!(integrity_resp.status(), StatusCode::OK);
        let integrity: StoreIntegrityReport = integrity_resp.json().await.unwrap();
        assert!(integrity.ok);
        assert_eq!(integrity.backend, "redb");
        assert_eq!(integrity.event_count, 3);
        assert_eq!(integrity.height_bucket_count, 3);

        // Call GET /prune/dry-run?keep_heights=1 (retains height 3, prunes heights 1 and 2)
        let prune_resp = reqwest::get(format!("http://{addr}/prune/dry-run?keep_heights=1"))
            .await
            .unwrap();
        assert_eq!(prune_resp.status(), StatusCode::OK);
        let prune: PruneDryRunReport = prune_resp.json().await.unwrap();
        assert!(!prune.mutated);
        assert_eq!(prune.cutoff_height, 3);
        assert_eq!(prune.prunable_heights, 2);
        assert_eq!(prune.prunable_events, 2);
        assert_eq!(prune.prunable_txs, 2);
        assert!(prune.prunable_bytes > 0);
        assert_eq!(prune.retained_heights, 1);
        assert_eq!(prune.retained_events, 1);

        // Ensure zero mutation after HTTP dry-run
        assert_eq!(store.event_count(), 3);

        // Verify OpenMetrics exposition reflects integrity and prune dry-run counters/gauges
        let metrics_body = reqwest::get(format!("http://{addr}/metrics"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(metrics_body.ends_with("# EOF\n"));
        assert!(metrics_body.contains("indexer_store_integrity_checks_total 1\n"));
        assert!(metrics_body.contains("indexer_store_integrity_check_failures_total 0\n"));
        assert!(metrics_body.contains("indexer_store_integrity_ok 1\n"));
        assert!(metrics_body.contains("indexer_store_integrity_issues 0\n"));
        assert!(metrics_body.contains("indexer_prune_dry_runs_total 1\n"));
        assert!(metrics_body.contains("indexer_prune_dry_run_prunable_heights 2\n"));
        assert!(metrics_body.contains("indexer_prune_dry_run_prunable_events 2\n"));
        assert!(metrics_body.contains("indexer_prune_dry_run_prunable_txs 2\n"));
        assert!(metrics_body.contains(&format!(
            "indexer_prune_dry_run_prunable_bytes {}\n",
            prune.prunable_bytes
        )));

        // Also verify failure metrics increment when recording a failing report
        let failing = StoreIntegrityReport {
            ok: false,
            checked_at_ms: 123_456,
            backend: "redb".to_string(),
            latest_indexed_height: 3,
            next_id: 4,
            event_count: 3,
            height_bucket_count: 3,
            address_bucket_count: 2,
            topic_bucket_count: 2,
            issues: vec!["synthetic issue 1".into(), "synthetic issue 2".into()],
        };
        indexer.metrics.record_integrity_report(&failing);
        let snap = indexer.metrics.snapshot();
        assert_eq!(snap.integrity_checks_total, 2);
        assert_eq!(snap.integrity_check_failures_total, 1);
        assert_eq!(snap.integrity_last_ok, 0);
        assert_eq!(snap.integrity_last_issues, 2);
        assert_eq!(snap.integrity_last_checked_at_ms, 123_456);
    }
}
