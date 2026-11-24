//! Persistent redb store for indexed events.

use crate::types::{IndexedEvent, PruneDryRunReport, StoreIntegrityReport};
use redb::{Database, ReadableTable, TableDefinition};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const T_EVENTS: TableDefinition<u64, Vec<u8>> = TableDefinition::new("idx_events");
const T_HEIGHTS: TableDefinition<u64, Vec<u8>> = TableDefinition::new("idx_heights");
const T_BY_ADDR: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("idx_by_addr");
const T_BY_TOPIC: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("idx_by_topic");
const T_META: TableDefinition<&'static str, u64> = TableDefinition::new("idx_meta");

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Other(String),
}

pub struct IndexerStore {
    db: Database,
}

impl IndexerStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(StoreError::Database)?;
        let write = db.begin_write().map_err(StoreError::Transaction)?;
        {
            let _ = write.open_table(T_EVENTS)?;
            let _ = write.open_table(T_HEIGHTS)?;
            let _ = write.open_table(T_BY_ADDR)?;
            let _ = write.open_table(T_BY_TOPIC)?;
            let _ = write.open_table(T_META)?;
        }
        write.commit().map_err(StoreError::Commit)?;
        Ok(Self { db })
    }

    fn hash_topic(topic: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let h = blake3::hash(topic);
        out.copy_from_slice(h.as_bytes());
        out
    }

    pub fn latest_indexed_height(&self) -> u64 {
        let txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return 0,
        };
        let table = match txn.open_table(T_META) {
            Ok(t) => t,
            Err(_) => return 0,
        };
        table
            .get("latest_height")
            .ok()
            .flatten()
            .map(|v| v.value())
            .unwrap_or(0)
    }

    pub fn set_latest_indexed_height(&self, height: u64) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(StoreError::Transaction)?;
        {
            let mut table = txn
                .open_table(T_META)
                .map_err(|e| StoreError::Other(e.to_string()))?;
            table
                .insert("latest_height", &height)
                .map_err(|e| StoreError::Other(e.to_string()))?;
        }
        txn.commit().map_err(StoreError::Commit)?;
        Ok(())
    }

    pub fn event_count(&self) -> u64 {
        let txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return 0,
        };
        let table = match txn.open_table(T_EVENTS) {
            Ok(t) => t,
            Err(_) => return 0,
        };
        {
            let mut c = 0u64;
            if let Ok(iter) = table.iter() {
                for _ in iter {
                    c += 1;
                }
            }
            c
        }
    }

    /// Insert a batch of events for one height. Assigns ids.
    pub fn insert_events(&self, events: &mut [IndexedEvent]) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(StoreError::Transaction)?;
        // next id
        let mut next_id: u64 = {
            let table = txn
                .open_table(T_META)
                .map_err(|e| StoreError::Other(e.to_string()))?;
            table
                .get("next_id")
                .ok()
                .flatten()
                .map(|v| v.value())
                .unwrap_or(1)
        };
        {
            let mut events_table = txn
                .open_table(T_EVENTS)
                .map_err(|e| StoreError::Other(e.to_string()))?;
            let mut heights_table = txn
                .open_table(T_HEIGHTS)
                .map_err(|e| StoreError::Other(e.to_string()))?;
            let mut by_addr = txn
                .open_table(T_BY_ADDR)
                .map_err(|e| StoreError::Other(e.to_string()))?;
            let mut by_topic = txn
                .open_table(T_BY_TOPIC)
                .map_err(|e| StoreError::Other(e.to_string()))?;

            // group ids by height for heights index (all same height usually)
            let mut height_ids: std::collections::BTreeMap<u64, Vec<u64>> =
                std::collections::BTreeMap::new();

            for ev in events.iter_mut() {
                let id = next_id;
                next_id += 1;
                ev.id = id;
                let bytes = bincode::serialize(ev).map_err(StoreError::Serialization)?;
                events_table
                    .insert(id, bytes)
                    .map_err(|e| StoreError::Other(e.to_string()))?;

                height_ids.entry(ev.height).or_default().push(id);

                // address index
                let addr_key = ev.address.0;
                let mut ids: Vec<u64> = match by_addr
                    .get(addr_key)
                    .map_err(|e| StoreError::Other(e.to_string()))?
                {
                    Some(v) => bincode::deserialize(&v.value()).unwrap_or_default(),
                    None => Vec::new(),
                };
                ids.push(id);
                let b = bincode::serialize(&ids).map_err(StoreError::Serialization)?;
                by_addr
                    .insert(addr_key, b)
                    .map_err(|e| StoreError::Other(e.to_string()))?;

                // topic index
                let topic_key = Self::hash_topic(&ev.topic);
                let mut ids: Vec<u64> = match by_topic
                    .get(topic_key)
                    .map_err(|e| StoreError::Other(e.to_string()))?
                {
                    Some(v) => bincode::deserialize(&v.value()).unwrap_or_default(),
                    None => Vec::new(),
                };
                ids.push(id);
                let b = bincode::serialize(&ids).map_err(StoreError::Serialization)?;
                by_topic
                    .insert(topic_key, b)
                    .map_err(|e| StoreError::Other(e.to_string()))?;
            }

            for (h, ids) in height_ids {
                let mut existing: Vec<u64> = match heights_table
                    .get(h)
                    .map_err(|e| StoreError::Other(e.to_string()))?
                {
                    Some(v) => bincode::deserialize(&v.value()).unwrap_or_default(),
                    None => Vec::new(),
                };
                existing.extend(ids);
                let b = bincode::serialize(&existing).map_err(StoreError::Serialization)?;
                heights_table
                    .insert(h, b)
                    .map_err(|e| StoreError::Other(e.to_string()))?;
            }
        }
        {
            let mut table = txn
                .open_table(T_META)
                .map_err(|e| StoreError::Other(e.to_string()))?;
            table
                .insert("next_id", &next_id)
                .map_err(|e| StoreError::Other(e.to_string()))?;
        }
        txn.commit().map_err(StoreError::Commit)?;
        Ok(())
    }

    pub fn get_event(&self, id: u64) -> Result<IndexedEvent, StoreError> {
        let txn = self.db.begin_read().map_err(StoreError::Transaction)?;
        let table = txn
            .open_table(T_EVENTS)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let v = table
            .get(id)
            .map_err(|e| StoreError::Other(e.to_string()))?
            .ok_or_else(|| StoreError::NotFound(format!("event {id}")))?;
        let ev: IndexedEvent =
            bincode::deserialize(&v.value()).map_err(StoreError::Serialization)?;
        Ok(ev)
    }

    /// Query events with filters.
    pub fn query(&self, filter: &crate::types::LogFilter) -> Result<Vec<IndexedEvent>, StoreError> {
        let txn = self.db.begin_read().map_err(StoreError::Transaction)?;
        let events_table = txn
            .open_table(T_EVENTS)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let heights_table = txn
            .open_table(T_HEIGHTS)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let by_addr = txn
            .open_table(T_BY_ADDR)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let by_topic = txn
            .open_table(T_BY_TOPIC)
            .map_err(|e| StoreError::Other(e.to_string()))?;

        // Determine candidate ids
        // height range
        let latest = self.latest_indexed_height();
        let from_h = filter.from_height.unwrap_or(0);
        let to_h = filter.to_height.unwrap_or(latest);
        if from_h > to_h {
            return Ok(Vec::new());
        }
        if to_h - from_h + 1 > 500 {
            return Err(StoreError::Other(
                "block range exceeds maximum of 500".into(),
            ));
        }
        // collect ids from heights in range
        let mut height_ids: Vec<u64> = Vec::new();
        for row in heights_table
            .range(from_h..=to_h)
            .map_err(|e| StoreError::Other(e.to_string()))?
        {
            let (_, v) = row.map_err(|e| StoreError::Other(e.to_string()))?;
            let ids: Vec<u64> = bincode::deserialize(&v.value()).unwrap_or_default();
            height_ids.extend(ids);
        }
        let mut set: std::collections::BTreeSet<u64> = height_ids.into_iter().collect();
        // if no heights rows, but to_h == u64::MAX and from 0, maybe all events? heights index covers all. ok.

        // address filter
        if let Some(addr_str) = &filter.address {
            if let Ok(addr) = addr_str.parse::<kovanica_types::Address>() {
                if let Some(v) = by_addr
                    .get(addr.0)
                    .map_err(|e| StoreError::Other(e.to_string()))?
                {
                    let ids: Vec<u64> = bincode::deserialize(&v.value()).unwrap_or_default();
                    let s: std::collections::BTreeSet<u64> = ids.into_iter().collect();
                    set = set.intersection(&s).copied().collect();
                } else {
                    set.clear();
                }
            }
        }

        // topic filter
        if let Some(topic_str) = &filter.topic {
            let topic_bytes = if let Some(hex_str) = topic_str.strip_prefix("0x") {
                hex::decode(hex_str).unwrap_or_else(|_| topic_str.as_bytes().to_vec())
            } else {
                topic_str.as_bytes().to_vec()
            };
            let key = Self::hash_topic(&topic_bytes);
            if let Some(v) = by_topic
                .get(key)
                .map_err(|e| StoreError::Other(e.to_string()))?
            {
                let ids: Vec<u64> = bincode::deserialize(&v.value()).unwrap_or_default();
                let s: std::collections::BTreeSet<u64> = ids.into_iter().collect();
                set = set.intersection(&s).copied().collect();
            } else {
                set.clear();
            }
        }

        let limit = filter.limit.unwrap_or(2000).min(2000);
        let mut out = Vec::new();
        for id in set.into_iter().take(limit) {
            if let Some(v) = events_table
                .get(id)
                .map_err(|e| StoreError::Other(e.to_string()))?
            {
                let ev: IndexedEvent =
                    bincode::deserialize(&v.value()).map_err(StoreError::Serialization)?;
                out.push(ev);
            }
        }
        // sort by height then id
        out.sort_by_key(|e| (e.height, e.id));
        Ok(out)
    }

    /// Run a read-only structural and cross-index integrity check across all store tables.
    pub fn integrity_check(&self) -> Result<StoreIntegrityReport, StoreError> {
        let txn = self.db.begin_read().map_err(StoreError::Transaction)?;
        let events_table = txn
            .open_table(T_EVENTS)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let heights_table = txn
            .open_table(T_HEIGHTS)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let by_addr = txn
            .open_table(T_BY_ADDR)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let by_topic = txn
            .open_table(T_BY_TOPIC)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let meta_table = txn
            .open_table(T_META)
            .map_err(|e| StoreError::Other(e.to_string()))?;

        let mut issues: Vec<String> = Vec::new();

        // 1. Scan primary events table and collect expected secondary index memberships.
        // Map: id -> (height, address bytes, topic hash)
        let mut events_meta: HashMap<u64, (u64, [u8; 32], [u8; 32])> = HashMap::new();
        let mut event_count: u64 = 0;
        let mut max_event_id: u64 = 0;
        let mut max_event_height: u64 = 0;

        for row in events_table
            .iter()
            .map_err(|e| StoreError::Other(e.to_string()))?
        {
            let (k, v) = row.map_err(|e| StoreError::Other(e.to_string()))?;
            let id = k.value();
            event_count += 1;
            if id > max_event_id {
                max_event_id = id;
            }
            match bincode::deserialize::<IndexedEvent>(&v.value()) {
                Ok(ev) => {
                    if ev.id != id {
                        issues.push(format!(
                            "idx_events key/payload id mismatch: key={id}, payload.id={}",
                            ev.id
                        ));
                    }
                    if ev.height > max_event_height {
                        max_event_height = ev.height;
                    }
                    events_meta.insert(id, (ev.height, ev.address.0, Self::hash_topic(&ev.topic)));
                }
                Err(e) => {
                    issues.push(format!("idx_events corrupt payload for id={id}: {e}"));
                }
            }
        }

        // 2. Verify metadata consistency.
        let latest_indexed_height_opt = meta_table
            .get("latest_height")
            .map_err(|e| StoreError::Other(e.to_string()))?
            .map(|v| v.value());
        let next_id_opt = meta_table
            .get("next_id")
            .map_err(|e| StoreError::Other(e.to_string()))?
            .map(|v| v.value());

        let latest_indexed_height = latest_indexed_height_opt.unwrap_or(0);
        let next_id = next_id_opt.unwrap_or(0);

        if event_count > 0 {
            if next_id <= max_event_id {
                issues.push(format!(
                    "idx_meta next_id ({next_id}) must be greater than max event id ({max_event_id})"
                ));
            }
            if max_event_height > latest_indexed_height {
                issues.push(format!(
                    "idx_meta latest_height ({latest_indexed_height}) is behind max indexed event height ({max_event_height})"
                ));
            }
        }

        // 3. Verify height index.
        let mut height_bucket_count: u64 = 0;
        let mut seen_in_heights: HashSet<u64> = HashSet::with_capacity(events_meta.len());
        for row in heights_table
            .iter()
            .map_err(|e| StoreError::Other(e.to_string()))?
        {
            let (k, v) = row.map_err(|e| StoreError::Other(e.to_string()))?;
            let bucket_height = k.value();
            height_bucket_count += 1;
            match bincode::deserialize::<Vec<u64>>(&v.value()) {
                Ok(ids) => {
                    for id in ids {
                        match events_meta.get(&id) {
                            Some(&(ev_height, _, _)) => {
                                if ev_height != bucket_height {
                                    issues.push(format!(
                                        "idx_heights mismatch for id={id}: bucket_height={bucket_height}, event.height={ev_height}"
                                    ));
                                }
                                seen_in_heights.insert(id);
                            }
                            None => {
                                issues.push(format!(
                                    "idx_heights dangling event reference id={id} at height={bucket_height}"
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    issues.push(format!(
                        "idx_heights corrupt bucket at height={bucket_height}: {e}"
                    ));
                }
            }
        }
        for (&id, &(ev_height, _, _)) in &events_meta {
            if !seen_in_heights.contains(&id) {
                issues.push(format!(
                    "event id={id} (height={ev_height}) missing from idx_heights"
                ));
            }
        }

        // 4. Verify address index.
        let mut address_bucket_count: u64 = 0;
        let mut seen_in_addr: HashSet<u64> = HashSet::with_capacity(events_meta.len());
        for row in by_addr
            .iter()
            .map_err(|e| StoreError::Other(e.to_string()))?
        {
            let (k, v) = row.map_err(|e| StoreError::Other(e.to_string()))?;
            let bucket_addr = k.value();
            address_bucket_count += 1;
            match bincode::deserialize::<Vec<u64>>(&v.value()) {
                Ok(ids) => {
                    for id in ids {
                        match events_meta.get(&id) {
                            Some(&(_, ev_addr, _)) => {
                                if ev_addr != bucket_addr {
                                    issues.push(format!(
                                        "idx_by_addr mismatch for id={id}: bucket does not match event address"
                                    ));
                                }
                                seen_in_addr.insert(id);
                            }
                            None => {
                                issues
                                    .push(format!("idx_by_addr dangling event reference id={id}"));
                            }
                        }
                    }
                }
                Err(e) => {
                    issues.push(format!("idx_by_addr corrupt bucket: {e}"));
                }
            }
        }
        for &id in events_meta.keys() {
            if !seen_in_addr.contains(&id) {
                issues.push(format!("event id={id} missing from idx_by_addr"));
            }
        }

        // 5. Verify topic index.
        let mut topic_bucket_count: u64 = 0;
        let mut seen_in_topic: HashSet<u64> = HashSet::with_capacity(events_meta.len());
        for row in by_topic
            .iter()
            .map_err(|e| StoreError::Other(e.to_string()))?
        {
            let (k, v) = row.map_err(|e| StoreError::Other(e.to_string()))?;
            let bucket_topic = k.value();
            topic_bucket_count += 1;
            match bincode::deserialize::<Vec<u64>>(&v.value()) {
                Ok(ids) => {
                    for id in ids {
                        match events_meta.get(&id) {
                            Some(&(_, _, ev_topic_hash)) => {
                                if ev_topic_hash != bucket_topic {
                                    issues.push(format!(
                                        "idx_by_topic mismatch for id={id}: bucket does not match event topic hash"
                                    ));
                                }
                                seen_in_topic.insert(id);
                            }
                            None => {
                                issues
                                    .push(format!("idx_by_topic dangling event reference id={id}"));
                            }
                        }
                    }
                }
                Err(e) => {
                    issues.push(format!("idx_by_topic corrupt bucket: {e}"));
                }
            }
        }
        for &id in events_meta.keys() {
            if !seen_in_topic.contains(&id) {
                issues.push(format!("event id={id} missing from idx_by_topic"));
            }
        }

        Ok(StoreIntegrityReport {
            ok: issues.is_empty(),
            checked_at_ms: now_unix_ms(),
            backend: "redb".to_string(),
            latest_indexed_height,
            next_id,
            event_count,
            height_bucket_count,
            address_bucket_count,
            topic_bucket_count,
            issues,
        })
    }

    /// Estimate how many heights, events, distinct transactions, and bytes would be pruned
    /// if retaining the most recent `keep_heights` blocks, without mutating the store.
    pub fn prune_dry_run(&self, keep_heights: u64) -> Result<PruneDryRunReport, StoreError> {
        let txn = self.db.begin_read().map_err(StoreError::Transaction)?;
        let meta_table = txn
            .open_table(T_META)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let heights_table = txn
            .open_table(T_HEIGHTS)
            .map_err(|e| StoreError::Other(e.to_string()))?;
        let events_table = txn
            .open_table(T_EVENTS)
            .map_err(|e| StoreError::Other(e.to_string()))?;

        let latest_indexed_height = meta_table
            .get("latest_height")
            .map_err(|e| StoreError::Other(e.to_string()))?
            .map(|v| v.value())
            .unwrap_or(0);

        let cutoff_height = if keep_heights == 0 {
            latest_indexed_height.saturating_add(1)
        } else {
            latest_indexed_height.saturating_sub(keep_heights.saturating_sub(1))
        };

        let mut prunable_heights: u64 = 0;
        let mut prunable_events: u64 = 0;
        let mut prunable_bytes: u64 = 0;
        let mut prunable_tx_set: HashSet<(u64, [u8; 32])> = HashSet::new();
        let mut retained_heights: u64 = 0;
        let mut retained_events: u64 = 0;

        for row in heights_table
            .iter()
            .map_err(|e| StoreError::Other(e.to_string()))?
        {
            let (k, v) = row.map_err(|e| StoreError::Other(e.to_string()))?;
            let height = k.value();
            let raw_bucket = v.value();
            let ids: Vec<u64> =
                bincode::deserialize(&raw_bucket).map_err(StoreError::Serialization)?;

            if height < cutoff_height {
                prunable_heights += 1;
                prunable_events += ids.len() as u64;
                prunable_bytes += 8 + raw_bucket.len() as u64;
                for id in ids {
                    if let Some(ev_raw) = events_table
                        .get(id)
                        .map_err(|e| StoreError::Other(e.to_string()))?
                    {
                        let bytes = ev_raw.value();
                        prunable_bytes += 8 + bytes.len() as u64;
                        let ev: IndexedEvent =
                            bincode::deserialize(&bytes).map_err(StoreError::Serialization)?;
                        prunable_tx_set.insert((ev.height, ev.tx_hash));
                    }
                }
            } else {
                retained_heights += 1;
                retained_events += ids.len() as u64;
            }
        }

        Ok(PruneDryRunReport {
            checked_at_ms: now_unix_ms(),
            keep_heights,
            latest_indexed_height,
            cutoff_height,
            prunable_heights,
            prunable_events,
            prunable_txs: prunable_tx_set.len() as u64,
            prunable_bytes,
            retained_heights,
            retained_events,
            mutated: false,
        })
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::Address;

    fn sample_event(
        height: u64,
        tx_seed: u8,
        log_index: u64,
        addr_seed: u8,
        topic: &[u8],
    ) -> IndexedEvent {
        IndexedEvent {
            id: 0,
            height,
            tx_hash: [tx_seed; 32],
            tx_index: 0,
            log_index,
            address: Address([addr_seed; 32]),
            topic: topic.to_vec(),
            data: vec![1, 2, 3, 4],
            success: true,
        }
    }

    fn populated_store(dir: &tempfile::TempDir) -> IndexerStore {
        let store = IndexerStore::new(dir.path().join("indexer.redb")).unwrap();
        // Heights 1..=5:
        // h=1: 2 events in 1 tx
        // h=2: 1 event in 1 tx
        // h=3: 2 events in 2 distinct txs
        // h=4: 1 event in 1 tx
        // h=5: 1 event in 1 tx
        let mut events = vec![
            sample_event(1, 10, 0, 1, b"transfer"),
            sample_event(1, 10, 1, 1, b"approval"),
            sample_event(2, 20, 0, 2, b"transfer"),
            sample_event(3, 30, 0, 1, b"mint"),
            sample_event(3, 31, 0, 2, b"burn"),
            sample_event(4, 40, 0, 3, b"transfer"),
            sample_event(5, 50, 0, 3, b"transfer"),
        ];
        store.insert_events(&mut events).unwrap();
        store.set_latest_indexed_height(5).unwrap();
        store
    }

    #[test]
    fn integrity_check_healthy_empty_and_populated_store() {
        let dir = tempfile::tempdir().unwrap();
        let empty_store = IndexerStore::new(dir.path().join("empty.redb")).unwrap();
        let empty_report = empty_store.integrity_check().unwrap();
        assert!(empty_report.ok);
        assert_eq!(empty_report.backend, "redb");
        assert_eq!(empty_report.event_count, 0);
        assert_eq!(empty_report.height_bucket_count, 0);
        assert!(empty_report.issues.is_empty());
        assert!(empty_report.checked_at_ms > 0);

        let store = populated_store(&dir);
        let report = store.integrity_check().unwrap();
        assert!(report.ok, "unexpected issues: {:?}", report.issues);
        assert_eq!(report.backend, "redb");
        assert_eq!(report.latest_indexed_height, 5);
        assert_eq!(report.next_id, 8);
        assert_eq!(report.event_count, 7);
        assert_eq!(report.height_bucket_count, 5);
        assert_eq!(report.address_bucket_count, 3);
        assert_eq!(report.topic_bucket_count, 4);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn integrity_check_detects_corrupt_event_and_broken_invariants() {
        let dir = tempfile::tempdir().unwrap();
        let store = populated_store(&dir);

        // Inject multiple independent corruptions directly into redb tables:
        // 1. Corrupt payload in idx_events for id=99
        // 2. Dangling reference id=999 in idx_heights at height=1
        // 3. Stale latest_height metadata (2 < max event height 5)
        // 4. Remove address bucket for Address([3u8; 32]) so events 6 and 7 are orphaned in idx_by_addr
        let txn = store.db.begin_write().unwrap();
        {
            let mut events_table = txn.open_table(T_EVENTS).unwrap();
            events_table.insert(99u64, vec![0xFF, 0xFF, 0xFF]).unwrap();

            let mut heights_table = txn.open_table(T_HEIGHTS).unwrap();
            let mut h1_ids: Vec<u64> =
                bincode::deserialize(&heights_table.get(1u64).unwrap().unwrap().value()).unwrap();
            h1_ids.push(999);
            heights_table
                .insert(1u64, bincode::serialize(&h1_ids).unwrap())
                .unwrap();

            let mut meta_table = txn.open_table(T_META).unwrap();
            meta_table.insert("latest_height", &2u64).unwrap();

            let mut by_addr = txn.open_table(T_BY_ADDR).unwrap();
            by_addr.remove([3u8; 32]).unwrap();
        }
        txn.commit().unwrap();

        let report = store.integrity_check().unwrap();
        assert!(!report.ok);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("idx_events corrupt payload for id=99")),
            "expected corrupt payload issue, got: {:?}",
            report.issues
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("idx_heights dangling event reference id=999")),
            "expected dangling ref issue, got: {:?}",
            report.issues
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("idx_meta latest_height (2) is behind")),
            "expected stale latest_height issue, got: {:?}",
            report.issues
        );
        assert!(
            report.issues.iter().any(|i| i.contains("idx_meta next_id")),
            "expected stale next_id issue (next_id=8 <= max_id=99), got: {:?}",
            report.issues
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("missing from idx_by_addr")),
            "expected missing idx_by_addr issue, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn prune_dry_run_reports_accurate_counts_without_mutating_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = populated_store(&dir);
        let before_count = store.event_count();
        let before_latest = store.latest_indexed_height();

        // Keep last 2 heights (4 and 5) -> cutoff_height = 4; prune heights 1, 2, 3.
        // h=1: 2 events (1 tx), h=2: 1 event (1 tx), h=3: 2 events (2 txs) => 3 heights, 5 events, 4 txs.
        let report = store.prune_dry_run(2).unwrap();
        assert!(!report.mutated);
        assert_eq!(report.keep_heights, 2);
        assert_eq!(report.latest_indexed_height, 5);
        assert_eq!(report.cutoff_height, 4);
        assert_eq!(report.prunable_heights, 3);
        assert_eq!(report.prunable_events, 5);
        assert_eq!(report.prunable_txs, 4);
        assert!(report.prunable_bytes > 0);
        assert_eq!(report.retained_heights, 2);
        assert_eq!(report.retained_events, 2);

        // Verify zero mutations occurred.
        assert_eq!(store.event_count(), before_count);
        assert_eq!(store.latest_indexed_height(), before_latest);
        for id in 1..=7 {
            assert!(store.get_event(id).is_ok(), "event {id} must still exist");
        }
        assert!(store.integrity_check().unwrap().ok);
    }

    #[test]
    fn prune_dry_run_edge_cases_empty_and_large_retention_and_zero_retention() {
        let dir = tempfile::tempdir().unwrap();
        let empty = IndexerStore::new(dir.path().join("empty_prune.redb")).unwrap();
        let empty_report = empty.prune_dry_run(10).unwrap();
        assert!(!empty_report.mutated);
        assert_eq!(empty_report.latest_indexed_height, 0);
        assert_eq!(empty_report.cutoff_height, 0);
        assert_eq!(empty_report.prunable_heights, 0);
        assert_eq!(empty_report.prunable_events, 0);
        assert_eq!(empty_report.prunable_txs, 0);
        assert_eq!(empty_report.prunable_bytes, 0);
        assert_eq!(empty_report.retained_heights, 0);
        assert_eq!(empty_report.retained_events, 0);

        let store = populated_store(&dir);
        // Retention larger than latest height -> nothing prunable.
        let large = store.prune_dry_run(100).unwrap();
        assert_eq!(large.cutoff_height, 0);
        assert_eq!(large.prunable_heights, 0);
        assert_eq!(large.prunable_events, 0);
        assert_eq!(large.prunable_txs, 0);
        assert_eq!(large.prunable_bytes, 0);
        assert_eq!(large.retained_heights, 5);
        assert_eq!(large.retained_events, 7);

        // Retention equal to latest height (5) -> keeps 1..=5, prunes nothing.
        let exact = store.prune_dry_run(5).unwrap();
        assert_eq!(exact.cutoff_height, 1);
        assert_eq!(exact.prunable_heights, 0);
        assert_eq!(exact.retained_heights, 5);
        assert_eq!(exact.retained_events, 7);

        // Retention == 0 -> all 5 heights / 7 events / 6 distinct txs prunable, still no mutation.
        let zero = store.prune_dry_run(0).unwrap();
        assert_eq!(zero.cutoff_height, 6);
        assert_eq!(zero.prunable_heights, 5);
        assert_eq!(zero.prunable_events, 7);
        assert_eq!(zero.prunable_txs, 6);
        assert_eq!(zero.retained_heights, 0);
        assert_eq!(zero.retained_events, 0);
        assert_eq!(store.event_count(), 7);
    }
}
