//! Persistent storage layer for Kovanica (redb backend + pruning).
//!
//! Provides three main storage components:
//! - `BlockStore`: Blocks, transactions, and block index
//! - `StateStore`: Account balances, nonces, contract code/storage, staking state
//! - `ConsensusStore`: DAG structure, commit tracker, decided rounds

#![deny(unsafe_code)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::borrow_deref_ref)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::map_flatten)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use kovanica_types::{hash::Hash, Address};
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tracing::warn;

pub mod address_tx_index;
pub mod block_store;
pub mod consensus_store;
pub mod state_store;

pub use address_tx_index::{
    index_committed_txs, query_tx_history, AddressTxIndexError, TxDirection, TxHistoryEntry,
    TxHistoryPage, TxHistoryQuery, ADDRESS_TX_INDEX_KEY_LEN, ADDRESS_TX_INDEX_VALUE_LEN,
    DEFAULT_TX_HISTORY_LIMIT, MAX_TX_HISTORY_LIMIT, ROLE_BOTH, ROLE_RECEIVED, ROLE_SENT,
};
pub use block_store::{BlockStore, BlockStoreError};
pub use consensus_store::{ConsensusStore, ConsensusStoreError};
pub use state_store::{StateStore, StateStoreError};
pub use tables::{
    ACCOUNTS, CONTRACT_CODE, CONTRACT_STORAGE, EMISSION_POLICY, FEE_ACCOUNTING_STATE,
    GENESIS_DIGEST, META, MINING_REWARD_STATE, STAKING_STATE, STATE_ROOT,
};

/// Main storage handle combining all stores.
pub struct Storage {
    db: Database,
    block_store: BlockStore,
    state_store: StateStore,
    consensus_store: ConsensusStore,
}

impl Storage {
    /// Open or create a new storage at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let db = Database::create(path).map_err(StorageError::Database)?;
        let block_store = BlockStore::new(&db)?;
        let state_store = StateStore::new(&db)?;
        let consensus_store = ConsensusStore::new(&db)?;

        Ok(Self {
            db,
            block_store,
            state_store,
            consensus_store,
        })
    }

    /// Get a reference to the block store.
    pub fn blocks(&self) -> &BlockStore {
        &self.block_store
    }

    /// Get a mutable reference to the block store.
    pub fn blocks_mut(&mut self) -> &mut BlockStore {
        &mut self.block_store
    }

    /// Get a reference to the state store.
    pub fn state(&self) -> &StateStore {
        &self.state_store
    }

    /// Get a mutable reference to the state store.
    pub fn state_mut(&mut self) -> &mut StateStore {
        &mut self.state_store
    }

    /// Get a reference to the consensus store.
    pub fn consensus(&self) -> &ConsensusStore {
        &self.consensus_store
    }

    /// Get a mutable reference to the consensus store.
    pub fn consensus_mut(&mut self) -> &mut ConsensusStore {
        &mut self.consensus_store
    }

    /// Begin a read transaction.
    pub fn begin_read(&self) -> Result<ReadTransaction, StorageError> {
        self.db.begin_read().map_err(StorageError::Transaction)
    }

    /// Begin a write transaction.
    pub fn begin_write(&self) -> Result<WriteTransaction, StorageError> {
        self.db.begin_write().map_err(StorageError::Transaction)
    }

    /// Prune both block store and consensus DAG tables strictly below `cutoff_round`
    /// for mobile / resource-constrained nodes.
    ///
    /// Preserves the state store, genesis digest, policy, and accounts, but drops
    /// older DAG links, parent-child edges, and block bodies to keep disk footprint bounded.
    pub fn prune_history_below(&self, cutoff_round: u64) -> Result<(u64, u64), StorageError> {
        let txn = self.begin_write()?;
        let pruned_blocks = self.block_store.prune_below(&txn, cutoff_round)?;
        let pruned_dag = if cutoff_round > 0 {
            self.consensus_store
                .prune_dag_below(&txn, cutoff_round - 1)?
        } else {
            0
        };
        let _ = self
            .consensus_store
            .prune_votes_below(&txn, cutoff_round, 10_000)?;
        txn.commit().map_err(StorageError::Commit)?;
        Ok((pruned_blocks, pruned_dag))
    }
}

/// Errors that can occur in storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("Transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("Table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("Commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("Storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("Block store error: {0}")]
    BlockStore(#[from] BlockStoreError),
    #[error("State store error: {0}")]
    StateStore(#[from] StateStoreError),
    #[error("Consensus store error: {0}")]
    ConsensusStore(#[from] ConsensusStoreError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Not found: {0}")]
    NotFound(String),
}

/// Table definitions for redb.
pub mod tables {
    use super::*;
    use kovanica_types::block::StatementBlock;
    use kovanica_types::hash::Hash;
    use kovanica_types::Address;

    // Block store tables
    pub const BLOCKS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("blocks");
    pub const BLOCK_HEIGHT: TableDefinition<u64, [u8; 32]> = TableDefinition::new("block_height");
    pub const BLOCK_TRANSACTIONS: TableDefinition<[u8; 32], Vec<u8>> =
        TableDefinition::new("block_transactions");
    pub const TRANSACTION_INDEX: TableDefinition<[u8; 32], [u8; 32]> =
        TableDefinition::new("tx_index"); // tx_hash -> block_hash
                                          // Address history (`address_tx_index`) is defined in `address_tx_index`.
                                          // It is a local RPC index: not a state-root input and not consensus bytes.

    // State store tables
    pub const ACCOUNTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("accounts");
    pub const CONTRACT_CODE: TableDefinition<[u8; 32], Vec<u8>> =
        TableDefinition::new("contract_code");
    pub const CONTRACT_STORAGE: TableDefinition<([u8; 32], [u8; 32]), Vec<u8>> =
        TableDefinition::new("contract_storage");
    pub const STAKING_STATE: TableDefinition<&'static str, Vec<u8>> =
        TableDefinition::new("staking_state");
    pub const STATE_ROOT: TableDefinition<u64, [u8; 32]> = TableDefinition::new("state_root"); // committed_leader_height -> state_root
    /// Committed-leader header (bincode), keyed by committed height.
    pub const LEADER_HEADERS: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("leader_headers");
    /// Leader block digest or header hash -> committed leader height (O(1) index).
    pub const LEADER_DIGEST_TO_HEIGHT: TableDefinition<[u8; 32], u64> =
        TableDefinition::new("leader_digest_to_height");
    /// One commit seal: `(committed height, authority index)` -> signature bytes.
    pub const COMMIT_SEALS: TableDefinition<(u64, u16), Vec<u8>> =
        TableDefinition::new("commit_seals");
    /// Frozen seal committee snapshot for an epoch (bincode `Vec<(AuthorityIndex,
    /// PublicKey, Stake)>`), keyed by epoch number.
    ///
    /// The first seal produced in an epoch writes the snapshot; every later
    /// seal in that epoch and the RPC `getCommittee` path read the SAME frozen
    /// snapshot, so a mid-epoch join/evict/unbond cannot make the sealed
    /// header's `committee_hash` disagree with the committee the RPC serves.
    pub const EPOCH_COMMITTEE: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("epoch_committee");
    /// Transaction hashes execution applied at a committed height, in order.
    pub const EXECUTED_TX_HASHES: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("executed_tx_hashes");
    /// Light-node set (bincode). Not a field of `StakingState`.
    pub const LIGHT_SET: TableDefinition<&'static str, Vec<u8>> = TableDefinition::new("light_set");
    /// Persisted digest of the configured genesis contents. Written once at
    /// genesis time (and on first start of a pre-existing data dir); every
    /// later start recomputes the digest and refuses on mismatch unless
    /// explicitly overridden. Key: `"genesis"`.
    pub const GENESIS_DIGEST: TableDefinition<&'static str, [u8; 32]> =
        TableDefinition::new("genesis_digest");
    /// Persisted emission and genesis policy: "legacy-81m" or "no-stake-82m".
    pub const EMISSION_POLICY: TableDefinition<&'static str, Vec<u8>> =
        TableDefinition::new("emission_policy");
    /// Persisted deterministic mining reward execution state for NO-stake networks.
    pub const MINING_REWARD_STATE: TableDefinition<&'static str, Vec<u8>> =
        TableDefinition::new("mining_reward_state");
    /// Persisted deterministic fee accounting counters for PRO-53 fee split and burn.
    pub const FEE_ACCOUNTING_STATE: TableDefinition<&'static str, Vec<u8>> =
        TableDefinition::new("fee_accounting_state");
    /// Metadata table for schema versions, migrations, and index backfill status flags.
    pub const META: TableDefinition<&'static str, Vec<u8>> = TableDefinition::new("meta");

    // Consensus store tables
    pub const DAG_BLOCKS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("dag_blocks"); // StatementBlock serialized
    pub const DAG_PARENTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("dag_parents"); // block_hash -> parent hashes
    pub const DAG_CHILDREN: TableDefinition<[u8; 32], Vec<u8>> =
        TableDefinition::new("dag_children"); // block_hash -> child hashes
    pub const DAG_BY_ROUND: TableDefinition<(u64, u16), Vec<u8>> =
        TableDefinition::new("dag_by_round"); // (round, author) -> block_hashes
    pub const DAG_BY_AUTHOR: TableDefinition<(u16, u64), Vec<u8>> =
        TableDefinition::new("dag_by_author"); // (author, round) -> block_hash
    pub const COMMITTED_LEADER_HEIGHT: TableDefinition<&'static str, u64> =
        TableDefinition::new("committed_leader_height");
    pub const DECIDED_ROUNDS: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("decided_rounds"); // round -> decided leader hashes
    pub const LAST_COMMITED: TableDefinition<&'static str, [u8; 32]> =
        TableDefinition::new("last_committed"); // "last" -> leader block hash

    /// Consensus votes (bincode `Vote`), keyed by `(leader round, voter index)`.
    ///
    /// A node keeps the votes it accepted so it can serve the decision evidence
    /// for a leader round to a peer that joins later. The invariant this table
    /// exists to uphold: if a node can serve the block for round R, it can serve
    /// the votes for round R.
    pub const VOTES: TableDefinition<(u64, u16), Vec<u8>> = TableDefinition::new("votes");

    /// Accepted leader-slot timeouts: (round, voter) → bincode `Timeout`
    /// (PRO-40 (b)).
    ///
    /// Holds this node's own timeouts — written before they are broadcast, so
    /// a restart can never vote for a slot it already timed out — and the
    /// verified timeouts of other validators, from which a skip certificate
    /// can be rebuilt and served to a peer.
    pub const TIMEOUTS: TableDefinition<(u64, u16), Vec<u8>> = TableDefinition::new("timeouts");
}

// Helper trait for bincode serialization
pub trait BincodeSerialize: Serialize + for<'de> Deserialize<'de> {
    fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error>
    where
        Self: Sized,
    {
        bincode::deserialize(bytes)
    }
}

impl<T: Serialize + for<'de> Deserialize<'de>> BincodeSerialize for T {}

/// Serialize a Hash to bytes for table keys.
pub fn hash_to_bytes(hash: &Hash) -> [u8; 32] {
    hash.0
}

/// Serialize an Address to bytes for table keys.
pub fn address_to_bytes(addr: &Address) -> [u8; 32] {
    addr.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_creation() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("test.db")).unwrap();
        let _txn = storage.begin_write().unwrap();
        // commit happens on transaction drop
    }

    #[test]
    fn test_state_root_determinism() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let state = StateStore::new(&db).unwrap();
        let txn = db.begin_read().unwrap();
        let root1 = state.compute_state_root(&txn).unwrap();
        drop(txn);
        let txn2 = db.begin_read().unwrap();
        let root2 = state.compute_state_root(&txn2).unwrap();
        assert_eq!(root1.0, root2.0, "state root must be deterministic");
    }

    #[test]
    fn genesis_digest_roundtrips_and_is_idempotent() {
        use kovanica_types::hash::Hash;
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("genesis.db")).unwrap();
        let digest = Hash::new([7u8; 32]);

        // Absent until written.
        {
            let read = storage.begin_read().unwrap();
            assert!(storage
                .state()
                .load_genesis_digest(&read)
                .unwrap()
                .is_none());
        }
        // Write once.
        {
            let txn = storage.begin_write().unwrap();
            storage.state().save_genesis_digest(&txn, &digest).unwrap();
            txn.commit().unwrap();
        }
        // Idempotent rewrite of the same value.
        {
            let txn = storage.begin_write().unwrap();
            storage.state().save_genesis_digest(&txn, &digest).unwrap();
            txn.commit().unwrap();
        }
        let read = storage.begin_read().unwrap();
        assert_eq!(
            storage.state().load_genesis_digest(&read).unwrap(),
            Some(digest)
        );
    }

    #[test]
    fn test_snapshot_roundtrip() {
        use crate::state_store::{Account, StateStore};
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("snap.db");
        let storage = Storage::new(&db_path).unwrap();

        // Write state
        {
            let txn = storage.begin_write().unwrap();
            let state = storage.state();
            let addr = kovanica_types::Address([7; 32]);
            let acct = Account {
                balance: 1000,
                nonce: 3,
                code_hash: [0; 32],
                code: vec![1, 2, 3],
            };
            state.set_account(&txn, &addr, &acct).unwrap();
            txn.commit().unwrap();
        }

        // Export
        let snap_path = dir.path().join("snap.bin");
        {
            let txn = storage.begin_read().unwrap();
            let state = storage.state();
            state.export_snapshot(&txn, &snap_path).unwrap();
        }

        // Restore into fresh DB
        let db_path2 = dir.path().join("snap2.db");
        let storage2 = Storage::new(&db_path2).unwrap();
        {
            let txn = storage2.begin_write().unwrap();
            let state = storage2.state();
            state.import_snapshot(&txn, &snap_path).unwrap();
            txn.commit().unwrap();
        }

        // Verify
        {
            let txn = storage2.begin_read().unwrap();
            let state = storage2.state();
            let addr = kovanica_types::Address([7; 32]);
            let restored = state.get_account(&txn, &addr).unwrap();
            assert_eq!(restored.balance, 1000);
            assert_eq!(restored.nonce, 3);
        }
    }

    #[test]
    fn test_mobile_prune_history_below() {
        use kovanica_types::block::StatementBlock;
        use kovanica_types::crypto::Signature;
        use kovanica_types::hash::Hash;

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("mobile_prune.db");
        let storage = Storage::new(&db_path).unwrap();

        // Populate blocks and DAG from round 1 to 10
        {
            let txn = storage.begin_write().unwrap();
            for round in 1..=10 {
                let digest = StatementBlock::compute_digest(0, round, &[], &[]);
                let block = StatementBlock {
                    author: 0,
                    round,
                    parents: vec![],
                    transactions: vec![],
                    statements: vec![],
                    signature: Signature([0; 64]),
                    digest,
                    merkle_root: Hash::zero(),
                };
                storage.blocks().put_block(&txn, &block, &[]).unwrap();
                storage.consensus().put_dag_block(&txn, &block).unwrap();
            }
            txn.commit().unwrap();
        }

        // Verify all 10 blocks are present
        {
            let read = storage.begin_read().unwrap();
            for round in 1..=10 {
                let digest = StatementBlock::compute_digest(0, round, &[], &[]);
                assert!(storage
                    .blocks()
                    .get_block_by_height(&read, round)
                    .unwrap()
                    .is_some());
                assert!(storage.consensus().get_dag_block(&read, &digest).is_ok());
            }
        }

        // Prune history below round 6 (keeps rounds 6..=10)
        let (pruned_blocks, pruned_dag) = storage.prune_history_below(6).unwrap();
        assert_eq!(pruned_blocks, 5);
        assert_eq!(pruned_dag, 5);

        // Verify rounds 1..5 are gone, 6..10 remain
        {
            let read = storage.begin_read().unwrap();
            for round in 1..6 {
                let digest = StatementBlock::compute_digest(0, round, &[], &[]);
                assert!(storage
                    .blocks()
                    .get_block_by_height(&read, round)
                    .unwrap()
                    .is_none());
                assert!(storage.consensus().get_dag_block(&read, &digest).is_err());
            }
            for round in 6..=10 {
                let digest = StatementBlock::compute_digest(0, round, &[], &[]);
                assert!(storage
                    .blocks()
                    .get_block_by_height(&read, round)
                    .unwrap()
                    .is_some());
                assert!(storage.consensus().get_dag_block(&read, &digest).is_ok());
            }
        }
    }

    fn test_leader_header(height: u64, seed: u8) -> kovanica_types::LeaderHeader {
        kovanica_types::LeaderHeader {
            committed_height: height,
            leader_round: height * 2,
            leader_digest: kovanica_types::Hash::new([seed; 32]),
            leader_author: 0,
            parent_leader_digest: kovanica_types::Hash::zero(),
            tx_merkle_root: kovanica_types::Hash::zero(),
            executed_tx_root: kovanica_types::Hash::zero(),
            non_blue_root: kovanica_types::Hash::zero(),
            blue_root: kovanica_types::Hash::zero(),
            mysticghost: false,
            state_root: kovanica_types::Hash::zero(),
            epoch: 0,
            committee_hash: kovanica_types::Hash::zero(),
            timestamp: 0,
        }
    }

    #[test]
    fn test_get_latest_leader_header_with_10k_rows() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("headers_10k.db")).unwrap();
        let txn = storage.begin_write().unwrap();
        for h in 1..=10_000 {
            let seed = (h % 250) as u8;
            let hdr = test_leader_header(h, seed);
            storage.state().save_leader_header(&txn, &hdr).unwrap();
        }
        txn.commit().unwrap();

        let read = storage.begin_read().unwrap();
        let latest = storage
            .state()
            .get_latest_leader_header(&read)
            .unwrap()
            .expect("must return latest header");
        assert_eq!(latest.committed_height, 10_000);
    }

    #[test]
    fn test_backfill_on_db_with_headers_and_empty_index_idempotent() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("backfill.db");
        let header1 = test_leader_header(1, 11);
        let header2 = test_leader_header(2, 22);

        // Seed raw LEADER_HEADERS table without index or META
        {
            let db = Database::create(&db_path).unwrap();
            let write_txn = db.begin_write().unwrap();
            {
                let mut tbl = write_txn.open_table(crate::tables::LEADER_HEADERS).unwrap();
                tbl.insert(1u64, bincode::serialize(&header1).unwrap())
                    .unwrap();
                tbl.insert(2u64, bincode::serialize(&header2).unwrap())
                    .unwrap();
            }
            write_txn.commit().unwrap();
        }

        // Open Storage: StateStore::with_pruning runs backfill automatically
        let storage = Storage::new(&db_path).unwrap();
        {
            let read = storage.begin_read().unwrap();
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &header1.leader_digest)
                    .unwrap(),
                Some(1)
            );
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &header1.hash())
                    .unwrap(),
                Some(1)
            );
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &header2.leader_digest)
                    .unwrap(),
                Some(2)
            );
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &header2.hash())
                    .unwrap(),
                Some(2)
            );
        }

        // A second run (manual or reopen) is an idempotent no-op
        {
            let write_txn = storage.begin_write().unwrap();
            let second_run = storage
                .state()
                .backfill_leader_digest_index(&write_txn)
                .unwrap();
            assert_eq!(second_run, None, "second backfill run must be a no-op");
            write_txn.commit().unwrap();
        }
    }

    #[test]
    fn test_header_replacement_deletes_old_hash_from_digest_index() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("replace.db")).unwrap();
        let hdr_a = test_leader_header(1, 101);
        let hash_a = hdr_a.hash();
        let digest_a = hdr_a.leader_digest;

        // Save header A at height 1
        {
            let txn = storage.begin_write().unwrap();
            storage.state().save_leader_header(&txn, &hdr_a).unwrap();
            txn.commit().unwrap();
        }

        {
            let read = storage.begin_read().unwrap();
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &hash_a)
                    .unwrap(),
                Some(1)
            );
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &digest_a)
                    .unwrap(),
                Some(1)
            );
        }

        // Save header B at height 1 (replacement)
        let hdr_b = test_leader_header(1, 102);
        let hash_b = hdr_b.hash();
        let digest_b = hdr_b.leader_digest;
        {
            let txn = storage.begin_write().unwrap();
            storage.state().save_leader_header(&txn, &hdr_b).unwrap();
            txn.commit().unwrap();
        }

        {
            let read = storage.begin_read().unwrap();
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &hash_b)
                    .unwrap(),
                Some(1)
            );
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &digest_b)
                    .unwrap(),
                Some(1)
            );
            // Old keys are gone
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &hash_a)
                    .unwrap(),
                None
            );
            assert_eq!(
                storage
                    .state()
                    .get_leader_height_by_digest(&read, &digest_a)
                    .unwrap(),
                None
            );
        }
    }
}
