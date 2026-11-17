//! Node mining worker and difficulty calculation for Hybrid PoW.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kovanica_consensus::daa::{calculate_next_target_bits, DaaConfig};
use kovanica_consensus::ghostdag::GhostdagCommitter;
use kovanica_consensus::mining::{mine_header_async, MiningWorker};
use kovanica_dag::DagStore;
use kovanica_mempool::Mempool;
use kovanica_types::block::{BlockHeader, BlockReference, StatementBlock};
use kovanica_types::hash::Hash;
use kovanica_types::CommittedSubDag;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::config::MiningConfig;
use crate::NetworkCommand;

/// Node mining service wrapper.
#[allow(dead_code)]
pub struct NodeMiner {
    worker: MiningWorker,
    /// DAA configuration for this miner.
    pub daa_config: DaaConfig,
}

impl Default for NodeMiner {
    fn default() -> Self {
        Self::new(kovanica_params::CHAIN_ID_TESTNET)
    }
}

#[allow(dead_code)]
impl NodeMiner {
    /// Create a new node miner configured for the specified chain.
    #[must_use]
    pub fn new(chain_id: u64) -> Self {
        Self {
            worker: MiningWorker::new(),
            daa_config: DaaConfig::for_chain(chain_id),
        }
    }

    /// Calculate next target bits for a candidate block from ancestor timestamps.
    #[must_use]
    pub fn next_target_bits(&self, current_target_bits: u32, timestamps: &[u64]) -> u32 {
        calculate_next_target_bits(current_target_bits, timestamps, &self.daa_config)
    }

    /// Synchronously mine `header` up to `max_iterations`.
    pub fn mine(&mut self, header: BlockHeader, max_iterations: u64) -> Option<BlockHeader> {
        self.worker.mine_header(header, max_iterations)
    }

    /// Asynchronously mine `header` up to `max_iterations`.
    pub async fn mine_async(
        &self,
        header: BlockHeader,
        max_iterations: u64,
    ) -> Option<BlockHeader> {
        mine_header_async(header, max_iterations).await
    }

    /// Asynchronously mine `header` up to `iterations_per_thread` across `threads` worker tasks.
    pub async fn mine_async_with_threads(
        &self,
        header: BlockHeader,
        iterations_per_thread: u64,
        threads: usize,
    ) -> Option<BlockHeader> {
        let threads = threads.max(1);
        if threads == 1 {
            return mine_header_async(header, iterations_per_thread).await;
        }

        let mut set = tokio::task::JoinSet::new();
        for i in 0..threads {
            let mut h = header.clone();
            h.nonce = header
                .nonce
                .wrapping_add((i as u64).wrapping_mul(iterations_per_thread));
            set.spawn_blocking(move || kovanica_consensus::mine_header(h, iterations_per_thread));
        }

        let mut result = None;
        while let Some(res) = set.join_next().await {
            if let Ok(Some(mined)) = res {
                result = Some(mined);
                set.abort_all();
                break;
            }
        }
        result
    }
}

pub use kovanica_consensus::daa::select_parents_from_tips;

/// Run the background PoW mining loop.
#[allow(clippy::too_many_arguments)]
pub async fn run_mining_loop(
    mining_config: MiningConfig,
    chain_id: u64,
    author: u16,
    payout_address: kovanica_types::Address,
    dag_store: Arc<DagStore>,
    mempool: Arc<Mempool>,
    network_cmd_tx: mpsc::UnboundedSender<NetworkCommand>,
    exec_tx: mpsc::UnboundedSender<CommittedSubDag>,
    ghostdag: Arc<parking_lot::Mutex<GhostdagCommitter>>,
    shutdown_rx: watch::Receiver<bool>,
) {
    if !mining_config.enabled {
        return;
    }

    info!(
        chain_id,
        author,
        %payout_address,
        threads = mining_config.threads,
        "PoW mining worker loop started"
    );

    let miner = NodeMiner::new(chain_id);
    let mut current_nonce: u64 = (author as u64).wrapping_mul(10_000_000);
    // (round, when hashing it started, whether the 30s wait was logged).
    let mut round_wait: Option<(u64, Instant, bool)> = None;
    let mut trailing_blocks_remaining: u32 = 0;

    loop {
        if *shutdown_rx.borrow() {
            info!("PoW miner loop received shutdown signal; stopping");
            break;
        }

        if mining_config.on_demand && mempool.is_empty() && trailing_blocks_remaining == 0 {
            let mut rx = shutdown_rx.clone();
            tokio::select! {
                _ = mempool.notified() => {}
                _ = rx.changed() => {
                    if *rx.borrow() {
                        info!("PoW miner loop received shutdown signal; stopping");
                        break;
                    }
                }
            }
            continue;
        }

        let parents = select_parents_from_tips(&dag_store, kovanica_params::GHOSTDAG_K as usize);
        let round = next_round(&dag_store, &parents);
        let (round_started, mut logged_wait) = match round_wait {
            Some((waiting_round, started, logged)) if waiting_round == round => (started, logged),
            _ => (Instant::now(), false),
        };
        round_wait = Some((round, round_started, logged_wait));

        let parent_refs: Vec<BlockReference> = parents
            .iter()
            .map(|h| {
                if let Ok(b) = dag_store.get_block(h) {
                    b.reference()
                } else {
                    BlockReference {
                        digest: *h,
                        round: round.saturating_sub(1),
                        author: 0,
                    }
                }
            })
            .collect();

        let target_bits = match kovanica_consensus::try_required_target_bits(
            &dag_store,
            &parent_refs,
            chain_id,
            &miner.daa_config,
        ) {
            Ok(bits) => bits,
            Err(e) => {
                warn!(error = %e, "skipping block generation: failed to derive required DAA target");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        kovanica_consensus::metrics::set_pow_target_bits(target_bits);

        // The transaction set of a round is chosen once. `get_next_transactions`
        // moves what it returns out of the fee queues and into the in-flight
        // set, so asking again while the same round is still being mined would
        // rebuild the next chunk without those transactions.
        let txs = mempool.get_next_transactions(kovanica_types::MAX_TXS_PER_BLOCK);
        let had_txs = !txs.is_empty();
        if mining_config.on_demand && !had_txs && trailing_blocks_remaining == 0 {
            continue;
        }
        let merkle_root = StatementBlock::compute_merkle_root(&txs);

        // Mine the round in bounded chunks so the loop cooperates with tokio,
        // reacts to shutdown, and abandons a header as soon as a peer settles the
        // round it belongs to.
        //
        // A chunk has to be short in wall clock, not only in iterations: a hash
        // costs the same everywhere, but the hashrate does not, and a fixed 50k
        // chunk is ~85 s on this repository's 3-node test cluster. Spending that
        // long on a stale header makes the loser publish a block after the round
        // was already won, and the extra same-round parent brings timestamps that
        // are seconds apart — which the DAA clamps to 4x tighter difficulty.
        // 5k keeps the re-check near ten seconds at test hashrates; the check is
        // a tips read, microseconds next to the hashing it interrupts.
        const CHUNK_ITERATIONS: u64 = 5_000;
        let chunk_span = CHUNK_ITERATIONS.saturating_mul(mining_config.threads.max(1) as u64);

        let mined = loop {
            if *shutdown_rx.borrow() {
                info!("PoW miner loop received shutdown signal; stopping");
                break None;
            }

            // A fresh timestamp per chunk, so a block that took several minutes
            // to find does not enter the DAA window with a stale one.
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let header = BlockHeader::new_with_payout(
                chain_id,
                round,
                author,
                parent_refs.clone(),
                merkle_root,
                now_ms,
                target_bits,
                current_nonce,
                payout_address,
            );
            current_nonce = current_nonce.wrapping_add(chunk_span);

            if let Some(mined_header) = miner
                .mine_async_with_threads(header, CHUNK_ITERATIONS, mining_config.threads)
                .await
            {
                break Some(mined_header);
            }

            let tips = select_parents_from_tips(&dag_store, kovanica_params::GHOSTDAG_K as usize);
            if next_round(&dag_store, &tips) > round {
                info!(
                    round,
                    "abandoning header: a peer already settled this round"
                );
                break None;
            }
            if !logged_wait && round_started.elapsed() >= Duration::from_secs(30) {
                info!(
                    round,
                    waited_secs = round_started.elapsed().as_secs(),
                    "no PoW block yet for this round; commit waits for a header that meets the target"
                );
                logged_wait = true;
                round_wait = Some((round, round_started, true));
            }
        };

        let Some(mined_header) = mined else {
            // Shutting down, or the round moved on under us: rebuild the header
            // from the new tips on the next iteration.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };

        info!(
            round = mined_header.round,
            pow_hash = ?mined_header.pow_hash,
            nonce = mined_header.nonce,
            "successfully mined new PoW block"
        );

        let statement_block = mined_header.to_statement_block(txs);
        if let Err(e) = dag_store.put_block(&statement_block) {
            error!(error = %e, "failed to persist mined block in dag_store");
            continue;
        }

        let subdags = {
            let mut gd = ghostdag.lock();
            gd.add_block(statement_block.clone());
            gd.commit_uncommitted_selected_chain()
        };

        for subdag in subdags {
            let _ = exec_tx.send(subdag);
        }

        if let Err(e) = network_cmd_tx.send(NetworkCommand::BroadcastBlock(statement_block)) {
            warn!(error = %e, "failed to broadcast mined block to P2P network");
        }

        if mining_config.on_demand {
            if had_txs {
                trailing_blocks_remaining = mining_config.on_demand_trailing_blocks;
            } else {
                trailing_blocks_remaining = trailing_blocks_remaining.saturating_sub(1);
            }
        }
    }
}

/// Round a candidate block built on `parents` would carry: one past the highest
/// round among them. Zero when there is no parent to build on yet.
fn next_round(dag_store: &DagStore, parents: &[Hash]) -> u64 {
    if parents.is_empty() {
        return 0;
    }
    let mut max_round = 0u64;
    for parent in parents {
        if let Ok(block) = dag_store.get_block(parent) {
            max_round = max_round.max(block.round);
        }
    }
    max_round.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_consensus::daa::extract_ancestor_timestamps;
    use kovanica_storage::Storage;
    use kovanica_types::hash::Hash;

    #[tokio::test]
    async fn node_miner_lifecycle() {
        let mut miner = NodeMiner::new(kovanica_params::CHAIN_ID_TESTNET);
        // Allow high target in test environment
        miner.daa_config.max_target_bits = 0x207fffff;
        miner.daa_config.target_block_time_ms = 4000;

        let target_bits = miner.next_target_bits(0x207fffff, &[1000, 5000, 9000]);
        assert_eq!(target_bits, 0x207fffff);

        let header = BlockHeader::new(5, 1, 0, vec![], Hash::zero(), 13000, target_bits, 0);
        let mined = miner
            .mine(header.clone(), 1_000)
            .expect("should mine block");
        assert!(mined.verify_pow().is_ok());

        let mined_async = miner
            .mine_async(header, 1_000)
            .await
            .expect("should mine block async");
        assert!(mined_async.verify_pow().is_ok());
    }

    #[test]
    fn next_round_is_one_past_the_highest_parent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("dag.redb")).unwrap();
        let dag = DagStore::new(storage).unwrap();

        // Nothing to build on yet.
        assert_eq!(next_round(&dag, &[]), 0);

        // A parent the store does not know is treated as round 0, the same way
        // the header used to be built when `get_block` failed.
        assert_eq!(next_round(&dag, &[Hash::zero()]), 1);

        let header = BlockHeader::new(5, 1, 0, vec![], Hash::zero(), 10_000, 0x207fffff, 0);
        let block = header.to_statement_block(vec![]);
        let digest = block.digest;
        dag.put_block(&block).unwrap();

        // The stored block is round 1, so a child of it is round 2, whether or
        // not an unknown parent is mixed in.
        assert_eq!(next_round(&dag, &[digest]), 2);
        assert_eq!(next_round(&dag, &[digest, Hash::zero()]), 2);
    }

    #[test]
    fn test_select_parents_and_extract_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("dag.redb")).unwrap();
        let dag = DagStore::new(storage).unwrap();

        // Empty dag returns no parents
        let tips = select_parents_from_tips(&dag, 5);
        assert!(tips.is_empty());

        let mut header = BlockHeader::new(5, 1, 0, vec![], Hash::zero(), 10_000, 0x207fffff, 0);
        header.pow_hash = Some(header.compute_pow_hash());
        let block = header.to_statement_block(vec![]);
        let digest = block.digest;
        dag.put_block(&block).unwrap();

        let tips = select_parents_from_tips(&dag, 5);
        assert_eq!(tips, vec![digest]);

        let timestamps = extract_ancestor_timestamps(&dag, &tips, 5, 10).unwrap();
        assert_eq!(timestamps, vec![10_000]);
    }

    #[tokio::test]
    async fn on_demand_miner_does_not_mine_when_mempool_empty() {
        let dir = tempfile::tempdir().unwrap();
        let dag_storage = Storage::new(dir.path().join("dag.redb")).unwrap();
        let dag_store = Arc::new(DagStore::new(dag_storage).unwrap());
        let state_storage = Arc::new(Storage::new(dir.path().join("state.redb")).unwrap());

        let chain_id = kovanica_types::signing::chain_id::LOCAL;
        let mempool = Arc::new(Mempool::new(
            kovanica_mempool::MempoolConfig::default(),
            state_storage,
            kovanica_types::SigningContext::new(chain_id),
        ));
        let (network_cmd_tx, _network_cmd_rx) = mpsc::unbounded_channel();
        let (exec_tx, _exec_rx) = mpsc::unbounded_channel();
        let ghostdag = Arc::new(parking_lot::Mutex::new(GhostdagCommitter::new(
            kovanica_params::GHOSTDAG_K as usize,
        )));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let mining_config = MiningConfig {
            enabled: true,
            threads: 1,
            author: Some(0),
            address: None,
            on_demand: true,
            on_demand_trailing_blocks: 0,
        };

        let dag_clone = Arc::clone(&dag_store);
        let handle = tokio::spawn(run_mining_loop(
            mining_config,
            chain_id,
            0,
            kovanica_types::Address([1u8; 32]),
            dag_clone,
            mempool,
            network_cmd_tx,
            exec_tx,
            ghostdag,
            shutdown_rx,
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            select_parents_from_tips(&dag_store, 5).is_empty(),
            "on_demand miner must not produce empty blocks while mempool is empty"
        );

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("on_demand miner should shut down promptly")
            .unwrap();
    }
}
