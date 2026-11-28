//! Stratum mining job tracking and block template reconstruction.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use kovanica_types::block::{compact_to_target, BlockHeader};
use kovanica_types::Address;

/// Maximum number of historical jobs retained for share submission verification.
pub const MAX_JOB_HISTORY: usize = 64;

/// A discrete mining job assigned to workers.
#[derive(Debug, Clone)]
pub struct Job {
    /// Unique job identifier broadcast in `mining.notify`.
    pub job_id: String,
    /// Base block header template from `kovanica_getWork`.
    pub header: BlockHeader,
    /// DAG round / height.
    pub round: u64,
    /// Network target bits.
    pub target_bits: u32,
    /// Network 256-bit target bytes.
    pub target: [u8; 32],
    /// Hex-encoded primary parent hash (or zero hash).
    pub prevhash: String,
    /// Serialized canonical block header preimage prefix (excluding the 8-byte trailing nonce).
    pub preimage_prefix: Vec<u8>,
    /// Hex string of the preimage prefix (used as `coinb1`).
    pub coinb1_hex: String,
    /// Creation timestamp.
    pub created_at: Instant,
}

impl Job {
    /// Create a new `Job` from a candidate `BlockHeader`.
    pub fn new(job_id: String, header: BlockHeader) -> Self {
        let round = header.round;
        let target_bits = header.target_bits;
        let target = compact_to_target(target_bits);

        let prevhash = if let Some(first_parent) = header.parents.first() {
            hex::encode(first_parent.digest.0)
        } else {
            hex::encode([0u8; 32])
        };

        let full_preimage = header.preimage();
        let prefix_len = full_preimage.len().saturating_sub(8);
        let preimage_prefix = full_preimage[..prefix_len].to_vec();
        let coinb1_hex = hex::encode(&preimage_prefix);

        Self {
            job_id,
            header,
            round,
            target_bits,
            target,
            prevhash,
            preimage_prefix,
            coinb1_hex,
            created_at: Instant::now(),
        }
    }

    /// Reconstruct candidate `BlockHeader` for share evaluation with candidate `nonce`,
    /// optional worker `payout`, and optional miner-submitted `ntime` (timestamp).
    pub fn reconstruct_header(
        &self,
        nonce: u64,
        payout: Option<Address>,
        ntime: Option<u64>,
    ) -> BlockHeader {
        let mut header = self.header.clone();
        header.nonce = nonce;
        if let Some(p) = payout {
            header.payout = Some(p);
        }
        if let Some(t) = ntime {
            header.timestamp = t;
        }
        header
    }
}

/// Thread-safe manager for Stratum mining jobs.
#[derive(Debug, Default)]
pub struct JobManager {
    counter: AtomicU64,
    current_job: RwLock<Option<Arc<Job>>>,
    jobs: RwLock<HashMap<String, Arc<Job>>>,
    job_order: RwLock<VecDeque<String>>,
}

impl JobManager {
    /// Create a new empty job manager.
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
            current_job: RwLock::new(None),
            jobs: RwLock::new(HashMap::new()),
            job_order: RwLock::new(VecDeque::with_capacity(MAX_JOB_HISTORY)),
        }
    }

    /// Register a new block template job, making it the active job.
    pub fn add_template(&self, header: BlockHeader) -> Arc<Job> {
        let id_num = self.counter.fetch_add(1, Ordering::SeqCst);
        let job_id = format!("job_{:x}", id_num);
        let job = Arc::new(Job::new(job_id.clone(), header));

        {
            let mut current = self.current_job.write();
            *current = Some(Arc::clone(&job));
        }

        {
            let mut map = self.jobs.write();
            let mut order = self.job_order.write();

            if order.len() >= MAX_JOB_HISTORY {
                if let Some(old_id) = order.pop_front() {
                    map.remove(&old_id);
                }
            }

            order.push_back(job_id.clone());
            map.insert(job_id, Arc::clone(&job));
        }

        job
    }

    /// Get the currently active job.
    pub fn get_current_job(&self) -> Option<Arc<Job>> {
        self.current_job.read().clone()
    }

    /// Lookup a job by its `job_id`.
    pub fn get_job(&self, job_id: &str) -> Option<Arc<Job>> {
        self.jobs.read().get(job_id).cloned()
    }
}
