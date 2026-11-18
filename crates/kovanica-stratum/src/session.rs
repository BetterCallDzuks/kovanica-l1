//! Miner session and authorization management.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use kovanica_types::Address;

/// Validated worker authorization record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedWorker {
    /// Full username string submitted by miner.
    pub full_username: String,
    /// Decoded canonical PRO-21 payout address.
    pub payout_address: Address,
    /// Worker identifier string (e.g. "rig1").
    pub worker_name: String,
}

/// Validate username against Kovanica canonical PRO-21 address rules.
///
/// Expected format: `<kvnc_address>.<worker_name>` or `<kvnc_address>`.
/// Must be exactly 64 characters starting with `kvnc` and ending with `dag`.
pub fn parse_and_validate_username(username: &str) -> Result<AuthorizedWorker, String> {
    let username = username.trim();
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    let (addr_str, worker_name) = if let Some(dot_idx) = username.find('.') {
        (&username[..dot_idx], &username[dot_idx + 1..])
    } else {
        (username, "default")
    };

    // PRO-21 canonical address validation:
    let addr = Address::decode(addr_str).map_err(|e| {
        format!(
            "Invalid PRO-21 address '{addr_str}': {e}. Must be canonical base32 (kvnc...dag, 64 chars)"
        )
    })?;

    Ok(AuthorizedWorker {
        full_username: username.to_string(),
        payout_address: addr,
        worker_name: worker_name.to_string(),
    })
}

/// Active connection session for a single Stratum client.
#[derive(Debug)]
pub struct WorkerSession {
    /// Unique connection session ID.
    pub session_id: String,
    /// Unique allocated `extranonce1` hex string (e.g. 8 hex characters).
    pub extranonce1: String,
    /// Size of `extranonce2` in bytes (4).
    pub extranonce2_size: usize,
    /// Authorized worker info (set upon `mining.authorize`).
    pub authorized_worker: RwLock<Option<AuthorizedWorker>>,
    /// Current assigned share difficulty.
    pub difficulty: RwLock<f64>,
    /// Set of submitted `(job_id, extranonce2, nonce)` to reject duplicates.
    submitted_shares: Mutex<HashSet<(String, String, u64)>>,
    /// Stats: count of accepted shares.
    pub accepted_shares: AtomicU64,
    /// Stats: count of rejected shares.
    pub rejected_shares: AtomicU64,
    /// Stats: count of valid network blocks found.
    pub blocks_found: AtomicU64,
}

impl WorkerSession {
    /// Create a new session with initial difficulty and assigned `extranonce1`.
    pub fn new(session_id: String, extranonce1: String, initial_difficulty: f64) -> Self {
        Self {
            session_id,
            extranonce1,
            extranonce2_size: 4,
            authorized_worker: RwLock::new(None),
            difficulty: RwLock::new(initial_difficulty),
            submitted_shares: Mutex::new(HashSet::new()),
            accepted_shares: AtomicU64::new(0),
            rejected_shares: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
        }
    }

    /// Check if this session is authorized.
    pub fn is_authorized(&self) -> bool {
        self.authorized_worker.read().is_some()
    }

    /// Authorize this session with validated worker credentials.
    pub fn authorize(&self, worker: AuthorizedWorker) {
        *self.authorized_worker.write() = Some(worker);
    }

    /// Get the current payout address for this session (if authorized).
    pub fn payout_address(&self) -> Option<Address> {
        self.authorized_worker
            .read()
            .as_ref()
            .map(|w| w.payout_address)
    }

    /// Check whether a share was already submitted in this session (duplicate check).
    /// If not duplicate, records it and returns `false`. If duplicate, returns `true`.
    pub fn check_and_record_share(&self, job_id: &str, extranonce2: &str, nonce: u64) -> bool {
        let key = (job_id.to_string(), extranonce2.to_string(), nonce);
        let mut guard = self.submitted_shares.lock();
        if guard.contains(&key) {
            true
        } else {
            guard.insert(key);
            false
        }
    }

    /// Update assigned share difficulty.
    pub fn set_difficulty(&self, diff: f64) {
        *self.difficulty.write() = diff;
    }

    /// Retrieve current share difficulty.
    pub fn get_difficulty(&self) -> f64 {
        *self.difficulty.read()
    }

    /// Increment accepted shares counter.
    pub fn record_accepted_share(&self) {
        self.accepted_shares.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment rejected shares counter.
    pub fn record_rejected_share(&self) {
        self.rejected_shares.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment blocks found counter.
    pub fn record_block_found(&self) {
        self.blocks_found.fetch_add(1, Ordering::Relaxed);
    }
}

/// Thread-safe session registry.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    counter: AtomicU64,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
        }
    }

    /// Generate a new session with a unique session ID and `extranonce1`.
    pub fn create_session(&self, initial_difficulty: f64) -> Arc<WorkerSession> {
        let id_val = self.counter.fetch_add(1, Ordering::SeqCst);
        let session_id = format!("sess_{:08x}", id_val);
        // 4 bytes / 8 hex characters extranonce1
        let extranonce1 = format!("{:08x}", id_val as u32);
        Arc::new(WorkerSession::new(
            session_id,
            extranonce1,
            initial_difficulty,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_username_with_worker() {
        let (_sk, pk) = kovanica_crypto::generate_keypair();
        let addr = Address(pk.0);
        let addr_str = addr.encode();
        assert_eq!(addr_str.len(), 64);
        assert!(addr_str.starts_with("kvnc"));
        assert!(addr_str.ends_with("dag"));

        let username = format!("{}.rig_1", addr_str);
        let worker = parse_and_validate_username(&username).expect("must parse valid username");
        assert_eq!(worker.worker_name, "rig_1");
        assert_eq!(worker.payout_address, addr);
    }

    #[test]
    fn test_valid_username_without_worker() {
        let (_sk, pk) = kovanica_crypto::generate_keypair();
        let addr = Address(pk.0);
        let addr_str = addr.encode();

        let worker = parse_and_validate_username(&addr_str).expect("must parse address alone");
        assert_eq!(worker.worker_name, "default");
        assert_eq!(worker.payout_address, addr);
    }

    #[test]
    fn test_invalid_address_rejected() {
        let res = parse_and_validate_username("not_an_address.rig1");
        assert!(res.is_err());

        // Hex address rejected
        let res2 = parse_and_validate_username("0x1234567890abcdef.rig1");
        assert!(res2.is_err());
    }

    #[test]
    fn test_duplicate_share_tracking() {
        let session = WorkerSession::new("s1".into(), "00000001".into(), 1.0);
        assert!(!session.check_and_record_share("job_1", "00000001", 42));
        // Submitting same share again must report duplicate
        assert!(session.check_and_record_share("job_1", "00000001", 42));
        // Different nonce is not duplicate
        assert!(!session.check_and_record_share("job_1", "00000001", 43));
    }
}
