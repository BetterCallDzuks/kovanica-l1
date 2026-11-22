//! Miner session and authorization management.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use kovanica_types::Address;

use crate::config::VarDiffConfig;

/// Maximum length of a worker identifier suffix (e.g. `rig_01`).
pub const MAX_WORKER_NAME_LEN: usize = 32;
/// Maximum number of submitted share keys retained per session for duplicate detection.
pub const MAX_SUBMITTED_SHARES_PER_SESSION: usize = 4_096;
/// Maximum number of share timestamps retained per session for VarDiff and hashrate estimation.
pub const MAX_SHARE_TIMESTAMPS_PER_SESSION: usize = 4_096;
/// Minimum allowed share difficulty.
pub const MIN_SHARE_DIFFICULTY: f64 = 0.01;
/// Maximum allowed share difficulty.
pub const MAX_SHARE_DIFFICULTY: f64 = 1_000_000.0;
/// Maximum upward difficulty multiplier per VarDiff retarget step (smooth ramp-up).
pub const MAX_VARDIFF_UP_FACTOR: f64 = 4.0;
/// Minimum downward difficulty multiplier per VarDiff retarget step (smooth ramp-down).
pub const MAX_VARDIFF_DOWN_FACTOR: f64 = 0.25;

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

    if worker_name.is_empty() || worker_name.len() > MAX_WORKER_NAME_LEN {
        return Err(format!(
            "Invalid worker name length ({}): must be 1..={MAX_WORKER_NAME_LEN} characters",
            worker_name.len()
        ));
    }
    if !worker_name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(
            "Invalid worker name: only ASCII alphanumeric, '_', and '-' characters are allowed"
                .to_string(),
        );
    }

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

/// Target time window for share submission rate (seconds).
/// Used for variable difficulty retargeting.
const SHARE_RATE_WINDOW_SECS: u64 = 60;
/// Target shares per window for difficulty adjustment.
const TARGET_SHARES_PER_WINDOW: f64 = 18.0; // ~1 share per 3.33 seconds at diff 1
/// Minimum shares required before first retarget is allowed.
const MIN_SHARES_FOR_RETARGET: usize = 5;

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
    /// Insertion order for bounded FIFO eviction of `submitted_shares`.
    submitted_shares_order: Mutex<VecDeque<(String, String, u64)>>,
    /// Stats: count of accepted shares.
    pub accepted_shares: AtomicU64,
    /// Stats: count of rejected shares.
    pub rejected_shares: AtomicU64,
    /// Stats: count of valid network blocks found.
    pub blocks_found: AtomicU64,
    /// Timestamps of recent accepted shares (Unix seconds) for hashrate estimation.
    share_timestamps: Mutex<Vec<u64>>,
    /// Last difficulty retarget time.
    last_retarget: Mutex<Option<u64>>,
    /// Session creation timestamp (Unix seconds).
    created_at: u64,
}

impl WorkerSession {
    /// Create a new session with initial difficulty and assigned `extranonce1`.
    pub fn new(session_id: String, extranonce1: String, initial_difficulty: f64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::new_at(session_id, extranonce1, initial_difficulty, now)
    }

    /// Create a new session with an explicit creation timestamp (Unix seconds).
    pub fn new_at(
        session_id: String,
        extranonce1: String,
        initial_difficulty: f64,
        created_at: u64,
    ) -> Self {
        Self {
            session_id,
            extranonce1,
            extranonce2_size: 4,
            authorized_worker: RwLock::new(None),
            difficulty: RwLock::new(initial_difficulty),
            submitted_shares: Mutex::new(HashSet::new()),
            submitted_shares_order: Mutex::new(VecDeque::new()),
            accepted_shares: AtomicU64::new(0),
            rejected_shares: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
            share_timestamps: Mutex::new(Vec::new()),
            last_retarget: Mutex::new(None),
            created_at,
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
    /// Bounds memory to [`MAX_SUBMITTED_SHARES_PER_SESSION`] entries per session via FIFO eviction.
    pub fn check_and_record_share(&self, job_id: &str, extranonce2: &str, nonce: u64) -> bool {
        let key = (job_id.to_string(), extranonce2.to_string(), nonce);
        let mut guard = self.submitted_shares.lock();
        if guard.contains(&key) {
            true
        } else {
            let mut order = self.submitted_shares_order.lock();
            while guard.len() >= MAX_SUBMITTED_SHARES_PER_SESSION {
                if let Some(oldest) = order.pop_front() {
                    guard.remove(&oldest);
                } else {
                    break;
                }
            }
            order.push_back(key.clone());
            guard.insert(key);
            false
        }
    }

    /// Update assigned share difficulty (clamped to safe finite bounds; 0.0 allowed only for test mode).
    pub fn set_difficulty(&self, diff: f64) {
        if !diff.is_finite() || diff < 0.0 {
            return;
        }
        let clamped = if diff == 0.0 {
            0.0
        } else {
            diff.clamp(MIN_SHARE_DIFFICULTY, MAX_SHARE_DIFFICULTY)
        };
        *self.difficulty.write() = clamped;
    }

    /// Update assigned share difficulty clamped to explicit `[min_diff, max_diff]` bounds.
    /// Returns the applied difficulty if `diff` was finite and positive.
    pub fn set_difficulty_bounded(&self, diff: f64, min_diff: f64, max_diff: f64) -> Option<f64> {
        if !diff.is_finite() || diff <= 0.0 || min_diff > max_diff {
            return None;
        }
        let clamped = diff.clamp(min_diff, max_diff);
        *self.difficulty.write() = clamped;
        Some(clamped)
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

    /// Record an accepted share timestamp for hashrate estimation and difficulty retargeting.
    pub fn record_share_timestamp(&self, timestamp: u64) {
        self.record_share_timestamp_with_window(timestamp, SHARE_RATE_WINDOW_SECS);
    }

    /// Record an accepted share timestamp and retain a bounded sliding window of `window_secs`.
    pub fn record_share_timestamp_with_window(&self, timestamp: u64, window_secs: u64) {
        let mut timestamps = self.share_timestamps.lock();
        timestamps.push(timestamp);
        let cutoff = timestamp.saturating_sub(window_secs.max(SHARE_RATE_WINDOW_SECS));
        timestamps.retain(|&ts| ts >= cutoff);
        if timestamps.len() > MAX_SHARE_TIMESTAMPS_PER_SESSION {
            let excess = timestamps.len() - MAX_SHARE_TIMESTAMPS_PER_SESSION;
            timestamps.drain(..excess);
        }
    }

    /// Calculate estimated hashrate based on recent shares and current difficulty.
    /// Returns hashrate in H/s (hashes per second).
    pub fn estimated_hashrate(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamps = self.share_timestamps.lock();
        if timestamps.is_empty() {
            return 0.0;
        }

        let window_start = now.saturating_sub(SHARE_RATE_WINDOW_SECS);
        let recent_shares: Vec<u64> = timestamps
            .iter()
            .filter(|&&ts| ts >= window_start)
            .copied()
            .collect();

        if recent_shares.len() < 2 {
            return 0.0;
        }

        let time_span = recent_shares.last().unwrap() - recent_shares.first().unwrap();
        if time_span == 0 {
            return 0.0;
        }

        let share_rate = recent_shares.len() as f64 / time_span as f64;
        let current_diff = *self.difficulty.read();

        // Hashrate = share_rate * difficulty * 2^32 (for Stratum difficulty scaling)
        share_rate * current_diff * 4294967296.0
    }

    /// Check if difficulty should be retargeted and perform retarget if needed.
    /// Returns the new difficulty if retargeted, None otherwise.
    pub fn maybe_retarget_difficulty(&self) -> Option<f64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut last_retarget = self.last_retarget.lock();
        let should_retarget = match *last_retarget {
            Some(last) => now.saturating_sub(last) >= SHARE_RATE_WINDOW_SECS,
            None => true, // First retarget after initial window
        };

        if !should_retarget {
            return None;
        }

        let timestamps = self.share_timestamps.lock();
        if timestamps.is_empty() {
            *last_retarget = Some(now);
            return None;
        }

        // Require minimum shares before first retarget
        if last_retarget.is_none() && timestamps.len() < MIN_SHARES_FOR_RETARGET {
            return None;
        }

        let window_start = now.saturating_sub(SHARE_RATE_WINDOW_SECS);
        let recent_count = timestamps.iter().filter(|&&ts| ts >= window_start).count() as f64;

        if recent_count == 0.0 {
            *last_retarget = Some(now);
            return None;
        }

        let current_diff = *self.difficulty.read();
        // Retarget formula: new_diff = current_diff * (actual_shares / target_shares)
        let new_diff = current_diff * (recent_count / TARGET_SHARES_PER_WINDOW);

        // Clamp difficulty to reasonable bounds
        let new_diff = new_diff.clamp(0.01, 1_000_000.0);

        if (new_diff - current_diff).abs() / current_diff > 0.05 {
            // >5% change
            *last_retarget = Some(now);
            drop(timestamps); // Release lock before updating difficulty
            *self.difficulty.write() = new_diff;
            Some(new_diff)
        } else {
            *last_retarget = Some(now);
            None
        }
    }

    /// Check if difficulty should be retargeted under the given [`VarDiffConfig`] at Unix time `now`.
    ///
    /// Applies deadband tolerance (`variance_percent`), smooth per-step damping
    /// (`[MAX_VARDIFF_DOWN_FACTOR, MAX_VARDIFF_UP_FACTOR]`), and strict clamping to
    /// `[min_difficulty, max_difficulty]`. Returns `Some(new_difficulty)` only when
    /// the difficulty actually changes.
    pub fn maybe_retarget_difficulty_with_config(
        &self,
        cfg: &VarDiffConfig,
        now: u64,
    ) -> Option<f64> {
        if !cfg.enabled
            || cfg.retarget_interval_secs == 0
            || !cfg.target_share_secs.is_finite()
            || cfg.target_share_secs <= 0.0
            || !cfg.min_difficulty.is_finite()
            || !cfg.max_difficulty.is_finite()
            || cfg.min_difficulty <= 0.0
            || cfg.min_difficulty > cfg.max_difficulty
        {
            return None;
        }

        let mut last_retarget = self.last_retarget.lock();
        if let Some(last) = *last_retarget {
            if now.saturating_sub(last) < cfg.retarget_interval_secs {
                return None;
            }
        }

        let timestamps = self.share_timestamps.lock();
        let window_start = now.saturating_sub(cfg.retarget_interval_secs);
        let recent_count = timestamps.iter().filter(|&&ts| ts >= window_start).count();

        if last_retarget.is_none()
            && recent_count < MIN_SHARES_FOR_RETARGET
            && now.saturating_sub(self.created_at) < cfg.retarget_interval_secs
        {
            return None;
        }

        if recent_count == 0 {
            *last_retarget = Some(now);
            return None;
        }

        let window_secs = cfg.retarget_interval_secs as f64;
        let actual_share_secs = window_secs / recent_count as f64;

        // Deadband check: avoid oscillation when within ±variance_percent of target_share_secs
        let variance_ratio = (cfg.variance_percent / 100.0).clamp(0.0, 0.99);
        let min_target_secs = cfg.target_share_secs * (1.0 - variance_ratio);
        let max_target_secs = cfg.target_share_secs * (1.0 + variance_ratio);
        if actual_share_secs >= min_target_secs && actual_share_secs <= max_target_secs {
            *last_retarget = Some(now);
            return None;
        }

        let current_diff = *self.difficulty.read();
        let base_diff = if current_diff.is_finite() && current_diff > 0.0 {
            current_diff
        } else {
            cfg.min_difficulty
        };

        // Smooth bounded adjustment factor per retarget step
        let raw_ratio = cfg.target_share_secs / actual_share_secs;
        let bounded_ratio = raw_ratio.clamp(MAX_VARDIFF_DOWN_FACTOR, MAX_VARDIFF_UP_FACTOR);
        let new_diff = (base_diff * bounded_ratio).clamp(cfg.min_difficulty, cfg.max_difficulty);

        *last_retarget = Some(now);
        drop(timestamps);

        if (new_diff - current_diff).abs() <= f64::EPSILON * current_diff.max(1.0) {
            return None;
        }

        *self.difficulty.write() = new_diff;
        Some(new_diff)
    }

    /// Get the last retarget time (for testing).
    pub fn last_retarget_time(&self) -> Option<u64> {
        *self.last_retarget.lock()
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

    #[test]
    fn test_hashrate_estimation_empty() {
        let session = WorkerSession::new("s1".into(), "00000001".into(), 1.0);
        assert_eq!(session.estimated_hashrate(), 0.0);
    }

    #[test]
    fn test_hashrate_estimation_single_share() {
        let session = WorkerSession::new("s1".into(), "00000001".into(), 1.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        session.record_share_timestamp(now);
        // Need at least 2 shares for rate calculation
        assert_eq!(session.estimated_hashrate(), 0.0);
    }

    #[test]
    fn test_difficulty_retarget_no_shares() {
        let session = WorkerSession::new("s1".into(), "00000001".into(), 1.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // First retarget should set last_retarget time
        let result = session.maybe_retarget_difficulty();
        assert!(result.is_none());
        assert_eq!(session.last_retarget_time(), Some(now));
    }

    #[test]
    fn test_difficulty_retarget_increase() {
        let session = WorkerSession::new("s1".into(), "00000001".into(), 1.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Submit many shares (more than target) to trigger difficulty increase
        // Use timestamps within the window relative to current time
        for i in 0..40 {
            session.record_share_timestamp(now - 30 + i);
        }

        let new_diff = session.maybe_retarget_difficulty();
        assert!(new_diff.is_some());
        assert!(new_diff.unwrap() > 1.0);
    }

    #[test]
    fn test_difficulty_retarget_decrease() {
        let session = WorkerSession::new("s1".into(), "00000001".into(), 10.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Submit very few shares to trigger difficulty decrease (need MIN_SHARES_FOR_RETARGET)
        // Use timestamps within the window relative to current time
        for i in 0..6 {
            session.record_share_timestamp(now - 30 + i * 5);
        }

        let new_diff = session.maybe_retarget_difficulty();
        eprintln!(
            "test_difficulty_retarget_decrease: new_diff={:?}, current_diff={}, timestamps={:?}",
            new_diff,
            *session.difficulty.read(),
            *session.share_timestamps.lock()
        );
        assert!(new_diff.is_some());
        assert!(new_diff.unwrap() < 10.0);
    }

    #[test]
    fn test_difficulty_retarget_clamp_bounds() {
        let session = WorkerSession::new("s1".into(), "00000001".into(), 1.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Submit extreme number of shares - should clamp to max
        // Use timestamps within the window relative to current time
        for i in 0..10000 {
            session.record_share_timestamp(now - 30 + i);
        }

        let new_diff = session.maybe_retarget_difficulty();
        assert!(new_diff.is_some());
        assert!(new_diff.unwrap() <= 1_000_000.0);
    }

    fn test_vardiff_cfg() -> VarDiffConfig {
        VarDiffConfig {
            enabled: true,
            min_difficulty: 0.5,
            max_difficulty: 100.0,
            target_share_secs: 15.0,
            retarget_interval_secs: 60,
            variance_percent: 30.0,
        }
    }

    #[test]
    fn test_vardiff_disabled_returns_none() {
        let mut cfg = test_vardiff_cfg();
        cfg.enabled = false;
        let session = WorkerSession::new_at("s1".into(), "00000001".into(), 1.0, 1_000);
        for i in 0..20 {
            session.record_share_timestamp_with_window(1_000 + i, cfg.retarget_interval_secs);
        }
        assert_eq!(
            session.maybe_retarget_difficulty_with_config(&cfg, 1_060),
            None
        );
        assert_eq!(session.get_difficulty(), 1.0);
    }

    #[test]
    fn test_vardiff_ramp_up_smooth_and_bounded() {
        let cfg = test_vardiff_cfg();
        // target = 15s in 60s window => 4 expected shares
        let session = WorkerSession::new_at("s1".into(), "00000001".into(), 1.0, 1_000);

        // Submit 32 shares (8x faster than target); single step must be capped at 4x
        for i in 0..32 {
            session.record_share_timestamp_with_window(1_000 + i, cfg.retarget_interval_secs);
        }
        let d1 = session
            .maybe_retarget_difficulty_with_config(&cfg, 1_035)
            .expect("must ramp up");
        assert!(
            (d1 - 4.0).abs() < 1e-6,
            "expected smooth 4x cap (4.0), got {d1}"
        );

        // Calling again before retarget_interval_secs must not retarget
        assert_eq!(
            session.maybe_retarget_difficulty_with_config(&cfg, 1_050),
            None
        );

        // After another interval with sustained high share rate, ramps up further
        for i in 0..32 {
            session.record_share_timestamp_with_window(1_065 + i, cfg.retarget_interval_secs);
        }
        let d2 = session
            .maybe_retarget_difficulty_with_config(&cfg, 1_096)
            .expect("must ramp up again");
        assert!((d2 - 16.0).abs() < 1e-6, "expected 16.0, got {d2}");
    }

    #[test]
    fn test_vardiff_ramp_down_smooth() {
        let cfg = test_vardiff_cfg();
        // Start at diff 20.0; submit only 1 share in 60s (actual = 60s/share vs target 15s => ratio 0.25)
        let session = WorkerSession::new_at("s1".into(), "00000001".into(), 20.0, 1_000);
        session.record_share_timestamp_with_window(1_055, cfg.retarget_interval_secs);

        let d1 = session
            .maybe_retarget_difficulty_with_config(&cfg, 1_060)
            .expect("must ramp down after interval elapsed");
        assert!((d1 - 5.0).abs() < 1e-6, "expected 5.0, got {d1}");
    }

    #[test]
    fn test_vardiff_deadband_tolerance_skips_retarget() {
        let cfg = test_vardiff_cfg();
        // target = 15s, variance = 30% => deadband [10.5s, 19.5s]
        // 4 shares in 60s => actual = 15.0s/share (exact target)
        // 5 shares in 60s => actual = 12.0s/share (inside [10.5, 19.5])
        let session = WorkerSession::new_at("s1".into(), "00000001".into(), 10.0, 1_000);
        for i in 0..5 {
            session.record_share_timestamp_with_window(1_005 + i * 10, cfg.retarget_interval_secs);
        }
        assert_eq!(
            session.maybe_retarget_difficulty_with_config(&cfg, 1_060),
            None
        );
        assert_eq!(session.get_difficulty(), 10.0);
    }

    #[test]
    fn test_vardiff_clamps_to_min_and_max() {
        let cfg = test_vardiff_cfg();

        // Clamp to max (100.0)
        let high_session = WorkerSession::new_at("s_hi".into(), "00000001".into(), 60.0, 1_000);
        for i in 0..40 {
            high_session.record_share_timestamp_with_window(1_000 + i, cfg.retarget_interval_secs);
        }
        let clamped_max = high_session
            .maybe_retarget_difficulty_with_config(&cfg, 1_045)
            .expect("must clamp to max");
        assert!((clamped_max - 100.0).abs() < 1e-6);

        // Already at max -> subsequent retarget returns None (no redundant notification)
        for i in 0..40 {
            high_session.record_share_timestamp_with_window(1_065 + i, cfg.retarget_interval_secs);
        }
        assert_eq!(
            high_session.maybe_retarget_difficulty_with_config(&cfg, 1_106),
            None
        );

        // Clamp to min (0.5)
        let low_session = WorkerSession::new_at("s_lo".into(), "00000002".into(), 0.8, 1_000);
        low_session.record_share_timestamp_with_window(1_050, cfg.retarget_interval_secs);
        let clamped_min = low_session
            .maybe_retarget_difficulty_with_config(&cfg, 1_060)
            .expect("must clamp to min");
        assert!((clamped_min - 0.5).abs() < 1e-6);

        // Already at min -> subsequent retarget returns None
        low_session.record_share_timestamp_with_window(1_115, cfg.retarget_interval_secs);
        assert_eq!(
            low_session.maybe_retarget_difficulty_with_config(&cfg, 1_120),
            None
        );
    }
}
