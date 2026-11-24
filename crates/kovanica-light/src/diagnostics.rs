//! Read-only light-client synchronization status summaries and checkpoint
//! verification diagnostics.
//!
//! All types and helpers in this module are purely observational and have no
//! effect on L1 consensus rules.

use std::collections::BTreeMap;

use kovanica_types::{Hash, LeaderHeader};
use serde::{Deserialize, Serialize};

/// Sync state string when no verified headers have been recorded yet.
pub const SYNC_STATE_UNINITIALIZED: &str = "uninitialized";
/// Sync state string when headers have been verified but the client is not yet
/// confirmed caught up to the network tip.
pub const SYNC_STATE_SYNCING: &str = "syncing";
/// Sync state string when the local tip height has reached or exceeded the
/// reported network tip height.
pub const SYNC_STATE_SYNCED: &str = "synced";

/// Trusted light-client checkpoint `(height, hash)` used to anchor header sync
/// and verify local header continuity against a known-good committed leader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCheckpoint {
    /// Committed leader height of the checkpoint.
    pub height: u64,
    /// Expected 64-character lowercase hex digest (`Hash::to_hex()`).
    pub hash: String,
}

impl TrustedCheckpoint {
    /// Construct a trusted checkpoint from a typed [`Hash`].
    #[must_use]
    pub fn new(height: u64, hash: Hash) -> Self {
        Self {
            height,
            hash: hash.to_hex(),
        }
    }

    /// Construct a trusted checkpoint from a hex-encoded hash string.
    #[must_use]
    pub fn from_hex(height: u64, hash: impl Into<String>) -> Self {
        Self {
            height,
            hash: hash.into().trim().to_ascii_lowercase(),
        }
    }
}

/// Read-only summary of a light client's header synchronization progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightSyncStatus {
    /// Highest locally verified header height, or `None` when uninitialized.
    pub local_tip_height: Option<u64>,
    /// Number of distinct verified headers currently tracked.
    pub verified_header_count: u64,
    /// Configured trusted checkpoint height, if any.
    pub checkpoint_height: Option<u64>,
    /// Configured trusted checkpoint hash (lowercase hex), if any.
    pub checkpoint_hash: Option<String>,
    /// Reported network tip height used to compute lag, if known.
    pub network_tip_height: Option<u64>,
    /// Estimated number of blocks the local tip trails behind `network_tip_height`.
    /// `None` when either `local_tip_height` or `network_tip_height` is unknown.
    pub blocks_behind: Option<u64>,
    /// Coarse sync state: `"uninitialized"`, `"syncing"`, or `"synced"`.
    pub sync_state: String,
}

/// Structured diagnostic report from verifying a stored or supplied header
/// against a trusted checkpoint `(checkpoint_height, expected_hash)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointVerificationReport {
    /// `true` iff a header at `checkpoint_height` was present and its digest
    /// matched `expected_hash` with no recorded issues.
    pub ok: bool,
    /// Trusted checkpoint height that was checked.
    pub checkpoint_height: u64,
    /// Expected header digest at `checkpoint_height` (lowercase hex).
    pub expected_hash: String,
    /// Observed header digest at `checkpoint_height` (lowercase hex), if present.
    pub actual_hash: Option<String>,
    /// Human-readable diagnostic issues discovered during verification.
    pub issues: Vec<String>,
}

/// Lightweight in-memory tracker for verified light-client headers and an
/// optional trusted checkpoint, exposing read-only sync and checkpoint
/// diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightHeaderSyncState {
    chain_id: u64,
    checkpoint: Option<TrustedCheckpoint>,
    verified_headers: BTreeMap<u64, Hash>,
}

impl LightHeaderSyncState {
    /// Create an empty sync state for `chain_id` with no configured checkpoint.
    #[must_use]
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            checkpoint: None,
            verified_headers: BTreeMap::new(),
        }
    }

    /// Create an empty sync state for `chain_id` anchored to `checkpoint`.
    #[must_use]
    pub fn with_checkpoint(chain_id: u64, checkpoint: TrustedCheckpoint) -> Self {
        Self {
            chain_id,
            checkpoint: Some(checkpoint),
            verified_headers: BTreeMap::new(),
        }
    }

    /// Configured chain ID for this tracker.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Configured trusted checkpoint, if any.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&TrustedCheckpoint> {
        self.checkpoint.as_ref()
    }

    /// Set or replace the trusted checkpoint.
    pub fn set_checkpoint(&mut self, checkpoint: TrustedCheckpoint) {
        self.checkpoint = Some(checkpoint);
    }

    /// Record a verified header digest at `height`.
    pub fn record_verified_header(&mut self, height: u64, hash: Hash) {
        self.verified_headers.insert(height, hash);
    }

    /// Record a verified [`LeaderHeader`] by its `committed_height` and `leader_digest`.
    pub fn record_verified_leader(&mut self, header: &LeaderHeader) {
        self.record_verified_header(header.committed_height, header.leader_digest);
    }

    /// Return the highest locally verified header height, if any.
    #[must_use]
    pub fn local_tip_height(&self) -> Option<u64> {
        self.verified_headers.keys().next_back().copied()
    }

    /// Return the number of distinct verified headers currently recorded.
    #[must_use]
    pub fn verified_header_count(&self) -> u64 {
        self.verified_headers.len() as u64
    }

    /// Look up the verified header digest recorded at `height`.
    #[must_use]
    pub fn header_hash_at(&self, height: u64) -> Option<Hash> {
        self.verified_headers.get(&height).copied()
    }

    /// Compute a read-only [`LightSyncStatus`] snapshot against an optional
    /// `network_tip_height`.
    #[must_use]
    pub fn sync_status(&self, network_tip_height: Option<u64>) -> LightSyncStatus {
        build_light_sync_status(
            self.local_tip_height(),
            self.verified_header_count(),
            self.checkpoint.as_ref(),
            network_tip_height,
        )
    }

    /// Verify the locally recorded header at `checkpoint_height` against
    /// `expected_hash`.
    #[must_use]
    pub fn verify_checkpoint(
        &self,
        checkpoint_height: u64,
        expected_hash: Hash,
    ) -> CheckpointVerificationReport {
        verify_checkpoint_hash(
            self.header_hash_at(checkpoint_height),
            checkpoint_height,
            expected_hash,
        )
    }

    /// Verify the locally recorded header against the configured
    /// [`TrustedCheckpoint`], returning `None` if no checkpoint is configured.
    #[must_use]
    pub fn verify_configured_checkpoint(&self) -> Option<CheckpointVerificationReport> {
        let cp = self.checkpoint.as_ref()?;
        Some(verify_checkpoint_hex(
            self.header_hash_at(cp.height),
            cp.height,
            &cp.hash,
        ))
    }
}

/// Build a [`LightSyncStatus`] from raw sync counters and an optional network
/// tip height.
///
/// Classification rules:
/// - `"uninitialized"` when `verified_header_count == 0` or `local_tip_height` is `None`.
/// - `"synced"` when `local_tip_height` is `Some(local)` and `network_tip_height` is
///   `Some(net)` with `net <= local` (`blocks_behind == Some(0)`).
/// - `"syncing"` otherwise (either `blocks_behind > Some(0)` or `network_tip_height` is `None`).
#[must_use]
pub fn build_light_sync_status(
    local_tip_height: Option<u64>,
    verified_header_count: u64,
    checkpoint: Option<&TrustedCheckpoint>,
    network_tip_height: Option<u64>,
) -> LightSyncStatus {
    let effective_tip = if verified_header_count == 0 {
        None
    } else {
        local_tip_height
    };

    let blocks_behind = match (effective_tip, network_tip_height) {
        (Some(local), Some(net)) => Some(net.saturating_sub(local)),
        _ => None,
    };

    let sync_state = match (effective_tip, blocks_behind) {
        (None, _) => SYNC_STATE_UNINITIALIZED,
        (Some(_), Some(0)) => SYNC_STATE_SYNCED,
        (Some(_), _) => SYNC_STATE_SYNCING,
    };

    LightSyncStatus {
        local_tip_height: effective_tip,
        verified_header_count,
        checkpoint_height: checkpoint.map(|cp| cp.height),
        checkpoint_hash: checkpoint.map(|cp| cp.hash.clone()),
        network_tip_height,
        blocks_behind,
        sync_state: sync_state.to_string(),
    }
}

/// Verify an optional [`LeaderHeader`] against a trusted checkpoint
/// `(checkpoint_height, expected_hash)`.
///
/// Checks both that a header is present at `checkpoint_height` and that its
/// `leader_digest` matches `expected_hash`.
#[must_use]
pub fn verify_checkpoint_header(
    header: Option<&LeaderHeader>,
    checkpoint_height: u64,
    expected_hash: Hash,
) -> CheckpointVerificationReport {
    let expected_hex = expected_hash.to_hex();
    let Some(header) = header else {
        return CheckpointVerificationReport {
            ok: false,
            checkpoint_height,
            expected_hash: expected_hex,
            actual_hash: None,
            issues: vec![format!(
                "missing header at checkpoint height {checkpoint_height}"
            )],
        };
    };

    let actual_hex = header.leader_digest.to_hex();
    let mut issues = Vec::new();
    if header.committed_height != checkpoint_height {
        issues.push(format!(
            "header height {} does not match checkpoint height {checkpoint_height}",
            header.committed_height
        ));
    }
    if header.leader_digest != expected_hash {
        issues.push(format!(
            "checkpoint hash mismatch at height {checkpoint_height}: expected {expected_hex}, got {actual_hex}"
        ));
    }

    CheckpointVerificationReport {
        ok: issues.is_empty(),
        checkpoint_height,
        expected_hash: expected_hex,
        actual_hash: Some(actual_hex),
        issues,
    }
}

/// Verify an optional stored header [`Hash`] at `checkpoint_height` against
/// `expected_hash`.
#[must_use]
pub fn verify_checkpoint_hash(
    actual_hash: Option<Hash>,
    checkpoint_height: u64,
    expected_hash: Hash,
) -> CheckpointVerificationReport {
    verify_checkpoint_hex(actual_hash, checkpoint_height, &expected_hash.to_hex())
}

/// Verify an optional stored header [`Hash`] at `checkpoint_height` against a
/// hex-encoded expected hash string.
#[must_use]
pub fn verify_checkpoint_hex(
    actual_hash: Option<Hash>,
    checkpoint_height: u64,
    expected_hash_hex: &str,
) -> CheckpointVerificationReport {
    let normalized_expected = expected_hash_hex.trim().to_ascii_lowercase();
    let mut issues = Vec::new();

    if normalized_expected.len() != 64
        || !normalized_expected.bytes().all(|b| b.is_ascii_hexdigit())
    {
        issues.push(format!(
            "invalid expected checkpoint hash hex at height {checkpoint_height}: must be 64 hex characters"
        ));
    }

    let actual_hex = actual_hash.map(|h| h.to_hex());
    match &actual_hex {
        None => {
            issues.push(format!(
                "missing header at checkpoint height {checkpoint_height}"
            ));
        }
        Some(actual) if issues.is_empty() && actual != &normalized_expected => {
            issues.push(format!(
                "checkpoint hash mismatch at height {checkpoint_height}: expected {normalized_expected}, got {actual}"
            ));
        }
        Some(_) => {}
    }

    CheckpointVerificationReport {
        ok: issues.is_empty(),
        checkpoint_height,
        expected_hash: normalized_expected,
        actual_hash: actual_hex,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::crypto::Signature;
    use kovanica_types::signing::chain_id;
    use kovanica_types::{
        committee_seal_hash, leader_header, Address, CommittedSubDag, PublicKey, SigningKey,
        StatementBlock,
    };

    use crate::committee_from_members;

    fn sample_leader_header(height: u64, seed: u8) -> LeaderHeader {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let pk = PublicKey::from(signer.verifying_key());
        let addr = Address::from_public_key(&pk);
        let committee = committee_from_members(0, &[(0, pk, 1, addr)]);
        let digest = Hash::new([seed]);
        let leader = StatementBlock {
            author: 0,
            round: height.saturating_mul(3),
            parents: vec![],
            transactions: vec![],
            statements: vec![],
            signature: Signature([0; 64]),
            digest,
            merkle_root: Hash::zero(),
        };
        let subdag = CommittedSubDag {
            blocks: vec![leader.clone()],
            leader,
            leader_round: height.saturating_mul(3),
            leader_author: 0,
            non_blue: vec![],
        };
        leader_header(
            &subdag,
            height,
            Hash::zero(),
            Hash::zero(),
            committee.epoch,
            committee_seal_hash(committee.epoch, &[(0, pk, 1)]),
            false,
        )
    }

    #[test]
    fn sync_status_uninitialized_without_headers() {
        let state = LightHeaderSyncState::new(chain_id::HYBRID_TESTNET);
        let status = state.sync_status(Some(100));
        assert_eq!(status.local_tip_height, None);
        assert_eq!(status.verified_header_count, 0);
        assert_eq!(status.checkpoint_height, None);
        assert_eq!(status.checkpoint_hash, None);
        assert_eq!(status.network_tip_height, Some(100));
        assert_eq!(status.blocks_behind, None);
        assert_eq!(status.sync_state, SYNC_STATE_UNINITIALIZED);
    }

    #[test]
    fn sync_status_syncing_and_synced_transitions() {
        let cp_hash = Hash::new([0xAA]);
        let cp = TrustedCheckpoint::new(10, cp_hash);
        let mut state = LightHeaderSyncState::with_checkpoint(chain_id::HYBRID_TESTNET, cp.clone());

        state.record_verified_header(10, cp_hash);
        state.record_verified_header(11, Hash::new([0xBB]));

        // Trailing behind network tip -> syncing
        let syncing = state.sync_status(Some(25));
        assert_eq!(syncing.local_tip_height, Some(11));
        assert_eq!(syncing.verified_header_count, 2);
        assert_eq!(syncing.checkpoint_height, Some(10));
        assert_eq!(syncing.checkpoint_hash, Some(cp.hash.clone()));
        assert_eq!(syncing.network_tip_height, Some(25));
        assert_eq!(syncing.blocks_behind, Some(14));
        assert_eq!(syncing.sync_state, SYNC_STATE_SYNCING);

        // Unknown network tip -> syncing with blocks_behind = None
        let unknown_tip = state.sync_status(None);
        assert_eq!(unknown_tip.blocks_behind, None);
        assert_eq!(unknown_tip.sync_state, SYNC_STATE_SYNCING);

        // Caught up to network tip -> synced
        let synced = state.sync_status(Some(11));
        assert_eq!(synced.blocks_behind, Some(0));
        assert_eq!(synced.sync_state, SYNC_STATE_SYNCED);

        // Local tip ahead of stale network tip saturates at 0 -> synced
        let ahead = state.sync_status(Some(9));
        assert_eq!(ahead.blocks_behind, Some(0));
        assert_eq!(ahead.sync_state, SYNC_STATE_SYNCED);
    }

    #[test]
    fn checkpoint_verification_passes_on_matching_header() {
        let header = sample_leader_header(42, 7);
        let mut state = LightHeaderSyncState::with_checkpoint(
            chain_id::MAINNET,
            TrustedCheckpoint::new(42, header.leader_digest),
        );
        state.record_verified_leader(&header);

        let report_from_state = state.verify_checkpoint(42, header.leader_digest);
        assert!(report_from_state.ok);
        assert_eq!(report_from_state.checkpoint_height, 42);
        assert_eq!(
            report_from_state.expected_hash,
            header.leader_digest.to_hex()
        );
        assert_eq!(
            report_from_state.actual_hash,
            Some(header.leader_digest.to_hex())
        );
        assert!(report_from_state.issues.is_empty());

        let report_configured = state.verify_configured_checkpoint().unwrap();
        assert_eq!(report_configured, report_from_state);

        let report_direct = verify_checkpoint_header(Some(&header), 42, header.leader_digest);
        assert_eq!(report_direct, report_from_state);
    }

    #[test]
    fn checkpoint_verification_detects_hash_mismatch() {
        let header = sample_leader_header(42, 7);
        let wrong_hash = Hash::new([99]);

        let mut state = LightHeaderSyncState::new(chain_id::MAINNET);
        state.record_verified_leader(&header);

        let report = state.verify_checkpoint(42, wrong_hash);
        assert!(!report.ok);
        assert_eq!(report.checkpoint_height, 42);
        assert_eq!(report.expected_hash, wrong_hash.to_hex());
        assert_eq!(report.actual_hash, Some(header.leader_digest.to_hex()));
        assert_eq!(report.issues.len(), 1);
        assert!(report.issues[0].contains("mismatch"));

        let direct = verify_checkpoint_header(Some(&header), 42, wrong_hash);
        assert_eq!(direct, report);
    }

    #[test]
    fn checkpoint_verification_detects_missing_checkpoint_height() {
        let state = LightHeaderSyncState::new(chain_id::DEVNET);
        let expected = Hash::new([5]);

        let report = state.verify_checkpoint(100, expected);
        assert!(!report.ok);
        assert_eq!(report.checkpoint_height, 100);
        assert_eq!(report.expected_hash, expected.to_hex());
        assert_eq!(report.actual_hash, None);
        assert_eq!(report.issues.len(), 1);
        assert!(report.issues[0].contains("missing header"));

        let direct = verify_checkpoint_header(None, 100, expected);
        assert_eq!(direct, report);
    }

    #[test]
    fn checkpoint_header_helper_detects_height_mismatch() {
        let header = sample_leader_header(50, 3);
        let report = verify_checkpoint_header(Some(&header), 51, header.leader_digest);
        assert!(!report.ok);
        assert_eq!(report.checkpoint_height, 51);
        assert_eq!(report.actual_hash, Some(header.leader_digest.to_hex()));
        assert_eq!(report.issues.len(), 1);
        assert!(report.issues[0].contains("header height 50"));
    }

    #[test]
    fn checkpoint_hex_helper_rejects_malformed_expected_hash() {
        let report = verify_checkpoint_hex(Some(Hash::new([1])), 10, "not-valid-hex");
        assert!(!report.ok);
        assert_eq!(report.issues.len(), 1);
        assert!(report.issues[0].contains("64 hex characters"));
    }

    #[test]
    fn diagnostics_types_round_trip_json() {
        let cp = TrustedCheckpoint::new(500, Hash::new([0x42]));
        let mut state = LightHeaderSyncState::with_checkpoint(chain_id::HYBRID_TESTNET, cp);
        state.record_verified_header(500, Hash::new([0x42]));
        state.record_verified_header(505, Hash::new([0x43]));

        let status = state.sync_status(Some(510));
        let status_json = serde_json::to_string(&status).expect("serialize LightSyncStatus");
        let status_decoded: LightSyncStatus =
            serde_json::from_str(&status_json).expect("deserialize LightSyncStatus");
        assert_eq!(status_decoded, status);

        let report = state.verify_configured_checkpoint().unwrap();
        let report_json =
            serde_json::to_string(&report).expect("serialize CheckpointVerificationReport");
        let report_decoded: CheckpointVerificationReport =
            serde_json::from_str(&report_json).expect("deserialize CheckpointVerificationReport");
        assert_eq!(report_decoded, report);
    }
}
