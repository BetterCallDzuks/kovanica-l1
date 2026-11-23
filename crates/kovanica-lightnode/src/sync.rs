//! Follow sealed committed-leader headers.
//!
//! The first accepted header is a checkpoint: the seal quorum is checked
//! and the parent digest is not. Every later header must name the previous
//! leader digest and the next height. A rejected seal is not written.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use kovanica_light::verify_sealed_header;
use kovanica_types::{Committee, Hash, LeaderHeader};
use serde::{Deserialize, Serialize};

use crate::config::LightConfig;
use crate::rpc::RpcClient;

/// File name of the last header whose seals verified.
pub const HEADER_FILE: &str = "last-header.json";

/// Canonical network tag for Kovanica Mainnet (chain 1).
pub const CANONICAL_MAINNET_TAG: &str = "1-f35df34c92001436";

/// Canonical network tag for Kovanica Testnet (chain 2).
pub const CANONICAL_TESTNET_TAG: &str = "2-24cdb5fadd98b207";

/// Maximum header lag considered fully synced when at least one verified peer is connected.
const SYNCED_MAX_LAG_HEADERS: u64 = 2;

/// Maximum header lag considered catching up before reporting a stall.
const CATCHING_UP_MAX_LAG_HEADERS: u64 = 50;

/// Coarse sync health classification for a light node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LightnodeSyncState {
    /// Within 2 headers of the network head with at least one verified peer.
    Synced,
    /// Between 3 and 50 headers behind the network head with at least one verified peer.
    CatchingUp,
    /// More than 50 headers behind the network head, or zero verified peers.
    Stalled,
}

/// Snapshot of light-node header sync progress and network identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightnodeSyncSummary {
    /// Current sync health classification.
    pub sync_state: LightnodeSyncState,
    /// Highest locally verified committed-leader header height.
    pub header_height: u64,
    /// Highest known network head height.
    pub network_head_height: u64,
    /// Saturated header lag (`network_head_height.saturating_sub(header_height)`).
    pub lag_headers: u64,
    /// Number of verified peers contributing to header sync.
    pub verified_peers: usize,
    /// Network tag observed from the peer / RPC endpoint.
    pub network_tag: String,
}

/// Verify that `observed_tag` matches the canonical network tag for `chain_id`.
///
/// Fails closed on Chains 1 (mainnet) and 2 (testnet) if the tag does not match
/// the exact canonical value. Allows any non-empty custom tag on Chain 3 / devnet.
pub fn verify_canonical_network_tag(chain_id: u64, observed_tag: &str) -> Result<(), String> {
    match chain_id {
        1 => {
            if observed_tag == CANONICAL_MAINNET_TAG {
                Ok(())
            } else {
                Err(format!(
                    "canonical network tag mismatch for chain 1 (mainnet): expected '{CANONICAL_MAINNET_TAG}', got '{observed_tag}'"
                ))
            }
        }
        2 => {
            if observed_tag == CANONICAL_TESTNET_TAG {
                Ok(())
            } else {
                Err(format!(
                    "canonical network tag mismatch for chain 2 (testnet): expected '{CANONICAL_TESTNET_TAG}', got '{observed_tag}'"
                ))
            }
        }
        _ => {
            if observed_tag.trim().is_empty() {
                Err(format!(
                    "empty network tag for chain {chain_id}: custom devnet tag must be non-empty"
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Summarize light-node header sync progress into a structured status report.
pub fn summarize_lightnode_sync(
    header_height: u64,
    network_head_height: u64,
    verified_peers: usize,
    network_tag: String,
) -> LightnodeSyncSummary {
    let lag_headers = network_head_height.saturating_sub(header_height);
    let sync_state = if verified_peers == 0 || lag_headers > CATCHING_UP_MAX_LAG_HEADERS {
        LightnodeSyncState::Stalled
    } else if lag_headers <= SYNCED_MAX_LAG_HEADERS {
        LightnodeSyncState::Synced
    } else {
        LightnodeSyncState::CatchingUp
    };

    LightnodeSyncSummary {
        sync_state,
        header_height,
        network_head_height,
        lag_headers,
        verified_peers,
        network_tag,
    }
}

/// What `sync` learned from the full node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The node has not stored a sealed header.
    NoHeader,
    /// The light node accepted `header` (and any headers between the
    /// previous checkpoint and it).
    Verified {
        /// Committed-leader height now stored.
        height: u64,
        /// Header hash.
        hash: Hash,
    },
}

/// Load the last accepted header, if this data directory has one.
pub fn load_header(dir: &Path) -> Result<Option<LeaderHeader>> {
    let path = dir.join(HEADER_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let header =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(header))
}

/// Persist a header that has already passed [`verify_sealed_header`].
pub fn save_header(dir: &Path, header: &LeaderHeader) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(HEADER_FILE);
    let text = serde_json::to_string_pretty(header).context("encoding leader header")?;
    let tmp = dir.join(format!("{HEADER_FILE}.tmp"));
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Download and verify headers, then store only those that passed.
pub fn sync_rpc(dir: &Path, cfg: &LightConfig, rpc: &RpcClient) -> Result<SyncOutcome> {
    let Some(latest) = rpc.latest_header()? else {
        return Ok(SyncOutcome::NoHeader);
    };
    let committee = rpc.committee(cfg.epoch)?;
    let stored = load_header(dir)?;
    match stored {
        None => {
            accept_and_store(
                dir,
                cfg.chain_id,
                &committee,
                &latest,
                &rpc.seals(latest.committed_height)?,
                None,
            )?;
            Ok(SyncOutcome::Verified {
                height: latest.committed_height,
                hash: latest.hash(),
            })
        }
        Some(stored) if latest.committed_height < stored.committed_height => {
            bail!(
                "full node height {} is behind the stored header {}",
                latest.committed_height,
                stored.committed_height
            )
        }
        Some(stored) if latest.committed_height == stored.committed_height => {
            if latest.hash() != stored.hash() {
                bail!(
                    "full node header at height {} does not match the stored header",
                    stored.committed_height
                );
            }
            accept_and_store(
                dir,
                cfg.chain_id,
                &committee,
                &latest,
                &rpc.seals(latest.committed_height)?,
                None,
            )?;
            Ok(SyncOutcome::Verified {
                height: latest.committed_height,
                hash: latest.hash(),
            })
        }
        Some(mut parent) => {
            for height in parent.committed_height.saturating_add(1)..=latest.committed_height {
                let Some(header) = rpc.header(Some(height))? else {
                    bail!("full node has no leader header at height {height}");
                };
                let seals = rpc.seals(height)?;
                accept_and_store(
                    dir,
                    cfg.chain_id,
                    &committee,
                    &header,
                    &seals,
                    Some(&parent),
                )?;
                parent = header;
            }
            Ok(SyncOutcome::Verified {
                height: parent.committed_height,
                hash: parent.hash(),
            })
        }
    }
}

/// Verify `header` against `parent` and write it. On failure the previous file stays.
pub fn accept_and_store(
    dir: &Path,
    chain_id: u64,
    committee: &Committee,
    header: &LeaderHeader,
    seals: &[kovanica_types::CommitSeal],
    parent: Option<&LeaderHeader>,
) -> Result<()> {
    verify_sealed_header(chain_id, committee, header, seals, parent).with_context(|| {
        format!(
            "rejected leader header at height {}",
            header.committed_height
        )
    })?;
    save_header(dir, header)
}

/// Linux runs under systemd. Windows runs the same executable as a service.
#[cfg(windows)]
pub fn platform_note() -> &'static str {
    "Windows: install this executable as a service that runs `kovanica-lightnode run`. A tray UI is not part of this binary."
}

/// Linux runs under systemd. Windows runs the same executable as a service.
#[cfg(not(windows))]
pub fn platform_note() -> &'static str {
    "Linux: run `kovanica-lightnode run` under systemd. The unit file is installed separately. A tray UI is not part of this binary."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_tag_accepts_exact_mainnet_and_testnet() {
        assert_eq!(
            verify_canonical_network_tag(1, CANONICAL_MAINNET_TAG),
            Ok(())
        );
        assert_eq!(
            verify_canonical_network_tag(2, CANONICAL_TESTNET_TAG),
            Ok(())
        );
    }

    #[test]
    fn canonical_tag_rejects_cross_chain_and_spoofed_tags() {
        let mainnet_with_testnet = verify_canonical_network_tag(1, CANONICAL_TESTNET_TAG)
            .expect_err("chain 1 must reject chain 2 tag");
        assert!(mainnet_with_testnet.contains("chain 1"));
        assert!(mainnet_with_testnet.contains(CANONICAL_MAINNET_TAG));

        let testnet_with_mainnet = verify_canonical_network_tag(2, CANONICAL_MAINNET_TAG)
            .expect_err("chain 2 must reject chain 1 tag");
        assert!(testnet_with_mainnet.contains("chain 2"));
        assert!(testnet_with_mainnet.contains(CANONICAL_TESTNET_TAG));

        assert!(verify_canonical_network_tag(1, "1-deadbeefdeadbeef").is_err());
        assert!(verify_canonical_network_tag(1, " 1-f35df34c92001436 ").is_err());
        assert!(verify_canonical_network_tag(1, "").is_err());
        assert!(verify_canonical_network_tag(2, "2-deadbeefdeadbeef").is_err());
        assert!(verify_canonical_network_tag(2, "").is_err());
    }

    #[test]
    fn canonical_tag_allows_non_empty_devnet_and_rejects_empty() {
        assert_eq!(
            verify_canonical_network_tag(3, "3-localdev00000001"),
            Ok(())
        );
        assert_eq!(verify_canonical_network_tag(3, "devnet-custom"), Ok(()));
        assert!(verify_canonical_network_tag(3, "").is_err());
        assert!(verify_canonical_network_tag(3, "   \t\n").is_err());
    }

    #[test]
    fn summarize_sync_reports_synced_within_threshold() {
        let at_head = summarize_lightnode_sync(100, 100, 3, CANONICAL_TESTNET_TAG.into());
        assert_eq!(
            at_head,
            LightnodeSyncSummary {
                sync_state: LightnodeSyncState::Synced,
                header_height: 100,
                network_head_height: 100,
                lag_headers: 0,
                verified_peers: 3,
                network_tag: CANONICAL_TESTNET_TAG.into(),
            }
        );

        let lag_two = summarize_lightnode_sync(98, 100, 1, CANONICAL_MAINNET_TAG.into());
        assert_eq!(lag_two.sync_state, LightnodeSyncState::Synced);
        assert_eq!(lag_two.lag_headers, 2);

        let ahead = summarize_lightnode_sync(105, 100, 2, CANONICAL_MAINNET_TAG.into());
        assert_eq!(ahead.sync_state, LightnodeSyncState::Synced);
        assert_eq!(ahead.lag_headers, 0);
    }

    #[test]
    fn summarize_sync_reports_catching_up_between_three_and_fifty() {
        let lag_three = summarize_lightnode_sync(97, 100, 1, CANONICAL_TESTNET_TAG.into());
        assert_eq!(lag_three.sync_state, LightnodeSyncState::CatchingUp);
        assert_eq!(lag_three.lag_headers, 3);

        let lag_fifty = summarize_lightnode_sync(50, 100, 4, CANONICAL_TESTNET_TAG.into());
        assert_eq!(lag_fifty.sync_state, LightnodeSyncState::CatchingUp);
        assert_eq!(lag_fifty.lag_headers, 50);
    }

    #[test]
    fn summarize_sync_reports_stalled_on_large_lag_or_zero_peers() {
        let lag_fifty_one = summarize_lightnode_sync(49, 100, 5, CANONICAL_MAINNET_TAG.into());
        assert_eq!(lag_fifty_one.sync_state, LightnodeSyncState::Stalled);
        assert_eq!(lag_fifty_one.lag_headers, 51);

        let zero_peers_at_head =
            summarize_lightnode_sync(100, 100, 0, CANONICAL_MAINNET_TAG.into());
        assert_eq!(zero_peers_at_head.sync_state, LightnodeSyncState::Stalled);
        assert_eq!(zero_peers_at_head.lag_headers, 0);
        assert_eq!(zero_peers_at_head.verified_peers, 0);
    }

    #[test]
    fn summarize_sync_serializes_cleanly() {
        let summary = summarize_lightnode_sync(42, 45, 2, CANONICAL_TESTNET_TAG.into());
        let json = serde_json::to_value(&summary).expect("serialize LightnodeSyncSummary");
        assert_eq!(json["sync_state"], "CatchingUp");
        assert_eq!(json["header_height"], 42);
        assert_eq!(json["network_head_height"], 45);
        assert_eq!(json["lag_headers"], 3);
        assert_eq!(json["verified_peers"], 2);
        assert_eq!(json["network_tag"], CANONICAL_TESTNET_TAG);
    }
}
