//! Offline snapshot integrity verification (`kovanica snapshot verify`).
//!
//! Validates a snapshot directory (containing `manifest.json` or
//! `snapshot-manifest.json`) or a direct manifest JSON file without mutating
//! state or requiring an RPC connection:
//! 1. Snapshot path & manifest file presence
//! 2. Manifest JSON schema, required fields, safe relative file paths, and hex format
//! 3. Chain ID expectation & frozen canonical network tag compliance
//!    (`1 -> 1-f35df34c92001436`, `2 -> 2-24cdb5fadd98b207`)
//! 4. Streaming BLAKE3 hash (and optional byte-size) verification of every payload file
//!
//! Fails closed: any missing file, schema error, hash mismatch, or chain/tag
//! mismatch yields `ok: false` and a non-zero exit code.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use kovanica_types::Hash;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::node_doctor::canonical_network_tag;
use crate::output;

/// Default manifest file names searched when `<path>` is a directory.
const MANIFEST_FILENAMES: &[&str] = &["manifest.json", "snapshot-manifest.json"];

/// Magic prefix of the versioned `kovanica-snapshot` / `StateStore` binary format.
const KVSNSP01_MAGIC: &[u8; 8] = b"KVSNSP01";

/// Snapshot subcommands (`kovanica snapshot ...`).
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum SnapshotCommand {
    /// Verify snapshot manifest, BLAKE3 payload hashes, chain ID, and canonical network tag
    Verify(SnapshotVerifyArgs),
}

/// Arguments for `kovanica snapshot verify`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct SnapshotVerifyArgs {
    /// Path to a snapshot directory (containing `manifest.json`) or a manifest JSON file
    pub path: PathBuf,
    /// Expected chain ID to verify against the snapshot (1 mainnet, 2 testnet, 3 devnet)
    #[arg(long)]
    pub expected_chain_id: Option<u64>,
}

/// Verdict for a single verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
}

impl CheckStatus {
    /// Uppercase label for human-readable checklist output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

/// Outcome of one snapshot verification check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerifyCheck {
    pub name: String,
    pub status: CheckStatus,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Structured integrity report produced by `kovanica snapshot verify`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SnapshotVerifyReport {
    pub ok: bool,
    pub path: String,
    pub chain_id: Option<u64>,
    pub network_tag: Option<String>,
    pub verified_files: usize,
    pub checks: Vec<VerifyCheck>,
}

/// Manifest JSON schema describing a Kovanica snapshot archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(alias = "chainId")]
    pub chain_id: u64,
    #[serde(default, alias = "networkTag")]
    pub network_tag: Option<String>,
    #[serde(default)]
    pub height: Option<u64>,
    #[serde(default, alias = "stateRoot")]
    pub state_root: Option<String>,
    #[serde(default)]
    pub files: Vec<SnapshotFileEntry>,
}

/// Single payload file entry inside [`SnapshotManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFileEntry {
    pub path: String,
    #[serde(alias = "hash", alias = "blake3_hash")]
    pub blake3: String,
    #[serde(default, alias = "size_bytes")]
    pub size: Option<u64>,
}

/// Return a non-canonicalized display string for the caller-supplied path.
///
/// Avoids calling `fs::canonicalize` so host directory layouts or symlink
/// targets are not unnecessarily disclosed.
fn display_target_path(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

/// Normalize and validate a 32-byte (64 hex char) digest string.
fn parse_hex_32(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.len() != 64 {
        return Err(format!(
            "expected 64 hex characters (32 bytes), got {}",
            stripped.len()
        ));
    }
    let bytes = hex::decode(stripped).map_err(|_| "contains non-hex characters".to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 decoded bytes, got {}", bytes.len()));
    }
    Ok(stripped.to_ascii_lowercase())
}

/// Ensure a manifest payload path is a safe relative path within the snapshot directory.
fn validate_relative_file_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("file path must not be empty".to_string());
    }
    let candidate = Path::new(trimmed);
    if candidate.is_absolute() {
        return Err(format!("absolute path `{trimmed}` is not allowed"));
    }
    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "unsafe path traversal component in `{trimmed}` is not allowed"
                ));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err("file path resolves to empty path".to_string());
    }
    Ok(normalized)
}

/// Hash a file with BLAKE3 and inspect whether it carries the `KVSNSP01` magic prefix.
fn hash_file_blake3(path: &Path) -> Result<(String, u64, bool), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("failed to read file: {e}"))?;
    let total_bytes = bytes.len() as u64;
    let is_kvsnsp01 = bytes.starts_with(KVSNSP01_MAGIC);
    let digest = Hash::new(&bytes).to_hex();
    Ok((digest, total_bytes, is_kvsnsp01))
}

/// Resolve the manifest file path and base payload directory from the user-supplied path.
fn resolve_manifest_path(input: &Path) -> Result<(PathBuf, PathBuf, String), String> {
    if !input.exists() {
        return Err("snapshot path does not exist".to_string());
    }
    if input.is_dir() {
        for candidate_name in MANIFEST_FILENAMES {
            let candidate = input.join(candidate_name);
            if candidate.is_file() {
                return Ok((
                    candidate,
                    input.to_path_buf(),
                    (*candidate_name).to_string(),
                ));
            }
        }
        return Err(format!(
            "no manifest file found in directory (expected one of: {})",
            MANIFEST_FILENAMES.join(", ")
        ));
    }
    if input.is_file() {
        let base_dir = input
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let file_name = input
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "manifest.json".to_string());
        return Ok((input.to_path_buf(), base_dir, file_name));
    }
    Err("snapshot path is neither a regular file nor a directory".to_string())
}

/// Validate chain ID expectations and frozen canonical network tags for Chains 1 and 2.
fn evaluate_chain_and_network_tag(
    chain_id: u64,
    expected_chain_id: Option<u64>,
    network_tag: Option<&str>,
) -> VerifyCheck {
    let trimmed_tag = network_tag.map(str::trim).filter(|s| !s.is_empty());

    if let Some(expected) = expected_chain_id {
        if chain_id != expected {
            return VerifyCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Fail,
                summary: format!("chain_id mismatch: expected {expected}, manifest has {chain_id}"),
                details: Some(json!({
                    "expected_chain_id": expected,
                    "chain_id": chain_id,
                    "network_tag": trimmed_tag,
                })),
            };
        }
    }

    if let Some(canonical_tag) = canonical_network_tag(chain_id) {
        match trimmed_tag {
            Some(tag) if tag == canonical_tag => VerifyCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Pass,
                summary: format!("chain_id={chain_id} matches canonical network tag `{tag}`"),
                details: Some(json!({
                    "chain_id": chain_id,
                    "network_tag": tag,
                    "canonical_network_tag": canonical_tag,
                })),
            },
            Some(tag) => VerifyCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Fail,
                summary: format!(
                    "non-canonical network tag for chain_id={chain_id}: got `{tag}`, expected `{canonical_tag}`"
                ),
                details: Some(json!({
                    "chain_id": chain_id,
                    "network_tag": tag,
                    "canonical_network_tag": canonical_tag,
                })),
            },
            None => VerifyCheck {
                name: "chain_id_and_network_tag".to_string(),
                status: CheckStatus::Fail,
                summary: format!(
                    "missing required canonical network tag for chain_id={chain_id} (expected `{canonical_tag}`)"
                ),
                details: Some(json!({
                    "chain_id": chain_id,
                    "network_tag": Value::Null,
                    "canonical_network_tag": canonical_tag,
                })),
            },
        }
    } else {
        if let Some(raw) = network_tag {
            if raw.trim().is_empty() {
                return VerifyCheck {
                    name: "chain_id_and_network_tag".to_string(),
                    status: CheckStatus::Fail,
                    summary: format!("chain_id={chain_id} has empty network_tag field in manifest"),
                    details: Some(json!({
                        "chain_id": chain_id,
                        "network_tag": raw,
                    })),
                };
            }
        }
        VerifyCheck {
            name: "chain_id_and_network_tag".to_string(),
            status: CheckStatus::Pass,
            summary: match trimmed_tag {
                Some(tag) => format!("chain_id={chain_id} (custom/devnet), network_tag=`{tag}`"),
                None => format!("chain_id={chain_id} (custom/devnet)"),
            },
            details: Some(json!({
                "chain_id": chain_id,
                "network_tag": trimmed_tag,
            })),
        }
    }
}

/// Verify a snapshot directory or manifest file and return a structured [`SnapshotVerifyReport`].
pub fn verify_snapshot(path: &Path, expected_chain_id: Option<u64>) -> SnapshotVerifyReport {
    let display_path = display_target_path(path);
    let mut checks = Vec::new();

    // 1. Presence check
    let (manifest_path, base_dir, manifest_label) = match resolve_manifest_path(path) {
        Ok(resolved) => {
            checks.push(VerifyCheck {
                name: "manifest_presence".to_string(),
                status: CheckStatus::Pass,
                summary: format!("found manifest `{}`", resolved.2),
                details: Some(json!({ "manifest": resolved.2 })),
            });
            resolved
        }
        Err(err) => {
            checks.push(VerifyCheck {
                name: "manifest_presence".to_string(),
                status: CheckStatus::Fail,
                summary: err,
                details: None,
            });
            return SnapshotVerifyReport {
                ok: false,
                path: display_path,
                chain_id: None,
                network_tag: None,
                verified_files: 0,
                checks,
            };
        }
    };

    // 2. Read & parse manifest schema
    let raw_manifest = match std::fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(err) => {
            checks.push(VerifyCheck {
                name: "manifest_schema".to_string(),
                status: CheckStatus::Fail,
                summary: format!("failed to read `{manifest_label}`: {err}"),
                details: None,
            });
            return SnapshotVerifyReport {
                ok: false,
                path: display_path,
                chain_id: None,
                network_tag: None,
                verified_files: 0,
                checks,
            };
        }
    };

    let manifest: SnapshotManifest = match serde_json::from_str(&raw_manifest) {
        Ok(parsed) => parsed,
        Err(err) => {
            checks.push(VerifyCheck {
                name: "manifest_schema".to_string(),
                status: CheckStatus::Fail,
                summary: format!("invalid manifest JSON schema: {err}"),
                details: None,
            });
            return SnapshotVerifyReport {
                ok: false,
                path: display_path,
                chain_id: None,
                network_tag: None,
                verified_files: 0,
                checks,
            };
        }
    };

    let chain_id = Some(manifest.chain_id);
    let network_tag = manifest
        .network_tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    // Schema semantic checks
    let mut schema_errors = Vec::new();
    if manifest.files.is_empty() {
        schema_errors.push("manifest `files` list must not be empty".to_string());
    }
    if let Some(root) = manifest.state_root.as_deref() {
        if let Err(err) = parse_hex_32(root) {
            schema_errors.push(format!("invalid `state_root`: {err}"));
        }
    }

    let mut validated_entries: Vec<(PathBuf, String, String, Option<u64>)> = Vec::new();
    let mut seen_paths = HashSet::new();
    for (idx, entry) in manifest.files.iter().enumerate() {
        let rel_path = match validate_relative_file_path(&entry.path) {
            Ok(p) => p,
            Err(err) => {
                schema_errors.push(format!("files[{idx}]: {err}"));
                continue;
            }
        };
        let normalized_label = rel_path.to_string_lossy().into_owned();
        if !seen_paths.insert(normalized_label.clone()) {
            schema_errors.push(format!("duplicate file entry `{normalized_label}`"));
            continue;
        }
        let expected_hash = match parse_hex_32(&entry.blake3) {
            Ok(h) => h,
            Err(err) => {
                schema_errors.push(format!(
                    "files[{idx}] (`{normalized_label}`) invalid blake3 digest: {err}"
                ));
                continue;
            }
        };
        validated_entries.push((rel_path, normalized_label, expected_hash, entry.size));
    }

    if !schema_errors.is_empty() {
        checks.push(VerifyCheck {
            name: "manifest_schema".to_string(),
            status: CheckStatus::Fail,
            summary: schema_errors.join("; "),
            details: Some(json!({ "errors": schema_errors })),
        });
    } else {
        checks.push(VerifyCheck {
            name: "manifest_schema".to_string(),
            status: CheckStatus::Pass,
            summary: format!(
                "valid schema ({} payload file{})",
                validated_entries.len(),
                if validated_entries.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            details: Some(json!({
                "version": manifest.version,
                "height": manifest.height,
                "file_count": validated_entries.len(),
            })),
        });
    }

    // 3. Chain ID & canonical network tag check
    checks.push(evaluate_chain_and_network_tag(
        manifest.chain_id,
        expected_chain_id,
        manifest.network_tag.as_deref(),
    ));

    // 4. Payload file presence, size, and BLAKE3 integrity checks
    let mut verified_files = 0usize;
    for (rel_path, label, expected_hash, expected_size) in validated_entries {
        let full_path = base_dir.join(&rel_path);
        let check_name = format!("file:{label}");

        if !full_path.exists() {
            checks.push(VerifyCheck {
                name: check_name,
                status: CheckStatus::Fail,
                summary: format!("missing referenced file `{label}`"),
                details: Some(json!({ "file": label, "present": false })),
            });
            continue;
        }
        if !full_path.is_file() {
            checks.push(VerifyCheck {
                name: check_name,
                status: CheckStatus::Fail,
                summary: format!("referenced path `{label}` is not a regular file"),
                details: Some(json!({ "file": label, "is_file": false })),
            });
            continue;
        }

        match hash_file_blake3(&full_path) {
            Ok((actual_hash, actual_size, is_kvsnsp01)) => {
                if let Some(exp_size) = expected_size {
                    if actual_size != exp_size {
                        checks.push(VerifyCheck {
                            name: check_name,
                            status: CheckStatus::Fail,
                            summary: format!(
                                "size mismatch for `{label}`: expected {exp_size} bytes, got {actual_size} bytes"
                            ),
                            details: Some(json!({
                                "file": label,
                                "expected_size": exp_size,
                                "actual_size": actual_size,
                            })),
                        });
                        continue;
                    }
                }

                if actual_hash != expected_hash {
                    checks.push(VerifyCheck {
                        name: check_name,
                        status: CheckStatus::Fail,
                        summary: format!(
                            "BLAKE3 mismatch for `{label}`: expected {expected_hash}, got {actual_hash}"
                        ),
                        details: Some(json!({
                            "file": label,
                            "expected_blake3": expected_hash,
                            "actual_blake3": actual_hash,
                            "size": actual_size,
                        })),
                    });
                    continue;
                }

                verified_files += 1;
                let format_note = if is_kvsnsp01 { " [KVSNSP01]" } else { "" };
                checks.push(VerifyCheck {
                    name: check_name,
                    status: CheckStatus::Pass,
                    summary: format!("BLAKE3 verified ({actual_size} bytes){format_note}"),
                    details: Some(json!({
                        "file": label,
                        "blake3": actual_hash,
                        "size": actual_size,
                        "format": if is_kvsnsp01 { "kvsnsp01" } else { "raw" },
                    })),
                });
            }
            Err(err) => {
                checks.push(VerifyCheck {
                    name: check_name,
                    status: CheckStatus::Fail,
                    summary: format!("failed to hash `{label}`: {err}"),
                    details: Some(json!({ "file": label })),
                });
            }
        }
    }

    let ok = !checks.is_empty() && checks.iter().all(|c| c.status == CheckStatus::Pass);
    SnapshotVerifyReport {
        ok,
        path: display_path,
        chain_id,
        network_tag,
        verified_files,
        checks,
    }
}

/// Format [`SnapshotVerifyReport`] checks into rows for human-readable table rendering.
pub fn format_verify_rows(report: &SnapshotVerifyReport) -> Vec<Vec<String>> {
    report
        .checks
        .iter()
        .map(|check| {
            vec![
                check.name.clone(),
                check.status.label().to_string(),
                check.summary.clone(),
            ]
        })
        .collect()
}

/// CLI entry point for `kovanica snapshot verify`.
///
/// Always prints the complete report (JSON when `--json` is set, or a
/// human-readable checklist otherwise) before returning an error on failure so
/// callers receive both structured output and a non-zero exit code.
pub fn run(args: SnapshotVerifyArgs, json_output: bool) -> Result<()> {
    let report = verify_snapshot(&args.path, args.expected_chain_id);

    if json_output {
        output::print_json(&serde_json::to_value(&report)?)?;
    } else {
        let status_label = if report.ok { "PASS" } else { "FAIL" };
        let chain_display = report
            .chain_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let tag_display = report
            .network_tag
            .clone()
            .unwrap_or_else(|| "-".to_string());

        output::print_kv(&[
            ("Snapshot", report.path.clone()),
            ("Status", status_label.to_string()),
            ("Chain ID", chain_display),
            ("Network Tag", tag_display),
            ("Verified Files", report.verified_files.to_string()),
        ]);
        println!();
        let rows = format_verify_rows(&report);
        output::print_table(&["CHECK", "STATUS", "SUMMARY"], &rows);
    }

    if !report.ok {
        let failed_count = report
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .count();
        bail!(
            "snapshot verification failed ({failed_count} check{} failed)",
            if failed_count == 1 { "" } else { "s" }
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn blake3_hex(bytes: &[u8]) -> String {
        Hash::new(bytes).to_hex()
    }

    fn write_valid_snapshot_dir(
        dir: &Path,
        chain_id: u64,
        network_tag: Option<&str>,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut state_payload = KVSNSP01_MAGIC.to_vec();
        state_payload.extend_from_slice(b"simulated-state-snapshot-payload-v1");
        let meta_payload = br#"{"height":42000}"#.to_vec();

        fs::write(dir.join("state.snap"), &state_payload).unwrap();
        fs::write(dir.join("metadata.json"), &meta_payload).unwrap();

        let manifest = SnapshotManifest {
            version: Some(1),
            chain_id,
            network_tag: network_tag.map(ToOwned::to_owned),
            height: Some(42_000),
            state_root: Some(blake3_hex(b"state-root")),
            files: vec![
                SnapshotFileEntry {
                    path: "state.snap".to_string(),
                    blake3: blake3_hex(&state_payload),
                    size: Some(state_payload.len() as u64),
                },
                SnapshotFileEntry {
                    path: "metadata.json".to_string(),
                    blake3: blake3_hex(&meta_payload),
                    size: Some(meta_payload.len() as u64),
                },
            ],
        };
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        (state_payload, meta_payload)
    }

    #[test]
    fn valid_mainnet_and_testnet_snapshots_pass_blake3_verification() {
        for (chain_id, tag) in [(1u64, "1-f35df34c92001436"), (2u64, "2-24cdb5fadd98b207")] {
            let dir = tempdir().unwrap();
            write_valid_snapshot_dir(dir.path(), chain_id, Some(tag));

            let report = verify_snapshot(dir.path(), Some(chain_id));
            assert!(report.ok, "expected pass for chain {chain_id}: {report:?}");
            assert_eq!(report.chain_id, Some(chain_id));
            assert_eq!(report.network_tag.as_deref(), Some(tag));
            assert_eq!(report.verified_files, 2);
            assert!(report.checks.iter().all(|c| c.status == CheckStatus::Pass));

            // Also works when passing the manifest.json file directly.
            let direct = verify_snapshot(&dir.path().join("manifest.json"), Some(chain_id));
            assert!(direct.ok);
            assert_eq!(direct.verified_files, 2);

            // CLI entry point returns Ok(()) on valid snapshot.
            let args = SnapshotVerifyArgs {
                path: dir.path().to_path_buf(),
                expected_chain_id: Some(chain_id),
            };
            assert!(run(args, true).is_ok());
        }
    }

    #[test]
    fn corrupted_payload_blake3_mismatch_fails_closed() {
        let dir = tempdir().unwrap();
        write_valid_snapshot_dir(dir.path(), 2, Some("2-24cdb5fadd98b207"));

        // Flip a byte in state.snap without updating manifest.json.
        let snap_path = dir.path().join("state.snap");
        let mut bytes = fs::read(&snap_path).unwrap();
        bytes[10] ^= 0xFF;
        fs::write(&snap_path, bytes).unwrap();

        let report = verify_snapshot(dir.path(), Some(2));
        assert!(!report.ok);
        assert_eq!(report.verified_files, 1);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "file:state.snap")
            .expect("state.snap check present");
        assert_eq!(failed.status, CheckStatus::Fail);
        assert!(failed.summary.contains("BLAKE3 mismatch"));

        let args = SnapshotVerifyArgs {
            path: dir.path().to_path_buf(),
            expected_chain_id: Some(2),
        };
        assert!(run(args, true).is_err());
    }

    #[test]
    fn missing_referenced_file_fails_closed() {
        let dir = tempdir().unwrap();
        write_valid_snapshot_dir(dir.path(), 2, Some("2-24cdb5fadd98b207"));
        fs::remove_file(dir.path().join("metadata.json")).unwrap();

        let report = verify_snapshot(dir.path(), Some(2));
        assert!(!report.ok);
        assert_eq!(report.verified_files, 1);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "file:metadata.json")
            .expect("metadata.json check present");
        assert_eq!(failed.status, CheckStatus::Fail);
        assert!(failed.summary.contains("missing referenced file"));
    }

    #[test]
    fn mismatched_expected_chain_id_fails_closed() {
        let dir = tempdir().unwrap();
        write_valid_snapshot_dir(dir.path(), 2, Some("2-24cdb5fadd98b207"));

        let report = verify_snapshot(dir.path(), Some(1));
        assert!(!report.ok);
        let chain_check = report
            .checks
            .iter()
            .find(|c| c.name == "chain_id_and_network_tag")
            .unwrap();
        assert_eq!(chain_check.status, CheckStatus::Fail);
        assert!(chain_check.summary.contains("chain_id mismatch"));
    }

    #[test]
    fn non_canonical_or_missing_network_tag_for_chains_1_and_2_fails_closed() {
        // Chain 1 with wrong network tag
        let dir1 = tempdir().unwrap();
        write_valid_snapshot_dir(dir1.path(), 1, Some("1-deadbeefdeadbeef"));
        let report1 = verify_snapshot(dir1.path(), Some(1));
        assert!(!report1.ok);
        let check1 = report1
            .checks
            .iter()
            .find(|c| c.name == "chain_id_and_network_tag")
            .unwrap();
        assert_eq!(check1.status, CheckStatus::Fail);
        assert!(check1.summary.contains("1-f35df34c92001436"));

        // Chain 2 with wrong network tag
        let dir2 = tempdir().unwrap();
        write_valid_snapshot_dir(dir2.path(), 2, Some("1-f35df34c92001436"));
        let report2 = verify_snapshot(dir2.path(), Some(2));
        assert!(!report2.ok);
        let check2 = report2
            .checks
            .iter()
            .find(|c| c.name == "chain_id_and_network_tag")
            .unwrap();
        assert_eq!(check2.status, CheckStatus::Fail);
        assert!(check2.summary.contains("2-24cdb5fadd98b207"));

        // Chain 1 with missing network tag
        let dir3 = tempdir().unwrap();
        write_valid_snapshot_dir(dir3.path(), 1, None);
        let report3 = verify_snapshot(dir3.path(), Some(1));
        assert!(!report3.ok);
        let check3 = report3
            .checks
            .iter()
            .find(|c| c.name == "chain_id_and_network_tag")
            .unwrap();
        assert_eq!(check3.status, CheckStatus::Fail);
        assert!(check3
            .summary
            .contains("missing required canonical network tag"));
    }

    #[test]
    fn devnet_chain_without_canonical_tag_passes_when_hashes_match() {
        let dir = tempdir().unwrap();
        write_valid_snapshot_dir(dir.path(), 3, None);

        let report = verify_snapshot(dir.path(), Some(3));
        assert!(report.ok, "expected devnet snapshot to pass: {report:?}");
        assert_eq!(report.chain_id, Some(3));
        assert_eq!(report.network_tag, None);
        assert_eq!(report.verified_files, 2);
    }

    #[test]
    fn schema_errors_and_path_traversal_fail_closed() {
        // Invalid JSON
        let dir_bad_json = tempdir().unwrap();
        fs::write(dir_bad_json.path().join("manifest.json"), "{not-json").unwrap();
        let report = verify_snapshot(dir_bad_json.path(), None);
        assert!(!report.ok);
        assert_eq!(report.verified_files, 0);

        // Path traversal attempt in manifest
        let dir_traversal = tempdir().unwrap();
        let manifest = json!({
            "chain_id": 2,
            "network_tag": "2-24cdb5fadd98b207",
            "files": [
                {
                    "path": "../outside.snap",
                    "blake3": blake3_hex(b"secret")
                }
            ]
        });
        fs::write(
            dir_traversal.path().join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let report = verify_snapshot(dir_traversal.path(), Some(2));
        assert!(!report.ok);
        let schema_check = report
            .checks
            .iter()
            .find(|c| c.name == "manifest_schema")
            .unwrap();
        assert_eq!(schema_check.status, CheckStatus::Fail);
        assert!(schema_check.summary.contains("path traversal"));

        // Missing directory
        let missing = dir_traversal.path().join("does-not-exist");
        let report = verify_snapshot(&missing, None);
        assert!(!report.ok);
        assert_eq!(report.checks[0].name, "manifest_presence");
        assert_eq!(report.checks[0].status, CheckStatus::Fail);
    }

    #[test]
    fn json_report_formatting_matches_expected_contract() {
        let dir = tempdir().unwrap();
        write_valid_snapshot_dir(dir.path(), 2, Some("2-24cdb5fadd98b207"));

        let report = verify_snapshot(dir.path(), Some(2));
        let serialized = serde_json::to_value(&report).unwrap();

        assert_eq!(serialized["ok"], Value::Bool(true));
        assert!(serialized["path"].is_string());
        assert_eq!(serialized["chain_id"], json!(2));
        assert_eq!(serialized["network_tag"], json!("2-24cdb5fadd98b207"));
        assert_eq!(serialized["verified_files"], json!(2));

        let checks = serialized["checks"]
            .as_array()
            .expect("checks must be an array");
        assert_eq!(checks.len(), 5);
        assert_eq!(checks[0]["name"], json!("manifest_presence"));
        assert_eq!(checks[0]["status"], json!("pass"));
        assert_eq!(checks[1]["name"], json!("manifest_schema"));
        assert_eq!(checks[2]["name"], json!("chain_id_and_network_tag"));
        assert_eq!(checks[3]["name"], json!("file:state.snap"));
        assert_eq!(checks[3]["details"]["format"], json!("kvsnsp01"));
        assert_eq!(checks[4]["name"], json!("file:metadata.json"));

        let rows = format_verify_rows(&report);
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0][1], "PASS");
    }
}
