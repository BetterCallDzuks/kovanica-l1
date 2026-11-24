//! Read-only snapshot manifest inspector and non-destructive chunk verification report.
//!
//! Validates snapshot manifests and their referenced chunk files without
//! mutating any files on disk. Checksums are verified using streaming BLAKE3,
//! matching the digest algorithm used across Kovanica storage and CLI tooling.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Default manifest filenames searched when a directory path is supplied.
pub const DEFAULT_MANIFEST_FILENAMES: &[&str] = &["manifest.json", "snapshot-manifest.json"];

/// Digest algorithm identifier reported in manifest summaries.
pub const DIGEST_ALGORITHM_BLAKE3: &str = "blake3";

/// Streaming I/O buffer size used when hashing chunk files (64 KiB).
const HASH_READ_BUFFER_BYTES: usize = 64 * 1024;

/// Single chunk / payload file entry inside [`SnapshotManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunkEntry {
    /// Relative path to the chunk file within the snapshot directory.
    pub path: String,
    /// Expected 32-byte BLAKE3 digest encoded as 64 hex characters (optional `0x` prefix).
    #[serde(alias = "hash", alias = "blake3_hash", alias = "checksum")]
    pub blake3: String,
    /// Expected byte length of the chunk file, if recorded in the manifest.
    #[serde(default, alias = "size_bytes", alias = "bytes")]
    pub size: Option<u64>,
}

/// JSON manifest describing a Kovanica snapshot archive and its chunk files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Snapshot manifest or archive format version, if recorded.
    #[serde(default, alias = "format_version")]
    pub version: Option<u32>,
    /// Chain ID (e.g. `1` mainnet, `2` testnet, `3` devnet), if recorded.
    #[serde(default, alias = "chainId")]
    pub chain_id: Option<u64>,
    /// Canonical network tag (e.g. `1-f35df34c92001436`), if recorded.
    #[serde(default, alias = "networkTag")]
    pub network_tag: Option<String>,
    /// Committed-leader height represented by the snapshot, if recorded.
    #[serde(default)]
    pub height: Option<u64>,
    /// Hex-encoded 32-byte state root, if recorded.
    #[serde(default, alias = "stateRoot")]
    pub state_root: Option<String>,
    /// Ordered list of chunk / payload files belonging to this snapshot.
    #[serde(default, alias = "files")]
    pub chunks: Vec<SnapshotChunkEntry>,
}

/// Read-only summary of a snapshot manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifestSummary {
    /// Filename of the inspected manifest (e.g. `manifest.json`).
    pub manifest_file: String,
    /// Snapshot format version, if present.
    pub format_version: Option<u32>,
    /// Chain ID, if present.
    pub chain_id: Option<u64>,
    /// Trimmed network tag, if present and non-empty.
    pub network_tag: Option<String>,
    /// Snapshot height, if present.
    pub height: Option<u64>,
    /// Normalized lowercase hex state root (when valid 32-byte hex), or trimmed raw string.
    pub state_root: Option<String>,
    /// Number of chunk entries listed in the manifest.
    pub chunk_count: usize,
    /// Sum of declared chunk byte sizes (using saturating addition).
    pub total_bytes: u64,
    /// Whether every chunk entry declared an explicit byte size.
    pub all_chunk_sizes_known: bool,
    /// Digest algorithm used for chunk verification (`"blake3"`).
    pub digest_algorithm: String,
}

/// Structured, JSON-serializable report produced by [`verify_snapshot_report`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotVerificationReport {
    /// `true` iff the manifest is valid, at least one chunk was verified, and no issues were found.
    pub ok: bool,
    /// Parsed manifest summary, if the manifest could be located and decoded.
    pub manifest: Option<SnapshotManifestSummary>,
    /// Total number of chunk entries inspected from the manifest.
    pub chunks_checked: usize,
    /// Number of chunks present on disk that passed size and BLAKE3 verification.
    pub chunks_valid: usize,
    /// Number of chunks that failed verification (corrupted bytes, size mismatch, unreadable, or invalid entry).
    pub chunks_corrupt: usize,
    /// Number of chunks referenced by the manifest that are missing on disk.
    pub chunks_missing: usize,
    /// Human-readable descriptions of all manifest and chunk verification issues.
    pub issues: Vec<String>,
    /// Total number of verified bytes across all valid chunks.
    pub verified_bytes: u64,
}

/// Resolve a manifest file path, its base directory, and its display filename from `input`.
///
/// Accepts either a directory (searched for [`DEFAULT_MANIFEST_FILENAMES`]) or a
/// direct path to a manifest JSON file.
fn resolve_manifest_path(input: &Path) -> Result<(PathBuf, PathBuf, String), String> {
    if !input.exists() {
        return Err(format!("snapshot path does not exist: {}", input.display()));
    }
    if input.is_dir() {
        for candidate_name in DEFAULT_MANIFEST_FILENAMES {
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
            DEFAULT_MANIFEST_FILENAMES.join(", ")
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

/// Normalize and validate a 32-byte (64 hex character) digest string.
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

/// Validate that a chunk path is a safe relative path within the snapshot directory.
fn validate_relative_chunk_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("chunk path must not be empty".to_string());
    }
    let candidate = Path::new(trimmed);
    if candidate.is_absolute() {
        return Err(format!("absolute chunk path `{trimmed}` is not allowed"));
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
        return Err("chunk path resolves to empty path".to_string());
    }
    Ok(normalized)
}

/// Stream-hash a file with BLAKE3 and return `(lowercase_hex_digest, byte_len)`.
fn hash_file_blake3_streaming(path: &Path) -> Result<(String, u64), String> {
    let file = File::open(path).map_err(|e| format!("failed to open file: {e}"))?;
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; HASH_READ_BUFFER_BYTES];
    let mut total_bytes: u64 = 0;

    loop {
        let read_n = reader
            .read(&mut buf)
            .map_err(|e| format!("failed to read file: {e}"))?;
        if read_n == 0 {
            break;
        }
        hasher.update(&buf[..read_n]);
        total_bytes = total_bytes.saturating_add(read_n as u64);
    }

    Ok((hasher.finalize().to_hex().to_string(), total_bytes))
}

/// Build a [`SnapshotManifestSummary`] from a parsed [`SnapshotManifest`].
fn summarize_manifest(
    manifest: &SnapshotManifest,
    manifest_file: String,
) -> SnapshotManifestSummary {
    let network_tag = manifest
        .network_tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let state_root = manifest
        .state_root
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|raw| parse_hex_32(raw).unwrap_or_else(|_| raw.to_string()));

    let total_bytes = manifest.chunks.iter().fold(0u64, |acc, chunk| {
        acc.saturating_add(chunk.size.unwrap_or(0))
    });

    let all_chunk_sizes_known = manifest.chunks.iter().all(|chunk| chunk.size.is_some());

    SnapshotManifestSummary {
        manifest_file,
        format_version: manifest.version,
        chain_id: manifest.chain_id,
        network_tag,
        height: manifest.height,
        state_root,
        chunk_count: manifest.chunks.len(),
        total_bytes,
        all_chunk_sizes_known,
        digest_algorithm: DIGEST_ALGORITHM_BLAKE3.to_string(),
    }
}

/// Read and summarize a snapshot manifest without reading chunk payloads or mutating any files.
///
/// `path` may be either a snapshot directory containing `manifest.json` /
/// `snapshot-manifest.json`, or a direct path to a manifest JSON file.
pub fn inspect_snapshot_manifest(path: &Path) -> Result<SnapshotManifestSummary> {
    let (manifest_path, _base_dir, manifest_file) =
        resolve_manifest_path(path).map_err(|e| anyhow!(e))?;
    let raw = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read manifest `{}`", manifest_path.display()))?;
    let manifest: SnapshotManifest = serde_json::from_str(&raw)
        .with_context(|| format!("parse manifest JSON `{}`", manifest_path.display()))?;
    Ok(summarize_manifest(&manifest, manifest_file))
}

/// Perform full non-destructive verification of a snapshot manifest and all referenced chunk files.
///
/// Verifies manifest presence and JSON schema, path safety, chunk file presence,
/// declared byte sizes (when present), and streaming BLAKE3 checksums. Never
/// mutates any files on disk.
pub fn verify_snapshot_report(path: &Path) -> SnapshotVerificationReport {
    let (manifest_path, base_dir, manifest_file) = match resolve_manifest_path(path) {
        Ok(resolved) => resolved,
        Err(err) => {
            return SnapshotVerificationReport {
                ok: false,
                manifest: None,
                chunks_checked: 0,
                chunks_valid: 0,
                chunks_corrupt: 0,
                chunks_missing: 0,
                issues: vec![err],
                verified_bytes: 0,
            };
        }
    };

    let raw = match std::fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(err) => {
            return SnapshotVerificationReport {
                ok: false,
                manifest: None,
                chunks_checked: 0,
                chunks_valid: 0,
                chunks_corrupt: 0,
                chunks_missing: 0,
                issues: vec![format!("failed to read `{manifest_file}`: {err}")],
                verified_bytes: 0,
            };
        }
    };

    let manifest: SnapshotManifest = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            return SnapshotVerificationReport {
                ok: false,
                manifest: None,
                chunks_checked: 0,
                chunks_valid: 0,
                chunks_corrupt: 0,
                chunks_missing: 0,
                issues: vec![format!("invalid manifest JSON schema: {err}")],
                verified_bytes: 0,
            };
        }
    };

    let summary = summarize_manifest(&manifest, manifest_file);
    let mut issues = Vec::new();

    if manifest.chunks.is_empty() {
        issues.push("manifest contains no chunk entries".to_string());
    }

    if let Some(root) = manifest.state_root.as_deref() {
        if let Err(err) = parse_hex_32(root) {
            issues.push(format!("invalid manifest `state_root`: {err}"));
        }
    }

    if let Some(raw_tag) = manifest.network_tag.as_deref() {
        if raw_tag.trim().is_empty() {
            issues.push("manifest `network_tag` must not be empty when present".to_string());
        }
    }

    let mut chunks_checked = 0usize;
    let mut chunks_valid = 0usize;
    let mut chunks_corrupt = 0usize;
    let mut chunks_missing = 0usize;
    let mut verified_bytes = 0u64;
    let mut seen_paths = HashSet::new();

    for (idx, entry) in manifest.chunks.iter().enumerate() {
        chunks_checked += 1;

        let rel_path = match validate_relative_chunk_path(&entry.path) {
            Ok(p) => p,
            Err(err) => {
                chunks_corrupt += 1;
                issues.push(format!("chunks[{idx}]: {err}"));
                continue;
            }
        };
        let label = rel_path.to_string_lossy().into_owned();

        if !seen_paths.insert(label.clone()) {
            chunks_corrupt += 1;
            issues.push(format!("duplicate chunk entry `{label}`"));
            continue;
        }

        let expected_hash = match parse_hex_32(&entry.blake3) {
            Ok(h) => h,
            Err(err) => {
                chunks_corrupt += 1;
                issues.push(format!("chunk `{label}` has invalid blake3 digest: {err}"));
                continue;
            }
        };

        let full_path = base_dir.join(&rel_path);
        if !full_path.exists() {
            chunks_missing += 1;
            issues.push(format!("missing chunk file `{label}`"));
            continue;
        }
        if !full_path.is_file() {
            chunks_corrupt += 1;
            issues.push(format!("chunk path `{label}` is not a regular file"));
            continue;
        }

        match hash_file_blake3_streaming(&full_path) {
            Ok((actual_hash, actual_bytes)) => {
                let mut chunk_failed = false;

                if let Some(expected_size) = entry.size {
                    if actual_bytes != expected_size {
                        chunk_failed = true;
                        issues.push(format!(
                            "size mismatch for `{label}`: expected {expected_size} bytes, got {actual_bytes} bytes"
                        ));
                    }
                }

                if actual_hash != expected_hash {
                    chunk_failed = true;
                    issues.push(format!(
                        "blake3 mismatch for `{label}`: expected {expected_hash}, got {actual_hash}"
                    ));
                }

                if chunk_failed {
                    chunks_corrupt += 1;
                } else {
                    chunks_valid += 1;
                    verified_bytes = verified_bytes.saturating_add(actual_bytes);
                }
            }
            Err(err) => {
                chunks_corrupt += 1;
                issues.push(format!("failed to read/hash chunk `{label}`: {err}"));
            }
        }
    }

    let ok = issues.is_empty()
        && chunks_checked > 0
        && chunks_valid == chunks_checked
        && chunks_corrupt == 0
        && chunks_missing == 0;

    SnapshotVerificationReport {
        ok,
        manifest: Some(summary),
        chunks_checked,
        chunks_valid,
        chunks_corrupt,
        chunks_missing,
        issues,
        verified_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn blake3_hex(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    fn write_valid_snapshot_fixture(dir: &Path) -> (SnapshotManifest, u64) {
        let chunk0 = b"KVSNSP01chunk-zero-payload-data".to_vec();
        let chunk1 = vec![0xABu8; 4096];

        fs::create_dir_all(dir.join("chunks")).unwrap();
        fs::write(dir.join("chunks/chunk-0000.bin"), &chunk0).unwrap();
        fs::write(dir.join("chunks/chunk-0001.bin"), &chunk1).unwrap();

        let total_bytes = (chunk0.len() + chunk1.len()) as u64;
        let manifest = SnapshotManifest {
            version: Some(1),
            chain_id: Some(1),
            network_tag: Some("1-f35df34c92001436".to_string()),
            height: Some(42_000),
            state_root: Some(format!("0x{}", "ab".repeat(32))),
            chunks: vec![
                SnapshotChunkEntry {
                    path: "chunks/chunk-0000.bin".to_string(),
                    blake3: blake3_hex(&chunk0),
                    size: Some(chunk0.len() as u64),
                },
                SnapshotChunkEntry {
                    path: "chunks/chunk-0001.bin".to_string(),
                    blake3: blake3_hex(&chunk1),
                    size: Some(chunk1.len() as u64),
                },
            ],
        };

        let raw = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(dir.join("manifest.json"), raw).unwrap();

        (manifest, total_bytes)
    }

    #[test]
    fn verify_valid_snapshot_returns_ok_true() {
        let tmp = TempDir::new().unwrap();
        let (_manifest, expected_bytes) = write_valid_snapshot_fixture(tmp.path());

        let report = verify_snapshot_report(tmp.path());
        assert!(
            report.ok,
            "expected ok report, got issues: {:?}",
            report.issues
        );
        assert_eq!(report.chunks_checked, 2);
        assert_eq!(report.chunks_valid, 2);
        assert_eq!(report.chunks_corrupt, 0);
        assert_eq!(report.chunks_missing, 0);
        assert_eq!(report.verified_bytes, expected_bytes);
        assert!(report.issues.is_empty());

        let summary = report.manifest.expect("manifest summary should be present");
        assert_eq!(summary.manifest_file, "manifest.json");
        assert_eq!(summary.format_version, Some(1));
        assert_eq!(summary.chain_id, Some(1));
        assert_eq!(summary.network_tag.as_deref(), Some("1-f35df34c92001436"));
        assert_eq!(summary.height, Some(42_000));
        assert_eq!(summary.state_root, Some("ab".repeat(32)));
        assert_eq!(summary.chunk_count, 2);
        assert_eq!(summary.total_bytes, expected_bytes);
        assert!(summary.all_chunk_sizes_known);
        assert_eq!(summary.digest_algorithm, DIGEST_ALGORITHM_BLAKE3);
    }

    #[test]
    fn verify_detects_corrupted_chunk_byte() {
        let tmp = TempDir::new().unwrap();
        let (_manifest, _) = write_valid_snapshot_fixture(tmp.path());

        // Flip a single byte in chunk-0001.bin without changing its length.
        let chunk_path = tmp.path().join("chunks/chunk-0001.bin");
        let mut bytes = fs::read(&chunk_path).unwrap();
        bytes[128] ^= 0x01;
        fs::write(&chunk_path, &bytes).unwrap();

        let report = verify_snapshot_report(tmp.path());
        assert!(!report.ok);
        assert_eq!(report.chunks_checked, 2);
        assert_eq!(report.chunks_valid, 1);
        assert_eq!(report.chunks_corrupt, 1);
        assert_eq!(report.chunks_missing, 0);
        assert_eq!(
            report.verified_bytes,
            b"KVSNSP01chunk-zero-payload-data".len() as u64
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("blake3 mismatch") && issue.contains("chunk-0001.bin")),
            "expected blake3 mismatch issue, got {:?}",
            report.issues
        );
    }

    #[test]
    fn verify_detects_chunk_size_mismatch_and_corruption() {
        let tmp = TempDir::new().unwrap();
        let (_manifest, _) = write_valid_snapshot_fixture(tmp.path());

        // Truncate chunk-0000.bin so both size and hash mismatch.
        let chunk_path = tmp.path().join("chunks/chunk-0000.bin");
        fs::write(&chunk_path, b"truncated").unwrap();

        let report = verify_snapshot_report(tmp.path());
        assert!(!report.ok);
        assert_eq!(report.chunks_checked, 2);
        assert_eq!(report.chunks_valid, 1);
        assert_eq!(report.chunks_corrupt, 1);
        assert_eq!(report.chunks_missing, 0);
        assert!(report.issues.iter().any(|i| i.contains("size mismatch")));
        assert!(report.issues.iter().any(|i| i.contains("blake3 mismatch")));
    }

    #[test]
    fn verify_detects_missing_chunk() {
        let tmp = TempDir::new().unwrap();
        let (_manifest, _) = write_valid_snapshot_fixture(tmp.path());

        fs::remove_file(tmp.path().join("chunks/chunk-0000.bin")).unwrap();

        let report = verify_snapshot_report(tmp.path());
        assert!(!report.ok);
        assert_eq!(report.chunks_checked, 2);
        assert_eq!(report.chunks_valid, 1);
        assert_eq!(report.chunks_corrupt, 0);
        assert_eq!(report.chunks_missing, 1);
        assert_eq!(report.verified_bytes, 4096);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("missing chunk file")
                    && issue.contains("chunk-0000.bin")),
            "expected missing chunk issue, got {:?}",
            report.issues
        );
    }

    #[test]
    fn inspect_manifest_only_does_not_require_chunk_files() {
        let tmp = TempDir::new().unwrap();
        let manifest_json = r#"{
            "version": 2,
            "chainId": 2,
            "networkTag": "2-24cdb5fadd98b207",
            "height": 123456,
            "stateRoot": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "files": [
                {
                    "path": "part-0.bin",
                    "hash": "2222222222222222222222222222222222222222222222222222222222222222",
                    "size_bytes": 1024
                },
                {
                    "path": "part-1.bin",
                    "blake3": "3333333333333333333333333333333333333333333333333333333333333333",
                    "size": 2048
                }
            ]
        }"#;
        let manifest_path = tmp.path().join("snapshot-manifest.json");
        fs::write(&manifest_path, manifest_json).unwrap();

        // Inspect both via directory and via direct manifest file path.
        for target in [tmp.path(), manifest_path.as_path()] {
            let summary = inspect_snapshot_manifest(target).unwrap();
            assert_eq!(summary.manifest_file, "snapshot-manifest.json");
            assert_eq!(summary.format_version, Some(2));
            assert_eq!(summary.chain_id, Some(2));
            assert_eq!(summary.network_tag.as_deref(), Some("2-24cdb5fadd98b207"));
            assert_eq!(summary.height, Some(123_456));
            assert_eq!(summary.state_root, Some("11".repeat(32)));
            assert_eq!(summary.chunk_count, 2);
            assert_eq!(summary.total_bytes, 3072);
            assert!(summary.all_chunk_sizes_known);
            assert_eq!(summary.digest_algorithm, "blake3");
        }
    }

    #[test]
    fn verify_rejects_path_traversal_and_duplicate_entries() {
        let tmp = TempDir::new().unwrap();
        let data = b"hello";
        fs::write(tmp.path().join("ok.bin"), data).unwrap();

        let manifest = SnapshotManifest {
            version: Some(1),
            chain_id: Some(3),
            network_tag: None,
            height: Some(10),
            state_root: None,
            chunks: vec![
                SnapshotChunkEntry {
                    path: "../escape.bin".to_string(),
                    blake3: blake3_hex(data),
                    size: Some(data.len() as u64),
                },
                SnapshotChunkEntry {
                    path: "ok.bin".to_string(),
                    blake3: blake3_hex(data),
                    size: Some(data.len() as u64),
                },
                SnapshotChunkEntry {
                    path: "./ok.bin".to_string(),
                    blake3: blake3_hex(data),
                    size: Some(data.len() as u64),
                },
            ],
        };
        fs::write(
            tmp.path().join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let report = verify_snapshot_report(tmp.path());
        assert!(!report.ok);
        assert_eq!(report.chunks_checked, 3);
        assert_eq!(report.chunks_valid, 1);
        assert_eq!(report.chunks_corrupt, 2);
        assert_eq!(report.chunks_missing, 0);
        assert!(report.issues.iter().any(|i| i.contains("path traversal")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("duplicate chunk entry")));
    }

    #[test]
    fn json_serialization_round_trip_for_summary_and_report() {
        let tmp = TempDir::new().unwrap();
        let (_manifest, _) = write_valid_snapshot_fixture(tmp.path());

        let summary = inspect_snapshot_manifest(tmp.path()).unwrap();
        let summary_json = serde_json::to_string(&summary).unwrap();
        let summary_decoded: SnapshotManifestSummary = serde_json::from_str(&summary_json).unwrap();
        assert_eq!(summary, summary_decoded);

        let report = verify_snapshot_report(tmp.path());
        let report_json = serde_json::to_string_pretty(&report).unwrap();
        let report_decoded: SnapshotVerificationReport =
            serde_json::from_str(&report_json).unwrap();
        assert_eq!(report, report_decoded);

        // Ensure JSON contains expected top-level fields.
        let value: serde_json::Value = serde_json::from_str(&report_json).unwrap();
        assert_eq!(value["ok"], serde_json::Value::Bool(true));
        assert_eq!(value["chunks_checked"], 2);
        assert_eq!(value["chunks_valid"], 2);
        assert_eq!(value["chunks_corrupt"], 0);
        assert_eq!(value["chunks_missing"], 0);
        assert!(value["issues"].as_array().unwrap().is_empty());
        assert!(value["verified_bytes"].as_u64().unwrap() > 0);
    }
}
