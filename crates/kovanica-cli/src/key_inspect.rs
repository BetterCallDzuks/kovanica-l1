//! Offline keystore auditor (`kovanica key inspect <keyfile> [--json]`).
//!
//! Reads and validates keystore v2 JSON metadata completely offline without
//! decrypting the keystore or prompting for a passphrase. Never prints or
//! serializes secrets, private keys, ciphertexts, salts, or nonces.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use kovanica_types::Address;
use serde::Serialize;

use crate::address_inspect::encode_testnet;
use crate::output;
use crate::wallet;

/// Subcommands under `kovanica key`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum KeyCommand {
    /// Audit a keystore v2 file offline (metadata, PRO-21 addresses, and file permissions)
    Inspect(KeyInspectArgs),
}

/// Arguments for `kovanica key inspect`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct KeyInspectArgs {
    /// Path to the keystore v2 JSON file
    pub keyfile: PathBuf,
}

/// KDF parameters stored in a keystore v2 file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KdfReport {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Outcome of the file permission check on the keystore file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionStatus {
    Ok,
    Warning,
    Insecure,
    Unknown,
}

impl PermissionStatus {
    /// Human-readable status label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Insecure => "insecure",
            Self::Unknown => "unknown",
        }
    }
}

/// Structured file permission audit details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionsReport {
    pub status: PermissionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_0600: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_accessible: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub world_accessible: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Structured offline audit report produced by `kovanica key inspect`.
///
/// Deliberately excludes all sensitive or cryptographic secret fields
/// (`secret_key` ciphertext, `salt`, `nonce`, private key/seed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyInspectReport {
    pub file: String,
    pub version: u32,
    pub encrypted: bool,
    pub cipher: String,
    pub kdf: KdfReport,
    pub public_key: String,
    pub stored_address: String,
    pub mainnet_address: String,
    pub testnet_address: String,
    pub address_matches_public_key: bool,
    pub permissions: PermissionsReport,
    pub warnings: Vec<String>,
}

/// Inspect file permissions on `path` without modifying the file.
fn audit_permissions(path: &Path, meta: &fs::Metadata) -> PermissionsReport {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode_bits = meta.permissions().mode() & 0o777;
        let mode_str = format!("{mode_bits:04o}");
        let group_accessible = (mode_bits & 0o070) != 0;
        let world_accessible = (mode_bits & 0o007) != 0;
        let owner_only = (mode_bits & 0o077) == 0;
        let is_0600 = mode_bits == 0o600;

        let (status, warning) = if !owner_only {
            let mut who = Vec::new();
            if group_accessible {
                who.push("group");
            }
            if world_accessible {
                who.push("world");
            }
            (
                PermissionStatus::Insecure,
                Some(format!(
                    "keystore file has mode {mode_str} ({}-accessible); restrict with `chmod 0600 {}`",
                    who.join("/"),
                    path.display()
                )),
            )
        } else if !is_0600 {
            (
                PermissionStatus::Warning,
                Some(format!(
                    "keystore file has mode {mode_str} (expected 0600); recommended: `chmod 0600 {}`",
                    path.display()
                )),
            )
        } else {
            (PermissionStatus::Ok, None)
        };

        PermissionsReport {
            status,
            mode: Some(mode_str),
            is_0600: Some(is_0600),
            owner_only: Some(owner_only),
            group_accessible: Some(group_accessible),
            world_accessible: Some(world_accessible),
            warning,
        }
    }

    #[cfg(windows)]
    {
        let _ = meta;
        match wallet::ensure_owner_only(path) {
            Ok(()) => PermissionsReport {
                status: PermissionStatus::Ok,
                mode: None,
                is_0600: None,
                owner_only: Some(true),
                group_accessible: None,
                world_accessible: None,
                warning: None,
            },
            Err(err) => PermissionsReport {
                status: PermissionStatus::Insecure,
                mode: None,
                is_0600: None,
                owner_only: Some(false),
                group_accessible: None,
                world_accessible: None,
                warning: Some(err.to_string()),
            },
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta);
        PermissionsReport {
            status: PermissionStatus::Unknown,
            mode: None,
            is_0600: None,
            owner_only: None,
            group_accessible: None,
            world_accessible: None,
            warning: Some("file permission auditing is not supported on this platform".to_string()),
        }
    }
}

/// Inspect a keystore v2 file offline without decrypting it.
pub fn inspect_keystore(path: &Path) -> Result<KeyInspectReport> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("reading keystore metadata {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "refusing to inspect keystore {} through a symlink",
            path.display()
        );
    }
    if !meta.is_file() {
        bail!("keystore path {} is not a regular file", path.display());
    }

    let permissions = audit_permissions(path, &meta);

    // Parses and validates v2 metadata without decrypting or requiring a passphrase.
    let ks = wallet::load(path)?;
    let stored_addr = wallet::address(&ks)?;
    let pubkey = wallet::public_key(&ks)?;
    let derived_addr = Address::from_public_key(&pubkey);
    let address_matches_public_key = derived_addr == stored_addr;

    let mainnet_address = stored_addr.encode();
    let testnet_address = encode_testnet(&stored_addr);

    let cipher = ks
        .cipher
        .clone()
        .ok_or_else(|| anyhow::anyhow!("keystore v2 is missing cipher metadata"))?;
    let kdf = KdfReport {
        algorithm: ks
            .kdf
            .clone()
            .ok_or_else(|| anyhow::anyhow!("keystore v2 is missing kdf metadata"))?,
        memory_kib: ks
            .kdf_memory_kib
            .ok_or_else(|| anyhow::anyhow!("keystore v2 is missing kdf_memory_kib"))?,
        iterations: ks
            .kdf_iterations
            .ok_or_else(|| anyhow::anyhow!("keystore v2 is missing kdf_iterations"))?,
        parallelism: ks
            .kdf_parallelism
            .ok_or_else(|| anyhow::anyhow!("keystore v2 is missing kdf_parallelism"))?,
    };

    let mut warnings = Vec::new();
    if let Some(ref perm_warn) = permissions.warning {
        warnings.push(perm_warn.clone());
    }
    if !address_matches_public_key {
        warnings.push(format!(
            "stored address ({mainnet_address}) does not match address derived from public_key ({})",
            derived_addr.encode()
        ));
    }
    if ks.address != mainnet_address {
        warnings.push(
            "keystore stores a legacy address label; canonical PRO-21 mainnet and testnet addresses are shown above"
                .to_string(),
        );
    }

    Ok(KeyInspectReport {
        file: path.display().to_string(),
        version: ks.version,
        encrypted: ks.encrypted,
        cipher,
        kdf,
        public_key: hex::encode(pubkey.as_bytes()),
        stored_address: ks.address,
        mainnet_address,
        testnet_address,
        address_matches_public_key,
        permissions,
        warnings,
    })
}

/// Format a [`KeyInspectReport`] as a human-readable key/value table.
pub fn format_human_report(report: &KeyInspectReport) -> String {
    let perm_summary = match &report.permissions.mode {
        Some(mode) => format!("{} (mode {mode})", report.permissions.status.as_str()),
        None => report.permissions.status.as_str().to_string(),
    };

    let mut rows: Vec<(&str, String)> = vec![
        ("file", report.file.clone()),
        ("version", format!("v{}", report.version)),
        ("encrypted", report.encrypted.to_string()),
        ("cipher", report.cipher.clone()),
        (
            "kdf",
            format!(
                "{} (m={} KiB, t={}, p={})",
                report.kdf.algorithm,
                report.kdf.memory_kib,
                report.kdf.iterations,
                report.kdf.parallelism
            ),
        ),
        ("public_key", report.public_key.clone()),
        ("mainnet_address", report.mainnet_address.clone()),
        ("testnet_address", report.testnet_address.clone()),
        ("stored_address", report.stored_address.clone()),
        (
            "identity_consistent",
            report.address_matches_public_key.to_string(),
        ),
        ("permissions", perm_summary),
    ];

    for warning in &report.warnings {
        rows.push(("warning", warning.clone()));
    }

    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in &rows {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }
    out
}

/// Execute `kovanica key inspect <keyfile> [--json]`.
pub fn run(args: KeyInspectArgs, json_output: bool) -> Result<()> {
    let report = inspect_keystore(&args.keyfile)?;
    if json_output {
        output::print_json(&serde_json::to_value(&report)?)?;
    } else {
        print!("{}", format_human_report(&report));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [0x42; 32];
    const TEST_PASS: &str = "audit-test-passphrase-never-needed";

    fn write_test_keystore(dir: &Path, name: &str) -> (PathBuf, wallet::Keystore) {
        let ks = wallet::from_seed(&TEST_SEED, TEST_PASS).expect("create v2 keystore");
        let path = dir.join(name);
        wallet::save(&path, &ks).expect("save v2 keystore");
        (path, ks)
    }

    #[test]
    fn inspect_v2_keystore_with_0600_permissions_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let (path, ks) = write_test_keystore(dir.path(), "clean.json");

        let report = inspect_keystore(&path).expect("inspect v2 keystore");
        let expected_addr = wallet::address(&ks).unwrap();
        let expected_mainnet = expected_addr.encode();
        let expected_testnet = encode_testnet(&expected_addr);

        assert_eq!(report.version, 2);
        assert!(report.encrypted);
        assert_eq!(report.cipher, "xchacha20poly1305");
        assert_eq!(report.kdf.algorithm, "argon2id");
        assert_eq!(report.kdf.memory_kib, 65_536);
        assert_eq!(report.kdf.iterations, 3);
        assert_eq!(report.kdf.parallelism, 4);
        assert_eq!(report.public_key, ks.public_key);
        assert_eq!(report.stored_address, expected_mainnet);
        assert_eq!(report.mainnet_address, expected_mainnet);
        assert_eq!(report.testnet_address, expected_testnet);
        assert!(report.mainnet_address.starts_with("kvnc"));
        assert!(report.mainnet_address.ends_with("dag"));
        assert_eq!(report.mainnet_address.len(), 64);
        assert!(report.testnet_address.starts_with("tknc"));
        assert!(report.testnet_address.ends_with("dag"));
        assert_eq!(report.testnet_address.len(), 64);
        assert!(report.address_matches_public_key);

        #[cfg(unix)]
        {
            assert_eq!(report.permissions.status, PermissionStatus::Ok);
            assert_eq!(report.permissions.mode.as_deref(), Some("0600"));
            assert_eq!(report.permissions.is_0600, Some(true));
            assert_eq!(report.permissions.owner_only, Some(true));
            assert_eq!(report.permissions.group_accessible, Some(false));
            assert_eq!(report.permissions.world_accessible, Some(false));
            assert!(report.permissions.warning.is_none());
            assert!(report.warnings.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn inspect_detects_insecure_0644_and_non_0600_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let (path, _ks) = write_test_keystore(dir.path(), "insecure.json");

        // World/group-readable 0644 must be flagged as insecure with a chmod 0600 warning.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let report_0644 = inspect_keystore(&path).expect("inspect 0644 keystore");
        assert_eq!(report_0644.permissions.status, PermissionStatus::Insecure);
        assert_eq!(report_0644.permissions.mode.as_deref(), Some("0644"));
        assert_eq!(report_0644.permissions.is_0600, Some(false));
        assert_eq!(report_0644.permissions.owner_only, Some(false));
        assert_eq!(report_0644.permissions.group_accessible, Some(true));
        assert_eq!(report_0644.permissions.world_accessible, Some(true));
        let warn = report_0644.permissions.warning.as_deref().unwrap_or("");
        assert!(warn.contains("0644"), "{warn}");
        assert!(warn.contains("chmod 0600"), "{warn}");
        assert!(!report_0644.warnings.is_empty());

        // Owner-only 0400 is not group/world accessible, but is not 0600 -> warning.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let report_0400 = inspect_keystore(&path).expect("inspect 0400 keystore");
        assert_eq!(report_0400.permissions.status, PermissionStatus::Warning);
        assert_eq!(report_0400.permissions.mode.as_deref(), Some("0400"));
        assert_eq!(report_0400.permissions.is_0600, Some(false));
        assert_eq!(report_0400.permissions.owner_only, Some(true));
        assert_eq!(report_0400.permissions.group_accessible, Some(false));
        assert_eq!(report_0400.permissions.world_accessible, Some(false));
        assert!(report_0400
            .permissions
            .warning
            .as_deref()
            .unwrap_or("")
            .contains("expected 0600"));

        // Restore 0600 so TempDir cleanup is always smooth.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn outputs_never_leak_secrets_ciphertext_salt_or_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let (path, ks) = write_test_keystore(dir.path(), "no-leaks.json");

        let report = inspect_keystore(&path).expect("inspect keystore");
        let json_output = serde_json::to_string_pretty(&report).expect("serialize JSON");
        let human_output = format_human_report(&report);

        let seed_hex = hex::encode(TEST_SEED);
        let salt = ks.salt.as_deref().expect("v2 salt");
        let nonce = ks.nonce.as_deref().expect("v2 nonce");
        let ciphertext = ks.secret_key.as_str();

        for (label, rendered) in [("json", &json_output), ("human", &human_output)] {
            assert!(
                !rendered.contains(&seed_hex),
                "{label} output leaked raw seed"
            );
            assert!(
                !rendered.contains(ciphertext),
                "{label} output leaked secret_key ciphertext"
            );
            assert!(!rendered.contains(salt), "{label} output leaked salt");
            assert!(!rendered.contains(nonce), "{label} output leaked nonce");
            assert!(
                !rendered.contains(TEST_PASS),
                "{label} output leaked passphrase"
            );
            assert!(
                !rendered.contains("secret_key"),
                "{label} output mentioned secret_key field"
            );
        }

        // Verify expected JSON schema keys are present.
        let val: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        let obj = val.as_object().unwrap();
        for key in [
            "file",
            "version",
            "encrypted",
            "cipher",
            "kdf",
            "public_key",
            "stored_address",
            "mainnet_address",
            "testnet_address",
            "address_matches_public_key",
            "permissions",
            "warnings",
        ] {
            assert!(obj.contains_key(key), "missing JSON key `{key}`");
        }
        assert_eq!(obj["version"], 2);
        assert_eq!(obj["encrypted"], true);
        assert_eq!(obj["cipher"], "xchacha20poly1305");
        assert_eq!(obj["kdf"]["algorithm"], "argon2id");
        assert_eq!(obj["kdf"]["memory_kib"], 65_536);
        assert_eq!(obj["kdf"]["iterations"], 3);
        assert_eq!(obj["kdf"]["parallelism"], 4);
    }

    #[test]
    fn inspect_warns_on_mismatched_public_key_and_address() {
        let dir = tempfile::tempdir().unwrap();
        let ks = wallet::from_seed(&TEST_SEED, TEST_PASS).unwrap();
        let mut tampered = serde_json::to_value(&ks).unwrap();
        let other_addr = Address([0x99; 32]).encode();
        tampered["address"] = serde_json::Value::String(other_addr.clone());

        let path = dir.path().join("mismatched.json");
        fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let report = inspect_keystore(&path).expect("parse mismatched v2 keystore");
        assert!(!report.address_matches_public_key);
        assert_eq!(report.mainnet_address, other_addr);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("does not match address derived from public_key")));
    }

    #[test]
    fn inspect_rejects_v1_keystore_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();

        // Missing file
        let missing = dir.path().join("does-not-exist.json");
        assert!(inspect_keystore(&missing).is_err());

        // Legacy v1 keystore is rejected with migration guidance
        let v1_path = dir.path().join("legacy-v1.json");
        let v1_json = serde_json::json!({
            "version": 1,
            "address": Address([0x11; 32]).to_hex(),
            "public_key": "22".repeat(32),
            "secret_key": "33".repeat(32),
            "encrypted": false
        });
        fs::write(&v1_path, serde_json::to_vec_pretty(&v1_json).unwrap()).unwrap();
        let err = inspect_keystore(&v1_path).unwrap_err().to_string();
        assert!(err.contains("legacy v1"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn inspect_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let (target, _ks) = write_test_keystore(dir.path(), "real.json");
        let link = dir.path().join("link.json");
        symlink(&target, &link).unwrap();

        let err = inspect_keystore(&link).unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn run_succeeds_in_both_human_and_json_modes() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _ks) = write_test_keystore(dir.path(), "run.json");

        assert!(run(
            KeyInspectArgs {
                keyfile: path.clone()
            },
            false
        )
        .is_ok());
        assert!(run(KeyInspectArgs { keyfile: path }, true).is_ok());
    }
}
