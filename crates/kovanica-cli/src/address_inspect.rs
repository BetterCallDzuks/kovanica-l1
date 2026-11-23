//! Offline Kovanica address inspection (`kovanica address inspect`).
//!
//! Decodes and validates a Kovanica address 100% offline without requiring an
//! RPC connection or keystore:
//! - Canonical PRO-21 mainnet (`kvnc...dag`, 64 chars, 29-bit BLAKE3 checksum)
//! - Canonical PRO-21 testnet (`tknc...dag`, 64 chars, 29-bit BLAKE3 checksum)
//! - Legacy 32-byte hex (bare 64-hex, `0x`-prefixed 64-hex, or `kvnc<72 hex>dag`)
//!
//! Legacy hex forms are devnet-only (Chain 3) and disallowed on Mainnet
//! (Chain 1) and Testnet (Chain 2). Fails closed with a non-zero exit code on
//! corrupted checksum, invalid length/prefix, or disallowed format for
//! `--expected-chain-id`.

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use kovanica_types::address::{
    legacy_address_allowed, AddressError, ADDRESS_LEN, ADDRESS_PREFIX, ADDRESS_SUFFIX,
};
use kovanica_types::signing::chain_id;
use kovanica_types::Address;
use serde::Serialize;

use crate::output;

/// Human-readable prefix of a canonical testnet PRO-21 address string.
pub const TESTNET_ADDRESS_PREFIX: &str = "tknc";

const LEGACY_HEX_NOTE: &str =
    "legacy hex addresses are devnet-only (chain 3) and disallowed on mainnet (chain 1) and testnet (chain 2)";

/// Subcommands under `kovanica address`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AddressCommand {
    /// Inspect and validate a Kovanica address offline (PRO-21 kvnc/tknc or 32-byte hex)
    Inspect(AddressInspectArgs),
}

/// Arguments for `kovanica address inspect`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct AddressInspectArgs {
    /// Kovanica address (`kvnc...dag`, `tknc...dag`, or 32-byte hex)
    pub address: String,
    /// Optional target chain ID to validate address format policy against (1 mainnet, 2 testnet, 3 devnet)
    #[arg(long)]
    pub expected_chain_id: Option<u64>,
}

/// Detected encoding format of the inspected address input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputFormat {
    CanonicalMainnet,
    CanonicalTestnet,
    LegacyHex,
    Legacy0xHex,
    LegacyKvncHex,
    Invalid,
}

impl InputFormat {
    /// Human-readable label for table output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalMainnet => "canonical_mainnet",
            Self::CanonicalTestnet => "canonical_testnet",
            Self::LegacyHex => "legacy_hex",
            Self::Legacy0xHex => "legacy_0x_hex",
            Self::LegacyKvncHex => "legacy_kvnc_hex",
            Self::Invalid => "invalid",
        }
    }

    /// Whether this format is one of the devnet-only legacy hex encodings.
    pub fn is_legacy_hex(self) -> bool {
        matches!(
            self,
            Self::LegacyHex | Self::Legacy0xHex | Self::LegacyKvncHex
        )
    }
}

/// Structured offline inspection report produced by `kovanica address inspect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressInspectReport {
    pub valid: bool,
    pub input_format: InputFormat,
    pub canonical_mainnet: Option<String>,
    pub canonical_testnet: Option<String>,
    pub payload_hex: Option<String>,
    pub checksum_valid: Option<bool>,
    pub expected_chain_id: Option<u64>,
    pub allowed_on_expected_chain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Encode an [`Address`] in canonical PRO-21 testnet (`tknc...dag`) form.
pub fn encode_testnet(address: &Address) -> String {
    let mainnet = address.encode();
    debug_assert!(mainnet.starts_with(ADDRESS_PREFIX));
    format!(
        "{TESTNET_ADDRESS_PREFIX}{}",
        &mainnet[ADDRESS_PREFIX.len()..]
    )
}

/// Decode a canonical PRO-21 testnet (`tknc...dag`) address string.
pub fn decode_testnet(value: &str) -> Result<Address, AddressError> {
    if !value.starts_with(TESTNET_ADDRESS_PREFIX) || !value.ends_with(ADDRESS_SUFFIX) {
        return Err(AddressError::MissingAffix);
    }
    if value.len() != ADDRESS_LEN {
        return Err(AddressError::InvalidStringLength(value.len()));
    }
    let normalized = format!("{ADDRESS_PREFIX}{}", &value[TESTNET_ADDRESS_PREFIX.len()..]);
    Address::decode(&normalized)
}

/// Evaluate whether `input_format` is permitted on `target_chain_id`.
fn format_allowed_on_chain(input_format: InputFormat, target_chain_id: u64) -> Result<(), String> {
    match input_format {
        InputFormat::CanonicalMainnet => Ok(()),
        InputFormat::CanonicalTestnet => {
            if target_chain_id == chain_id::TESTNET {
                Ok(())
            } else {
                Err(format!(
                    "testnet `{TESTNET_ADDRESS_PREFIX}…{ADDRESS_SUFFIX}` addresses are only allowed on testnet (chain {}); use `{ADDRESS_PREFIX}…{ADDRESS_SUFFIX}` on chain {target_chain_id}",
                    chain_id::TESTNET
                ))
            }
        }
        InputFormat::LegacyHex | InputFormat::Legacy0xHex | InputFormat::LegacyKvncHex => {
            if legacy_address_allowed(target_chain_id) {
                Ok(())
            } else {
                Err(AddressError::LegacyNotAllowed(target_chain_id).to_string())
            }
        }
        InputFormat::Invalid => Err("invalid address format".to_string()),
    }
}

/// Inspect an address string offline and return a structured [`AddressInspectReport`].
pub fn inspect_address(raw: &str, expected_chain_id: Option<u64>) -> AddressInspectReport {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return invalid_report(
            InputFormat::Invalid,
            None,
            expected_chain_id,
            "address must not be empty".to_string(),
        );
    }

    // 1. Canonical PRO-21 mainnet (`kvnc...dag`, 64 chars)
    if trimmed.len() == ADDRESS_LEN
        && trimmed.starts_with(ADDRESS_PREFIX)
        && trimmed.ends_with(ADDRESS_SUFFIX)
    {
        return match Address::decode(trimmed) {
            Ok(address) => build_decoded_report(
                address,
                InputFormat::CanonicalMainnet,
                Some(true),
                expected_chain_id,
            ),
            Err(AddressError::ChecksumMismatch) => invalid_report(
                InputFormat::CanonicalMainnet,
                Some(false),
                expected_chain_id,
                AddressError::ChecksumMismatch.to_string(),
            ),
            Err(err) => invalid_report(
                InputFormat::Invalid,
                None,
                expected_chain_id,
                err.to_string(),
            ),
        };
    }

    // 2. Canonical PRO-21 testnet (`tknc...dag`, 64 chars)
    if trimmed.starts_with(TESTNET_ADDRESS_PREFIX) {
        return match decode_testnet(trimmed) {
            Ok(address) => build_decoded_report(
                address,
                InputFormat::CanonicalTestnet,
                Some(true),
                expected_chain_id,
            ),
            Err(AddressError::ChecksumMismatch) => invalid_report(
                InputFormat::CanonicalTestnet,
                Some(false),
                expected_chain_id,
                AddressError::ChecksumMismatch.to_string(),
            ),
            Err(err) => invalid_report(
                InputFormat::Invalid,
                None,
                expected_chain_id,
                err.to_string(),
            ),
        };
    }

    // 3. Affixed `kvnc...` / `...dag` (non-64-char): either legacy `kvnc<72 hex>dag` or malformed canonical
    if trimmed.starts_with(ADDRESS_PREFIX) || trimmed.ends_with(ADDRESS_SUFFIX) {
        let is_hex_body = trimmed
            .strip_prefix(ADDRESS_PREFIX)
            .and_then(|rest| rest.strip_suffix(ADDRESS_SUFFIX))
            .is_some_and(|body| !body.is_empty() && body.bytes().all(|b| b.is_ascii_hexdigit()));

        return match Address::parse_stored_label(trimmed) {
            Ok(address) => build_decoded_report(
                address,
                InputFormat::LegacyKvncHex,
                Some(true),
                expected_chain_id,
            ),
            Err(AddressError::ChecksumMismatch) => invalid_report(
                if is_hex_body {
                    InputFormat::LegacyKvncHex
                } else {
                    InputFormat::Invalid
                },
                Some(false),
                expected_chain_id,
                AddressError::ChecksumMismatch.to_string(),
            ),
            Err(err) => invalid_report(
                InputFormat::Invalid,
                None,
                expected_chain_id,
                err.to_string(),
            ),
        };
    }

    // 4. Bare 64-hex or `0x`-prefixed 64-hex (legacy devnet-only format)
    let format = if trimmed.starts_with("0x") {
        InputFormat::Legacy0xHex
    } else {
        InputFormat::LegacyHex
    };

    match Address::parse_stored_label(trimmed) {
        Ok(address) => build_decoded_report(address, format, None, expected_chain_id),
        Err(err) => invalid_report(
            InputFormat::Invalid,
            None,
            expected_chain_id,
            err.to_string(),
        ),
    }
}

fn build_decoded_report(
    address: Address,
    input_format: InputFormat,
    checksum_valid: Option<bool>,
    expected_chain_id: Option<u64>,
) -> AddressInspectReport {
    let note = if input_format.is_legacy_hex() {
        Some(LEGACY_HEX_NOTE.to_string())
    } else {
        None
    };

    let (allowed_on_expected_chain, error) = match expected_chain_id {
        Some(target_chain) => match format_allowed_on_chain(input_format, target_chain) {
            Ok(()) => (Some(true), None),
            Err(err) => (Some(false), Some(err)),
        },
        None => (None, None),
    };

    let valid = allowed_on_expected_chain.unwrap_or(true);

    AddressInspectReport {
        valid,
        input_format,
        canonical_mainnet: Some(address.encode()),
        canonical_testnet: Some(encode_testnet(&address)),
        payload_hex: Some(address.to_hex()),
        checksum_valid,
        expected_chain_id,
        allowed_on_expected_chain,
        note,
        error,
    }
}

fn invalid_report(
    input_format: InputFormat,
    checksum_valid: Option<bool>,
    expected_chain_id: Option<u64>,
    error: String,
) -> AddressInspectReport {
    AddressInspectReport {
        valid: false,
        input_format,
        canonical_mainnet: None,
        canonical_testnet: None,
        payload_hex: None,
        checksum_valid,
        expected_chain_id,
        allowed_on_expected_chain: expected_chain_id.map(|_| false),
        note: None,
        error: Some(error),
    }
}

/// Render a human-readable key/value table for an [`AddressInspectReport`].
fn print_human_report(report: &AddressInspectReport) {
    let mut rows: Vec<(&str, String)> = vec![
        ("valid", report.valid.to_string()),
        ("input_format", report.input_format.as_str().to_string()),
        (
            "canonical_mainnet",
            report
                .canonical_mainnet
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "canonical_testnet",
            report
                .canonical_testnet
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "payload_hex",
            report
                .payload_hex
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "checksum_valid",
            match report.checksum_valid {
                Some(v) => v.to_string(),
                None => "n/a".to_string(),
            },
        ),
        (
            "allowed_on_expected_chain",
            match (report.expected_chain_id, report.allowed_on_expected_chain) {
                (Some(cid), Some(allowed)) => format!("{allowed} (chain {cid})"),
                _ => "n/a".to_string(),
            },
        ),
    ];

    if let Some(ref note) = report.note {
        rows.push(("note", note.clone()));
    }
    if let Some(ref error) = report.error {
        rows.push(("error", error.clone()));
    }

    output::print_kv(&rows);
}

/// Execute `kovanica address inspect <address> [--expected-chain-id <u64>] [--json]`.
///
/// Always prints the structured report (JSON or key/value table) and fails
/// closed with a non-zero exit code when `report.valid` is `false`.
pub fn run(args: AddressInspectArgs, json_output: bool) -> Result<()> {
    let report = inspect_address(&args.address, args.expected_chain_id);

    if json_output {
        output::print_json(&serde_json::to_value(&report)?)?;
    } else {
        print_human_report(&report);
    }

    if !report.valid {
        bail!(
            "address inspection failed: {}",
            report
                .error
                .as_deref()
                .unwrap_or("invalid or disallowed address")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_address() -> Address {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        Address(bytes)
    }

    #[test]
    fn valid_canonical_mainnet_address_inspects_cleanly() {
        let addr = sample_address();
        let mainnet = addr.encode();
        let testnet = encode_testnet(&addr);

        let report = inspect_address(&mainnet, None);
        assert!(report.valid);
        assert_eq!(report.input_format, InputFormat::CanonicalMainnet);
        assert_eq!(report.canonical_mainnet.as_deref(), Some(mainnet.as_str()));
        assert_eq!(report.canonical_testnet.as_deref(), Some(testnet.as_str()));
        assert_eq!(report.payload_hex.as_deref(), Some(addr.to_hex().as_str()));
        assert_eq!(report.checksum_valid, Some(true));
        assert_eq!(report.allowed_on_expected_chain, None);
        assert!(report.error.is_none());

        // Allowed on mainnet (1), testnet (2), and devnet (3)
        for cid in [chain_id::MAINNET, chain_id::TESTNET, chain_id::DEVNET] {
            let r = inspect_address(&mainnet, Some(cid));
            assert!(r.valid, "chain {cid}");
            assert_eq!(r.allowed_on_expected_chain, Some(true), "chain {cid}");
        }
    }

    #[test]
    fn valid_canonical_testnet_address_inspects_and_enforces_chain_policy() {
        let addr = sample_address();
        let mainnet = addr.encode();
        let testnet = encode_testnet(&addr);
        assert!(testnet.starts_with("tknc") && testnet.ends_with("dag"));
        assert_eq!(testnet.len(), ADDRESS_LEN);

        // No expected chain: valid
        let report = inspect_address(&testnet, None);
        assert!(report.valid);
        assert_eq!(report.input_format, InputFormat::CanonicalTestnet);
        assert_eq!(report.canonical_mainnet.as_deref(), Some(mainnet.as_str()));
        assert_eq!(report.canonical_testnet.as_deref(), Some(testnet.as_str()));
        assert_eq!(report.payload_hex.as_deref(), Some(addr.to_hex().as_str()));
        assert_eq!(report.checksum_valid, Some(true));
        assert_eq!(report.allowed_on_expected_chain, None);

        // Expected chain 2 (testnet): allowed
        let on_testnet = inspect_address(&testnet, Some(chain_id::TESTNET));
        assert!(on_testnet.valid);
        assert_eq!(on_testnet.allowed_on_expected_chain, Some(true));

        // Expected chain 1 (mainnet): rejected
        let on_mainnet = inspect_address(&testnet, Some(chain_id::MAINNET));
        assert!(!on_mainnet.valid);
        assert_eq!(on_mainnet.allowed_on_expected_chain, Some(false));
        assert!(on_mainnet.error.is_some());
    }

    #[test]
    fn valid_legacy_64_hex_addresses_follow_devnet_only_policy() {
        let addr = sample_address();
        let bare_hex = addr.to_hex();
        let prefixed_hex = format!("0x{bare_hex}");

        for (input, expected_fmt) in [
            (bare_hex.as_str(), InputFormat::LegacyHex),
            (prefixed_hex.as_str(), InputFormat::Legacy0xHex),
        ] {
            // Without expected_chain_id: decodes and notes devnet-only policy
            let report = inspect_address(input, None);
            assert!(report.valid, "{input}");
            assert_eq!(report.input_format, expected_fmt);
            assert_eq!(report.canonical_mainnet, Some(addr.encode()));
            assert_eq!(report.canonical_testnet, Some(encode_testnet(&addr)));
            assert_eq!(report.payload_hex, Some(bare_hex.clone()));
            assert_eq!(report.checksum_valid, None);
            assert_eq!(report.allowed_on_expected_chain, None);
            assert!(report.note.as_deref().unwrap_or("").contains("devnet-only"));

            // Disallowed on Chain 1 (Mainnet) and Chain 2 (Testnet)
            for disallowed_chain in [chain_id::MAINNET, chain_id::TESTNET] {
                let rejected = inspect_address(input, Some(disallowed_chain));
                assert!(!rejected.valid, "{input} on chain {disallowed_chain}");
                assert_eq!(rejected.input_format, expected_fmt);
                assert_eq!(rejected.allowed_on_expected_chain, Some(false));
                assert!(rejected.error.is_some());

                // run() fails closed with non-zero error
                let res = run(
                    AddressInspectArgs {
                        address: input.to_string(),
                        expected_chain_id: Some(disallowed_chain),
                    },
                    true,
                );
                assert!(res.is_err(), "{input} on chain {disallowed_chain}");
            }

            // Allowed on Chain 3 (Devnet)
            let allowed = inspect_address(input, Some(chain_id::DEVNET));
            assert!(allowed.valid, "{input} on devnet");
            assert_eq!(allowed.allowed_on_expected_chain, Some(true));
            assert!(allowed.error.is_none());

            let res = run(
                AddressInspectArgs {
                    address: input.to_string(),
                    expected_chain_id: Some(chain_id::DEVNET),
                },
                true,
            );
            assert!(res.is_ok(), "{input} on devnet");
        }
    }

    #[test]
    fn corrupted_pro21_checksum_fails_closed() {
        let addr = sample_address();
        let alphabet = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

        for (encoded, expected_fmt) in [
            (addr.encode(), InputFormat::CanonicalMainnet),
            (encode_testnet(&addr), InputFormat::CanonicalTestnet),
        ] {
            let mut bytes = encoded.into_bytes();
            let pos = 55; // inside the 57-char base32 body
            let cur = alphabet.iter().position(|&b| b == bytes[pos]).unwrap();
            bytes[pos] = alphabet[(cur + 1) % alphabet.len()];
            let tampered = String::from_utf8(bytes).unwrap();

            let report = inspect_address(&tampered, Some(chain_id::TESTNET));
            assert!(!report.valid);
            assert_eq!(report.input_format, expected_fmt);
            assert_eq!(report.checksum_valid, Some(false));
            assert_eq!(report.canonical_mainnet, None);
            assert_eq!(report.canonical_testnet, None);
            assert_eq!(report.payload_hex, None);
            assert_eq!(report.allowed_on_expected_chain, Some(false));
            assert!(
                report
                    .error
                    .as_deref()
                    .unwrap_or("")
                    .contains("checksum mismatch"),
                "{:?}",
                report.error
            );

            // run() fails closed
            let res = run(
                AddressInspectArgs {
                    address: tampered,
                    expected_chain_id: None,
                },
                false,
            );
            assert!(res.is_err());
        }
    }

    #[test]
    fn invalid_length_and_prefix_fail_closed() {
        let bad_inputs = [
            "",
            "   ",
            "0x1234",
            "not-an-address",
            "kvncshortdag",
            "tkncshortdag",
            "xxxxqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz4k5rcdag",
        ];

        for bad in bad_inputs {
            let report = inspect_address(bad, None);
            assert!(!report.valid, "expected invalid for `{bad}`");
            assert_eq!(report.input_format, InputFormat::Invalid, "`{bad}`");
            assert!(report.error.is_some(), "`{bad}`");
            assert!(run(
                AddressInspectArgs {
                    address: bad.to_string(),
                    expected_chain_id: None,
                },
                true,
            )
            .is_err());
        }
    }

    #[test]
    fn json_serialization_contains_all_required_fields() {
        let addr = sample_address();
        let report = inspect_address(&addr.encode(), Some(chain_id::MAINNET));
        let value = serde_json::to_value(&report).unwrap();
        let obj = value.as_object().unwrap();

        for key in [
            "valid",
            "input_format",
            "canonical_mainnet",
            "canonical_testnet",
            "payload_hex",
            "checksum_valid",
            "allowed_on_expected_chain",
        ] {
            assert!(obj.contains_key(key), "missing JSON key `{key}`");
        }
        assert_eq!(obj["valid"], true);
        assert_eq!(obj["input_format"], "canonical_mainnet");
        assert_eq!(obj["checksum_valid"], true);
        assert_eq!(obj["allowed_on_expected_chain"], true);
    }
}
