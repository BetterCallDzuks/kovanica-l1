//! Read-only contract inspection subcommands (`kovanica contract call` & `kovanica contract storage`).
//!
//! These commands never sign or submit transactions; they invoke the node's
//! read-only JSON-RPC endpoints (`kovanica_call` and `kovanica_getStorageAt`)
//! and derive canonical BLAKE3-256 contract storage slots locally.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use kovanica_types::Address;
use serde_json::{json, Value};

use crate::output;
use crate::rpc::RpcClient;

/// Default gas limit for read-only `kovanica contract call` simulations.
pub const DEFAULT_CALL_GAS: u64 = 100_000;

/// Canonical raw storage key for singleton token/NFT/multisig state.
const SINGLETON_STATE_KEY: &[u8] = b"kvnc/v1/state";
/// Canonical raw storage key prefix for name-registry entries.
const NAME_KEY_PREFIX: &[u8] = b"kvnc/v1/name/";
/// Canonical raw storage key prefix for HTLC records.
const HTLC_KEY_PREFIX: &[u8] = b"kvnc/v1/htlc/";
/// Canonical raw storage key prefix for escrow records.
const ESCROW_KEY_PREFIX: &[u8] = b"kvnc/v1/escrow/";
/// Canonical raw storage key prefix for vault records.
const VAULT_KEY_PREFIX: &[u8] = b"kvnc/v1/vault/";

/// Read-only contract inspection commands (`kovanica contract …`).
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ContractInspectCommand {
    /// Simulate a read-only contract call via `kovanica_call`
    Call(ContractCallArgs),
    /// Read a raw contract storage slot via `kovanica_getStorageAt`
    Storage(ContractStorageArgs),
}

/// Arguments for `kovanica contract call`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ContractCallArgs {
    /// Target contract address (`kvnc...dag` or 32-byte hex)
    #[arg(long)]
    pub contract: String,
    /// Contract entry point / method name to simulate
    #[arg(long)]
    pub method: String,
    /// Hex-encoded call payload bytes
    #[arg(long, default_value = "0x")]
    pub data: String,
    /// Optional caller address (`kvnc...dag` or 32-byte hex)
    #[arg(long)]
    pub from: Option<String>,
    /// Native value attached to the simulated call (in atoms)
    #[arg(long, default_value_t = 0)]
    pub value: u64,
    /// Gas limit for the simulated call
    #[arg(long, default_value_t = DEFAULT_CALL_GAS)]
    pub gas: u64,
}

/// Arguments for `kovanica contract storage`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ContractStorageArgs {
    /// Target contract address (`kvnc...dag` or 32-byte hex)
    #[arg(long)]
    pub contract: String,
    /// Explicit 32-byte storage slot (64 hex chars, optional `0x` prefix)
    #[arg(long, conflicts_with_all = ["prefix", "key", "preset"])]
    pub slot: Option<String>,
    /// Raw storage key prefix (hashed with `--key` via BLAKE3-256)
    #[arg(long, requires = "key", conflicts_with_all = ["slot", "preset"])]
    pub prefix: Option<String>,
    /// Raw storage key suffix (UTF-8, or `0x`-prefixed hex bytes) combined with `--prefix`
    #[arg(long, requires = "prefix", conflicts_with_all = ["slot", "preset"])]
    pub key: Option<String>,
    /// Canonical contract storage preset: `name:<key>`, `htlc:<key>`, `escrow:<key>`,
    /// `vault:<key>`, `token:meta`, `nft:meta`, or `multisig:state`
    #[arg(long, conflicts_with_all = ["slot", "prefix", "key"])]
    pub preset: Option<String>,
}

/// Resolved 32-byte storage slot with its human-readable derivation label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSlot {
    pub slot: [u8; 32],
    pub slot_hex: String,
    pub source: String,
}

/// Validate a contract or caller address in canonical `kvnc...dag` or 32-byte hex form.
pub fn parse_contract_address(input: &str, what: &str) -> Result<Address> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("{what}: address must not be empty");
    }
    if trimmed.starts_with("kvnc") && trimmed.ends_with("dag") {
        return Address::decode(trimmed)
            .map_err(|e| anyhow!("{what}: invalid canonical address: {e}"));
    }
    let raw_hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(raw_hex)
        .map_err(|_| anyhow!("{what}: expected canonical `kvnc...dag` address or 32-byte hex"))?;
    if bytes.len() != 32 {
        bail!(
            "{what}: expected 32-byte hex address (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Address(arr))
}

/// Validate and normalize an arbitrary hex payload to `0x<lowercase hex>`.
pub fn normalize_hex_data(input: &str, what: &str) -> Result<String> {
    let trimmed = input.trim();
    let raw = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if raw.is_empty() {
        return Ok("0x".to_string());
    }
    let bytes = hex::decode(raw).with_context(|| format!("{what}: invalid hex"))?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Parse a 32-byte hex string (with or without `0x` prefix).
pub fn parse_bytes32_hex(input: &str, what: &str) -> Result<[u8; 32]> {
    let trimmed = input.trim();
    let raw = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(raw).with_context(|| format!("{what}: invalid hex"))?;
    if bytes.len() != 32 {
        bail!(
            "{what}: expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive the canonical 32-byte BLAKE3-256 contract storage slot for `prefix || key`.
///
/// Mirrors the host execution rule `blake3(raw_key)` used by Kovanica contracts.
pub fn derive_storage_slot(prefix: &[u8], key: &[u8]) -> [u8; 32] {
    let mut raw = Vec::with_capacity(prefix.len() + key.len());
    raw.extend_from_slice(prefix);
    raw.extend_from_slice(key);
    kovanica_common::hash(&raw)
}

/// Derive the canonical `0x`-prefixed 32-byte BLAKE3-256 storage slot hex for `prefix || key`.
pub fn derive_storage_slot_hex(prefix: &[u8], key: &[u8]) -> String {
    format!("0x{}", hex::encode(derive_storage_slot(prefix, key)))
}

/// Decode a `--key` value: `0x`/`0X`-prefixed strings are decoded as hex bytes,
/// while plain strings are encoded as UTF-8 bytes.
fn decode_key_bytes(key: &str) -> Result<Vec<u8>> {
    if let Some(hex_part) = key.strip_prefix("0x").or_else(|| key.strip_prefix("0X")) {
        hex::decode(hex_part).context("--key: invalid hex")
    } else {
        Ok(key.as_bytes().to_vec())
    }
}

/// Derive the canonical 32-byte BLAKE3 storage slot for a `--preset` specification.
///
/// Supported presets:
/// - `name:<key>` -> `blake3(b"kvnc/v1/name/" || key.to_ascii_lowercase())`
/// - `htlc:<key>` -> `blake3(b"kvnc/v1/htlc/" || bytes32(key))`
/// - `escrow:<key>` -> `blake3(b"kvnc/v1/escrow/" || bytes32(key))`
/// - `vault:<key>` -> `blake3(b"kvnc/v1/vault/" || bytes32(key))`
/// - `token:meta` -> `blake3(b"kvnc/v1/state")`
/// - `nft:meta` -> `blake3(b"kvnc/v1/state")`
/// - `multisig:state` -> `blake3(b"kvnc/v1/state")`
pub fn derive_preset_slot(preset: &str) -> Result<ResolvedSlot> {
    let spec = preset.trim();
    let slot = match spec {
        "token:meta" | "nft:meta" | "multisig:state" => {
            derive_storage_slot(SINGLETON_STATE_KEY, b"")
        }
        _ => {
            let (kind, value) = spec.split_once(':').ok_or_else(|| {
                anyhow!(
                    "invalid --preset `{spec}`: expected one of name:<key>, htlc:<key>, escrow:<key>, vault:<key>, token:meta, nft:meta, multisig:state"
                )
            })?;
            match kind {
                "name" => {
                    let normalized = value.trim().to_ascii_lowercase();
                    if normalized.is_empty() {
                        bail!("--preset name:<key> requires a non-empty name");
                    }
                    derive_storage_slot(NAME_KEY_PREFIX, normalized.as_bytes())
                }
                "htlc" => {
                    let id = parse_bytes32_hex(value, "htlc preset key")?;
                    derive_storage_slot(HTLC_KEY_PREFIX, &id)
                }
                "escrow" => {
                    let id = parse_bytes32_hex(value, "escrow preset key")?;
                    derive_storage_slot(ESCROW_KEY_PREFIX, &id)
                }
                "vault" => {
                    let id = parse_bytes32_hex(value, "vault preset key")?;
                    derive_storage_slot(VAULT_KEY_PREFIX, &id)
                }
                _ => {
                    bail!(
                        "unknown --preset `{spec}`: expected one of name:<key>, htlc:<key>, escrow:<key>, vault:<key>, token:meta, nft:meta, multisig:state"
                    );
                }
            }
        }
    };

    Ok(ResolvedSlot {
        slot,
        slot_hex: format!("0x{}", hex::encode(slot)),
        source: format!("preset:{spec}"),
    })
}

/// Resolve the storage slot from `--slot`, `--prefix`+`--key`, or `--preset`.
pub fn resolve_storage_slot(args: &ContractStorageArgs) -> Result<ResolvedSlot> {
    if let Some(slot_str) = &args.slot {
        let slot = parse_bytes32_hex(slot_str, "--slot")?;
        return Ok(ResolvedSlot {
            slot,
            slot_hex: format!("0x{}", hex::encode(slot)),
            source: "slot".to_string(),
        });
    }
    if let Some(preset) = &args.preset {
        return derive_preset_slot(preset);
    }
    if let (Some(prefix), Some(key)) = (&args.prefix, &args.key) {
        let key_bytes = decode_key_bytes(key)?;
        let slot = derive_storage_slot(prefix.as_bytes(), &key_bytes);
        return Ok(ResolvedSlot {
            slot,
            slot_hex: format!("0x{}", hex::encode(slot)),
            source: format!("blake3({prefix} + {key})"),
        });
    }
    bail!(
        "must specify one of `--slot <hex>`, `--prefix <prefix> --key <key>`, or `--preset <spec>`"
    )
}

/// Build the JSON-RPC params array for `kovanica_call`.
pub fn build_call_params(
    args: &ContractCallArgs,
) -> Result<(Address, Option<Address>, String, Value)> {
    let contract = parse_contract_address(&args.contract, "--contract")?;
    let method = args.method.trim();
    if method.is_empty() {
        bail!("--method must not be empty");
    }
    let data = normalize_hex_data(&args.data, "--data")?;
    let from = match &args.from {
        Some(raw_from) => Some(parse_contract_address(raw_from, "--from")?),
        None => None,
    };

    let mut call_obj = serde_json::Map::new();
    call_obj.insert("to".to_string(), json!(contract.to_string()));
    call_obj.insert("method".to_string(), json!(method));
    call_obj.insert("data".to_string(), json!(data));
    call_obj.insert("value".to_string(), json!(format!("0x{:x}", args.value)));
    call_obj.insert("gas".to_string(), json!(format!("0x{:x}", args.gas)));
    if let Some(from_addr) = from {
        call_obj.insert("from".to_string(), json!(from_addr.to_string()));
    }

    Ok((contract, from, data, json!([Value::Object(call_obj)])))
}

/// Build the JSON-RPC params array for `kovanica_getStorageAt`.
pub fn build_get_storage_at_params(contract: &Address, slot_hex: &str) -> Value {
    json!([contract.to_string(), slot_hex])
}

/// Decode a hex string returned by RPC (`0x...`) into raw bytes.
fn decode_rpc_hex(raw: &str) -> Result<Vec<u8>> {
    let stripped = raw
        .trim()
        .strip_prefix("0x")
        .or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or(raw.trim());
    if stripped.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(stripped).with_context(|| format!("invalid hex returned by node: `{raw}`"))
}

/// Return a printable UTF-8 preview if all bytes decode cleanly without control chars.
fn printable_utf8(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    if text
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
    {
        Some(text.to_string())
    } else {
        None
    }
}

/// Format the JSON output object for `kovanica contract call --json`.
pub fn format_call_json(
    contract: &Address,
    method: &str,
    data: &str,
    from: Option<&Address>,
    value: u64,
    gas: u64,
    raw_output: &str,
) -> Result<Value> {
    let bytes = decode_rpc_hex(raw_output)?;
    let normalized = format!("0x{}", hex::encode(&bytes));
    let utf8 = printable_utf8(&bytes);
    Ok(json!({
        "contract": contract.to_string(),
        "method": method,
        "data": data,
        "from": from.map(|a| a.to_string()),
        "value": value,
        "gas": gas,
        "output": normalized,
        "bytes_len": bytes.len(),
        "utf8": utf8,
    }))
}

/// Format the JSON output object for `kovanica contract storage --json`.
pub fn format_storage_json(
    contract: &Address,
    resolved: &ResolvedSlot,
    raw_value: &str,
) -> Result<Value> {
    let bytes = decode_rpc_hex(raw_value)?;
    let empty = bytes.is_empty() || bytes.iter().all(|&b| b == 0);
    let normalized = format!("0x{}", hex::encode(&bytes));
    let utf8 = if empty { None } else { printable_utf8(&bytes) };
    Ok(json!({
        "contract": contract.to_string(),
        "slot": resolved.slot_hex,
        "source": resolved.source,
        "value": normalized,
        "empty": empty,
        "bytes_len": bytes.len(),
        "utf8": utf8,
    }))
}

/// Execute `kovanica contract <subcommand>`.
pub async fn run(
    client: &RpcClient,
    command: ContractInspectCommand,
    json_output: bool,
) -> Result<()> {
    match command {
        ContractInspectCommand::Call(args) => run_call(client, args, json_output).await,
        ContractInspectCommand::Storage(args) => run_storage(client, args, json_output).await,
    }
}

async fn run_call(client: &RpcClient, args: ContractCallArgs, json_output: bool) -> Result<()> {
    let (contract, from, data, params) = build_call_params(&args)?;
    let result = client.call("kovanica_call", params).await?;
    let raw_output = result.as_str().unwrap_or("0x");
    let formatted = format_call_json(
        &contract,
        args.method.trim(),
        &data,
        from.as_ref(),
        args.value,
        args.gas,
        raw_output,
    )?;

    if json_output {
        return output::print_json(&formatted);
    }

    let output_hex = formatted["output"].as_str().unwrap_or("0x");
    let bytes_len = formatted["bytes_len"].as_u64().unwrap_or(0);
    let mut rows = vec![
        ("Contract", contract.to_string()),
        ("Method", args.method.trim().to_string()),
        (
            "Output",
            if bytes_len == 0 {
                "(empty)".to_string()
            } else {
                output_hex.to_string()
            },
        ),
        ("Bytes", bytes_len.to_string()),
    ];
    if let Some(utf8) = formatted["utf8"].as_str() {
        rows.push(("UTF-8", utf8.to_string()));
    }
    output::print_kv(&rows);
    Ok(())
}

async fn run_storage(
    client: &RpcClient,
    args: ContractStorageArgs,
    json_output: bool,
) -> Result<()> {
    let contract = parse_contract_address(&args.contract, "--contract")?;
    let resolved = resolve_storage_slot(&args)?;
    let params = build_get_storage_at_params(&contract, &resolved.slot_hex);
    let result = client.call("kovanica_getStorageAt", params).await?;
    let raw_value = result.as_str().unwrap_or("0x");
    let formatted = format_storage_json(&contract, &resolved, raw_value)?;

    if json_output {
        return output::print_json(&formatted);
    }

    let is_empty = formatted["empty"].as_bool().unwrap_or(true);
    let value_hex = formatted["value"].as_str().unwrap_or("0x");
    let bytes_len = formatted["bytes_len"].as_u64().unwrap_or(0);
    let mut rows = vec![
        ("Contract", contract.to_string()),
        ("Slot", resolved.slot_hex),
        ("Source", resolved.source),
        (
            "Value",
            if is_empty {
                "(empty)".to_string()
            } else {
                value_hex.to_string()
            },
        ),
    ];
    if !is_empty {
        rows.push(("Bytes", bytes_len.to_string()));
        if let Some(utf8) = formatted["utf8"].as_str() {
            rows.push(("UTF-8", utf8.to_string()));
        }
    }
    output::print_kv(&rows);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_address() -> Address {
        Address([0x42; 32])
    }

    #[test]
    fn parse_contract_address_accepts_canonical_and_32_byte_hex() {
        let addr = sample_address();
        let canonical = addr.to_string();
        assert_eq!(
            parse_contract_address(&canonical, "--contract").unwrap(),
            addr
        );
        assert_eq!(
            parse_contract_address(&format!("0x{}", hex::encode(addr.0)), "--contract").unwrap(),
            addr
        );
        assert_eq!(
            parse_contract_address(&hex::encode(addr.0), "--contract").unwrap(),
            addr
        );
    }

    #[test]
    fn parse_contract_address_rejects_invalid_inputs() {
        assert!(parse_contract_address("", "--contract").is_err());
        assert!(parse_contract_address("not-an-address", "--contract").is_err());
        assert!(parse_contract_address("0x1234", "--contract").is_err());
        assert!(parse_contract_address("kvncinvalidchecksumdag", "--contract").is_err());
    }

    #[test]
    fn derive_storage_slot_hex_matches_canonical_blake3_slots() {
        // Token singleton state slot must match `kovanica_token::state_slot()`
        let expected_token = format!("0x{}", hex::encode(kovanica_token::state_slot()));
        assert_eq!(
            derive_storage_slot_hex(b"kvnc/v1/state", b""),
            expected_token
        );

        // Name registry entry key `b"kvnc/v1/name/" || b"alice"`
        let expected_name = format!(
            "0x{}",
            hex::encode(kovanica_common::hash(b"kvnc/v1/name/alice"))
        );
        assert_eq!(
            derive_storage_slot_hex(b"kvnc/v1/name/", b"alice"),
            expected_name
        );

        // HTLC record key `b"kvnc/v1/htlc/" || [0xab; 32]`
        let mut htlc_raw = b"kvnc/v1/htlc/".to_vec();
        htlc_raw.extend_from_slice(&[0xab; 32]);
        let expected_htlc = format!("0x{}", hex::encode(kovanica_common::hash(&htlc_raw)));
        assert_eq!(
            derive_storage_slot_hex(b"kvnc/v1/htlc/", &[0xab; 32]),
            expected_htlc
        );
    }

    #[test]
    fn derive_preset_slot_supports_all_canonical_presets() {
        let id_hex = "ab".repeat(32);

        // Singleton presets
        let token = derive_preset_slot("token:meta").unwrap();
        let nft = derive_preset_slot("nft:meta").unwrap();
        let multisig = derive_preset_slot("multisig:state").unwrap();
        assert_eq!(token.slot, kovanica_token::state_slot());
        assert_eq!(nft.slot, kovanica_token::state_slot());
        assert_eq!(multisig.slot, kovanica_token::state_slot());
        assert_eq!(token.source, "preset:token:meta");

        // Name preset normalizes ASCII case
        let name_lower = derive_preset_slot("name:alice").unwrap();
        let name_upper = derive_preset_slot("name:ALICE").unwrap();
        assert_eq!(name_lower.slot, name_upper.slot);
        assert_eq!(
            name_lower.slot_hex,
            derive_storage_slot_hex(b"kvnc/v1/name/", b"alice")
        );

        // HTLC, escrow, vault presets decode 32-byte hex IDs (with or without 0x)
        let htlc = derive_preset_slot(&format!("htlc:0x{id_hex}")).unwrap();
        assert_eq!(
            htlc.slot_hex,
            derive_storage_slot_hex(b"kvnc/v1/htlc/", &[0xab; 32])
        );

        let escrow = derive_preset_slot(&format!("escrow:{id_hex}")).unwrap();
        assert_eq!(
            escrow.slot_hex,
            derive_storage_slot_hex(b"kvnc/v1/escrow/", &[0xab; 32])
        );

        let vault = derive_preset_slot(&format!("vault:0x{id_hex}")).unwrap();
        assert_eq!(
            vault.slot_hex,
            derive_storage_slot_hex(b"kvnc/v1/vault/", &[0xab; 32])
        );
    }

    #[test]
    fn derive_preset_slot_rejects_unknown_or_malformed_presets() {
        assert!(derive_preset_slot("unknown:foo").is_err());
        assert!(derive_preset_slot("token").is_err());
        assert!(derive_preset_slot("name:").is_err());
        assert!(derive_preset_slot("htlc:deadbeef").is_err());
        assert!(derive_preset_slot("escrow:nothex").is_err());
        assert!(derive_preset_slot("vault:1234").is_err());
    }

    #[test]
    fn resolve_storage_slot_handles_explicit_slot_and_prefix_key() {
        let contract = sample_address().to_string();

        // Explicit --slot
        let slot_args = ContractStorageArgs {
            contract: contract.clone(),
            slot: Some(format!("0x{}", "cd".repeat(32))),
            prefix: None,
            key: None,
            preset: None,
        };
        let resolved = resolve_storage_slot(&slot_args).unwrap();
        assert_eq!(resolved.slot, [0xcd; 32]);
        assert_eq!(resolved.slot_hex, format!("0x{}", "cd".repeat(32)));
        assert_eq!(resolved.source, "slot");

        // --prefix + UTF-8 --key
        let prefix_utf8 = ContractStorageArgs {
            contract: contract.clone(),
            slot: None,
            prefix: Some("kvnc/v1/name/".to_string()),
            key: Some("bob".to_string()),
            preset: None,
        };
        let resolved_utf8 = resolve_storage_slot(&prefix_utf8).unwrap();
        assert_eq!(
            resolved_utf8.slot_hex,
            derive_storage_slot_hex(b"kvnc/v1/name/", b"bob")
        );

        // --prefix + 0x hex --key
        let prefix_hex = ContractStorageArgs {
            contract: contract.clone(),
            slot: None,
            prefix: Some("kvnc/v1/htlc/".to_string()),
            key: Some(format!("0x{}", "11".repeat(32))),
            preset: None,
        };
        let resolved_hex = resolve_storage_slot(&prefix_hex).unwrap();
        assert_eq!(
            resolved_hex.slot_hex,
            derive_storage_slot_hex(b"kvnc/v1/htlc/", &[0x11; 32])
        );

        // Missing slot selector fails
        let empty_args = ContractStorageArgs {
            contract,
            slot: None,
            prefix: None,
            key: None,
            preset: None,
        };
        assert!(resolve_storage_slot(&empty_args).is_err());
    }

    #[test]
    fn build_call_params_constructs_valid_kovanica_call_payload() {
        let contract = sample_address();
        let caller = Address([0x99; 32]);
        let args = ContractCallArgs {
            contract: format!("0x{}", hex::encode(contract.0)),
            method: "balance_of".to_string(),
            data: "0xDEADBEEF".to_string(),
            from: Some(caller.to_string()),
            value: 42,
            gas: 250_000,
        };

        let (parsed_contract, parsed_from, data, params) = build_call_params(&args).unwrap();
        assert_eq!(parsed_contract, contract);
        assert_eq!(parsed_from, Some(caller));
        assert_eq!(data, "0xdeadbeef");
        assert_eq!(
            params,
            json!([{
                "to": contract.to_string(),
                "from": caller.to_string(),
                "method": "balance_of",
                "data": "0xdeadbeef",
                "value": "0x2a",
                "gas": "0x3d090",
            }])
        );

        // Without --from, the `from` key is omitted
        let no_from = ContractCallArgs {
            contract: contract.to_string(),
            method: "total_supply".to_string(),
            data: "0x".to_string(),
            from: None,
            value: 0,
            gas: DEFAULT_CALL_GAS,
        };
        let (_, parsed_from, data, params) = build_call_params(&no_from).unwrap();
        assert!(parsed_from.is_none());
        assert_eq!(data, "0x");
        assert!(params[0].get("from").is_none());
        assert_eq!(params[0]["value"], "0x0");
        assert_eq!(params[0]["gas"], "0x186a0");
    }

    #[test]
    fn build_call_params_rejects_empty_method_or_bad_hex() {
        let contract = sample_address().to_string();
        assert!(build_call_params(&ContractCallArgs {
            contract: contract.clone(),
            method: "   ".to_string(),
            data: "0x".to_string(),
            from: None,
            value: 0,
            gas: DEFAULT_CALL_GAS,
        })
        .is_err());

        assert!(build_call_params(&ContractCallArgs {
            contract,
            method: "call".to_string(),
            data: "0xzzzz".to_string(),
            from: None,
            value: 0,
            gas: DEFAULT_CALL_GAS,
        })
        .is_err());
    }

    #[test]
    fn build_get_storage_at_params_formats_tuple() {
        let contract = sample_address();
        let slot_hex = derive_storage_slot_hex(b"kvnc/v1/state", b"");
        let params = build_get_storage_at_params(&contract, &slot_hex);
        assert_eq!(params, json!([contract.to_string(), slot_hex]));
    }

    #[test]
    fn format_call_and_storage_json_shapes() {
        let contract = sample_address();

        // Call output with printable UTF-8
        let call_json = format_call_json(
            &contract,
            "symbol",
            "0x",
            None,
            0,
            DEFAULT_CALL_GAS,
            "0x4b564e43",
        )
        .unwrap();
        assert_eq!(call_json["contract"], contract.to_string());
        assert_eq!(call_json["method"], "symbol");
        assert_eq!(call_json["output"], "0x4b564e43");
        assert_eq!(call_json["bytes_len"], 4);
        assert_eq!(call_json["utf8"], "KVNC");

        // Storage output empty vs non-empty
        let resolved = derive_preset_slot("token:meta").unwrap();
        let empty_json = format_storage_json(&contract, &resolved, "0x").unwrap();
        assert_eq!(empty_json["empty"], true);
        assert_eq!(empty_json["value"], "0x");
        assert_eq!(empty_json["bytes_len"], 0);
        assert!(empty_json["utf8"].is_null());

        let zero_json =
            format_storage_json(&contract, &resolved, &format!("0x{}", "00".repeat(32))).unwrap();
        assert_eq!(zero_json["empty"], true);

        let non_empty_json = format_storage_json(&contract, &resolved, "0xdeadbeef").unwrap();
        assert_eq!(non_empty_json["empty"], false);
        assert_eq!(non_empty_json["value"], "0xdeadbeef");
        assert_eq!(non_empty_json["bytes_len"], 4);
        assert!(non_empty_json["utf8"].is_null());
    }
}
