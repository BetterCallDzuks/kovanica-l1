//! Offline raw transaction decoder (`kovanica tx decode`).
//!
//! Decodes a Bincode-encoded [`kovanica_types::Transaction`] from bare or
//! `0x`-prefixed hex completely offline (no RPC calls) and verifies its
//! Ed25519 signature against the sender's public key and signing hash.

use anyhow::{bail, Context, Result};
use bincode::Options;
use clap::Args;
use kovanica_types::signing::{chain_id, SigningContext};
use kovanica_types::{Hash, Transaction, TransactionKind, MAX_TX_BYTES};
use serde::Serialize;
use serde_json::{json, Value};

use crate::amount::{format_atoms_pair, format_kuna_fixed};
use crate::output;

/// Maximum number of raw argument bytes shown inline in human-readable output
/// before truncating with a byte-length summary.
const HUMAN_ARGS_PREVIEW_BYTES: usize = 64;

/// Arguments for `kovanica tx decode`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct TxDecodeArgs {
    /// Raw Bincode-encoded transaction hex (bare or `0x`-prefixed)
    pub raw_tx: String,
}

/// Structured offline inspection summary of a decoded [`Transaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodedTransaction {
    pub tx_hash: String,
    pub sender: String,
    pub sender_hex: String,
    pub nonce: u64,
    pub fee: u64,
    pub fee_kvnc: String,
    pub kind: String,
    pub kind_details: Value,
    pub signature_valid: bool,
    pub signature_hex: String,
    pub signing_hash: String,
    pub chain_id: Option<u64>,
    pub wire_size_bytes: usize,
}

/// Parse a bare or `0x`-prefixed hex payload into raw transaction bytes,
/// failing closed on empty input, invalid hex, or oversized payloads.
pub fn parse_raw_tx_hex(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    let hex_body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if hex_body.is_empty() {
        bail!("raw transaction hex cannot be empty");
    }
    if !hex_body.len().is_multiple_of(2) {
        bail!(
            "raw transaction hex must have an even number of characters (got {})",
            hex_body.len()
        );
    }

    let max_hex_chars = MAX_TX_BYTES.saturating_mul(2);
    if hex_body.len() > max_hex_chars {
        bail!(
            "raw transaction payload exceeds maximum wire size of {MAX_TX_BYTES} bytes (got {} bytes)",
            hex_body.len() / 2
        );
    }

    let bytes = hex::decode(hex_body).context("raw transaction is not valid hex")?;
    if bytes.len() > MAX_TX_BYTES {
        bail!(
            "raw transaction payload exceeds maximum wire size of {MAX_TX_BYTES} bytes (got {} bytes)",
            bytes.len()
        );
    }

    Ok(bytes)
}

/// Decode a Bincode-encoded [`Transaction`] from bare or `0x`-prefixed hex.
///
/// Uses bounded fixint Bincode deserialization (`MAX_TX_BYTES` limit) and
/// rejects trailing bytes so malformed or oversized payloads fail closed.
pub fn decode_raw_transaction(raw_hex: &str) -> Result<(Transaction, usize)> {
    let bytes = parse_raw_tx_hex(raw_hex)?;
    let wire_size_bytes = bytes.len();

    let tx: Transaction = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_TX_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&bytes)
        .context("failed to decode Bincode transaction")?;

    Ok((tx, wire_size_bytes))
}

/// Inspect a decoded [`Transaction`] offline and verify its Ed25519 signature.
///
/// If `expected_chain_id` is supplied (via `--chain-id` / `KOVANICA_CHAIN_ID`),
/// verification checks that `tx.hash` matches `tx.signing_hash(&ctx)` for that
/// chain and that `tx.verify_signature(&ctx)` succeeds.
///
/// Otherwise, registered chain IDs (`1` mainnet, `2` testnet, `3` devnet) are
/// probed to identify the network whose `signing_hash` matches `tx.hash`; if
/// one matches, `tx.verify_signature(&ctx)` is evaluated against it. If none
/// matches (tampered payload, unsigned tx, or unregistered chain), verification
/// fails closed (`signature_valid = false`).
pub fn inspect_transaction(
    tx: &Transaction,
    wire_size_bytes: usize,
    expected_chain_id: Option<u64>,
) -> DecodedTransaction {
    let (resolved_chain_id, signing_hash, signature_valid) = match expected_chain_id {
        Some(cid) => {
            let ctx = SigningContext::new(cid);
            let computed = tx.signing_hash(&ctx);
            let valid = computed == tx.hash && tx.verify_signature(&ctx);
            (Some(cid), computed, valid)
        }
        None => {
            let mut matched = None;
            for cid in [chain_id::MAINNET, chain_id::TESTNET, chain_id::DEVNET] {
                let ctx = SigningContext::new(cid);
                if tx.signing_hash(&ctx) == tx.hash {
                    let valid = tx.verify_signature(&ctx);
                    matched = Some((cid, tx.hash, valid));
                    break;
                }
            }
            match matched {
                Some((cid, hash, valid)) => (Some(cid), hash, valid),
                None => (None, tx.hash, false),
            }
        }
    };

    let (kind, kind_details) = summarize_kind(&tx.kind);

    DecodedTransaction {
        tx_hash: format!("0x{}", tx.hash.to_hex()),
        sender: tx.sender.encode(),
        sender_hex: format!("0x{}", tx.sender.to_hex()),
        nonce: tx.nonce,
        fee: tx.fee,
        fee_kvnc: format_kuna_fixed(tx.fee),
        kind: kind.to_string(),
        kind_details,
        signature_valid,
        signature_hex: format!("0x{}", hex::encode(tx.signature.0)),
        signing_hash: format!("0x{}", signing_hash.to_hex()),
        chain_id: resolved_chain_id,
        wire_size_bytes,
    }
}

/// Decode and inspect a raw hex transaction in one offline step.
pub fn decode_and_inspect(
    raw_hex: &str,
    expected_chain_id: Option<u64>,
) -> Result<DecodedTransaction> {
    let (tx, wire_size_bytes) = decode_raw_transaction(raw_hex)?;
    Ok(inspect_transaction(&tx, wire_size_bytes, expected_chain_id))
}

fn summarize_kind(kind: &TransactionKind) -> (&'static str, Value) {
    match kind {
        TransactionKind::Transfer { to, amount } => (
            "Transfer",
            json!({
                "to": to.encode(),
                "to_hex": format!("0x{}", to.to_hex()),
                "amount": amount,
                "amount_kvnc": format_kuna_fixed(*amount),
            }),
        ),
        TransactionKind::Stake { amount } => (
            "Stake",
            json!({
                "amount": amount,
                "amount_kvnc": format_kuna_fixed(*amount),
            }),
        ),
        TransactionKind::Unstake { amount } => (
            "Unstake",
            json!({
                "amount": amount,
                "amount_kvnc": format_kuna_fixed(*amount),
            }),
        ),
        TransactionKind::Delegate { validator, amount } => (
            "Delegate",
            json!({
                "validator": validator.encode(),
                "validator_hex": format!("0x{}", validator.to_hex()),
                "amount": amount,
                "amount_kvnc": format_kuna_fixed(*amount),
            }),
        ),
        TransactionKind::ClaimRewards { validator } => (
            "ClaimRewards",
            json!({
                "validator": validator.map(|v| v.encode()),
                "validator_hex": validator.map(|v| format!("0x{}", v.to_hex())),
            }),
        ),
        TransactionKind::Deploy { code } => (
            "Deploy",
            json!({
                "code_len": code.len(),
                "code_hash": format!("0x{}", Hash::new(code).to_hex()),
            }),
        ),
        TransactionKind::Call {
            contract,
            value,
            method,
            args,
            gas_limit,
        } => (
            "Call",
            json!({
                "contract": contract.encode(),
                "contract_hex": format!("0x{}", contract.to_hex()),
                "method": method,
                "value": value,
                "value_kvnc": format_kuna_fixed(*value),
                "gas_limit": gas_limit,
                "args_len": args.len(),
                "args_hex": format!("0x{}", hex::encode(args)),
            }),
        ),
        TransactionKind::RegisterLightNode {
            vrf_public_key,
            stake,
        } => (
            "RegisterLightNode",
            json!({
                "vrf_public_key": format!("0x{}", hex::encode(vrf_public_key.0)),
                "stake": stake,
                "stake_kvnc": format_kuna_fixed(*stake),
            }),
        ),
        TransactionKind::ExitLightNode => ("ExitLightNode", json!({})),
        TransactionKind::SubmitLightWitness {
            epoch,
            vrf_hash,
            vrf_proof,
        } => (
            "SubmitLightWitness",
            json!({
                "epoch": epoch,
                "vrf_hash": format!("0x{}", hex::encode(vrf_hash)),
                "vrf_proof_len": vrf_proof.len(),
            }),
        ),
        TransactionKind::SetCommission {
            validator,
            commission_bps,
        } => (
            "SetCommission",
            json!({
                "validator": validator.encode(),
                "validator_hex": format!("0x{}", validator.to_hex()),
                "commission_bps": commission_bps,
            }),
        ),
        TransactionKind::ClaimTreasury { amount } => (
            "ClaimTreasury",
            json!({
                "amount": amount,
                "amount_kvnc": format_kuna_fixed(*amount),
            }),
        ),
        TransactionKind::Evidence { evidence } => (
            "Evidence",
            json!({
                "author": evidence.header_a.author.encode(),
                "author_hex": format!("0x{}", evidence.header_a.author.to_hex()),
                "round": evidence.header_a.round,
                "digest_a": format!("0x{}", evidence.header_a.digest.to_hex()),
                "digest_b": format!("0x{}", evidence.header_b.digest.to_hex()),
            }),
        ),
        TransactionKind::Batch { actions } => (
            "Batch",
            json!({
                "action_count": actions.len(),
            }),
        ),
        TransactionKind::Sponsored {
            fee_payer, inner, ..
        } => {
            let (inner_kind, inner_fields) = summarize_kind(inner);
            (
                "Sponsored",
                json!({
                    "fee_payer": fee_payer.encode(),
                    "fee_payer_hex": format!("0x{}", fee_payer.to_hex()),
                    "inner_kind": inner_kind,
                    "inner": inner_fields,
                }),
            )
        }
        TransactionKind::RegisterSessionKey { policy } => (
            "RegisterSessionKey",
            json!({
                "owner": policy.owner.encode(),
                "session_pubkey": format!("0x{}", hex::encode(policy.session_pubkey.0)),
                "expires_round": policy.expires_round,
            }),
        ),
        TransactionKind::RevokeSessionKey { session_pubkey } => (
            "RevokeSessionKey",
            json!({
                "session_pubkey": format!("0x{}", hex::encode(session_pubkey)),
            }),
        ),
    }
}

fn chain_label(cid: u64) -> &'static str {
    match cid {
        chain_id::MAINNET => "mainnet",
        chain_id::TESTNET => "testnet",
        chain_id::DEVNET => "devnet",
        _ => "custom",
    }
}

fn format_args_preview(args_hex: &str, args_len: u64) -> String {
    if args_len == 0 {
        return "0x (0 bytes)".to_string();
    }
    let body = args_hex.strip_prefix("0x").unwrap_or(args_hex);
    let max_chars = HUMAN_ARGS_PREVIEW_BYTES * 2;
    if body.len() > max_chars {
        format!("0x{}... ({args_len} bytes)", &body[..max_chars])
    } else {
        format!("0x{body} ({args_len} bytes)")
    }
}

/// Format a [`DecodedTransaction`] into key/value rows for human-readable output.
pub fn format_decoded_rows(decoded: &DecodedTransaction) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("Tx Hash", decoded.tx_hash.clone()),
        ("Sender", decoded.sender.clone()),
        ("Sender (Hex)", decoded.sender_hex.clone()),
        ("Nonce", decoded.nonce.to_string()),
        ("Fee", format_atoms_pair(decoded.fee)),
        ("Kind", decoded.kind.clone()),
    ];

    match decoded.kind.as_str() {
        "Transfer" => {
            if let Some(to) = decoded.kind_details["to"].as_str() {
                rows.push(("Recipient", to.to_string()));
            }
            if let Some(to_hex) = decoded.kind_details["to_hex"].as_str() {
                rows.push(("Recipient (Hex)", to_hex.to_string()));
            }
            if let Some(amount) = decoded.kind_details["amount"].as_u64() {
                rows.push(("Amount", format_atoms_pair(amount)));
            }
        }
        "Call" => {
            if let Some(contract) = decoded.kind_details["contract"].as_str() {
                rows.push(("Contract", contract.to_string()));
            }
            if let Some(contract_hex) = decoded.kind_details["contract_hex"].as_str() {
                rows.push(("Contract (Hex)", contract_hex.to_string()));
            }
            if let Some(method) = decoded.kind_details["method"].as_str() {
                rows.push(("Method", method.to_string()));
            }
            if let Some(value) = decoded.kind_details["value"].as_u64() {
                rows.push(("Value", format_atoms_pair(value)));
            }
            if let Some(gas_limit) = decoded.kind_details["gas_limit"].as_u64() {
                rows.push(("Gas Limit", gas_limit.to_string()));
            }
            if let (Some(args_hex), Some(args_len)) = (
                decoded.kind_details["args_hex"].as_str(),
                decoded.kind_details["args_len"].as_u64(),
            ) {
                rows.push(("Args", format_args_preview(args_hex, args_len)));
            }
        }
        "Deploy" => {
            if let Some(code_len) = decoded.kind_details["code_len"].as_u64() {
                rows.push(("Code Size", format!("{code_len} bytes")));
            }
            if let Some(code_hash) = decoded.kind_details["code_hash"].as_str() {
                rows.push(("Code Hash", code_hash.to_string()));
            }
        }
        "Stake" | "Unstake" | "ClaimTreasury" => {
            if let Some(amount) = decoded.kind_details["amount"].as_u64() {
                rows.push(("Amount", format_atoms_pair(amount)));
            }
        }
        "Delegate" => {
            if let Some(validator) = decoded.kind_details["validator"].as_str() {
                rows.push(("Validator", validator.to_string()));
            }
            if let Some(amount) = decoded.kind_details["amount"].as_u64() {
                rows.push(("Amount", format_atoms_pair(amount)));
            }
        }
        "ClaimRewards" => {
            let target = decoded.kind_details["validator"]
                .as_str()
                .unwrap_or("(all validators)");
            rows.push(("Validator", target.to_string()));
        }
        "RegisterLightNode" => {
            if let Some(vrf_pk) = decoded.kind_details["vrf_public_key"].as_str() {
                rows.push(("VRF Public Key", vrf_pk.to_string()));
            }
            if let Some(stake) = decoded.kind_details["stake"].as_u64() {
                rows.push(("Stake", format_atoms_pair(stake)));
            }
        }
        "SubmitLightWitness" => {
            if let Some(epoch) = decoded.kind_details["epoch"].as_u64() {
                rows.push(("Epoch", epoch.to_string()));
            }
            if let Some(vrf_hash) = decoded.kind_details["vrf_hash"].as_str() {
                rows.push(("VRF Hash", vrf_hash.to_string()));
            }
            if let Some(proof_len) = decoded.kind_details["vrf_proof_len"].as_u64() {
                rows.push(("VRF Proof", format!("{proof_len} bytes")));
            }
        }
        "SetCommission" => {
            if let Some(validator) = decoded.kind_details["validator"].as_str() {
                rows.push(("Validator", validator.to_string()));
            }
            if let Some(bps) = decoded.kind_details["commission_bps"].as_u64() {
                rows.push(("Commission", format!("{bps} bps")));
            }
        }
        "Evidence" => {
            if let Some(author) = decoded.kind_details["author"].as_str() {
                rows.push(("Author", author.to_string()));
            }
            if let Some(round) = decoded.kind_details["round"].as_u64() {
                rows.push(("Round", round.to_string()));
            }
        }
        _ => {}
    }

    let chain_display = match decoded.chain_id {
        Some(cid) => format!("{cid} ({})", chain_label(cid)),
        None => "unknown (pass --chain-id to verify)".to_string(),
    };
    rows.push(("Chain ID", chain_display));
    rows.push(("Signing Hash", decoded.signing_hash.clone()));
    rows.push(("Signature", decoded.signature_hex.clone()));
    rows.push(("Signature Valid", decoded.signature_valid.to_string()));
    rows.push(("Wire Size", format!("{} bytes", decoded.wire_size_bytes)));

    rows
}

/// Execute `kovanica tx decode <hex>` completely offline.
pub fn run_decode(args: TxDecodeArgs, chain_id: Option<u64>, json_output: bool) -> Result<()> {
    let decoded = decode_and_inspect(&args.raw_tx, chain_id)?;
    if json_output {
        return output::print_json(&serde_json::to_value(&decoded)?);
    }
    output::print_kv(&format_decoded_rows(&decoded));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx;
    use kovanica_types::{Address, PublicKey, SigningKey};

    const TESTNET_CTX: SigningContext = SigningContext::new(chain_id::TESTNET);

    fn spec_signer() -> (SigningKey, Address) {
        let sk = SigningKey::from_bytes(&[0x07u8; 32]);
        let pk = PublicKey::from(sk.verifying_key());
        (sk, Address::from_public_key(&pk))
    }

    #[test]
    fn decode_valid_signed_transfer_human_and_json() {
        let (sk, sender) = spec_signer();
        let recipient = Address([0x22u8; 32]);
        let signed_tx = tx::build_signed(
            &TESTNET_CTX,
            sender,
            5,
            TransactionKind::Transfer {
                to: recipient,
                amount: 1_500_000_000,
            },
            1_000,
            &sk,
        )
        .unwrap();
        let raw_hex = tx::encode_raw(&signed_tx).unwrap();
        let prefixed = format!("0x{raw_hex}");

        // Accepts both bare hex and 0x-prefixed hex.
        let decoded_bare = decode_and_inspect(&raw_hex, None).unwrap();
        let decoded_prefixed = decode_and_inspect(&prefixed, None).unwrap();
        assert_eq!(decoded_bare, decoded_prefixed);

        assert_eq!(
            decoded_bare.tx_hash,
            format!("0x{}", signed_tx.hash.to_hex())
        );
        assert_eq!(decoded_bare.sender, sender.encode());
        assert_eq!(decoded_bare.sender_hex, format!("0x{}", sender.to_hex()));
        assert_eq!(decoded_bare.nonce, 5);
        assert_eq!(decoded_bare.fee, 1_000);
        assert_eq!(decoded_bare.fee_kvnc, "0.000001000 KVNC");
        assert_eq!(decoded_bare.kind, "Transfer");
        assert_eq!(decoded_bare.kind_details["to"], recipient.encode());
        assert_eq!(
            decoded_bare.kind_details["to_hex"],
            format!("0x{}", recipient.to_hex())
        );
        assert_eq!(decoded_bare.kind_details["amount"], 1_500_000_000);
        assert_eq!(decoded_bare.kind_details["amount_kvnc"], "1.500000000 KVNC");
        assert!(decoded_bare.signature_valid);
        assert_eq!(decoded_bare.chain_id, Some(chain_id::TESTNET));
        assert_eq!(decoded_bare.wire_size_bytes, raw_hex.len() / 2);

        // JSON serialization contains all expected fields.
        let json_val = serde_json::to_value(&decoded_bare).unwrap();
        assert_eq!(json_val["tx_hash"], decoded_bare.tx_hash);
        assert_eq!(json_val["sender"], sender.encode());
        assert_eq!(json_val["sender_hex"], format!("0x{}", sender.to_hex()));
        assert_eq!(json_val["nonce"], 5);
        assert_eq!(json_val["fee"], 1_000);
        assert_eq!(json_val["fee_kvnc"], "0.000001000 KVNC");
        assert_eq!(json_val["kind"], "Transfer");
        assert_eq!(json_val["signature_valid"], true);
        assert_eq!(json_val["wire_size_bytes"], raw_hex.len() / 2);

        // Human-readable rows include all key fields.
        let rows = format_decoded_rows(&decoded_bare);
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Tx Hash" && v == &decoded_bare.tx_hash));
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Sender" && v == &sender.encode()));
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Recipient" && v == &recipient.encode()));
        assert!(rows.iter().any(|(k, v)| *k == "Kind" && v == "Transfer"));
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Signature Valid" && v == "true"));

        // Explicit mismatched chain_id fails signature verification.
        let wrong_chain = decode_and_inspect(&prefixed, Some(chain_id::MAINNET)).unwrap();
        assert!(!wrong_chain.signature_valid);
        assert_eq!(wrong_chain.chain_id, Some(chain_id::MAINNET));
    }

    #[test]
    fn decode_valid_signed_call_with_contract_and_payload() {
        let (sk, sender) = spec_signer();
        let contract = Address([0x33u8; 32]);
        let args = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let signed_tx = tx::build_signed(
            &TESTNET_CTX,
            sender,
            6,
            TransactionKind::Call {
                contract,
                value: 500,
                method: "token_transfer".to_string(),
                args: args.clone(),
                gas_limit: 100_000,
            },
            10,
            &sk,
        )
        .unwrap();
        let raw_hex = format!("0x{}", tx::encode_raw(&signed_tx).unwrap());

        let decoded = decode_and_inspect(&raw_hex, None).unwrap();
        assert_eq!(decoded.kind, "Call");
        assert_eq!(decoded.nonce, 6);
        assert_eq!(decoded.fee, 10);
        assert!(decoded.signature_valid);
        assert_eq!(decoded.chain_id, Some(chain_id::TESTNET));
        assert_eq!(decoded.kind_details["contract"], contract.encode());
        assert_eq!(
            decoded.kind_details["contract_hex"],
            format!("0x{}", contract.to_hex())
        );
        assert_eq!(decoded.kind_details["method"], "token_transfer");
        assert_eq!(decoded.kind_details["value"], 500);
        assert_eq!(decoded.kind_details["gas_limit"], 100_000);
        assert_eq!(decoded.kind_details["args_len"], args.len());
        assert_eq!(decoded.kind_details["args_hex"], "0xdeadbeef0102");

        let rows = format_decoded_rows(&decoded);
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Contract" && v == &contract.encode()));
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Method" && v == "token_transfer"));
        assert!(rows.iter().any(|(k, v)| *k == "Gas Limit" && v == "100000"));
        assert!(rows
            .iter()
            .any(|(k, v)| *k == "Args" && v == "0xdeadbeef0102 (6 bytes)"));
    }

    #[test]
    fn decode_detects_tampered_transaction_and_fails_signature_check() {
        let (sk, sender) = spec_signer();
        let mut signed_tx = tx::build_signed(
            &TESTNET_CTX,
            sender,
            1,
            TransactionKind::Transfer {
                to: Address([0x44u8; 32]),
                amount: 100,
            },
            1,
            &sk,
        )
        .unwrap();
        // Tamper with nonce after signing without updating signature/hash.
        signed_tx.nonce = 2;
        let raw_hex = tx::encode_raw(&signed_tx).unwrap();

        let decoded = decode_and_inspect(&raw_hex, None).unwrap();
        assert!(!decoded.signature_valid);
        assert_eq!(decoded.chain_id, None);
    }

    #[test]
    fn decode_fails_closed_on_invalid_hex_oversized_or_truncated_bincode() {
        // Empty / prefix-only
        assert!(decode_raw_transaction("").is_err());
        assert!(decode_raw_transaction("   ").is_err());
        assert!(decode_raw_transaction("0x").is_err());

        // Odd-length / non-hex
        assert!(decode_raw_transaction("0xabc").is_err());
        assert!(decode_raw_transaction("0xzzzz").is_err());

        // Oversized payload (> MAX_TX_BYTES)
        let oversized = "aa".repeat(MAX_TX_BYTES + 1);
        let err = decode_raw_transaction(&oversized).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum wire size"),
            "unexpected error: {err}"
        );

        // Truncated valid transaction Bincode
        let (sk, sender) = spec_signer();
        let signed_tx = tx::build_signed(
            &TESTNET_CTX,
            sender,
            1,
            TransactionKind::Stake { amount: 500 },
            1,
            &sk,
        )
        .unwrap();
        let raw_hex = tx::encode_raw(&signed_tx).unwrap();
        let truncated = &raw_hex[..raw_hex.len() / 2];
        assert!(decode_raw_transaction(truncated).is_err());

        // Trailing garbage bytes after valid Bincode are rejected
        let with_trailing = format!("{raw_hex}deadbeef");
        assert!(decode_raw_transaction(&with_trailing).is_err());
    }
}
