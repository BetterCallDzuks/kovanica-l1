//! Offline air-gapped transaction envelope encoder & decoder (`kovanica tx envelope`).
//!
//! Byte-for-byte compatible with `kovanica-sdk`'s `kvnc-tx:v1:<base64url(JSON)>`
//! wire format (`kovanica-sdk/src/airgap.ts`) with BLAKE3 integrity verification
//! and canonical network-tag pinning for Mainnet (Chain 1) and Testnet (Chain 2).

use anyhow::{bail, Result};
use clap::{Args, Subcommand, ValueEnum};
use kovanica_types::signing::chain_id;
use kovanica_types::Hash;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::output;

/// Current air-gap transaction envelope wire format version.
pub const AIRGAP_ENVELOPE_VERSION: u8 = 1;

/// Wire prefix for compact base64url-encoded air-gap transaction envelopes.
pub const AIRGAP_ENVELOPE_PREFIX: &str = "kvnc-tx:v1:";

/// Canonical network tag for Kovanica Mainnet (Chain 1).
pub const MAINNET_NETWORK_TAG: &str = "1-f35df34c92001436";

/// Canonical network tag for Kovanica Testnet (Chain 2).
pub const TESTNET_NETWORK_TAG: &str = "2-24cdb5fadd98b207";

const CHECKSUM_DOMAIN_PREFIX: &str = "KVNC/airgap-tx/v1\n";

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Subcommands under `kovanica tx envelope`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum TxEnvelopeCommand {
    /// Encode a raw transaction hex payload into a verified `kvnc-tx:v1:...` air-gap envelope
    Encode(TxEnvelopeEncodeArgs),
    /// Decode and verify an air-gap envelope (`kvnc-tx:v1:...` or raw JSON) offline
    Decode(TxEnvelopeDecodeArgs),
}

/// Kind of transaction carried inside an air-gapped envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AirgapTxKind {
    Transfer,
    Call,
    Raw,
}

impl AirgapTxKind {
    /// Return the canonical lowercase wire string (`"transfer"`, `"call"`, or `"raw"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Call => "call",
            Self::Raw => "raw",
        }
    }

    fn parse_wire(s: &str) -> Result<Self> {
        match s {
            "transfer" => Ok(Self::Transfer),
            "call" => Ok(Self::Call),
            "raw" => Ok(Self::Raw),
            other => {
                bail!("invalid air-gap tx kind '{other}': expected 'transfer', 'call', or 'raw'")
            }
        }
    }
}

/// Arguments for `kovanica tx envelope encode`.
///
/// Uses the global `--chain-id` (or `KOVANICA_CHAIN_ID`) and `--json` flags.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct TxEnvelopeEncodeArgs {
    /// Raw transaction hex (bare or `0x`-prefixed)
    pub raw_tx_hex: String,
    /// Transaction kind (`transfer`, `call`, or `raw`)
    #[arg(long, value_enum, default_value_t = AirgapTxKind::Raw)]
    pub kind: AirgapTxKind,
    /// Network tag (auto-filled with canonical tag for Chains 1 & 2; spoofed tags are rejected)
    #[arg(long)]
    pub network_tag: Option<String>,
    /// Optional 32-byte signing hash hex (bare or `0x`-prefixed)
    #[arg(long)]
    pub signing_hash: Option<String>,
}

/// Arguments for `kovanica tx envelope decode`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct TxEnvelopeDecodeArgs {
    /// Encoded air-gap envelope (`kvnc-tx:v1:<base64url>`) or raw JSON object
    pub envelope: String,
    /// Expected chain ID; decoding fails closed if the envelope's `chainId` differs
    #[arg(long)]
    pub expected_chain_id: Option<u64>,
}

/// Verified air-gapped transaction envelope matching `kovanica-sdk`'s `AirgapTxEnvelope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AirgapTxEnvelope {
    pub version: u8,
    pub chain_id: u64,
    pub network_tag: String,
    pub kind: AirgapTxKind,
    pub raw_tx_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_hash_hex: Option<String>,
    pub checksum_hex: String,
}

/// Result of encoding an air-gapped transaction envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedAirgapTxEnvelope {
    pub envelope: AirgapTxEnvelope,
    pub encoded: String,
}

/// Input fields for [`encode_airgap_tx_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeAirgapTxEnvelopeInput<'a> {
    pub chain_id: u64,
    pub network_tag: Option<&'a str>,
    pub kind: AirgapTxKind,
    pub raw_tx_hex: &'a str,
    pub signing_hash_hex: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayload<'a> {
    version: u8,
    chain_id: u64,
    network_tag: &'a str,
    kind: AirgapTxKind,
    raw_tx_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_hash_hex: Option<&'a str>,
}

/// Return the canonical frozen network tag for Chains 1 and 2, if applicable.
pub const fn canonical_network_tag(cid: u64) -> Option<&'static str> {
    match cid {
        chain_id::MAINNET => Some(MAINNET_NETWORK_TAG),
        chain_id::TESTNET => Some(TESTNET_NETWORK_TAG),
        _ => None,
    }
}

/// Encode bytes using unpadded RFC 4648 §5 base64url.
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(BASE64URL_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(BASE64URL_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(BASE64URL_ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(BASE64URL_ALPHABET[(n & 0x3f) as usize] as char);
    }
    match chunks.remainder() {
        [a] => {
            let n = (*a as u32) << 16;
            out.push(BASE64URL_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(BASE64URL_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            out.push(BASE64URL_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(BASE64URL_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(BASE64URL_ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

fn decode_base64url_char(byte: u8, offset: usize) -> Result<u32> {
    let val = match byte {
        b'A'..=b'Z' => (byte - b'A') as u32,
        b'a'..=b'z' => (byte - b'a' + 26) as u32,
        b'0'..=b'9' => (byte - b'0' + 52) as u32,
        b'-' => 62,
        b'_' => 63,
        _ => bail!("invalid base64url character at offset {offset}"),
    };
    Ok(val)
}

/// Strictly decode an unpadded RFC 4648 §5 base64url string.
///
/// Rejects empty inputs, `len % 4 == 1`, padding (`=`), non-alphabet characters,
/// and non-canonical trailing bits.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        bail!("air-gap envelope base64url payload must not be empty");
    }
    let rem = bytes.len() % 4;
    if rem == 1 {
        bail!(
            "invalid base64url length ({}) in air-gap envelope",
            bytes.len()
        );
    }

    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let full_len = bytes.len() - rem;
    let mut i = 0;
    while i < full_len {
        let a = decode_base64url_char(bytes[i], i)?;
        let b = decode_base64url_char(bytes[i + 1], i + 1)?;
        let c = decode_base64url_char(bytes[i + 2], i + 2)?;
        let d = decode_base64url_char(bytes[i + 3], i + 3)?;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
        i += 4;
    }

    if rem == 2 {
        let a = decode_base64url_char(bytes[i], i)?;
        let b = decode_base64url_char(bytes[i + 1], i + 1)?;
        if (b & 0x0f) != 0 {
            bail!("non-canonical trailing bits in base64url payload");
        }
        out.push(((a << 2) | (b >> 4)) as u8);
    } else if rem == 3 {
        let a = decode_base64url_char(bytes[i], i)?;
        let b = decode_base64url_char(bytes[i + 1], i + 1)?;
        let c = decode_base64url_char(bytes[i + 2], i + 2)?;
        if (c & 0x03) != 0 {
            bail!("non-canonical trailing bits in base64url payload");
        }
        out.push(((a << 2) | (b >> 4)) as u8);
        out.push((((b & 0x0f) << 4) | (c >> 2)) as u8);
    }

    Ok(out)
}

fn validate_chain_id(cid: u64, field: &str) -> Result<u64> {
    if cid == 0 {
        bail!("invalid {field}: expected a positive integer, got 0");
    }
    Ok(cid)
}

fn validate_and_resolve_network_tag(
    cid: u64,
    network_tag: Option<&str>,
    allow_default: bool,
) -> Result<String> {
    let canonical = canonical_network_tag(cid);

    let Some(tag) = network_tag else {
        if !allow_default {
            bail!("missing required field 'networkTag' in air-gap envelope");
        }
        return Ok(canonical
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| cid.to_string()));
    };

    if tag.trim().is_empty() {
        bail!("invalid networkTag: expected a non-empty string");
    }

    if let Some(expected) = canonical {
        if tag != expected {
            bail!(
                "invalid networkTag '{tag}' for chainId {cid}: expected canonical tag '{expected}'"
            );
        }
    }

    Ok(tag.to_string())
}

fn normalize_raw_tx_hex(raw_tx_hex: &str) -> Result<String> {
    let trimmed = raw_tx_hex.trim();
    let clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if clean.is_empty()
        || !clean.len().is_multiple_of(2)
        || !clean.bytes().all(|b| b.is_ascii_hexdigit())
    {
        bail!("invalid rawTxHex: expected non-empty even-length hex bytes");
    }
    let bytes = hex::decode(clean)?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn normalize_signing_hash_hex(signing_hash_hex: Option<&str>) -> Result<Option<String>> {
    let Some(input) = signing_hash_hex else {
        return Ok(None);
    };
    let trimmed = input.trim();
    let clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "invalid signingHashHex: expected 32 bytes (64 hex chars), got {} hex char(s)",
            clean.len()
        );
    }
    let bytes = hex::decode(clean)?;
    Ok(Some(format!("0x{}", hex::encode(bytes))))
}

fn is_lowercase_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn compute_envelope_checksum(
    cid: u64,
    network_tag: &str,
    kind: AirgapTxKind,
    raw_tx_hex: &str,
    signing_hash_hex: Option<&str>,
) -> Result<String> {
    let payload = ChecksumPayload {
        version: AIRGAP_ENVELOPE_VERSION,
        chain_id: cid,
        network_tag,
        kind,
        raw_tx_hex,
        signing_hash_hex,
    };
    let canonical_json = serde_json::to_string(&payload)?;
    let mut preimage = Vec::with_capacity(CHECKSUM_DOMAIN_PREFIX.len() + canonical_json.len());
    preimage.extend_from_slice(CHECKSUM_DOMAIN_PREFIX.as_bytes());
    preimage.extend_from_slice(canonical_json.as_bytes());
    let digest = Hash::new(&preimage);
    Ok(hex::encode(&digest.0[..8]))
}

fn constant_time_eq_ascii(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate fields, pin canonical network tags for Chains 1 & 2, compute the
/// 8-byte BLAKE3 integrity checksum, and encode as `kvnc-tx:v1:<base64url(JSON)>`.
pub fn encode_airgap_tx_envelope(
    input: EncodeAirgapTxEnvelopeInput<'_>,
) -> Result<EncodedAirgapTxEnvelope> {
    let cid = validate_chain_id(input.chain_id, "chainId")?;
    let network_tag = validate_and_resolve_network_tag(cid, input.network_tag, true)?;
    let raw_tx_hex = normalize_raw_tx_hex(input.raw_tx_hex)?;
    let signing_hash_hex = normalize_signing_hash_hex(input.signing_hash_hex)?;

    let checksum_hex = compute_envelope_checksum(
        cid,
        &network_tag,
        input.kind,
        &raw_tx_hex,
        signing_hash_hex.as_deref(),
    )?;

    let envelope = AirgapTxEnvelope {
        version: AIRGAP_ENVELOPE_VERSION,
        chain_id: cid,
        network_tag,
        kind: input.kind,
        raw_tx_hex,
        signing_hash_hex,
        checksum_hex,
    };

    let json = serde_json::to_string(&envelope)?;
    let encoded = format!(
        "{AIRGAP_ENVELOPE_PREFIX}{}",
        base64url_encode(json.as_bytes())
    );
    Ok(EncodedAirgapTxEnvelope { envelope, encoded })
}

fn extract_u64_field(obj: &Map<String, Value>, field: &str) -> Result<u64> {
    match obj.get(field).and_then(Value::as_u64) {
        Some(v) => Ok(v),
        None => bail!("invalid or missing integer field '{field}' in air-gap envelope"),
    }
}

/// Decode and verify an air-gapped transaction envelope from either
/// `kvnc-tx:v1:<base64url>` or a raw JSON object string.
///
/// Fails closed on malformed framing, invalid base64url/UTF-8/JSON, unsupported
/// versions, invalid hex, spoofed Chain 1/2 network tags, checksum mismatches,
/// or `expected_chain_id` mismatches.
pub fn decode_airgap_tx_envelope(
    encoded_or_json: &str,
    expected_chain_id: Option<u64>,
) -> Result<AirgapTxEnvelope> {
    let trimmed = encoded_or_json.trim();
    if trimmed.is_empty() {
        bail!("air-gap envelope input must not be empty");
    }

    let json_text = if trimmed.starts_with('{') {
        trimmed.to_string()
    } else if let Some(b64) = trimmed.strip_prefix(AIRGAP_ENVELOPE_PREFIX) {
        let json_bytes = base64url_decode(b64)?;
        String::from_utf8(json_bytes)
            .map_err(|_| anyhow::anyhow!("air-gap envelope payload is not valid UTF-8"))?
    } else {
        bail!(
            "invalid air-gap envelope prefix: expected '{AIRGAP_ENVELOPE_PREFIX}' or JSON object"
        );
    };

    let parsed: Value = serde_json::from_str(&json_text)
        .map_err(|_| anyhow::anyhow!("air-gap envelope payload is not valid JSON"))?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("air-gap envelope JSON must be an object"))?;

    let version = extract_u64_field(obj, "version")?;
    if version != u64::from(AIRGAP_ENVELOPE_VERSION) {
        bail!(
            "unsupported air-gap envelope version: {version} (expected {AIRGAP_ENVELOPE_VERSION})"
        );
    }

    let cid = validate_chain_id(extract_u64_field(obj, "chainId")?, "chainId")?;
    let network_tag_raw = match obj.get("networkTag") {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => bail!("invalid networkTag: expected a non-empty string"),
    };
    let network_tag = validate_and_resolve_network_tag(cid, network_tag_raw, false)?;

    let kind_str = obj
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("invalid or missing field 'kind' in air-gap envelope"))?;
    let kind = AirgapTxKind::parse_wire(kind_str)?;

    let raw_tx_hex = obj.get("rawTxHex").and_then(Value::as_str).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid rawTxHex in air-gap envelope: expected lowercase 0x-prefixed even-length hex"
        )
    })?;
    let Some(raw_body) = raw_tx_hex.strip_prefix("0x") else {
        bail!(
            "invalid rawTxHex in air-gap envelope: expected lowercase 0x-prefixed even-length hex"
        );
    };
    if raw_body.is_empty() || !raw_body.len().is_multiple_of(2) || !is_lowercase_hex(raw_body) {
        bail!(
            "invalid rawTxHex in air-gap envelope: expected lowercase 0x-prefixed even-length hex"
        );
    }

    let signing_hash_hex = match obj.get("signingHashHex") {
        None => None,
        Some(Value::String(s)) => {
            let Some(body) = s.strip_prefix("0x") else {
                bail!("invalid signingHashHex in air-gap envelope: expected lowercase 0x + 64 hex chars");
            };
            if body.len() != 64 || !is_lowercase_hex(body) {
                bail!("invalid signingHashHex in air-gap envelope: expected lowercase 0x + 64 hex chars");
            }
            Some(s.clone())
        }
        Some(_) => {
            bail!(
                "invalid signingHashHex in air-gap envelope: expected lowercase 0x + 64 hex chars"
            )
        }
    };

    let checksum_hex = obj
        .get("checksumHex")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "invalid checksumHex in air-gap envelope: expected 16 lowercase hex chars"
            )
        })?;
    if checksum_hex.len() != 16 || !is_lowercase_hex(checksum_hex) {
        bail!("invalid checksumHex in air-gap envelope: expected 16 lowercase hex chars");
    }

    let expected_checksum = compute_envelope_checksum(
        cid,
        &network_tag,
        kind,
        raw_tx_hex,
        signing_hash_hex.as_deref(),
    )?;
    if !constant_time_eq_ascii(checksum_hex, &expected_checksum) {
        bail!(
            "air-gap envelope checksum mismatch: expected {expected_checksum}, got {checksum_hex}"
        );
    }

    if let Some(expected) = expected_chain_id {
        let expected = validate_chain_id(expected, "expectedChainId")?;
        if cid != expected {
            bail!("air-gap envelope chainId mismatch: expected {expected}, got {cid}");
        }
    }

    Ok(AirgapTxEnvelope {
        version: AIRGAP_ENVELOPE_VERSION,
        chain_id: cid,
        network_tag,
        kind,
        raw_tx_hex: raw_tx_hex.to_string(),
        signing_hash_hex,
        checksum_hex: checksum_hex.to_string(),
    })
}

/// Format an encoded air-gap envelope into key/value rows for human-readable output.
pub fn format_encoded_rows(encoded: &EncodedAirgapTxEnvelope) -> Vec<(&'static str, String)> {
    let mut rows = format_envelope_rows(&encoded.envelope);
    rows.push(("Envelope", encoded.encoded.clone()));
    rows
}

/// Format a decoded air-gap envelope into key/value rows for human-readable output.
pub fn format_decoded_rows(envelope: &AirgapTxEnvelope) -> Vec<(&'static str, String)> {
    let mut rows = format_envelope_rows(envelope);
    rows.push(("Checksum Valid", "true".to_string()));
    rows
}

fn format_envelope_rows(envelope: &AirgapTxEnvelope) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("Version", envelope.version.to_string()),
        ("Chain ID", envelope.chain_id.to_string()),
        ("Network Tag", envelope.network_tag.clone()),
        ("Kind", envelope.kind.as_str().to_string()),
        ("Raw Tx Hex", envelope.raw_tx_hex.clone()),
    ];
    if let Some(ref signing_hash) = envelope.signing_hash_hex {
        rows.push(("Signing Hash", signing_hash.clone()));
    }
    rows.push(("Checksum", envelope.checksum_hex.clone()));
    rows
}

/// Execute `kovanica tx envelope <encode|decode>` completely offline.
pub fn run(command: TxEnvelopeCommand, chain_id: Option<u64>, json_output: bool) -> Result<()> {
    match command {
        TxEnvelopeCommand::Encode(args) => run_encode(args, chain_id, json_output),
        TxEnvelopeCommand::Decode(args) => run_decode(args, json_output),
    }
}

/// Execute `kovanica tx envelope encode`.
pub fn run_encode(
    args: TxEnvelopeEncodeArgs,
    chain_id: Option<u64>,
    json_output: bool,
) -> Result<()> {
    let cid = chain_id.ok_or_else(|| {
        anyhow::anyhow!(
            "--chain-id is required for `kovanica tx envelope encode` (or set KOVANICA_CHAIN_ID)"
        )
    })?;
    let result = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
        chain_id: cid,
        network_tag: args.network_tag.as_deref(),
        kind: args.kind,
        raw_tx_hex: &args.raw_tx_hex,
        signing_hash_hex: args.signing_hash.as_deref(),
    })?;

    if json_output {
        return output::print_json(&serde_json::to_value(&result)?);
    }
    output::print_kv(&format_encoded_rows(&result));
    Ok(())
}

/// Execute `kovanica tx envelope decode`.
pub fn run_decode(args: TxEnvelopeDecodeArgs, json_output: bool) -> Result<()> {
    let envelope = decode_airgap_tx_envelope(&args.envelope, args.expected_chain_id)?;
    if json_output {
        return output::print_json(&serde_json::to_value(&envelope)?);
    }
    output::print_kv(&format_decoded_rows(&envelope));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SAMPLE_RAW_TX_HEX: &str = "deadbeef0102030405060708090a0b0c";

    /// Cross-check vector generated directly by `kovanica-sdk/src/airgap.ts`
    /// (`encodeAirgapTxEnvelope({ chainId: 1, kind: "transfer", rawTxHex: "0xdeadbeef0102030405060708090a0b0c", signingHashHex: "0x" + "ab".repeat(32) })`).
    const SDK_VECTOR_MAINNET_CHECKSUM: &str = "ba5ffb09aa6d578e";
    const SDK_VECTOR_MAINNET_ENCODED: &str = "kvnc-tx:v1:eyJ2ZXJzaW9uIjoxLCJjaGFpbklkIjoxLCJuZXR3b3JrVGFnIjoiMS1mMzVkZjM0YzkyMDAxNDM2Iiwia2luZCI6InRyYW5zZmVyIiwicmF3VHhIZXgiOiIweGRlYWRiZWVmMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjIiwic2lnbmluZ0hhc2hIZXgiOiIweGFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIiLCJjaGVja3N1bUhleCI6ImJhNWZmYjA5YWE2ZDU3OGUifQ";

    /// Cross-check vector generated directly by `kovanica-sdk/src/airgap.ts`
    /// (`encodeAirgapTxEnvelope({ chainId: 2, kind: "call", rawTxHex: "0xdeadbeef0102030405060708090a0b0c" })`).
    const SDK_VECTOR_TESTNET_CHECKSUM: &str = "d59d05a2b468cc58";
    const SDK_VECTOR_TESTNET_ENCODED: &str = "kvnc-tx:v1:eyJ2ZXJzaW9uIjoxLCJjaGFpbklkIjoyLCJuZXR3b3JrVGFnIjoiMi0yNGNkYjVmYWRkOThiMjA3Iiwia2luZCI6ImNhbGwiLCJyYXdUeEhleCI6IjB4ZGVhZGJlZWYwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMiLCJjaGVja3N1bUhleCI6ImQ1OWQwNWEyYjQ2OGNjNTgifQ";

    #[test]
    fn cross_check_vectors_match_kovanica_sdk_byte_for_byte() {
        let signing_hash = format!("0x{}", "AB".repeat(32));
        let v1 = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::MAINNET,
            network_tag: None,
            kind: AirgapTxKind::Transfer,
            raw_tx_hex: &format!("0X{}", SAMPLE_RAW_TX_HEX.to_ascii_uppercase()),
            signing_hash_hex: Some(&signing_hash),
        })
        .unwrap();

        assert_eq!(v1.envelope.version, 1);
        assert_eq!(v1.envelope.chain_id, 1);
        assert_eq!(v1.envelope.network_tag, MAINNET_NETWORK_TAG);
        assert_eq!(v1.envelope.kind, AirgapTxKind::Transfer);
        assert_eq!(v1.envelope.raw_tx_hex, format!("0x{SAMPLE_RAW_TX_HEX}"));
        assert_eq!(
            v1.envelope.signing_hash_hex.as_deref(),
            Some(format!("0x{}", "ab".repeat(32)).as_str())
        );
        assert_eq!(v1.envelope.checksum_hex, SDK_VECTOR_MAINNET_CHECKSUM);
        assert_eq!(v1.encoded, SDK_VECTOR_MAINNET_ENCODED);

        let decoded_v1 = decode_airgap_tx_envelope(SDK_VECTOR_MAINNET_ENCODED, Some(1)).unwrap();
        assert_eq!(decoded_v1, v1.envelope);

        let v2 = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::TESTNET,
            network_tag: None,
            kind: AirgapTxKind::Call,
            raw_tx_hex: SAMPLE_RAW_TX_HEX,
            signing_hash_hex: None,
        })
        .unwrap();

        assert_eq!(v2.envelope.chain_id, 2);
        assert_eq!(v2.envelope.network_tag, TESTNET_NETWORK_TAG);
        assert_eq!(v2.envelope.signing_hash_hex, None);
        assert_eq!(v2.envelope.checksum_hex, SDK_VECTOR_TESTNET_CHECKSUM);
        assert_eq!(v2.encoded, SDK_VECTOR_TESTNET_ENCODED);

        let decoded_v2 = decode_airgap_tx_envelope(SDK_VECTOR_TESTNET_ENCODED, Some(2)).unwrap();
        assert_eq!(decoded_v2, v2.envelope);
    }

    #[test]
    fn round_trip_compact_and_raw_json_regardless_of_key_order() {
        let encoded = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::TESTNET,
            network_tag: Some(TESTNET_NETWORK_TAG),
            kind: AirgapTxKind::Raw,
            raw_tx_hex: "0x010203",
            signing_hash_hex: None,
        })
        .unwrap();

        // Compact envelope with surrounding whitespace.
        let decoded_compact =
            decode_airgap_tx_envelope(&format!("  {}\n", encoded.encoded), Some(2)).unwrap();
        assert_eq!(decoded_compact, encoded.envelope);

        // Raw JSON string in canonical order.
        let raw_json = serde_json::to_string(&encoded.envelope).unwrap();
        let decoded_json = decode_airgap_tx_envelope(&raw_json, Some(2)).unwrap();
        assert_eq!(decoded_json, encoded.envelope);

        // Raw JSON with reordered keys still verifies against canonical checksum.
        let reordered = json!({
            "checksumHex": encoded.envelope.checksum_hex,
            "rawTxHex": encoded.envelope.raw_tx_hex,
            "kind": "raw",
            "networkTag": encoded.envelope.network_tag,
            "chainId": encoded.envelope.chain_id,
            "version": 1
        })
        .to_string();
        assert_eq!(
            decode_airgap_tx_envelope(&reordered, None).unwrap(),
            encoded.envelope
        );

        // Custom devnet chain defaults networkTag to stringified chainId.
        let custom = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::DEVNET,
            network_tag: None,
            kind: AirgapTxKind::Transfer,
            raw_tx_hex: "0xabcd",
            signing_hash_hex: None,
        })
        .unwrap();
        assert_eq!(custom.envelope.network_tag, "3");
        assert_eq!(
            decode_airgap_tx_envelope(&custom.encoded, Some(3)).unwrap(),
            custom.envelope
        );
    }

    #[test]
    fn tampered_fields_and_checksum_fail_closed() {
        let encoded = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::MAINNET,
            network_tag: None,
            kind: AirgapTxKind::Transfer,
            raw_tx_hex: &format!("0x{SAMPLE_RAW_TX_HEX}"),
            signing_hash_hex: Some(&format!("0x{}", "11".repeat(32))),
        })
        .unwrap();

        // 1. Tampered checksumHex
        let mut tampered_checksum = encoded.envelope.clone();
        let first = if tampered_checksum.checksum_hex.starts_with('0') {
            "1"
        } else {
            "0"
        };
        tampered_checksum.checksum_hex = format!("{first}{}", &tampered_checksum.checksum_hex[1..]);
        let err =
            decode_airgap_tx_envelope(&serde_json::to_string(&tampered_checksum).unwrap(), None)
                .unwrap_err();
        assert!(
            err.to_string().contains("checksum mismatch"),
            "unexpected error: {err}"
        );

        // 2. Tampered rawTxHex
        let mut tampered_raw = encoded.envelope.clone();
        tampered_raw.raw_tx_hex =
            format!("0x{}ff", &SAMPLE_RAW_TX_HEX[..SAMPLE_RAW_TX_HEX.len() - 2]);
        assert!(
            decode_airgap_tx_envelope(&serde_json::to_string(&tampered_raw).unwrap(), None)
                .is_err()
        );

        // 3. Tampered chainId (even with matching canonical tag for the new chain)
        let mut tampered_chain = encoded.envelope.clone();
        tampered_chain.chain_id = chain_id::TESTNET;
        tampered_chain.network_tag = TESTNET_NETWORK_TAG.to_string();
        assert!(
            decode_airgap_tx_envelope(&serde_json::to_string(&tampered_chain).unwrap(), None)
                .is_err()
        );

        // 4. Tampered signingHashHex
        let mut tampered_hash = encoded.envelope.clone();
        tampered_hash.signing_hash_hex = Some(format!("0x{}", "22".repeat(32)));
        assert!(
            decode_airgap_tx_envelope(&serde_json::to_string(&tampered_hash).unwrap(), None)
                .is_err()
        );

        // 5. Tampered kind
        let mut tampered_kind = encoded.envelope.clone();
        tampered_kind.kind = AirgapTxKind::Call;
        assert!(
            decode_airgap_tx_envelope(&serde_json::to_string(&tampered_kind).unwrap(), None)
                .is_err()
        );
    }

    #[test]
    fn spoofed_network_tag_fails_closed_on_encode_and_decode() {
        // Encode: Chain 1 with Chain 2 tag
        assert!(encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::MAINNET,
            network_tag: Some(TESTNET_NETWORK_TAG),
            kind: AirgapTxKind::Transfer,
            raw_tx_hex: "0xabcd",
            signing_hash_hex: None,
        })
        .is_err());

        // Encode: Chain 2 with spoofed tag
        assert!(encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::TESTNET,
            network_tag: Some("2-0000000000000000"),
            kind: AirgapTxKind::Transfer,
            raw_tx_hex: "0xabcd",
            signing_hash_hex: None,
        })
        .is_err());

        // Decode: spoofed tag even if checksum were recomputed for the spoofed tag
        let spoofed_tag = "1-0000000000000000";
        let forged_checksum =
            compute_envelope_checksum(1, spoofed_tag, AirgapTxKind::Transfer, "0xabcd", None)
                .unwrap();
        let forged_json = json!({
            "version": 1,
            "chainId": 1,
            "networkTag": spoofed_tag,
            "kind": "transfer",
            "rawTxHex": "0xabcd",
            "checksumHex": forged_checksum,
        })
        .to_string();
        let err = decode_airgap_tx_envelope(&forged_json, None).unwrap_err();
        assert!(
            err.to_string().contains("expected canonical tag"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expected_chain_id_mismatch_fails_closed() {
        let encoded = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::TESTNET,
            network_tag: None,
            kind: AirgapTxKind::Transfer,
            raw_tx_hex: "0xdeadbeef",
            signing_hash_hex: None,
        })
        .unwrap();

        let err = decode_airgap_tx_envelope(&encoded.encoded, Some(chain_id::MAINNET)).unwrap_err();
        assert!(
            err.to_string().contains("chainId mismatch"),
            "unexpected error: {err}"
        );

        // expected_chain_id = 0 also fails closed
        assert!(decode_airgap_tx_envelope(&encoded.encoded, Some(0)).is_err());
    }

    #[test]
    fn invalid_base64url_framing_version_and_hex_fail_closed() {
        // Empty / wrong prefix
        assert!(decode_airgap_tx_envelope("", None).is_err());
        assert!(decode_airgap_tx_envelope("   ", None).is_err());
        assert!(decode_airgap_tx_envelope("kvnc-tx:v2:e30", None).is_err());
        assert!(decode_airgap_tx_envelope("other:e30", None).is_err());

        // Invalid base64url: empty payload, len % 4 == 1, invalid chars, padding '=', non-canonical trailing bits
        assert!(decode_airgap_tx_envelope(AIRGAP_ENVELOPE_PREFIX, None).is_err());
        assert!(decode_airgap_tx_envelope(&format!("{AIRGAP_ENVELOPE_PREFIX}a"), None).is_err());
        assert!(
            decode_airgap_tx_envelope(&format!("{AIRGAP_ENVELOPE_PREFIX}!!!not-b64!!!"), None)
                .is_err()
        );
        assert!(decode_airgap_tx_envelope(&format!("{AIRGAP_ENVELOPE_PREFIX}e30="), None).is_err());
        // 'AB' has trailing bits 0x01 != 0 for rem == 2
        assert!(base64url_decode("AB").is_err());
        // 'AAB' has trailing bits 0x01 != 0 for rem == 3
        assert!(base64url_decode("AAB").is_err());
        // Invalid UTF-8 bytes inside valid base64url (0xff 0xfe)
        let invalid_utf8 = format!(
            "{AIRGAP_ENVELOPE_PREFIX}{}",
            base64url_encode(&[0xff, 0xfe])
        );
        assert!(decode_airgap_tx_envelope(&invalid_utf8, None).is_err());

        // Unsupported version
        let valid = encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: chain_id::MAINNET,
            network_tag: None,
            kind: AirgapTxKind::Raw,
            raw_tx_hex: "0x0102",
            signing_hash_hex: None,
        })
        .unwrap();
        let mut wrong_ver = serde_json::to_value(&valid.envelope).unwrap();
        wrong_ver["version"] = json!(2);
        assert!(decode_airgap_tx_envelope(&wrong_ver.to_string(), None).is_err());

        // Invalid encode inputs: chainId 0, empty hex, odd hex, bad signing hash
        assert!(encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: 0,
            network_tag: None,
            kind: AirgapTxKind::Raw,
            raw_tx_hex: "0x01",
            signing_hash_hex: None,
        })
        .is_err());
        assert!(encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: 1,
            network_tag: None,
            kind: AirgapTxKind::Raw,
            raw_tx_hex: "0x",
            signing_hash_hex: None,
        })
        .is_err());
        assert!(encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: 1,
            network_tag: None,
            kind: AirgapTxKind::Raw,
            raw_tx_hex: "0xabc",
            signing_hash_hex: None,
        })
        .is_err());
        assert!(encode_airgap_tx_envelope(EncodeAirgapTxEnvelopeInput {
            chain_id: 1,
            network_tag: None,
            kind: AirgapTxKind::Raw,
            raw_tx_hex: "0xabcd",
            signing_hash_hex: Some("0x1234"),
        })
        .is_err());

        // run_encode requires chain_id
        let err = run_encode(
            TxEnvelopeEncodeArgs {
                raw_tx_hex: "0xabcd".to_string(),
                kind: AirgapTxKind::Raw,
                network_tag: None,
                signing_hash: None,
            },
            None,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--chain-id is required"));
    }
}
