#![deny(unsafe_code)]

//! Transparent transaction preview and sighash binding.
//!
//! Enforces that the caller (webview or mobile UI) submits human-interpretable fields,
//! and the Rust core deterministically constructs the v1 preimage, computes the
//! keyed BLAKE3 hash, and signs it.

use kovanica_types::signing::TX_DOMAIN_TAG;
use kovanica_types::transaction::{Transaction, TransactionKind};
use kovanica_types::{Address, Hash, PublicKey, SigningKey};
use serde::{Deserialize, Serialize};

use crate::error::WalletError;

/// Human-readable transaction preview strictly bound to the signing preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxPreview {
    /// Sender address (canonical PRO-21).
    pub sender: Address,
    /// Recipient address (canonical PRO-21).
    pub to: Address,
    /// Transfer amount in atoms (1 KVNC = 10^9 atoms).
    pub amount: u64,
    /// Gas / network fee in atoms.
    pub fee: u64,
    /// Sequential account nonce.
    pub nonce: u64,
    /// Target network chain ID.
    pub chain_id: u64,
}

impl TxPreview {
    /// Construct a new transfer preview.
    pub fn new(
        sender: Address,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Self {
        Self {
            sender,
            to,
            amount,
            fee,
            nonce,
            chain_id,
        }
    }

    /// Formatted KVNC display string with 9 decimal places (e.g. "1.500000000 KVNC").
    pub fn display_amount_kvnc(&self) -> String {
        format_atoms_kvnc(self.amount)
    }

    /// Formatted fee string in KVNC.
    pub fn display_fee_kvnc(&self) -> String {
        format_atoms_kvnc(self.fee)
    }

    /// Construct the deterministic v1 little-endian signing preimage.
    ///
    /// Layout:
    /// - `DomainTag16("KVNC/tx/v1")` (16 bytes)
    /// - `chain_id` (8 bytes LE)
    /// - `sender` pubkey (32 bytes)
    /// - `nonce` (8 bytes LE)
    /// - `kind`: Transfer tag `0` (1 byte), `to` (32 bytes), `amount` (8 bytes LE)
    /// - `fee` (8 bytes LE)
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(16 + 8 + 32 + 8 + 1 + 32 + 8 + 8);
        data.extend_from_slice(&TX_DOMAIN_TAG);
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.sender.0);
        data.extend_from_slice(&self.nonce.to_le_bytes());
        // Transfer kind: signing tag 0
        data.push(0);
        data.extend_from_slice(&self.to.0);
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.extend_from_slice(&self.fee.to_le_bytes());
        data
    }

    /// Compute the 32-byte signing hash using BLAKE3 keyed with `pad32("KVNC-TX-v1")`.
    pub fn signing_hash(&self) -> Hash {
        Hash::new_keyed(Hash::DOMAIN_TX, self.signing_preimage())
    }

    /// Sign the preview with an Ed25519 signing key, asserting that the key matches the sender.
    /// Returns the verified [`Transaction`] and the raw broadcast hex string (lowercase, no `0x`).
    pub fn sign(&self, signing_key: &SigningKey) -> Result<(Transaction, String), WalletError> {
        let derived_pk = PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        if derived_pk.0 != self.sender.0 {
            return Err(WalletError::Signing(format!(
                "signing key public key {} does not match preview sender {}",
                hex::encode(derived_pk.as_bytes()),
                self.sender
            )));
        }

        let sighash = self.signing_hash();
        let signature = kovanica_crypto::sign(signing_key, &sighash.0);

        let tx = Transaction {
            sender: self.sender,
            nonce: self.nonce,
            kind: TransactionKind::Transfer {
                to: self.to,
                amount: self.amount,
            },
            fee: self.fee,
            signature,
            hash: sighash,
        };

        // Wire broadcast encoding matching packages/signer/src/tx.ts
        let raw_hex = encode_broadcast_tx(&tx, &sighash)?;
        Ok((tx, raw_hex))
    }
}

/// Format atoms into decimal KVNC string without floating-point math.
pub fn format_atoms_kvnc(atoms: u64) -> String {
    let whole = atoms / 1_000_000_000;
    let fraction = atoms % 1_000_000_000;
    format!("{}.{:09} KVNC", whole, fraction)
}

/// Encode a signed transaction for broadcast over RPC `kovanica_sendRawTransaction`.
///
/// Produces the canonical `bincode 1.x` little-endian fixint binary wire layout
/// decoded by `kovanica-rpc`:
/// - `sender`: 32 bytes
/// - `nonce`: 8 bytes LE (`u64`)
/// - `kind`: 4-byte `u32` LE enum discriminant (matching `TransactionKind` variant
///   order in `kovanica-types`) followed by the variant's fields in declaration order:
///   - `Transfer` (`0`): `to` (32 bytes), `amount` (`u64` LE)
///   - `Deploy` (`5`): `code.len()` (`u64` LE), `code` bytes
///   - `Call` (`6`): `contract` (32 bytes), `value` (`u64` LE), `method.len()` (`u64` LE),
///     `method` UTF-8 bytes, `args.len()` (`u64` LE), `args` bytes, `gas_limit` (`u64` LE)
///   - `RegisterLightNode` (`7`): `vrf_public_key` (32 bytes), `stake` (`u64` LE)
///   - `ExitLightNode` (`8`): no payload bytes
/// - `fee`: 8 bytes LE (`u64`)
/// - `signature`: 8-byte LE length (`64u64`) + 64 signature bytes
/// - `hash`: 32 bytes
pub fn encode_broadcast_tx(tx: &Transaction, hash: &Hash) -> Result<String, WalletError> {
    let payload_cap = match &tx.kind {
        TransactionKind::Transfer { .. } => 32 + 8,
        TransactionKind::Deploy { code } => 8 + code.len(),
        TransactionKind::Call { method, args, .. } => {
            32 + 8 + 8 + method.len() + 8 + args.len() + 8
        }
        TransactionKind::RegisterLightNode { .. } => 32 + 8,
        TransactionKind::ExitLightNode => 0,
        other => {
            return Err(WalletError::Signing(format!(
                "encode_broadcast_tx does not support transaction kind {other:?}"
            )));
        }
    };

    let mut buf = Vec::with_capacity(32 + 8 + 4 + payload_cap + 8 + 8 + 64 + 32);
    buf.extend_from_slice(&tx.sender.0);
    buf.extend_from_slice(&tx.nonce.to_le_bytes());

    match &tx.kind {
        TransactionKind::Transfer { to, amount } => {
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&to.0);
            buf.extend_from_slice(&amount.to_le_bytes());
        }
        TransactionKind::Deploy { code } => {
            buf.extend_from_slice(&5u32.to_le_bytes());
            buf.extend_from_slice(&(code.len() as u64).to_le_bytes());
            buf.extend_from_slice(code);
        }
        TransactionKind::Call {
            contract,
            value,
            method,
            args,
            gas_limit,
        } => {
            buf.extend_from_slice(&6u32.to_le_bytes());
            buf.extend_from_slice(&contract.0);
            buf.extend_from_slice(&value.to_le_bytes());
            buf.extend_from_slice(&(method.len() as u64).to_le_bytes());
            buf.extend_from_slice(method.as_bytes());
            buf.extend_from_slice(&(args.len() as u64).to_le_bytes());
            buf.extend_from_slice(args);
            buf.extend_from_slice(&gas_limit.to_le_bytes());
        }
        TransactionKind::RegisterLightNode {
            vrf_public_key,
            stake,
        } => {
            buf.extend_from_slice(&7u32.to_le_bytes());
            buf.extend_from_slice(&vrf_public_key.0);
            buf.extend_from_slice(&stake.to_le_bytes());
        }
        TransactionKind::ExitLightNode => {
            buf.extend_from_slice(&8u32.to_le_bytes());
        }
        _ => unreachable!("unsupported kinds rejected above"),
    }

    buf.extend_from_slice(&tx.fee.to_le_bytes());
    // Signature vector: u64 length prefix followed by 64 bytes
    buf.extend_from_slice(&64u64.to_le_bytes());
    buf.extend_from_slice(&tx.signature.0);
    buf.extend_from_slice(&hash.0);

    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::Options as _;
    use kovanica_types::signing::SigningContext;
    use kovanica_types::Signature;

    fn assert_canonical_broadcast_roundtrip(tx: &Transaction) {
        let raw_hex = encode_broadcast_tx(tx, &tx.hash).expect("encoding must succeed");
        assert!(!raw_hex.starts_with("0x"));
        let bytes = hex::decode(&raw_hex).expect("valid lowercase hex");

        // 1. Byte-for-byte identity with bincode::serialize (fixint LE).
        let expected = bincode::serialize(tx).expect("bincode serialize succeeds");
        assert_eq!(bytes, expected, "wire bytes must match bincode::serialize");

        // 2. Round-trip with standard bincode::deserialize.
        let decoded: Transaction =
            bincode::deserialize(&bytes).expect("bincode::deserialize must succeed");
        assert_eq!(&decoded, tx);

        // 3. Round-trip with the exact bounded options used by kovanica-rpc.
        let rpc_decoded: Transaction = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(bytes.len() as u64)
            .deserialize(&bytes)
            .expect("RPC bounded bincode deserialize must succeed");
        assert_eq!(&rpc_decoded, tx);
    }

    fn sign_test_tx(kind: TransactionKind, nonce: u64, fee: u64) -> Transaction {
        let sk = SigningKey::from_bytes(&[0x07u8; 32]);
        let sender = Address(sk.verifying_key().to_bytes());
        let mut tx = Transaction {
            sender,
            nonce,
            kind,
            fee,
            signature: Signature([0u8; 64]),
            hash: Hash::zero(),
        };
        let ctx = SigningContext::new(2);
        let sighash = tx.signing_hash(&ctx);
        tx.signature = kovanica_crypto::sign(&sk, &sighash.0);
        tx.hash = sighash;
        assert!(tx.verify_signature(&ctx));
        tx
    }

    #[test]
    fn format_atoms_tests() {
        assert_eq!(format_atoms_kvnc(1_000_000_000), "1.000000000 KVNC");
        assert_eq!(format_atoms_kvnc(500), "0.000000500 KVNC");
        assert_eq!(format_atoms_kvnc(0), "0.000000000 KVNC");
    }

    #[test]
    fn golden_vector_t1_acceptance() {
        // Acceptance vector T1 from specification:
        // raw seed 07×32, not HD
        // chain 2, nonce 5, to 22×32, amount 1000000, fee 1000
        // sender ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
        // hash 0aae8c1832e09bf7da6f897d20b8bc6a017aaeefd50ea10015218a5c4a54c21d
        let seed = [0x07u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = PublicKey::from_bytes(sk.verifying_key().to_bytes());
        assert_eq!(
            hex::encode(pk.0),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );

        let preview = TxPreview::new(Address(pk.0), Address([0x22u8; 32]), 1_000_000, 1_000, 5, 2);

        let sighash = preview.signing_hash();
        assert_eq!(
            hex::encode(sighash.0),
            "0aae8c1832e09bf7da6f897d20b8bc6a017aaeefd50ea10015218a5c4a54c21d"
        );

        let (tx, raw_hex) = preview.sign(&sk).expect("signing succeeds");
        assert!(tx.verify_signature(&SigningContext::new(2)));
        assert!(!raw_hex.starts_with("0x"));
        assert_eq!(
            hex::decode(&raw_hex).expect("valid hex"),
            bincode::serialize(&tx).expect("bincode serialize")
        );
    }

    #[test]
    fn encode_broadcast_tx_transfer_roundtrips() {
        let tx = sign_test_tx(
            TransactionKind::Transfer {
                to: Address([0x22u8; 32]),
                amount: 1_000_000,
            },
            5,
            1_000,
        );
        assert_canonical_broadcast_roundtrip(&tx);
    }

    #[test]
    fn encode_broadcast_tx_call_roundtrips() {
        let tx_with_value = sign_test_tx(
            TransactionKind::Call {
                contract: Address([0x33u8; 32]),
                value: 500,
                method: "transfer".to_string(),
                args: vec![1, 2, 3, 4],
                gas_limit: 100_000,
            },
            6,
            10,
        );
        assert_canonical_broadcast_roundtrip(&tx_with_value);

        let tx_empty = sign_test_tx(
            TransactionKind::Call {
                contract: Address([0x44u8; 32]),
                value: 0,
                method: String::new(),
                args: Vec::new(),
                gas_limit: 50_000,
            },
            7,
            25,
        );
        assert_canonical_broadcast_roundtrip(&tx_empty);
    }

    #[test]
    fn encode_broadcast_tx_deploy_roundtrips() {
        let tx = sign_test_tx(
            TransactionKind::Deploy {
                code: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            },
            8,
            5_000,
        );
        assert_canonical_broadcast_roundtrip(&tx);

        let tx_empty = sign_test_tx(TransactionKind::Deploy { code: Vec::new() }, 9, 1_000);
        assert_canonical_broadcast_roundtrip(&tx_empty);
    }

    #[test]
    fn encode_broadcast_tx_register_light_node_roundtrips() {
        let tx = sign_test_tx(
            TransactionKind::RegisterLightNode {
                vrf_public_key: PublicKey([0x55u8; 32]),
                stake: 10_000_000_000,
            },
            10,
            1_000,
        );
        assert_canonical_broadcast_roundtrip(&tx);
    }

    #[test]
    fn encode_broadcast_tx_exit_light_node_roundtrips() {
        let tx = sign_test_tx(TransactionKind::ExitLightNode, 11, 1_000);
        assert_canonical_broadcast_roundtrip(&tx);
    }

    #[test]
    fn encode_broadcast_tx_rejects_unsupported_variants_without_panicking() {
        let unsupported = [
            TransactionKind::Stake { amount: 1_000 },
            TransactionKind::Unstake { amount: 500 },
            TransactionKind::ClaimTreasury { amount: 42 },
        ];
        for kind in unsupported {
            let tx = Transaction {
                sender: Address([0x11u8; 32]),
                nonce: 1,
                kind,
                fee: 1_000,
                signature: Signature([0u8; 64]),
                hash: Hash([0u8; 32]),
            };
            let err = encode_broadcast_tx(&tx, &tx.hash)
                .expect_err("unsupported kind must return Err instead of panicking");
            assert!(
                err.to_string().contains("does not support"),
                "unexpected error message: {err}"
            );
        }
    }
}
