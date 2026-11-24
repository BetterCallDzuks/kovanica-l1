//! Native transaction types.

use crate::address::Address;
use crate::crypto::{PublicKey, Signature};
use crate::evidence::EquivocationEvidence;
use crate::hash::Hash;
use crate::signing::{SigningContext, TX_DOMAIN_TAG};
use serde::{Deserialize, Serialize};

/// Kind of native transaction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TransactionKind {
    /// Simple transfer of KVNC.
    Transfer {
        /// Recipient address.
        to: Address,
        /// Amount in base units.
        amount: u64,
    },
    /// Stake tokens (self-stake for validator).
    Stake {
        /// Amount to stake in base units.
        amount: u64,
    },
    /// Unstake tokens (begin unbonding).
    Unstake {
        /// Amount to unstake in base units.
        amount: u64,
    },
    /// Delegate stake to a validator.
    Delegate {
        /// Validator address to delegate to.
        validator: Address,
        /// Amount to delegate in base units.
        amount: u64,
    },
    /// Claim delegation rewards.
    ClaimRewards {
        /// Validator whose rewards to claim (optional, claims all if None).
        validator: Option<Address>,
    },
    /// Deploy a WASM contract.
    Deploy {
        /// WASM bytecode.
        code: Vec<u8>,
        // init args later
    },
    /// Call a WASM contract.
    Call {
        /// Contract address.
        contract: Address,
        /// Native KVNC (base units) transferred to the contract with the call
        /// (`0` when unused). Part of signature format v1.
        value: u64,
        /// Method name to call.
        method: String,
        /// Encoded arguments.
        args: Vec<u8>,
        /// Gas limit for execution.
        gas_limit: u64,
    },
    /// Bond KVNC and register a light-node VRF key.
    ///
    /// This is not validator stake. It does not enter the committee.
    /// The registration becomes active at the next epoch.
    RegisterLightNode {
        /// ECVRF public key used for the light-node lottery.
        vrf_public_key: PublicKey,
        /// Bond in atoms. The execution layer enforces the minimum.
        stake: u64,
    },
    /// Leave the light-node set and start unbonding the bond.
    ExitLightNode,
    /// Submit an ECVRF witness for one light-node epoch.
    SubmitLightWitness {
        /// Epoch the witness is for (`epoch_for_height(committed_height)`, 2 400 heights ≈ 8 h).
        epoch: u64,
        /// 32-byte VRF hash.
        vrf_hash: [u8; 32],
        /// 96-byte VRF proof.
        #[serde(with = "crate::crypto::vrf_proof_bytes")]
        vrf_proof: [u8; 96],
    },
    /// Set validator commission in basis points (10000 = 100%).
    SetCommission {
        /// Validator address.
        validator: Address,
        /// Commission in basis points.
        commission_bps: u16,
    },
    /// Claim vested treasury funds to the treasury address.
    ClaimTreasury {
        /// Amount to claim in base units.
        amount: u64,
    },
    /// Report a validator that signed two different blocks in one round.
    ///
    /// Gated on [`crate::slashing_active_from`]; below the activation round
    /// the transaction fails deterministically. Self-authenticating: the
    /// sender's signature only authorises inclusion, the proof is the pair of
    /// headers inside `evidence`.
    Evidence {
        /// The two conflicting signed headers.
        evidence: EquivocationEvidence,
    },
    /// Atomic batch of actions executed all-or-nothing in one transaction (Wave A).
    Batch {
        /// Ordered actions (`1..=MAX_BATCH_ACTIONS`).
        actions: Vec<BatchAction>,
    },
    /// Sponsored (gasless) transaction where `fee_payer` co-signs and pays `tx.fee` (Wave A).
    Sponsored {
        /// Account paying `tx.fee`.
        fee_payer: Address,
        /// Ed25519 signature by `fee_payer` over `Transaction::sponsor_signing_hash`.
        fee_payer_signature: Signature,
        /// Inner transaction kind (must not be nested `Sponsored`).
        inner: Box<TransactionKind>,
    },
}

/// One action inside [`TransactionKind::Batch`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BatchAction {
    /// Native KVNC transfer.
    Transfer {
        /// Recipient address.
        to: Address,
        /// Amount in base units.
        amount: u64,
    },
    /// Deploy a WASM contract.
    Deploy {
        /// WASM bytecode.
        code: Vec<u8>,
    },
    /// Call a WASM contract. If `contract == Address::zero()`, targets the most
    /// recently deployed contract in the same batch (`Deploy + token_create` / `rwa_create`).
    Call {
        /// Target contract address (or `Address::zero()` for the previous deploy in this batch).
        contract: Address,
        /// Attached native KVNC in base units.
        value: u64,
        /// Contract entry point name.
        method: String,
        /// Encoded arguments.
        args: Vec<u8>,
        /// Gas limit for execution.
        gas_limit: u64,
    },
}

/// 16-byte domain tag for sponsored transaction fee-payer co-signatures.
pub const SPONSOR_DOMAIN_TAG: [u8; 16] = *b"KVNC/sponsor/v1\0";

/// Full signed transaction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender address.
    pub sender: Address,
    /// Sender nonce (prevents replay).
    pub nonce: u64,
    /// Transaction kind (transfer, stake, call, etc.).
    pub kind: TransactionKind,
    /// Fee in base units.
    pub fee: u64,
    /// Ed25519 signature over the transaction hash.
    pub signature: Signature,
    /// Cached hash of the transaction.
    pub hash: Hash,
}

impl Transaction {
    /// Return the cached transaction hash.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// Compute the signing hash for this transaction (excluding signature),
    /// signature format **v1** (`docs/SIGNATURE_FORMAT.md` §2).
    ///
    /// Preimage: `"KVNC/tx/v1"` 16-byte tag, `ctx.chain_id` u64 LE, sender,
    /// nonce, kind, fee; hashed with BLAKE3 keyed by [`Hash::DOMAIN_TX`].
    /// `ctx.epoch` is not part of transactions.
    pub fn signing_hash(&self, ctx: &SigningContext) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&TX_DOMAIN_TAG);
        data.extend_from_slice(&ctx.chain_id.to_le_bytes());
        data.extend_from_slice(&self.sender.0);
        data.extend_from_slice(&self.nonce.to_le_bytes());
        encode_kind_into(&self.kind, &mut data);
        data.extend_from_slice(&self.fee.to_le_bytes());
        Hash::new_keyed(Hash::DOMAIN_TX, &data)
    }

    /// Returns the account responsible for paying `self.fee` (`fee_payer` for
    /// [`TransactionKind::Sponsored`], otherwise `self.sender`).
    pub fn fee_payer(&self) -> Address {
        match &self.kind {
            TransactionKind::Sponsored { fee_payer, .. } => *fee_payer,
            _ => self.sender,
        }
    }

    /// Domain-separated hash signed by `fee_payer` for [`TransactionKind::Sponsored`].
    /// Returns `None` for non-sponsored transactions.
    pub fn sponsor_signing_hash(&self, ctx: &SigningContext) -> Option<Hash> {
        let TransactionKind::Sponsored { fee_payer, .. } = &self.kind else {
            return None;
        };
        let tx_hash = self.signing_hash(ctx);
        let mut data = Vec::with_capacity(16 + 8 + 32 + 32 + 8);
        data.extend_from_slice(&SPONSOR_DOMAIN_TAG);
        data.extend_from_slice(&ctx.chain_id.to_le_bytes());
        data.extend_from_slice(&tx_hash.0);
        data.extend_from_slice(&fee_payer.0);
        data.extend_from_slice(&self.fee.to_le_bytes());
        Some(Hash::new_keyed(Hash::DOMAIN_TX, &data))
    }

    /// Verify the transaction signature against the sender's public key
    /// (and against `fee_payer` for [`TransactionKind::Sponsored`]).
    pub fn verify_signature(&self, ctx: &SigningContext) -> bool {
        // The sender address is the public key (32 bytes)
        let public_key = crate::crypto::PublicKey(self.sender.0);
        if !self
            .signature
            .verify(&self.signing_hash(ctx).0, &public_key)
        {
            return false;
        }
        if let TransactionKind::Sponsored {
            fee_payer,
            fee_payer_signature,
            inner,
        } = &self.kind
        {
            // Disallow nested Sponsored transactions.
            if matches!(inner.as_ref(), TransactionKind::Sponsored { .. }) {
                return false;
            }
            let Some(sponsor_hash) = self.sponsor_signing_hash(ctx) else {
                return false;
            };
            let sponsor_pk = crate::crypto::PublicKey(fee_payer.0);
            if !fee_payer_signature.verify(&sponsor_hash.0, &sponsor_pk) {
                return false;
            }
        }
        true
    }
}

fn encode_kind_into(kind: &TransactionKind, data: &mut Vec<u8>) {
    match kind {
        TransactionKind::Transfer { to, amount } => {
            data.push(0);
            data.extend_from_slice(&to.0);
            data.extend_from_slice(&amount.to_le_bytes());
        }
        TransactionKind::Stake { amount } => {
            data.push(1);
            data.extend_from_slice(&amount.to_le_bytes());
        }
        TransactionKind::Unstake { amount } => {
            data.push(2);
            data.extend_from_slice(&amount.to_le_bytes());
        }
        TransactionKind::Delegate { validator, amount } => {
            data.push(5);
            data.extend_from_slice(&validator.0);
            data.extend_from_slice(&amount.to_le_bytes());
        }
        TransactionKind::ClaimRewards { validator } => {
            data.push(6);
            if let Some(v) = validator {
                data.push(1);
                data.extend_from_slice(&v.0);
            } else {
                data.push(0);
            }
        }
        TransactionKind::Deploy { code } => {
            data.push(3);
            data.extend_from_slice(&(code.len() as u64).to_le_bytes());
            data.extend_from_slice(code);
        }
        TransactionKind::Call {
            contract,
            value,
            method,
            args,
            gas_limit,
        } => {
            data.push(4);
            data.extend_from_slice(&contract.0);
            data.extend_from_slice(&value.to_le_bytes());
            data.extend_from_slice(&(method.len() as u64).to_le_bytes());
            data.extend_from_slice(method.as_bytes());
            data.extend_from_slice(&(args.len() as u64).to_le_bytes());
            data.extend_from_slice(args);
            data.extend_from_slice(&gas_limit.to_le_bytes());
        }
        TransactionKind::RegisterLightNode {
            vrf_public_key,
            stake,
        } => {
            data.push(7);
            data.extend_from_slice(&vrf_public_key.0);
            data.extend_from_slice(&stake.to_le_bytes());
        }
        TransactionKind::ExitLightNode => {
            data.push(8);
        }
        TransactionKind::SubmitLightWitness {
            epoch,
            vrf_hash,
            vrf_proof,
        } => {
            data.push(9);
            data.extend_from_slice(&epoch.to_le_bytes());
            data.extend_from_slice(vrf_hash);
            data.extend_from_slice(vrf_proof);
        }
        TransactionKind::SetCommission {
            validator,
            commission_bps,
        } => {
            data.push(10);
            data.extend_from_slice(&validator.0);
            data.extend_from_slice(&commission_bps.to_le_bytes());
        }
        TransactionKind::ClaimTreasury { amount } => {
            data.push(11);
            data.extend_from_slice(&amount.to_le_bytes());
        }
        TransactionKind::Evidence { evidence } => {
            data.push(12);
            for header in [&evidence.header_a, &evidence.header_b] {
                data.extend_from_slice(&header.author.0);
                data.extend_from_slice(&header.round.to_le_bytes());
                data.extend_from_slice(&header.digest.0);
                data.extend_from_slice(&header.signature.0);
            }
        }
        TransactionKind::Batch { actions } => {
            data.push(13);
            data.extend_from_slice(&(actions.len() as u64).to_le_bytes());
            for action in actions {
                match action {
                    BatchAction::Transfer { to, amount } => {
                        data.push(0);
                        data.extend_from_slice(&to.0);
                        data.extend_from_slice(&amount.to_le_bytes());
                    }
                    BatchAction::Deploy { code } => {
                        data.push(1);
                        data.extend_from_slice(&(code.len() as u64).to_le_bytes());
                        data.extend_from_slice(code);
                    }
                    BatchAction::Call {
                        contract,
                        value,
                        method,
                        args,
                        gas_limit,
                    } => {
                        data.push(2);
                        data.extend_from_slice(&contract.0);
                        data.extend_from_slice(&value.to_le_bytes());
                        data.extend_from_slice(&(method.len() as u64).to_le_bytes());
                        data.extend_from_slice(method.as_bytes());
                        data.extend_from_slice(&(args.len() as u64).to_le_bytes());
                        data.extend_from_slice(args);
                        data.extend_from_slice(&gas_limit.to_le_bytes());
                    }
                }
            }
        }
        TransactionKind::Sponsored {
            fee_payer,
            fee_payer_signature: _,
            inner,
        } => {
            data.push(14);
            data.extend_from_slice(&fee_payer.0);
            encode_kind_into(inner, data);
        }
    }
}

impl TransactionKind {
    /// Whether this kind is a validator-staking operation.
    ///
    /// The five staking kinds (`Stake`, `Unstake`, `Delegate`, `ClaimRewards`,
    /// `SetCommission`) are the ones that mutate validator stake, delegation,
    /// commission or move funds into unbonding. They are all refused on hybrid
    /// PoW + GHOSTDAG chains — see [`hybrid_refuses_stake_kind`].
    ///
    /// [`TransactionKind::RegisterLightNode`] / `ExitLightNode` are a separate
    /// light-node bond and are deliberately *not* included here.
    pub fn is_stake_kind(&self) -> bool {
        match self {
            TransactionKind::Stake { .. }
            | TransactionKind::Unstake { .. }
            | TransactionKind::Delegate { .. }
            | TransactionKind::ClaimRewards { .. }
            | TransactionKind::SetCommission { .. } => true,
            TransactionKind::Sponsored { inner, .. } => inner.is_stake_kind(),
            _ => false,
        }
    }
}

/// Why a staking transaction was refused on a hybrid chain.
pub const HYBRID_STAKE_REFUSAL: &str =
    "Staking transactions are not supported on hybrid PoW + GHOSTDAG chains";

/// Whether `kind` must be refused on the chain `chain_id`.
///
/// Hybrid chains (mainnet `1` and the public testnet `2`) order blocks with
/// GHOSTDAG and mine them with KovanicaHash PoW. Stake is not part of their
/// consensus, so the five staking kinds fail closed there rather than
/// half-applying. Non-hybrid chains (`3`, devnet) keep their existing staking
/// behaviour.
pub fn hybrid_refuses_stake_kind(chain_id: u64, kind: &TransactionKind) -> bool {
    crate::signing::chain_id::is_hybrid(chain_id) && kind.is_stake_kind()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    const CTX: SigningContext = SigningContext::new(2);

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sender() -> Address {
        Address(key().verifying_key().to_bytes())
    }

    fn tx(nonce: u64, kind: TransactionKind, fee: u64) -> Transaction {
        Transaction {
            sender: sender(),
            nonce,
            kind,
            fee,
            signature: Signature([0u8; 64]),
            hash: Hash::zero(),
        }
    }

    fn call(value: u64) -> Transaction {
        tx(
            6,
            TransactionKind::Call {
                contract: Address([0x33; 32]),
                value,
                method: "transfer".to_string(),
                args: vec![1, 2, 3],
                gas_limit: 100_000,
            },
            10,
        )
    }

    /// Check hash and the deterministic Ed25519 signature of a spec vector.
    fn check(tx: &Transaction, hash_hex: &str, sig_hex: &str) {
        let hash = tx.signing_hash(&CTX);
        assert_eq!(hash.to_hex(), hash_hex);
        use ed25519_dalek::Signer;
        let sig = key().sign(&hash.0);
        assert_eq!(hex::encode(sig.to_bytes()), sig_hex);
        let mut signed = tx.clone();
        signed.signature = Signature(sig.to_bytes());
        signed.hash = hash;
        assert!(signed.verify_signature(&CTX));
    }

    #[test]
    fn sender_matches_spec_key() {
        assert_eq!(
            hex::encode(sender().0),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
    }

    /// Golden vector T1 (Transfer) from `docs/SIGNATURE_FORMAT.md` §4.
    #[test]
    fn t1_transfer_golden() {
        let t = tx(
            5,
            TransactionKind::Transfer {
                to: Address([0x22; 32]),
                amount: 1_000_000,
            },
            1000,
        );
        check(
            &t,
            "0aae8c1832e09bf7da6f897d20b8bc6a017aaeefd50ea10015218a5c4a54c21d",
            "c24cd02ec98045a34e4b3102a1cafe70883a83763d5915528554b54797b139df1768cad71220e78bcb6702b109f37bb79513c1f768bacab4bf6e96f4e16cdf06",
        );
    }

    /// Golden vector T2 (Call, value = 0).
    #[test]
    fn t2_call_value_zero_golden() {
        check(
            &call(0),
            "e6ee05c494bc9197cdbf32f02558a36c0bf9f9ce92d7aceff99b65fa7ee3df92",
            "938f46f0d12493a4a9f6b12b6b2270d519b3704006db70f1406f844d51d79a9e89169816863e2c9d3a86680a01ca09593ca63d53c350b133156e3c5a73f2b904",
        );
    }

    /// Golden vector T3 (Call, value = 500).
    #[test]
    fn t3_call_value_golden() {
        check(
            &call(500),
            "616a96c5e4568b1e165670cd9c4afb4c8d2dd603dbf5b61142f7187a93d29df7",
            "48b532f19c6867e21907f829614864ca5cc54baf0177eab1dc4bbbc48b192d48507acdbd97731621c76498e33fb68ccfc37979cd0f17a959a14b94d159606c0b",
        );
    }

    #[test]
    fn chain_id_is_committed() {
        let t = call(0);
        let other = SigningContext::new(3);
        assert_ne!(t.signing_hash(&CTX), t.signing_hash(&other));
        let mut signed = t.clone();
        signed.signature =
            Signature(ed25519_dalek::Signer::sign(&key(), &t.signing_hash(&CTX).0).to_bytes());
        assert!(signed.verify_signature(&CTX));
        assert!(!signed.verify_signature(&other));
    }

    #[test]
    fn epoch_is_not_part_of_tx_hash() {
        let t = call(1);
        assert_eq!(t.signing_hash(&CTX), t.signing_hash(&CTX.with_epoch(9)));
    }

    #[test]
    fn call_value_is_committed() {
        assert_ne!(call(0).signing_hash(&CTX), call(1).signing_hash(&CTX));
    }

    #[test]
    fn light_node_kinds_use_signing_tags_7_8_and_9() {
        let vrf = crate::PublicKey([0x44; 32]);
        let register = tx(
            1,
            TransactionKind::RegisterLightNode {
                vrf_public_key: vrf,
                stake: 100,
            },
            2,
        );
        let exit = tx(1, TransactionKind::ExitLightNode, 2);
        let witness = tx(
            1,
            TransactionKind::SubmitLightWitness {
                epoch: 4,
                vrf_hash: [5u8; 32],
                vrf_proof: [6u8; 96],
            },
            2,
        );
        assert_eq!(
            register.signing_hash(&CTX),
            preimage(1, 7, &register_body())
        );
        assert_eq!(exit.signing_hash(&CTX), preimage(1, 8, &[]));
        assert_eq!(witness.signing_hash(&CTX), preimage(1, 9, &witness_body()));
        assert_ne!(register.signing_hash(&CTX), exit.signing_hash(&CTX));

        fn register_body() -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&[0x44; 32]);
            body.extend_from_slice(&100u64.to_le_bytes());
            body
        }
        fn witness_body() -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&4u64.to_le_bytes());
            body.extend_from_slice(&[5u8; 32]);
            body.extend_from_slice(&[6u8; 96]);
            body
        }
        fn preimage(nonce: u64, tag: u8, body: &[u8]) -> Hash {
            let mut data = Vec::new();
            data.extend_from_slice(&TX_DOMAIN_TAG);
            data.extend_from_slice(&CTX.chain_id.to_le_bytes());
            data.extend_from_slice(&sender().0);
            data.extend_from_slice(&nonce.to_le_bytes());
            data.push(tag);
            data.extend_from_slice(body);
            data.extend_from_slice(&2u64.to_le_bytes());
            Hash::new_keyed(Hash::DOMAIN_TX, &data)
        }
    }

    #[test]
    fn tx_and_vote_domains_are_disjoint() {
        assert_ne!(
            crate::signing::TX_DOMAIN_TAG,
            crate::signing::VOTE_DOMAIN_TAG
        );
    }

    #[test]
    fn batch_and_sponsored_signing_and_verification() {
        use ed25519_dalek::Signer;
        let sponsor_key = SigningKey::from_bytes(&[9u8; 32]);
        let sponsor_addr = Address(sponsor_key.verifying_key().to_bytes());

        // 1. Atomic Batch tx
        let mut batch_tx = tx(
            1,
            TransactionKind::Batch {
                actions: vec![
                    BatchAction::Transfer {
                        to: Address([0x11; 32]),
                        amount: 500,
                    },
                    BatchAction::Transfer {
                        to: Address([0x22; 32]),
                        amount: 250,
                    },
                ],
            },
            100,
        );
        let bh = batch_tx.signing_hash(&CTX);
        batch_tx.signature = Signature(key().sign(&bh.0).to_bytes());
        batch_tx.hash = bh;
        assert!(batch_tx.verify_signature(&CTX));
        assert_eq!(batch_tx.fee_payer(), sender());

        // 2. Sponsored (gasless) tx
        let mut sponsored_tx = tx(
            2,
            TransactionKind::Sponsored {
                fee_payer: sponsor_addr,
                fee_payer_signature: Signature([0u8; 64]),
                inner: Box::new(TransactionKind::Transfer {
                    to: Address([0x33; 32]),
                    amount: 100,
                }),
            },
            500,
        );
        let sh = sponsored_tx.signing_hash(&CTX);
        sponsored_tx.signature = Signature(key().sign(&sh.0).to_bytes());
        sponsored_tx.hash = sh;
        // Missing sponsor signature must fail verification
        assert!(!sponsored_tx.verify_signature(&CTX));

        // Co-sign with sponsor key
        let sponsor_hash = sponsored_tx.sponsor_signing_hash(&CTX).unwrap();
        let sponsor_sig = Signature(sponsor_key.sign(&sponsor_hash.0).to_bytes());
        if let TransactionKind::Sponsored {
            ref mut fee_payer_signature,
            ..
        } = sponsored_tx.kind
        {
            *fee_payer_signature = sponsor_sig;
        }
        assert!(sponsored_tx.verify_signature(&CTX));
        assert_eq!(sponsored_tx.fee_payer(), sponsor_addr);
    }

    #[test]
    fn stake_kinds_are_refused_only_on_hybrid_chains() {
        use crate::signing::chain_id;

        let kinds = [
            TransactionKind::Stake { amount: 1 },
            TransactionKind::Unstake { amount: 1 },
            TransactionKind::Delegate {
                validator: Address([1u8; 32]),
                amount: 1,
            },
            TransactionKind::ClaimRewards { validator: None },
            TransactionKind::SetCommission {
                validator: Address([1u8; 32]),
                commission_bps: 1,
            },
        ];
        for kind in &kinds {
            assert!(kind.is_stake_kind());
            for hybrid in [chain_id::MAINNET, chain_id::TESTNET] {
                assert!(hybrid_refuses_stake_kind(hybrid, kind));
            }
            assert!(!hybrid_refuses_stake_kind(chain_id::DEVNET, kind));
        }

        // Non-staking kinds are never refused, and the light-node bond is a
        // separate product, not validator stake.
        let others = [
            TransactionKind::Transfer {
                to: Address([1u8; 32]),
                amount: 1,
            },
            TransactionKind::RegisterLightNode {
                vrf_public_key: PublicKey([2u8; 32]),
                stake: 1,
            },
            TransactionKind::ExitLightNode,
            TransactionKind::ClaimTreasury { amount: 1 },
        ];
        for kind in &others {
            assert!(!kind.is_stake_kind());
            for chain in [chain_id::MAINNET, chain_id::TESTNET] {
                assert!(!hybrid_refuses_stake_kind(chain, kind));
            }
        }
    }
}
