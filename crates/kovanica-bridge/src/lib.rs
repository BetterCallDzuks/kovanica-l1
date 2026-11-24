//! Canonical Stablecoin & Cross-Chain Bridge Contract (Wave D #10).
//!
//! M-of-N threshold relayer bridge for bringing external assets (e.g. USDC/EURC
//! from Ethereum, Base, or Solana) onto Kovanica as wrapped KVP-102 tokens via
//! Wave A CPI (`token_mint`) and burning on outbound withdrawal.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use kovanica_common::events::{
    BRIDGE_DEPOSIT_ATTESTED, BRIDGE_INITIALIZED, BRIDGE_MINTED, BRIDGE_PAUSED,
    BRIDGE_WITHDRAW_REQUESTED,
};
use kovanica_common::{Address, Amount, ContractError, ContractResult, Host};

pub const STATE_KEY: &[u8] = b"kvnc/v1/bridge_state";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingDeposit {
    pub source_chain_id: u64,
    pub source_tx_hash: [u8; 32],
    pub recipient: Address,
    pub amount: Amount,
    pub approvals: BTreeSet<Address>,
    pub executed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BridgeState {
    pub admin: Address,
    pub wrapped_token: Address,
    pub asset_symbol: String,
    pub relayers: BTreeSet<Address>,
    pub threshold: u8,
    pub paused: bool,
    pub total_minted: Amount,
    pub total_burned: Amount,
    pub deposits: BTreeMap<[u8; 32], PendingDeposit>,
    pub next_withdraw_nonce: u64,
}

impl BridgeState {
    pub fn load(host: &impl Host) -> ContractResult<Self> {
        let bytes = host.storage_get(STATE_KEY).ok_or(ContractError::NotFound)?;
        bincode::deserialize(&bytes).map_err(|_| ContractError::Custom(2))
    }

    fn store(&self, host: &mut impl Host) -> ContractResult<()> {
        let bytes = bincode::serialize(self).map_err(|_| ContractError::Custom(1))?;
        host.storage_set(STATE_KEY, &bytes);
        Ok(())
    }
}

/// Deterministic deposit ID preventing cross-chain replay attacks.
pub fn derive_deposit_id(
    source_chain_id: u64,
    source_tx_hash: &[u8; 32],
    recipient: &Address,
    amount: Amount,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(14 + 8 + 32 + 32 + 16);
    buf.extend_from_slice(b"kvnc:bridge:v1");
    buf.extend_from_slice(&source_chain_id.to_le_bytes());
    buf.extend_from_slice(source_tx_hash);
    buf.extend_from_slice(recipient);
    buf.extend_from_slice(&amount.to_le_bytes());
    kovanica_common::hash(&buf)
}

pub struct Bridge;

impl Bridge {
    /// Initialize a new threshold bridge bound to a KVP-102 wrapped token contract.
    pub fn init(
        host: &mut impl Host,
        wrapped_token: Address,
        asset_symbol: String,
        relayers: Vec<Address>,
        threshold: u8,
    ) -> ContractResult<()> {
        if host.storage_get(STATE_KEY).is_some() {
            return Err(ContractError::AlreadyExists);
        }
        if asset_symbol.is_empty() || relayers.is_empty() {
            return Err(ContractError::InvalidInput);
        }
        let relayer_set: BTreeSet<Address> = relayers.into_iter().collect();
        if threshold == 0 || usize::from(threshold) > relayer_set.len() {
            return Err(ContractError::InvalidInput);
        }
        let state = BridgeState {
            admin: host.caller(),
            wrapped_token,
            asset_symbol,
            relayers: relayer_set,
            threshold,
            paused: false,
            total_minted: 0,
            total_burned: 0,
            deposits: BTreeMap::new(),
            next_withdraw_nonce: 0,
        };
        state.store(host)?;
        host.emit_event(BRIDGE_INITIALIZED, &wrapped_token);
        Ok(())
    }

    /// Relayer attests an inbound deposit from `source_chain_id`. Once `threshold`
    /// unique relayers attest the same deposit, mints wrapped KVP-102 tokens via CPI.
    pub fn attest_mint(
        host: &mut impl Host,
        source_chain_id: u64,
        source_tx_hash: [u8; 32],
        recipient: Address,
        amount: Amount,
    ) -> ContractResult<bool> {
        if amount == 0 {
            return Err(ContractError::InvalidInput);
        }
        let mut state = BridgeState::load(host)?;
        if state.paused {
            return Err(ContractError::Paused);
        }
        let caller = host.caller();
        if !state.relayers.contains(&caller) {
            return Err(ContractError::Unauthorized);
        }

        let deposit_id = derive_deposit_id(source_chain_id, &source_tx_hash, &recipient, amount);
        let wrapped_token = state.wrapped_token;
        let threshold = usize::from(state.threshold);

        let dep = state
            .deposits
            .entry(deposit_id)
            .or_insert_with(|| PendingDeposit {
                source_chain_id,
                source_tx_hash,
                recipient,
                amount,
                approvals: BTreeSet::new(),
                executed: false,
            });
        if dep.executed {
            return Err(ContractError::AlreadyExists);
        }
        if !dep.approvals.insert(caller) {
            return Err(ContractError::AlreadyExists);
        }
        let reached_quorum = dep.approvals.len() >= threshold;
        if reached_quorum {
            dep.executed = true;
            state.total_minted = state
                .total_minted
                .checked_add(amount)
                .ok_or(ContractError::Overflow)?;
        }
        state.store(host)?;
        host.emit_event(BRIDGE_DEPOSIT_ATTESTED, &deposit_id);

        if reached_quorum {
            let mint_args =
                bincode::serialize(&(recipient, amount)).map_err(|_| ContractError::Custom(1))?;
            host.call_contract(&wrapped_token, "token_mint", &mint_args, 0)?;
            host.emit_event(BRIDGE_MINTED, &deposit_id);
        }
        Ok(reached_quorum)
    }

    /// Request an outbound withdrawal to `dest_chain_id` / `dest_address`.
    /// Records the burn intent and emits `BRIDGE_WITHDRAW_REQUESTED` for relayers.
    pub fn request_withdraw(
        host: &mut impl Host,
        dest_chain_id: u64,
        dest_address: Vec<u8>,
        amount: Amount,
    ) -> ContractResult<u64> {
        if amount == 0 || dest_address.is_empty() || dest_address.len() > 64 {
            return Err(ContractError::InvalidInput);
        }
        let mut state = BridgeState::load(host)?;
        if state.paused {
            return Err(ContractError::Paused);
        }
        let nonce = state.next_withdraw_nonce;
        state.next_withdraw_nonce = state
            .next_withdraw_nonce
            .checked_add(1)
            .ok_or(ContractError::Overflow)?;
        state.total_burned = state
            .total_burned
            .checked_add(amount)
            .ok_or(ContractError::Overflow)?;
        state.store(host)?;

        let mut payload = Vec::with_capacity(8 + 8 + 16 + dest_address.len());
        payload.extend_from_slice(&nonce.to_le_bytes());
        payload.extend_from_slice(&dest_chain_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&dest_address);
        host.emit_event(BRIDGE_WITHDRAW_REQUESTED, &payload);
        Ok(nonce)
    }

    /// Emergency pause/unpause by bridge admin.
    pub fn set_paused(host: &mut impl Host, paused: bool) -> ContractResult<()> {
        let mut state = BridgeState::load(host)?;
        if host.caller() != state.admin {
            return Err(ContractError::Unauthorized);
        }
        state.paused = paused;
        state.store(host)?;
        host.emit_event(BRIDGE_PAUSED, &[u8::from(paused)]);
        Ok(())
    }

    pub fn decode_state(bytes: &[u8]) -> Option<BridgeState> {
        bincode::deserialize(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use kovanica_common::MemHost;

    struct BridgeTestHost {
        inner: MemHost,
        minted: Vec<(Address, Vec<u8>)>,
    }

    impl Host for BridgeTestHost {
        fn caller(&self) -> Address {
            self.inner.caller()
        }
        fn contract_address(&self) -> Address {
            self.inner.contract_address()
        }
        fn block_height(&self) -> u64 {
            self.inner.block_height()
        }
        fn timestamp(&self) -> u64 {
            self.inner.timestamp()
        }
        fn balance_of(&self, addr: &Address) -> Amount {
            self.inner.balance_of(addr)
        }
        fn transfer(&mut self, from: &Address, to: &Address, amount: Amount) -> ContractResult<()> {
            self.inner.transfer(from, to, amount)
        }
        fn emit_event(&mut self, topic: &[u8], data: &[u8]) {
            self.inner.emit_event(topic, data)
        }
        fn storage_get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.storage_get(key)
        }
        fn storage_set(&mut self, key: &[u8], value: &[u8]) {
            self.inner.storage_set(key, value)
        }
        fn call_contract(
            &mut self,
            target: &Address,
            method: &str,
            args: &[u8],
            _value: Amount,
        ) -> ContractResult<Vec<u8>> {
            assert_eq!(method, "token_mint");
            self.minted.push((*target, args.to_vec()));
            Ok(Vec::new())
        }
    }

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    #[test]
    fn threshold_relayer_attestation_mints_once_and_prevents_replay() {
        let mut host = BridgeTestHost {
            inner: MemHost::new(addr(1), addr(95)),
            minted: Vec::new(),
        };
        Bridge::init(
            &mut host,
            addr(80),
            "wUSDC".into(),
            vec![addr(10), addr(11), addr(12)],
            2,
        )
        .unwrap();

        // First attestation: quorum not yet met
        host.inner.set_caller(addr(10));
        assert!(!Bridge::attest_mint(&mut host, 1, [0xAA; 32], addr(2), 1_000_000).unwrap());
        assert!(host.minted.is_empty());

        // Duplicate attestation by same relayer rejected
        assert_eq!(
            Bridge::attest_mint(&mut host, 1, [0xAA; 32], addr(2), 1_000_000),
            Err(ContractError::AlreadyExists)
        );

        // Second unique relayer reaches 2-of-3 quorum -> mints via CPI
        host.inner.set_caller(addr(11));
        assert!(Bridge::attest_mint(&mut host, 1, [0xAA; 32], addr(2), 1_000_000).unwrap());
        assert_eq!(host.minted.len(), 1);
        assert_eq!(host.minted[0].0, addr(80));

        // Third relayer replay rejected
        host.inner.set_caller(addr(12));
        assert_eq!(
            Bridge::attest_mint(&mut host, 1, [0xAA; 32], addr(2), 1_000_000),
            Err(ContractError::AlreadyExists)
        );

        // Outbound withdrawal request
        host.inner.set_caller(addr(2));
        let nonce = Bridge::request_withdraw(&mut host, 1, vec![0xDE, 0xAD], 500_000).unwrap();
        assert_eq!(nonce, 0);
    }
}
