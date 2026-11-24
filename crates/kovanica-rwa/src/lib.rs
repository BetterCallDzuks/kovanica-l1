//! KVP-106 Real-World Asset (RWA) contract for Kovanica.
//!
//! Models compliant, issuer-controlled real-world assets (real estate, bonds,
//! invoices, commodities, funds, and other regulated assets) with:
//! - Deterministic `asset_id` derivation (`kvp106:rwa:v1 || issuer || class || unique_id || version`)
//! - On-chain metadata hash + IPFS/HTTPS URIs for legal and custody proofs
//! - Optional supply cap (`max_supply`, `0` = uncapped)
//! - Issuer-controlled minting, metadata updates, and per-account compliance freeze
//! - Holder-controlled transfers and burns (subject to freeze & pause checks)

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use kovanica_common::events::{
    RWA_BURN, RWA_CREATED, RWA_FROZEN, RWA_METADATA_UPDATED, RWA_MINT, RWA_TRANSFER,
};
use kovanica_common::{Address, Amount, ContractError, ContractResult, Host};

pub const STATE_KEY: &[u8] = b"kvnc/v1/rwa_state";
pub const MAX_URI_LEN: usize = 512;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_SYMBOL_LEN: usize = 32;
pub const MAX_UNIQUE_ID_LEN: usize = 128;

pub type AssetId = [u8; 32];

/// Valid KVP-106 asset classes.
pub const VALID_ASSET_CLASSES: &[&str] = &["RE", "BOND", "INVOICE", "COMMODITY", "FUND", "OTHER"];

/// Returns `true` if `asset_class` is one of the canonical KVP-106 asset classes.
pub fn is_valid_asset_class(asset_class: &str) -> bool {
    VALID_ASSET_CLASSES.contains(&asset_class)
}

/// Deterministically derive the 32-byte KVP-106 `asset_id` from issuer and asset parameters.
pub fn derive_asset_id(
    issuer: &Address,
    asset_class: &str,
    unique_id: &str,
    version: u32,
) -> AssetId {
    let mut buf = Vec::with_capacity(13 + 32 + asset_class.len() + unique_id.len() + 4 + 2);
    buf.extend_from_slice(b"kvp106:rwa:v1");
    buf.extend_from_slice(issuer);
    buf.push(0);
    buf.extend_from_slice(asset_class.as_bytes());
    buf.push(0);
    buf.extend_from_slice(unique_id.as_bytes());
    buf.extend_from_slice(&version.to_le_bytes());
    kovanica_common::hash(&buf)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RwaState {
    pub asset_id: AssetId,
    pub name: String,
    pub symbol: String,
    pub asset_class: String,
    pub unique_id: String,
    pub version: u32,
    pub jurisdiction: String,
    pub metadata_hash: [u8; 32],
    pub metadata_uri: String,
    pub legal_uri: String,
    pub custody_uri: String,
    pub issuer: Address,
    pub decimals: u8,
    pub max_supply: Amount,
    pub total_supply: Amount,
    pub paused: bool,
    pub balances: BTreeMap<Address, Amount>,
    pub frozen: BTreeMap<Address, bool>,
}

impl RwaState {
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

pub struct Rwa;

impl Rwa {
    /// Register/initialize a new KVP-106 RWA contract and optionally mint `initial_supply`
    /// to the issuer. Returns the deterministic 32-byte `asset_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        host: &mut impl Host,
        name: String,
        symbol: String,
        asset_class: String,
        unique_id: String,
        version: u32,
        jurisdiction: String,
        metadata_hash: [u8; 32],
        metadata_uri: String,
        legal_uri: String,
        custody_uri: String,
        decimals: u8,
        max_supply: Amount,
        initial_supply: Amount,
    ) -> ContractResult<AssetId> {
        if host.storage_get(STATE_KEY).is_some() {
            return Err(ContractError::AlreadyExists);
        }
        if name.is_empty()
            || name.len() > MAX_NAME_LEN
            || symbol.is_empty()
            || symbol.len() > MAX_SYMBOL_LEN
            || !is_valid_asset_class(&asset_class)
            || unique_id.is_empty()
            || unique_id.len() > MAX_UNIQUE_ID_LEN
            || version == 0
            || (!jurisdiction.is_empty() && jurisdiction.len() != 2)
            || metadata_uri.len() > MAX_URI_LEN
            || legal_uri.len() > MAX_URI_LEN
            || custody_uri.len() > MAX_URI_LEN
            || decimals > 18
        {
            return Err(ContractError::InvalidInput);
        }
        if max_supply > 0 && initial_supply > max_supply {
            return Err(ContractError::InvalidInput);
        }

        let issuer = host.caller();
        let asset_id = derive_asset_id(&issuer, &asset_class, &unique_id, version);
        let mut balances = BTreeMap::new();
        if initial_supply > 0 {
            balances.insert(issuer, initial_supply);
        }

        let state = RwaState {
            asset_id,
            name,
            symbol,
            asset_class,
            unique_id,
            version,
            jurisdiction,
            metadata_hash,
            metadata_uri,
            legal_uri,
            custody_uri,
            issuer,
            decimals,
            max_supply,
            total_supply: initial_supply,
            paused: false,
            balances,
            frozen: BTreeMap::new(),
        };
        state.store(host)?;
        host.emit_event(RWA_CREATED, &asset_id);
        Ok(asset_id)
    }

    /// Mint additional RWA units/shares to `to`. Issuer-only.
    pub fn mint(host: &mut impl Host, to: Address, amount: Amount) -> ContractResult<()> {
        if amount == 0 {
            return Err(ContractError::InvalidInput);
        }
        let mut state = RwaState::load(host)?;
        if host.caller() != state.issuer {
            return Err(ContractError::Unauthorized);
        }
        if state.paused || state.frozen.get(&to).copied().unwrap_or(false) {
            return Err(ContractError::Unauthorized);
        }
        let new_total = state
            .total_supply
            .checked_add(amount)
            .ok_or(ContractError::Overflow)?;
        if state.max_supply > 0 && new_total > state.max_supply {
            return Err(ContractError::Overflow);
        }
        let prev = state.balances.get(&to).copied().unwrap_or(0);
        let next = prev.checked_add(amount).ok_or(ContractError::Overflow)?;
        state.balances.insert(to, next);
        state.total_supply = new_total;
        state.store(host)?;
        host.emit_event(RWA_MINT, &state.asset_id);
        Ok(())
    }

    /// Transfer RWA units/shares from caller to `to`.
    pub fn transfer(host: &mut impl Host, to: Address, amount: Amount) -> ContractResult<()> {
        if amount == 0 {
            return Err(ContractError::InvalidInput);
        }
        let mut state = RwaState::load(host)?;
        let caller = host.caller();
        if state.paused
            || state.frozen.get(&caller).copied().unwrap_or(false)
            || state.frozen.get(&to).copied().unwrap_or(false)
        {
            return Err(ContractError::Unauthorized);
        }
        let from_bal = state.balances.get(&caller).copied().unwrap_or(0);
        if from_bal < amount {
            return Err(ContractError::InsufficientBalance);
        }
        let remaining = from_bal - amount;
        if remaining == 0 {
            state.balances.remove(&caller);
        } else {
            state.balances.insert(caller, remaining);
        }
        let to_bal = state.balances.get(&to).copied().unwrap_or(0);
        let next_to = to_bal.checked_add(amount).ok_or(ContractError::Overflow)?;
        state.balances.insert(to, next_to);
        state.store(host)?;
        host.emit_event(RWA_TRANSFER, &state.asset_id);
        Ok(())
    }

    /// Burn RWA units/shares held by the caller (e.g. redemption).
    pub fn burn(host: &mut impl Host, amount: Amount) -> ContractResult<()> {
        if amount == 0 {
            return Err(ContractError::InvalidInput);
        }
        let mut state = RwaState::load(host)?;
        let caller = host.caller();
        if state.paused || state.frozen.get(&caller).copied().unwrap_or(false) {
            return Err(ContractError::Unauthorized);
        }
        let bal = state.balances.get(&caller).copied().unwrap_or(0);
        if bal < amount {
            return Err(ContractError::InsufficientBalance);
        }
        let remaining = bal - amount;
        if remaining == 0 {
            state.balances.remove(&caller);
        } else {
            state.balances.insert(caller, remaining);
        }
        state.total_supply = state.total_supply.saturating_sub(amount);
        state.store(host)?;
        host.emit_event(RWA_BURN, &state.asset_id);
        Ok(())
    }

    /// Freeze or unfreeze an account for compliance enforcement. Issuer-only.
    pub fn freeze(host: &mut impl Host, account: Address, frozen: bool) -> ContractResult<()> {
        let mut state = RwaState::load(host)?;
        if host.caller() != state.issuer {
            return Err(ContractError::Unauthorized);
        }
        if frozen {
            state.frozen.insert(account, true);
        } else {
            state.frozen.remove(&account);
        }
        state.store(host)?;
        host.emit_event(RWA_FROZEN, &account);
        Ok(())
    }

    /// Update off-chain metadata hash and legal/custody URIs. Issuer-only.
    pub fn update_metadata(
        host: &mut impl Host,
        metadata_hash: [u8; 32],
        metadata_uri: String,
        legal_uri: String,
        custody_uri: String,
    ) -> ContractResult<()> {
        if metadata_uri.len() > MAX_URI_LEN
            || legal_uri.len() > MAX_URI_LEN
            || custody_uri.len() > MAX_URI_LEN
        {
            return Err(ContractError::InvalidInput);
        }
        let mut state = RwaState::load(host)?;
        if host.caller() != state.issuer {
            return Err(ContractError::Unauthorized);
        }
        state.metadata_hash = metadata_hash;
        state.metadata_uri = metadata_uri;
        state.legal_uri = legal_uri;
        state.custody_uri = custody_uri;
        state.store(host)?;
        host.emit_event(RWA_METADATA_UPDATED, &state.asset_id);
        Ok(())
    }

    pub fn balance_of(host: &impl Host, account: Address) -> ContractResult<Amount> {
        let state = RwaState::load(host)?;
        Ok(state.balances.get(&account).copied().unwrap_or(0))
    }

    pub fn is_frozen(host: &impl Host, account: Address) -> ContractResult<bool> {
        let state = RwaState::load(host)?;
        Ok(state.frozen.get(&account).copied().unwrap_or(false))
    }

    pub fn state_slot() -> [u8; 32] {
        kovanica_common::hash(STATE_KEY)
    }

    pub fn decode_state(bytes: &[u8]) -> Option<RwaState> {
        bincode::deserialize(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_common::MemHost;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    fn create_sample_rwa(issuer: u8) -> (MemHost, AssetId) {
        let mut host = MemHost::new(addr(issuer), addr(99));
        let asset_id = Rwa::create(
            &mut host,
            "Zagreb Tower 12A".into(),
            "ZT12A".into(),
            "RE".into(),
            "tower-12a".into(),
            1,
            "HR".into(),
            [0xAB; 32],
            "ipfs://QmMeta".into(),
            "ipfs://QmLegal".into(),
            "ipfs://QmCustody".into(),
            6,
            1_000_000,
            100_000,
        )
        .expect("rwa create");
        (host, asset_id)
    }

    #[test]
    fn create_and_derive_asset_id_deterministic() {
        let (host, asset_id) = create_sample_rwa(1);
        assert_eq!(asset_id, derive_asset_id(&addr(1), "RE", "tower-12a", 1));
        assert_eq!(Rwa::balance_of(&host, addr(1)).unwrap(), 100_000);
        let st = Rwa::decode_state(&host.storage_get(STATE_KEY).unwrap()).unwrap();
        assert_eq!(st.name, "Zagreb Tower 12A");
        assert_eq!(st.jurisdiction, "HR");
        assert_eq!(st.total_supply, 100_000);
        assert_eq!(st.max_supply, 1_000_000);
    }

    #[test]
    fn rejects_invalid_asset_class_and_supply_cap() {
        let mut host = MemHost::new(addr(1), addr(99));
        let err = Rwa::create(
            &mut host,
            "Bad".into(),
            "BAD".into(),
            "INVALID".into(),
            "id-1".into(),
            1,
            "HR".into(),
            [0u8; 32],
            "".into(),
            "".into(),
            "".into(),
            6,
            100,
            10,
        );
        assert_eq!(err, Err(ContractError::InvalidInput));

        let err2 = Rwa::create(
            &mut host,
            "Over".into(),
            "OVR".into(),
            "BOND".into(),
            "id-2".into(),
            1,
            "HR".into(),
            [0u8; 32],
            "".into(),
            "".into(),
            "".into(),
            6,
            100,
            101,
        );
        assert_eq!(err2, Err(ContractError::InvalidInput));
    }

    #[test]
    fn mint_transfer_burn_and_cap_enforced() {
        let (mut host, _) = create_sample_rwa(1);
        Rwa::mint(&mut host, addr(2), 900_000).unwrap();
        assert_eq!(Rwa::balance_of(&host, addr(2)).unwrap(), 900_000);
        // Exceeding max_supply fails
        assert_eq!(
            Rwa::mint(&mut host, addr(2), 1),
            Err(ContractError::Overflow)
        );
        // Transfer & burn
        host.set_caller(addr(2));
        Rwa::transfer(&mut host, addr(3), 250_000).unwrap();
        assert_eq!(Rwa::balance_of(&host, addr(2)).unwrap(), 650_000);
        assert_eq!(Rwa::balance_of(&host, addr(3)).unwrap(), 250_000);
        Rwa::burn(&mut host, 50_000).unwrap();
        assert_eq!(Rwa::balance_of(&host, addr(2)).unwrap(), 600_000);
    }

    #[test]
    fn compliance_freeze_blocks_transfer_mint_and_burn() {
        let (mut host, _) = create_sample_rwa(1);
        Rwa::mint(&mut host, addr(2), 500).unwrap();
        Rwa::freeze(&mut host, addr(2), true).unwrap();
        assert!(Rwa::is_frozen(&host, addr(2)).unwrap());
        assert_eq!(
            Rwa::mint(&mut host, addr(2), 10),
            Err(ContractError::Unauthorized)
        );
        host.set_caller(addr(2));
        assert_eq!(
            Rwa::transfer(&mut host, addr(3), 10),
            Err(ContractError::Unauthorized)
        );
        assert_eq!(Rwa::burn(&mut host, 10), Err(ContractError::Unauthorized));
        // Unfreeze restores movement
        host.set_caller(addr(1));
        Rwa::freeze(&mut host, addr(2), false).unwrap();
        host.set_caller(addr(2));
        Rwa::transfer(&mut host, addr(3), 100).unwrap();
        assert_eq!(Rwa::balance_of(&host, addr(3)).unwrap(), 100);
    }

    #[test]
    fn update_metadata_issuer_only() {
        let (mut host, _) = create_sample_rwa(1);
        host.set_caller(addr(2));
        assert_eq!(
            Rwa::update_metadata(
                &mut host,
                [1u8; 32],
                "ipfs://new".into(),
                "".into(),
                "".into()
            ),
            Err(ContractError::Unauthorized)
        );
        host.set_caller(addr(1));
        Rwa::update_metadata(
            &mut host,
            [2u8; 32],
            "ipfs://new-meta".into(),
            "ipfs://new-legal".into(),
            "ipfs://new-custody".into(),
        )
        .unwrap();
        let st = Rwa::decode_state(&host.storage_get(STATE_KEY).unwrap()).unwrap();
        assert_eq!(st.metadata_hash, [2u8; 32]);
        assert_eq!(st.metadata_uri, "ipfs://new-meta");
    }
}
