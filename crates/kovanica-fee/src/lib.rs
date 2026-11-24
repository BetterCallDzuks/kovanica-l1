//! Canonical gas cost policy and fee estimation for Kovanica.
//!
//! This crate is the **single source of truth** for gas cost tables (intrinsic
//! and per host-call) and for fee estimation helpers. It is pure: no
//! networking, no storage, no node dependency. See
//! `docs/GAS_SCHEDULE.md` for the normative schedule this crate mirrors.
//!
//! Activation of the gated costs is controlled by
//! `kovanica_types::GAS_HARDENING_ACTIVE_FROM_ROUND`; this crate only provides
//! the numbers and helpers.

#![deny(unsafe_code)]

/// Per-byte module compile floor (mirrors `kovanica_runtime::GAS_PER_MODULE_BYTE`).
pub use kovanica_params::{
    FIXED_FEES_ACTIVE_FROM_ROUND, FIXED_FEE_CONTRACT_DEPLOY, FIXED_FEE_NFT_CREATE_COLLECTION,
    FIXED_FEE_NFT_MINT, FIXED_FEE_RWA_CREATE, FIXED_FEE_RWA_MINT, FIXED_FEE_TOKEN_CREATE,
    GAS_PER_MODULE_BYTE,
};

/// Returns the canonical fixed minimum fee (in atoms) for a contract `Call`
/// entry point, or `0` if the method has no fixed fee floor.
pub fn fixed_min_fee_for_call_method(method: &str) -> u64 {
    match method {
        "token_create" => FIXED_FEE_TOKEN_CREATE,
        "nft_create_collection" => FIXED_FEE_NFT_CREATE_COLLECTION,
        "nft_mint" => FIXED_FEE_NFT_MINT,
        "rwa_create" => FIXED_FEE_RWA_CREATE,
        "rwa_mint" => FIXED_FEE_RWA_MINT,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Intrinsic / base costs (GAS_SCHEDULE.md §6)
// ---------------------------------------------------------------------------

pub const CALL_BASE_GAS: u64 = 2_100;
pub const MEMORY_PAGE_GAS: u64 = 3_000;
pub const STORAGE_READ_GAS: u64 = 200;
pub const STORAGE_WRITE_GAS: u64 = 5_000;
pub const BALANCE_READ_GAS: u64 = 100;
pub const NATIVE_TRANSFER_GAS: u64 = 1_500;
pub const EVENT_EMIT_GAS: u64 = 500;
pub const CONTRACT_CREATION_GAS: u64 = 32_000;
pub const DEPLOY_BASE_GAS: u64 = CONTRACT_CREATION_GAS;

// ---------------------------------------------------------------------------
// Host-function costs (GAS_SCHEDULE.md §7): (base, per-call, per-unit)
// ---------------------------------------------------------------------------

pub const HOST_CALLER_BASE_GAS: u64 = 0;
pub const HOST_CALLER_PER_CALL_GAS: u64 = 50;

pub const HOST_CONTRACT_ADDRESS_BASE_GAS: u64 = 0;
pub const HOST_CONTRACT_ADDRESS_PER_CALL_GAS: u64 = 50;

pub const HOST_BLOCK_HEIGHT_BASE_GAS: u64 = 0;
pub const HOST_BLOCK_HEIGHT_PER_CALL_GAS: u64 = 10;

pub const HOST_TIMESTAMP_BASE_GAS: u64 = 0;
pub const HOST_TIMESTAMP_PER_CALL_GAS: u64 = 10;

pub const HOST_CALL_VALUE_BASE_GAS: u64 = 0;
pub const HOST_CALL_VALUE_PER_CALL_GAS: u64 = 50;

pub const HOST_BALANCE_OF_BASE_GAS: u64 = 100;
pub const HOST_BALANCE_OF_PER_CALL_GAS: u64 = 50;

pub const HOST_TRANSFER_BASE_GAS: u64 = 1_500;
pub const HOST_TRANSFER_PER_CALL_GAS: u64 = 200;

pub const HOST_STORAGE_GET_BASE_GAS: u64 = 200;
pub const HOST_STORAGE_GET_PER_CALL_GAS: u64 = 50;
pub const HOST_STORAGE_GET_PER_32_BYTES_GAS: u64 = 2;

pub const HOST_STORAGE_SET_BASE_GAS: u64 = 5_000;
pub const HOST_STORAGE_SET_PER_CALL_GAS: u64 = 100;
pub const HOST_STORAGE_SET_PER_32_BYTES_GAS: u64 = 2;

pub const HOST_EMIT_EVENT_BASE_GAS: u64 = 500;
pub const HOST_EMIT_EVENT_PER_CALL_GAS: u64 = 20;
pub const HOST_EMIT_EVENT_PER_BYTE_GAS: u64 = 1;

pub const HOST_CALL_CONTRACT_BASE_GAS: u64 = 2_600;
pub const HOST_CALL_CONTRACT_PER_CALL_GAS: u64 = 200;
pub const GAS_KOVANICA_CALL_CONTRACT: u64 =
    HOST_CALL_CONTRACT_BASE_GAS + HOST_CALL_CONTRACT_PER_CALL_GAS;

// Aggregate convenience constants (total per invocation, no per-byte component).
pub const GAS_KOVANICA_CALLER: u64 = HOST_CALLER_BASE_GAS + HOST_CALLER_PER_CALL_GAS;
pub const GAS_KOVANICA_CONTRACT_ADDRESS: u64 =
    HOST_CONTRACT_ADDRESS_BASE_GAS + HOST_CONTRACT_ADDRESS_PER_CALL_GAS;
pub const GAS_KOVANICA_BLOCK_HEIGHT: u64 =
    HOST_BLOCK_HEIGHT_BASE_GAS + HOST_BLOCK_HEIGHT_PER_CALL_GAS;
pub const GAS_KOVANICA_TIMESTAMP: u64 = HOST_TIMESTAMP_BASE_GAS + HOST_TIMESTAMP_PER_CALL_GAS;
pub const GAS_KOVANICA_CALL_VALUE: u64 = HOST_CALL_VALUE_BASE_GAS + HOST_CALL_VALUE_PER_CALL_GAS;
pub const GAS_KOVANICA_BALANCE_OF: u64 = HOST_BALANCE_OF_BASE_GAS + HOST_BALANCE_OF_PER_CALL_GAS;
pub const GAS_KOVANICA_TRANSFER: u64 = HOST_TRANSFER_BASE_GAS + HOST_TRANSFER_PER_CALL_GAS;
pub const GAS_KOVANICA_STORAGE_GET: u64 = HOST_STORAGE_GET_BASE_GAS + HOST_STORAGE_GET_PER_CALL_GAS;
pub const GAS_KOVANICA_STORAGE_SET: u64 = HOST_STORAGE_SET_BASE_GAS + HOST_STORAGE_SET_PER_CALL_GAS;
pub const GAS_KOVANICA_EMIT_EVENT: u64 = HOST_EMIT_EVENT_BASE_GAS + HOST_EMIT_EVENT_PER_CALL_GAS;

/// Minimum interpreter gas a `Call` must carry per byte of target module
/// bytecode.
pub fn min_gas_for_module(byte_len: usize) -> u64 {
    (byte_len as u64).saturating_mul(GAS_PER_MODULE_BYTE)
}

/// Saturating helper for 32-byte chunk counts.
fn chunks_32(bytes: usize) -> u64 {
    if bytes == 0 {
        0
    } else {
        (bytes as u64).div_ceil(32)
    }
}

/// Canonical gas cost table shared by runtime and execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasSchedule {
    pub call_base: u64,
    pub memory_page: u64,
    pub storage_read: u64,
    pub storage_write: u64,
    pub balance_read: u64,
    pub native_transfer: u64,
    pub event_emit: u64,
    pub contract_creation: u64,

    pub host_caller_base: u64,
    pub host_caller_per_call: u64,
    pub host_contract_address_base: u64,
    pub host_contract_address_per_call: u64,
    pub host_block_height_base: u64,
    pub host_block_height_per_call: u64,
    pub host_timestamp_base: u64,
    pub host_timestamp_per_call: u64,
    pub host_call_value_base: u64,
    pub host_call_value_per_call: u64,
    pub host_balance_of_base: u64,
    pub host_balance_of_per_call: u64,
    pub host_transfer_base: u64,
    pub host_transfer_per_call: u64,
    pub host_storage_get_base: u64,
    pub host_storage_get_per_call: u64,
    pub host_storage_get_per_32_bytes: u64,
    pub host_storage_set_base: u64,
    pub host_storage_set_per_call: u64,
    pub host_storage_set_per_32_bytes: u64,
    pub host_emit_event_base: u64,
    pub host_emit_event_per_call: u64,
    pub host_emit_event_per_byte: u64,
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self {
            call_base: CALL_BASE_GAS,
            memory_page: MEMORY_PAGE_GAS,
            storage_read: STORAGE_READ_GAS,
            storage_write: STORAGE_WRITE_GAS,
            balance_read: BALANCE_READ_GAS,
            native_transfer: NATIVE_TRANSFER_GAS,
            event_emit: EVENT_EMIT_GAS,
            contract_creation: CONTRACT_CREATION_GAS,

            host_caller_base: HOST_CALLER_BASE_GAS,
            host_caller_per_call: HOST_CALLER_PER_CALL_GAS,
            host_contract_address_base: HOST_CONTRACT_ADDRESS_BASE_GAS,
            host_contract_address_per_call: HOST_CONTRACT_ADDRESS_PER_CALL_GAS,
            host_block_height_base: HOST_BLOCK_HEIGHT_BASE_GAS,
            host_block_height_per_call: HOST_BLOCK_HEIGHT_PER_CALL_GAS,
            host_timestamp_base: HOST_TIMESTAMP_BASE_GAS,
            host_timestamp_per_call: HOST_TIMESTAMP_PER_CALL_GAS,
            host_call_value_base: HOST_CALL_VALUE_BASE_GAS,
            host_call_value_per_call: HOST_CALL_VALUE_PER_CALL_GAS,
            host_balance_of_base: HOST_BALANCE_OF_BASE_GAS,
            host_balance_of_per_call: HOST_BALANCE_OF_PER_CALL_GAS,
            host_transfer_base: HOST_TRANSFER_BASE_GAS,
            host_transfer_per_call: HOST_TRANSFER_PER_CALL_GAS,
            host_storage_get_base: HOST_STORAGE_GET_BASE_GAS,
            host_storage_get_per_call: HOST_STORAGE_GET_PER_CALL_GAS,
            host_storage_get_per_32_bytes: HOST_STORAGE_GET_PER_32_BYTES_GAS,
            host_storage_set_base: HOST_STORAGE_SET_BASE_GAS,
            host_storage_set_per_call: HOST_STORAGE_SET_PER_CALL_GAS,
            host_storage_set_per_32_bytes: HOST_STORAGE_SET_PER_32_BYTES_GAS,
            host_emit_event_base: HOST_EMIT_EVENT_BASE_GAS,
            host_emit_event_per_call: HOST_EMIT_EVENT_PER_CALL_GAS,
            host_emit_event_per_byte: HOST_EMIT_EVENT_PER_BYTE_GAS,
        }
    }
}

impl GasSchedule {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn host_caller_cost(&self) -> u64 {
        self.host_caller_base
            .saturating_add(self.host_caller_per_call)
    }
    pub fn host_contract_address_cost(&self) -> u64 {
        self.host_contract_address_base
            .saturating_add(self.host_contract_address_per_call)
    }
    pub fn host_block_height_cost(&self) -> u64 {
        self.host_block_height_base
            .saturating_add(self.host_block_height_per_call)
    }
    pub fn host_timestamp_cost(&self) -> u64 {
        self.host_timestamp_base
            .saturating_add(self.host_timestamp_per_call)
    }
    pub fn host_call_value_cost(&self) -> u64 {
        self.host_call_value_base
            .saturating_add(self.host_call_value_per_call)
    }
    pub fn host_balance_of_cost(&self) -> u64 {
        self.host_balance_of_base
            .saturating_add(self.host_balance_of_per_call)
    }
    pub fn host_transfer_cost(&self) -> u64 {
        self.host_transfer_base
            .saturating_add(self.host_transfer_per_call)
    }
    pub fn host_storage_get_cost(&self, bytes_copied: usize) -> u64 {
        self.host_storage_get_base
            .saturating_add(self.host_storage_get_per_call)
            .saturating_add(
                chunks_32(bytes_copied).saturating_mul(self.host_storage_get_per_32_bytes),
            )
    }
    pub fn host_storage_set_cost(&self, bytes_written: usize) -> u64 {
        self.host_storage_set_base
            .saturating_add(self.host_storage_set_per_call)
            .saturating_add(
                chunks_32(bytes_written).saturating_mul(self.host_storage_set_per_32_bytes),
            )
    }
    pub fn host_emit_event_cost(&self, topic_and_data_bytes: usize) -> u64 {
        self.host_emit_event_base
            .saturating_add(self.host_emit_event_per_call)
            .saturating_add(topic_and_data_bytes as u64)
    }

    pub fn estimate_call_gas(&self, code_len: usize) -> u64 {
        self.call_base.saturating_add(min_gas_for_module(code_len))
    }
}

/// Fee policy: schedule + pricing inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicy {
    pub schedule: GasSchedule,
    pub min_fee_rate: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            schedule: GasSchedule::default(),
            min_fee_rate: 1,
        }
    }
}

impl FeePolicy {
    pub fn new(schedule: GasSchedule, min_fee_rate: u64) -> Self {
        Self {
            schedule,
            min_fee_rate,
        }
    }

    pub fn min_fee_for_tx(&self, size_bytes: usize) -> u64 {
        (size_bytes as u64).saturating_mul(self.min_fee_rate)
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

pub const DEFAULT_GAS_SCHEDULE: GasSchedule = GasSchedule {
    call_base: CALL_BASE_GAS,
    memory_page: MEMORY_PAGE_GAS,
    storage_read: STORAGE_READ_GAS,
    storage_write: STORAGE_WRITE_GAS,
    balance_read: BALANCE_READ_GAS,
    native_transfer: NATIVE_TRANSFER_GAS,
    event_emit: EVENT_EMIT_GAS,
    contract_creation: CONTRACT_CREATION_GAS,
    host_caller_base: HOST_CALLER_BASE_GAS,
    host_caller_per_call: HOST_CALLER_PER_CALL_GAS,
    host_contract_address_base: HOST_CONTRACT_ADDRESS_BASE_GAS,
    host_contract_address_per_call: HOST_CONTRACT_ADDRESS_PER_CALL_GAS,
    host_block_height_base: HOST_BLOCK_HEIGHT_BASE_GAS,
    host_block_height_per_call: HOST_BLOCK_HEIGHT_PER_CALL_GAS,
    host_timestamp_base: HOST_TIMESTAMP_BASE_GAS,
    host_timestamp_per_call: HOST_TIMESTAMP_PER_CALL_GAS,
    host_call_value_base: HOST_CALL_VALUE_BASE_GAS,
    host_call_value_per_call: HOST_CALL_VALUE_PER_CALL_GAS,
    host_balance_of_base: HOST_BALANCE_OF_BASE_GAS,
    host_balance_of_per_call: HOST_BALANCE_OF_PER_CALL_GAS,
    host_transfer_base: HOST_TRANSFER_BASE_GAS,
    host_transfer_per_call: HOST_TRANSFER_PER_CALL_GAS,
    host_storage_get_base: HOST_STORAGE_GET_BASE_GAS,
    host_storage_get_per_call: HOST_STORAGE_GET_PER_CALL_GAS,
    host_storage_get_per_32_bytes: HOST_STORAGE_GET_PER_32_BYTES_GAS,
    host_storage_set_base: HOST_STORAGE_SET_BASE_GAS,
    host_storage_set_per_call: HOST_STORAGE_SET_PER_CALL_GAS,
    host_storage_set_per_32_bytes: HOST_STORAGE_SET_PER_32_BYTES_GAS,
    host_emit_event_base: HOST_EMIT_EVENT_BASE_GAS,
    host_emit_event_per_call: HOST_EMIT_EVENT_PER_CALL_GAS,
    host_emit_event_per_byte: HOST_EMIT_EVENT_PER_BYTE_GAS,
};

pub const DEFAULT_FEE_POLICY: FeePolicy = FeePolicy {
    schedule: DEFAULT_GAS_SCHEDULE,
    min_fee_rate: 1,
};

/// Trait allowing `estimate_call_gas` to accept either a byte length or
/// contract bytecode.
pub trait IntoCodeLen {
    fn code_len(&self) -> usize;
}

impl IntoCodeLen for usize {
    fn code_len(&self) -> usize {
        *self
    }
}
impl IntoCodeLen for u64 {
    fn code_len(&self) -> usize {
        *self as usize
    }
}
impl IntoCodeLen for u32 {
    fn code_len(&self) -> usize {
        *self as usize
    }
}
impl IntoCodeLen for i32 {
    fn code_len(&self) -> usize {
        *self as usize
    }
}
impl IntoCodeLen for &[u8] {
    fn code_len(&self) -> usize {
        self.len()
    }
}
impl IntoCodeLen for Vec<u8> {
    fn code_len(&self) -> usize {
        self.len()
    }
}
impl<const N: usize> IntoCodeLen for [u8; N] {
    fn code_len(&self) -> usize {
        N
    }
}
impl IntoCodeLen for &Vec<u8> {
    fn code_len(&self) -> usize {
        self.len()
    }
}

/// Estimate gas for a contract call given target module size or bytecode.
pub fn estimate_call_gas<T: IntoCodeLen>(input: T) -> u64 {
    DEFAULT_GAS_SCHEDULE.estimate_call_gas(input.code_len())
}

/// Minimum fee (atoms) for a transaction of `size_bytes`.
pub fn min_fee_for_tx<T: IntoCodeLen>(input: T) -> u64 {
    input.code_len() as u64
}

/// Fee from gas price and gas used.
pub fn fee_from_gas(gas_price: u64, gas_used: u64) -> u64 {
    gas_price.saturating_mul(gas_used)
}

// Free host-cost helpers (default schedule).
pub fn host_caller_cost() -> u64 {
    DEFAULT_GAS_SCHEDULE.host_caller_cost()
}
pub fn host_contract_address_cost() -> u64 {
    DEFAULT_GAS_SCHEDULE.host_contract_address_cost()
}
pub fn host_block_height_cost() -> u64 {
    DEFAULT_GAS_SCHEDULE.host_block_height_cost()
}
pub fn host_timestamp_cost() -> u64 {
    DEFAULT_GAS_SCHEDULE.host_timestamp_cost()
}
pub fn host_call_value_cost() -> u64 {
    DEFAULT_GAS_SCHEDULE.host_call_value_cost()
}
pub fn host_balance_of_cost() -> u64 {
    DEFAULT_GAS_SCHEDULE.host_balance_of_cost()
}
pub fn host_transfer_cost() -> u64 {
    DEFAULT_GAS_SCHEDULE.host_transfer_cost()
}
pub fn host_storage_get_cost(bytes_copied: usize) -> u64 {
    DEFAULT_GAS_SCHEDULE.host_storage_get_cost(bytes_copied)
}
pub fn host_storage_set_cost(bytes_written: usize) -> u64 {
    DEFAULT_GAS_SCHEDULE.host_storage_set_cost(bytes_written)
}
pub fn host_emit_event_cost(topic_and_data_bytes: usize) -> u64 {
    DEFAULT_GAS_SCHEDULE.host_emit_event_cost(topic_and_data_bytes)
}

// ---------------------------------------------------------------------------
// Wave B: EIP-1559 Dynamic Base Fee, Storage Deposits, and Gas-Priced Fees
// ---------------------------------------------------------------------------

/// Compute the next round's EIP-1559 `base_fee_per_byte` (atoms/byte) from the
/// parent round's `parent_base_fee` and `parent_block_bytes` against `TARGET_BLOCK_BYTES`.
pub fn next_base_fee_per_byte(parent_base_fee: u64, parent_block_bytes: usize) -> u64 {
    let base = parent_base_fee.max(kovanica_params::MIN_BASE_FEE_PER_BYTE);
    let target = kovanica_params::TARGET_BLOCK_BYTES as u128;
    let used = parent_block_bytes as u128;
    let denom = kovanica_params::BASE_FEE_MAX_CHANGE_DENOMINATOR as u128;

    if used == target {
        return base;
    }
    if used > target {
        let delta = used - target;
        let inc = (u128::from(base) * delta / target / denom).max(1);
        base.saturating_add(u64::try_from(inc).unwrap_or(u64::MAX))
    } else {
        let delta = target - used;
        let dec = u128::from(base) * delta / target / denom;
        base.saturating_sub(u64::try_from(dec).unwrap_or(u64::MAX))
            .max(kovanica_params::MIN_BASE_FEE_PER_BYTE)
    }
}

/// Refundable storage deposit delta when a contract's persistent storage size changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageDepositDelta {
    /// Additional KVNC atoms to lock as refundable storage deposit.
    Charge(u64),
    /// KVNC atoms to refund back to the caller after freeing storage bytes.
    Refund(u64),
    /// Net storage bytes unchanged.
    Unchanged,
}

/// Compute the refundable KVNC storage deposit delta for a net byte change.
pub fn compute_storage_deposit_delta(prev_bytes: usize, new_bytes: usize) -> StorageDepositDelta {
    if new_bytes > prev_bytes {
        let diff = (new_bytes - prev_bytes) as u64;
        StorageDepositDelta::Charge(diff.saturating_mul(kovanica_params::STORAGE_DEPOSIT_PER_BYTE))
    } else if prev_bytes > new_bytes {
        let diff = (prev_bytes - new_bytes) as u64;
        StorageDepositDelta::Refund(diff.saturating_mul(kovanica_params::STORAGE_DEPOSIT_PER_BYTE))
    } else {
        StorageDepositDelta::Unchanged
    }
}

/// Compute total required fee combining fixed operation floors, EIP-1559 dynamic
/// byte pricing, and WASM fuel gas pricing (`GAS_SCHEDULE.md` §8).
pub fn compute_total_required_fee(
    fixed_min_fee: u64,
    tx_bytes: usize,
    base_fee_per_byte: u64,
    gas_used: u64,
    gas_price: u64,
) -> u64 {
    let dynamic_byte_fee = (tx_bytes as u64).saturating_mul(base_fee_per_byte);
    let gas_fee = fee_from_gas(gas_price, gas_used);
    fixed_min_fee.max(dynamic_byte_fee.saturating_add(gas_fee))
}

#[cfg(test)]
mod wave_b_tests {
    use super::*;

    #[test]
    fn eip1559_base_fee_increases_above_target_and_decreases_below() {
        let target = kovanica_params::TARGET_BLOCK_BYTES;
        assert_eq!(next_base_fee_per_byte(100, target), 100);
        // Full block (2x target) increases by 12.5% (100 -> 112)
        assert_eq!(next_base_fee_per_byte(100, target * 2), 112);
        // Empty block decreases by 12.5% (100 -> 88)
        assert_eq!(next_base_fee_per_byte(100, 0), 88);
        // Never drops below MIN_BASE_FEE_PER_BYTE
        assert_eq!(
            next_base_fee_per_byte(1, 0),
            kovanica_params::MIN_BASE_FEE_PER_BYTE
        );
    }

    #[test]
    fn storage_deposit_charges_and_refunds_symmetrically() {
        assert_eq!(
            compute_storage_deposit_delta(0, 1024),
            StorageDepositDelta::Charge(1024 * kovanica_params::STORAGE_DEPOSIT_PER_BYTE)
        );
        assert_eq!(
            compute_storage_deposit_delta(1024, 512),
            StorageDepositDelta::Refund(512 * kovanica_params::STORAGE_DEPOSIT_PER_BYTE)
        );
        assert_eq!(
            compute_storage_deposit_delta(512, 512),
            StorageDepositDelta::Unchanged
        );
    }

    #[test]
    fn total_required_fee_respects_fixed_floor_and_gas_pricing() {
        // Under normal load, fixed floor (5 KVNC) dominates token_create
        assert_eq!(
            compute_total_required_fee(FIXED_FEE_TOKEN_CREATE, 300, 1, 50_000, 1),
            FIXED_FEE_TOKEN_CREATE
        );
        // Under high gas/congestion, dynamic byte + gas fee dominates
        assert_eq!(
            compute_total_required_fee(0, 500, 10, 20_000, 2),
            500 * 10 + 20_000 * 2
        );
    }
}
