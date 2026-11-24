//! Canonical protocol parameters for Kovanica.
//!
//! Single source of truth for consensus, tokenomics, gas, size limits and
//! activation-round constants. Pure data + accessors only.

#![deny(unsafe_code)]

// ============================================================
// Chain / identity
// ============================================================
pub const TICKER: &str = "KVNC";
pub const DECIMALS: u32 = 9;
/// Base units per KVNC (1 KVNC = 10^9 base units).
pub const ONE_KVNC: u64 = 1_000_000_000;

/// Mainnet chain id (`1`). Canonical PRO-21 addresses only.
pub const CHAIN_ID_MAINNET: u64 = 1;
/// Official testnet chain id (`2`). Hybrid PoW + GHOSTDAG.
pub const CHAIN_ID_TESTNET: u64 = 2;
/// Devnet chain id (`3`).
pub const CHAIN_ID_DEVNET: u64 = 3;
/// Alias for testnet chain id (`2`) for backward compatibility during transition.
pub const CHAIN_ID_HYBRID_TESTNET: u64 = CHAIN_ID_TESTNET;

/// Canonical network tag for kovanica-testnet (chain ID 2).
pub const NETWORK_TAG_TESTNET: &str = "kovanica-testnet";
/// Canonical network tag for hybrid testnet (alias).
pub const NETWORK_TAG_HYBRID_TESTNET: &str = NETWORK_TAG_TESTNET;

// ============================================================
// Consensus
// ============================================================
/// Hybrid PoW + GHOSTDAG target block time in milliseconds (Toni 2026-11-05).
/// Used by kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2).
pub const TARGET_BLOCK_MS: u64 = 4_000;
/// Hybrid PoW + GHOSTDAG default parameter k (Toni 2026-11-05).
pub const GHOSTDAG_K: u32 = 5;

/// Initial/maximum target bits for hybrid PoW kovanica-testnet (chain ID 2).
/// Compact representation `0x1f00ffff` (exponent 31, mantissa 0x00ffff).
pub const INITIAL_TARGET_BITS_HYBRID: u32 = 0x1f00_ffff;
/// Minimum difficulty target bits (ceiling on target, easiest difficulty).
pub const MAX_TARGET_BITS: u32 = 0x1f00_ffff;
/// Maximum difficulty target bits (floor on target, hardest difficulty).
pub const MIN_TARGET_BITS: u32 = 0x0101_0000;

/// Canonical difficulty floor (easiest target) for kovanica-testnet (chain ID 2).
/// Easiest target 0x1f7f_ffff (~512 hashes per block), set by #242; round 1 takes config.max_target_bits.
pub const DAA_MAX_TARGET_BITS_TESTNET: u32 = 0x1f7f_ffff;
/// Canonical difficulty ceiling (hardest target) for kovanica-testnet (chain ID 2).
/// Capped at exact ratio 2,147,483,392 / 65,535 (~32,768.496x easiest difficulty, target 0x1e00_ffff) so that mining clusters still make 4s blocks.
pub const DAA_MIN_TARGET_BITS_TESTNET: u32 = 0x1e00_ffff;

/// Difficulty floor (easiest target) for kovanica-devnet (chain ID 3).
/// Inert until devnet mines.
pub const DAA_MAX_TARGET_BITS_DEVNET: u32 = 0x1f7f_ffff;
/// Difficulty ceiling (hardest target) for kovanica-devnet (chain ID 3).
/// Inert until devnet mines.
pub const DAA_MIN_TARGET_BITS_DEVNET: u32 = 0x1e00_ffff;
/// Default DAA adjustment window in blocks.
pub const DAA_WINDOW_BLOCKS: u64 = 60;
/// Maximum future timestamp drift in milliseconds (30 seconds).
pub const MAX_FUTURE_TIMESTAMP_DRIFT_MS: u64 = 30_000;

// NON-CONSENSUS under Hybrid PoW + GHOSTDAG (chains 1 and 2):
// Legacy Mysticeti timing constants (still imported by dev/legacy paths).
pub const WAVE_LENGTH: u64 = 3;
pub const EPOCH_ROUNDS: u64 = 7_200;
pub const EPOCH_LEADER_HEIGHTS: u64 = EPOCH_ROUNDS / WAVE_LENGTH;
pub const LEADER_INTERVAL_SECS: u64 = 12;
pub const ROUND_SECS: u64 = 4;

pub const fn next_leader_slot(round: u64) -> u64 {
    (round / WAVE_LENGTH + 1).saturating_mul(WAVE_LENGTH)
}

// ============================================================
// Tokenomics
// ============================================================
pub const TOTAL_SUPPLY: u64 = 90_200_000 * ONE_KVNC;
pub const FOUNDER_PREMINE: u64 = 200_000 * ONE_KVNC;
pub const GENESIS_VALIDATOR_ALLOCATION: u64 = 1_000_000 * ONE_KVNC;
pub const TREASURY_TOTAL: u64 = 8_000_000 * ONE_KVNC;
pub const TREASURY_ANNUAL: u64 = 1_000_000 * ONE_KVNC;
pub const TREASURY_YEARS: u32 = 8;
pub const BLOCKS_PER_YEAR: u64 = 31_536_000 / LEADER_INTERVAL_SECS;
pub const MINING_SUBSIDY_BUDGET: u64 =
    TOTAL_SUPPLY - FOUNDER_PREMINE - TREASURY_TOTAL - GENESIS_VALIDATOR_ALLOCATION;
pub const INITIAL_BLOCK_REWARD: u64 = 5 * ONE_KVNC / 2;
pub const SUBSIDY_ERA_BLOCKS: u64 = 8_100_000;
pub const DECAY_NUM: u64 = 3;
pub const DECAY_DEN: u64 = 4;

// NEW NO-stake policy tokenomics constants (Approved 2026-11-06)
pub const GENESIS_VALIDATOR_ALLOCATION_NO_STAKE: u64 = 0;
pub const MINING_SUBSIDY_BUDGET_NO_STAKE_82M: u64 =
    TOTAL_SUPPLY - FOUNDER_PREMINE - TREASURY_TOTAL - GENESIS_VALIDATOR_ALLOCATION_NO_STAKE;
pub const SUBSIDY_ERA_BLOCKS_NO_STAKE_82M: u64 = 8_200_000;

// ============================================================
// Staking — NON-CONSENSUS under Hybrid PoW + GHOSTDAG (chains 1 and 2)
// Retained for legacy/dev chains and historical storage compatibility.
// ============================================================
pub const MIN_VALIDATOR_STAKE: u64 = 50_000 * ONE_KVNC;
pub const MIN_DELEGATION: u64 = 50_000 * ONE_KVNC;
pub const MIN_ACTIVE_VALIDATORS: u32 = 15;
pub const UNBONDING_ROUNDS: u64 = 100_000;
pub const JAIL_ROUNDS: u64 = 7_200;
pub const MAX_MISSED_LEADERS_BEFORE_OFFLINE: u64 = 100;
pub const COMMISSION_CHANGE_COOLDOWN: u64 = 3 * EPOCH_LEADER_HEIGHTS;
pub const SLASH_PCT_BPS: u16 = 500;

// Light nodes
pub const LIGHT_REWARD_BPS: u16 = 2_000;
pub const MIN_LIGHT_BOND: u64 = 100 * ONE_KVNC;
pub const MAX_LIGHT_NODES: usize = 4_096;
pub const LIGHT_WITNESS_SLOTS: usize = 32;

// ============================================================
// Execution / gas
// ============================================================
pub const MAX_TX_GAS_LIMIT: u64 = 10_000_000;
pub const BLOCK_GAS_BUDGET_FACTOR: u64 = 8;
pub const GAS_PER_MODULE_BYTE: u64 = 8;
pub const DEFAULT_CONTRACT_MEMORY_PAGES: u32 = 256;

// ============================================================
// Size limits
// ============================================================
pub const MAX_TXS_PER_BLOCK: usize = 10_000;
pub const MAX_PARENT_ROUND_GAP: u64 = 300;
pub const MAX_TX_BYTES: usize = 512 * 1024;
pub const MAX_BLOCK_BYTES: usize = 960 * 1024;
pub const GENESIS_ROUND: u64 = 0;

// ============================================================
// Activation gates (active from genesis, round 0)
// ============================================================
//
// These four hardening rules were shipped inert (`u64::MAX`) so a live chain
// could upgrade without forking. On 2026-11-17 the owner approved P4-6:
// fresh chains (mainnet genesis and empty-volume re-genesis) activate them at
// round 0 instead of carrying a runtime switch that is never flipped.
//
// Do not move them back to a non-zero round without an activation plan.
pub const GAS_HARDENING_ACTIVE_FROM_ROUND: u64 = GENESIS_ROUND;
pub const CONTRACT_HARDENING_ACTIVE_FROM_ROUND: u64 = GENESIS_ROUND;
pub const SLASHING_ACTIVE_FROM_ROUND: u64 = GENESIS_ROUND;
pub const STATE_COMMITMENT_ACTIVE_FROM_ROUND: u64 = 500_000;
pub const SIZE_LIMITS_ACTIVE_FROM_ROUND: u64 = GENESIS_ROUND;
/// Activation round for fixed operation fee floors on testnet/devnet (500,000),
/// matching `STATE_COMMITMENT_ACTIVE_FROM_ROUND` so the live seed1 testnet never forks.
/// Mainnet (chain 1) enforces fixed fees from genesis (round 0).
pub const FIXED_FEES_ACTIVE_FROM_ROUND: u64 = 500_000;
/// Activation round for Wave A upgrades (Atomic Batch, Sponsored Txs, Cross-Contract Calls).
/// Mainnet (chain 1) activates from genesis (round 0); testnet/devnet at round 500,000.
pub const WAVE_A_ACTIVE_FROM_ROUND: u64 = 500_000;
/// Maximum number of actions in a single `TransactionKind::Batch`.
pub const MAX_BATCH_ACTIONS: usize = 16;
/// Maximum nested cross-contract call depth (CPI).
pub const MAX_CROSS_CONTRACT_CALL_DEPTH: u8 = 4;

// ============================================================
// Fixed operation fee floors (Balanced tier; 75% burn / 25% miner)
// ============================================================
/// Minimum fee to deploy a WASM contract (1 KVNC).
pub const FIXED_FEE_CONTRACT_DEPLOY: u64 = ONE_KVNC;
/// Minimum fee to create a KVP-102 token via `token_create` (5 KVNC).
pub const FIXED_FEE_TOKEN_CREATE: u64 = 5 * ONE_KVNC;
/// Minimum fee to create an NFT collection via `nft_create_collection` (2 KVNC).
pub const FIXED_FEE_NFT_CREATE_COLLECTION: u64 = 2 * ONE_KVNC;
/// Minimum fee to mint an NFT via `nft_mint` (0.1 KVNC).
pub const FIXED_FEE_NFT_MINT: u64 = ONE_KVNC / 10;
/// Minimum fee to register a KVP-106 RWA asset via `rwa_create` (10 KVNC).
pub const FIXED_FEE_RWA_CREATE: u64 = 10 * ONE_KVNC;
/// Minimum fee to mint KVP-106 RWA shares via `rwa_mint` (0.5 KVNC).
pub const FIXED_FEE_RWA_MINT: u64 = ONE_KVNC / 2;

#[allow(clippy::absurd_extreme_comparisons)]
pub fn gas_hardening_active_from(round: u64) -> bool {
    round >= GAS_HARDENING_ACTIVE_FROM_ROUND
}
#[allow(clippy::absurd_extreme_comparisons)]
pub fn contract_hardening_active_from(round: u64) -> bool {
    round >= CONTRACT_HARDENING_ACTIVE_FROM_ROUND
}
#[allow(clippy::absurd_extreme_comparisons)]
pub fn slashing_active_from(round: u64) -> bool {
    round >= SLASHING_ACTIVE_FROM_ROUND
}
pub fn state_commitment_active_from(round: u64) -> bool {
    round >= STATE_COMMITMENT_ACTIVE_FROM_ROUND
}

/// Chain-scoped full-state commitment activation round.
///
/// Mainnet (chain 1) enforces the full-state commitment from genesis (round 0);
/// public Testnet (chain 2) retains `STATE_COMMITMENT_ACTIVE_FROM_ROUND` (500_000)
/// so the live seed1 cluster never forks.
pub const fn state_commitment_active_from_round_for_chain(chain_id: u64) -> u64 {
    if chain_id == CHAIN_ID_MAINNET {
        GENESIS_ROUND
    } else {
        STATE_COMMITMENT_ACTIVE_FROM_ROUND
    }
}

/// Whether `round` enforces the full-state commitment on `chain_id`.
pub const fn state_commitment_active_from_for_chain(chain_id: u64, round: u64) -> bool {
    round >= state_commitment_active_from_round_for_chain(chain_id)
}

/// Chain-scoped fixed-fee activation round.
///
/// Mainnet (chain 1) enforces fixed operation fee floors from genesis (round 0);
/// public Testnet (chain 2) and Devnet (chain 3) activate at `FIXED_FEES_ACTIVE_FROM_ROUND`
/// (500,000) so the live seed1 testnet never forks.
pub const fn fixed_fees_active_from_round_for_chain(chain_id: u64) -> u64 {
    if chain_id == CHAIN_ID_MAINNET {
        GENESIS_ROUND
    } else {
        FIXED_FEES_ACTIVE_FROM_ROUND
    }
}

/// Whether `round` enforces fixed operation fee floors on `chain_id`.
pub const fn fixed_fees_active_from_for_chain(chain_id: u64, round: u64) -> bool {
    round >= fixed_fees_active_from_round_for_chain(chain_id)
}

/// Chain-scoped Wave A activation round (Atomic Batch, Sponsored Txs, Cross-Contract Calls).
pub const fn wave_a_active_from_round_for_chain(chain_id: u64) -> u64 {
    if chain_id == CHAIN_ID_MAINNET {
        GENESIS_ROUND
    } else {
        WAVE_A_ACTIVE_FROM_ROUND
    }
}

/// Whether `round` enables Wave A upgrades on `chain_id`.
pub const fn wave_a_active_from_for_chain(chain_id: u64, round: u64) -> bool {
    round >= wave_a_active_from_round_for_chain(chain_id)
}
#[allow(clippy::absurd_extreme_comparisons)]
pub fn size_limits_active_from(round: u64) -> bool {
    round >= SIZE_LIMITS_ACTIVE_FROM_ROUND
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    #[test]
    fn supply_decomposition() {
        assert_eq!(
            FOUNDER_PREMINE + GENESIS_VALIDATOR_ALLOCATION + TREASURY_TOTAL + MINING_SUBSIDY_BUDGET,
            TOTAL_SUPPLY
        );
    }

    #[test]
    fn committee_bounds() {
        assert!(MIN_ACTIVE_VALIDATORS >= 1);
        assert_eq!(MIN_VALIDATOR_STAKE, 50_000 * ONE_KVNC);
        assert_eq!(MIN_DELEGATION, 50_000 * ONE_KVNC);
    }

    #[test]
    fn hardening_gates_are_active_from_genesis() {
        // P4-6 (owner-approved 2026-11-17): fresh chains enforce every
        // hardening rule from the genesis round. A non-zero value here would
        // silently disable consensus rules on new chains, so pin it.
        assert_eq!(GAS_HARDENING_ACTIVE_FROM_ROUND, GENESIS_ROUND);
        assert_eq!(CONTRACT_HARDENING_ACTIVE_FROM_ROUND, GENESIS_ROUND);
        assert_eq!(SLASHING_ACTIVE_FROM_ROUND, GENESIS_ROUND);
        assert_eq!(SIZE_LIMITS_ACTIVE_FROM_ROUND, GENESIS_ROUND);
        assert!(gas_hardening_active_from(GENESIS_ROUND));
        assert!(contract_hardening_active_from(GENESIS_ROUND));
        assert!(slashing_active_from(GENESIS_ROUND));
        assert!(size_limits_active_from(GENESIS_ROUND));
        // The state-commitment root keeps its separate, finite activation on testnet
        // while mainnet enforces full-state commitment from genesis (round 0).
        assert_eq!(STATE_COMMITMENT_ACTIVE_FROM_ROUND, 500_000);
        assert_eq!(
            state_commitment_active_from_round_for_chain(CHAIN_ID_MAINNET),
            GENESIS_ROUND
        );
        assert!(state_commitment_active_from_for_chain(
            CHAIN_ID_MAINNET,
            GENESIS_ROUND
        ));
        assert_eq!(
            state_commitment_active_from_round_for_chain(CHAIN_ID_TESTNET),
            500_000
        );
        assert!(!state_commitment_active_from_for_chain(CHAIN_ID_TESTNET, 0));
        assert!(state_commitment_active_from_for_chain(
            CHAIN_ID_TESTNET,
            500_000
        ));
    }

    #[test]
    fn no_stake_supply_decomposition() {
        assert_eq!(
            FOUNDER_PREMINE
                + GENESIS_VALIDATOR_ALLOCATION_NO_STAKE
                + TREASURY_TOTAL
                + MINING_SUBSIDY_BUDGET_NO_STAKE_82M,
            TOTAL_SUPPLY
        );
        assert_eq!(MINING_SUBSIDY_BUDGET_NO_STAKE_82M, 82_000_000 * ONE_KVNC);
        assert_eq!(SUBSIDY_ERA_BLOCKS_NO_STAKE_82M, 8_200_000);
    }

    #[test]
    fn era_math() {
        assert!(SUBSIDY_ERA_BLOCKS > 0);
        assert!(DECAY_DEN > 0);
    }

    #[test]
    fn fixed_fee_schedule_and_activation_gate() {
        assert_eq!(FIXED_FEE_CONTRACT_DEPLOY, ONE_KVNC);
        assert_eq!(FIXED_FEE_TOKEN_CREATE, 5 * ONE_KVNC);
        assert_eq!(FIXED_FEE_NFT_CREATE_COLLECTION, 2 * ONE_KVNC);
        assert_eq!(FIXED_FEE_NFT_MINT, ONE_KVNC / 10);
        assert_eq!(FIXED_FEE_RWA_CREATE, 10 * ONE_KVNC);
        assert_eq!(FIXED_FEE_RWA_MINT, ONE_KVNC / 2);

        assert_eq!(
            fixed_fees_active_from_round_for_chain(CHAIN_ID_MAINNET),
            GENESIS_ROUND
        );
        assert!(fixed_fees_active_from_for_chain(CHAIN_ID_MAINNET, 0));
        assert_eq!(
            fixed_fees_active_from_round_for_chain(CHAIN_ID_TESTNET),
            FIXED_FEES_ACTIVE_FROM_ROUND
        );
        assert!(!fixed_fees_active_from_for_chain(CHAIN_ID_TESTNET, 0));
        assert!(fixed_fees_active_from_for_chain(
            CHAIN_ID_TESTNET,
            FIXED_FEES_ACTIVE_FROM_ROUND
        ));
    }
}
