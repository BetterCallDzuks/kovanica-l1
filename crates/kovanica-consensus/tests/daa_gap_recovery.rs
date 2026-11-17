//! Integration tests verifying that DAA (`calculate_next_target_bits` and
//! `calculate_next_target_bits_lwma`) recovers smoothly after multi-hour and
//! multi-day timestamp gaps without oscillation, underflow, or 256-bit overflow.
//!
//! Covers both `kovanica-testnet` (chain ID 2) and `kovanica-mainnet` (chain ID 1).

use kovanica_consensus::daa::{
    calculate_next_target_bits, calculate_next_target_bits_lwma, DaaConfig,
};
use kovanica_params::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET, TARGET_BLOCK_MS};
use kovanica_types::block::compact_to_target;

const SIX_HOURS_MS: u64 = 6 * 3_600 * 1_000;
const THREE_DAYS_MS: u64 = 3 * 86_400 * 1_000;
const THIRTY_DAYS_MS: u64 = 30 * 86_400 * 1_000;

fn assert_within_bounds(bits: u32, config: &DaaConfig, context: &str) {
    let target = compact_to_target(bits);
    let min_target = compact_to_target(config.min_target_bits);
    let max_target = compact_to_target(config.max_target_bits);

    assert_ne!(target, [0u8; 32], "{context}: target must never be zero");
    assert!(
        target >= min_target,
        "{context}: target {bits:#010x} fell below min_target {:#010x}",
        config.min_target_bits
    );
    assert!(
        target <= max_target,
        "{context}: target {bits:#010x} exceeded max_target {:#010x}",
        config.max_target_bits
    );
}

/// Simulate steady 4s blocks, a large timestamp gap, and then steady 4s recovery
/// using `calculate_next_target_bits`.
fn run_sliding_window_gap_recovery(chain_id: u64, initial_bits: u32, gap_ms: u64, label: &str) {
    let config = DaaConfig::for_chain(chain_id);
    let w = config.window_size as usize;

    let mut timestamps = Vec::with_capacity(w * 4);
    let mut ts: u64 = 1_700_000_000_000;
    let mut bits = initial_bits;

    // 1. Warm up a full steady window at TARGET_BLOCK_MS (4,000 ms).
    for _ in 0..w {
        timestamps.push(ts);
        ts += TARGET_BLOCK_MS;
    }

    // 2. Inject the multi-hour / multi-day gap.
    ts = ts.saturating_add(gap_ms);
    timestamps.push(ts);

    let post_gap_bits = calculate_next_target_bits(bits, &timestamps, &config);
    assert_within_bounds(post_gap_bits, &config, &format!("{label}: post-gap"));
    assert!(
        compact_to_target(post_gap_bits) >= compact_to_target(bits),
        "{label}: target must ease (or stay at max_target) after gap: before={bits:#010x}, after={post_gap_bits:#010x}"
    );
    bits = post_gap_bits;

    // 3. Resume steady 4s blocks for 3 windows so the gap enters and exits the window.
    let mut recovery_targets = Vec::with_capacity(w * 3);
    for step in 0..(w * 3) {
        ts = ts.saturating_add(TARGET_BLOCK_MS);
        timestamps.push(ts);
        bits = calculate_next_target_bits(bits, &timestamps, &config);
        assert_within_bounds(bits, &config, &format!("{label}: recovery step {step}"));
        recovery_targets.push(bits);
    }

    // Once the gap has fully exited the sliding window, consecutive steps under
    // steady 4s blocks must remain completely stable (zero oscillation).
    let tail = &recovery_targets[(w * 2)..];
    for pair in tail.windows(2) {
        assert_eq!(
            pair[0], pair[1],
            "{label}: target oscillated after gap exited window: {:#010x} -> {:#010x}",
            pair[0], pair[1]
        );
    }
}

/// Simulate steady 4s blocks, a large timestamp gap, and then steady 4s recovery
/// using `calculate_next_target_bits_lwma`.
fn run_lwma_gap_recovery(chain_id: u64, initial_bits: u32, gap_ms: u64, label: &str) {
    let config = DaaConfig::for_chain(chain_id);
    let w = config.window_size as usize;

    let mut entries: Vec<(u64, u32)> = Vec::with_capacity(w * 4);
    let mut ts: u64 = 1_700_000_000_000;
    let mut bits = initial_bits;

    // 1. Warm up a full steady window at TARGET_BLOCK_MS (4,000 ms).
    for _ in 0..w {
        entries.push((ts, bits));
        ts += TARGET_BLOCK_MS;
    }

    // 2. Inject the multi-hour / multi-day gap.
    ts = ts.saturating_add(gap_ms);
    entries.push((ts, bits));

    let post_gap_bits = calculate_next_target_bits_lwma(&entries, &config);
    assert_within_bounds(post_gap_bits, &config, &format!("{label}: lwma post-gap"));
    assert!(
        compact_to_target(post_gap_bits) >= compact_to_target(bits),
        "{label}: LWMA target must ease (or stay at max_target) after gap: before={bits:#010x}, after={post_gap_bits:#010x}"
    );
    bits = post_gap_bits;

    // 3. Resume steady 4s blocks for 3 windows.
    let mut recovery_targets = Vec::with_capacity(w * 3);
    for step in 0..(w * 3) {
        ts = ts.saturating_add(TARGET_BLOCK_MS);
        entries.push((ts, bits));
        bits = calculate_next_target_bits_lwma(&entries, &config);
        assert_within_bounds(
            bits,
            &config,
            &format!("{label}: lwma recovery step {step}"),
        );
        recovery_targets.push(bits);
    }

    // Verify no wild oscillation in the post-gap tail: once the gap has exited
    // the window, consecutive targets under steady 4s blocks settle smoothly
    // (only tiny compact-encoding rounding is possible, never large swings).
    let tail = &recovery_targets[(w * 2)..];
    for pair in tail.windows(2) {
        let a = compact_to_target(pair[0]);
        let b = compact_to_target(pair[1]);
        // Neither step should jump by more than 5% (factor 1.05x) under steady 4s blocks.
        let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
        let hi_lim = kovanica_consensus::daa::mul_div_u256(lo, 105, 100);
        assert!(
            hi <= hi_lim,
            "{label}: LWMA target swung >5% in steady tail: {:#010x} -> {:#010x}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn test_calculate_next_target_bits_recovers_after_multi_hour_and_multi_day_gaps() {
    // Chain 2 (kovanica-testnet): mid-range difficulty (harder than 0x1f7f_ffff)
    for (gap_ms, gap_name) in [
        (SIX_HOURS_MS, "6h"),
        (THREE_DAYS_MS, "3d"),
        (THIRTY_DAYS_MS, "30d"),
    ] {
        run_sliding_window_gap_recovery(
            CHAIN_ID_TESTNET,
            0x1e20_ffff,
            gap_ms,
            &format!("testnet-{gap_name}"),
        );
        run_lwma_gap_recovery(
            CHAIN_ID_TESTNET,
            0x1e20_ffff,
            gap_ms,
            &format!("testnet-lwma-{gap_name}"),
        );
    }

    // Chain 1 (kovanica-mainnet): mid-range difficulty (harder than 0x1f00_ffff)
    for (gap_ms, gap_name) in [
        (SIX_HOURS_MS, "6h"),
        (THREE_DAYS_MS, "3d"),
        (THIRTY_DAYS_MS, "30d"),
    ] {
        run_sliding_window_gap_recovery(
            CHAIN_ID_MAINNET,
            0x1d0f_ffff,
            gap_ms,
            &format!("mainnet-{gap_name}"),
        );
        run_lwma_gap_recovery(
            CHAIN_ID_MAINNET,
            0x1d0f_ffff,
            gap_ms,
            &format!("mainnet-lwma-{gap_name}"),
        );
    }
}

#[test]
fn test_daa_extreme_timestamp_jump_does_not_overflow_or_panic() {
    for chain_id in [CHAIN_ID_TESTNET, CHAIN_ID_MAINNET] {
        let config = DaaConfig::for_chain(chain_id);
        let timestamps = vec![1_000, 5_000, 9_000, u64::MAX / 2, (u64::MAX / 2) + 4_000];
        let next = calculate_next_target_bits(config.max_target_bits, &timestamps, &config);
        assert_within_bounds(next, &config, "extreme-jump-sliding");

        let entries: Vec<(u64, u32)> = timestamps
            .iter()
            .map(|&ts| (ts, config.max_target_bits))
            .collect();
        let next_lwma = calculate_next_target_bits_lwma(&entries, &config);
        assert_within_bounds(next_lwma, &config, "extreme-jump-lwma");
    }
}
