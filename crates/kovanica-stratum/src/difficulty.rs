//! Share difficulty computation and target verification for Stratum V1.

use kovanica_types::block::{check_pow_hash_meets_target, compact_to_target};
use kovanica_types::Hash;

/// Standard PoW difficulty 1 compact bits (0x1d00ffff).
pub const DIFFICULTY_1_TARGET_BITS: u32 = 0x1d00ffff;

/// Convert a floating-point Stratum share difficulty into 256-bit big-endian target bytes.
///
/// Difficulty 1 corresponds to `compact_to_target(0x1d00ffff)` (~2^224).
/// Higher difficulty yields a lower numerical target (harder);
/// lower difficulty yields a higher numerical target (easier).
pub fn target_from_difficulty(difficulty: f64) -> [u8; 32] {
    if difficulty <= 0.0 {
        return [0xff; 32];
    }
    if (difficulty - 1.0).abs() < 1e-9 {
        return compact_to_target(DIFFICULTY_1_TARGET_BITS);
    }

    // T1 has 32 bits (4 bytes) of 0s, followed by 0xffff, followed by 208 bits of 0s.
    // T = T1 / difficulty = (65535.0 / difficulty) * 2^208.
    // In high 128 bits (shifted by 2^64):
    let scaled = (65535.0 / difficulty) * 65536.0 * 18446744073709551616.0;
    if scaled >= u128::MAX as f64 {
        return [0xff; 32];
    }

    let val_128 = scaled as u128;
    let mut target = [0u8; 32];
    target[..16].copy_from_slice(&val_128.to_be_bytes());
    target
}

/// Verify whether a solution hash satisfies the worker's share target.
#[inline]
pub fn check_share_hash_meets_target(hash: &Hash, share_target: &[u8; 32]) -> bool {
    if *share_target == [0u8; 32] {
        return false;
    }
    hash.0 <= *share_target
}

/// Verify whether a solution hash satisfies a floating-point share difficulty.
#[inline]
pub fn check_share_hash_meets_difficulty(hash: &Hash, difficulty: f64) -> bool {
    let target = target_from_difficulty(difficulty);
    check_share_hash_meets_target(hash, &target)
}

/// Verify whether a solution hash meets the full network target bits.
#[inline]
pub fn check_network_solution(hash: &Hash, network_target_bits: u32) -> bool {
    check_pow_hash_meets_target(hash, network_target_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_1_target() {
        let t1 = compact_to_target(DIFFICULTY_1_TARGET_BITS);
        let from_diff = target_from_difficulty(1.0);
        assert_eq!(t1, from_diff);
    }

    #[test]
    fn test_difficulty_scaling() {
        let t_easy = target_from_difficulty(0.5);
        let t_normal = target_from_difficulty(1.0);
        let t_hard = target_from_difficulty(2.0);

        // Lower difficulty -> larger target (easier)
        assert!(t_easy > t_normal);
        // Higher difficulty -> smaller target (harder)
        assert!(t_normal > t_hard);
    }

    #[test]
    fn test_zero_or_negative_difficulty() {
        assert_eq!(target_from_difficulty(0.0), [0xff; 32]);
        assert_eq!(target_from_difficulty(-5.0), [0xff; 32]);
    }
}
