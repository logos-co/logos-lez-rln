//! Helpers shared by the `rln_registration` program's handlers.

use lee_core::program::Response;

// Re-export expiration constants / helpers from shared crate
pub use crate::layouts::{CLOCK_CLAIM_TOLERANCE_MS, is_expired, is_in_grace_period};
use crate::hash::{hash_pair, validate_field_element};

/// Price of a membership at `rate_limit`, in native atomic units.
///
/// Saturating rather than wrapping: a wrapped product would price a debit
/// against a real balance at an amount nobody asked for, while a saturated
/// one is unaffordable and the native transfer refuses it.
pub fn calculate_payment_amount(rate_limit: u64, price_per_unit: u128) -> u128 {
    price_per_unit.saturating_mul(rate_limit as u128)
}

// ============================================================================
// Leaf Computation
// ============================================================================

/// Compute the leaf value for merkle tree insertion.
///
/// The leaf is H(id_commitment, rate_limit).
pub fn compute_registration_leaf(id_commitment: &[u8; 32], rate_limit: u64) -> [u8; 32] {
    validate_field_element(id_commitment);
    let mut rate_bytes = [0u8; 32];
    rate_bytes[..8].copy_from_slice(&rate_limit.to_le_bytes());
    hash_pair(id_commitment, &rate_bytes)
}

// ============================================================================
// Time
// ============================================================================

/// Pin `response`'s transaction to the blocks whose timestamp lies in
/// `[now_ms, now_ms + CLOCK_CLAIM_TOLERANCE_MS)`: the claimed `now_ms` may be
/// at most the tolerance behind chain time and never ahead of it. A
/// transaction included outside the window is reverted (and charged), so the
/// claim, which dates the membership, can never lengthen it.
pub fn time_window(response: Response, now_ms: u64) -> Response {
    let end = now_ms
        .checked_add(CLOCK_CLAIM_TOLERANCE_MS)
        .expect("now_ms plus the tolerance overflows u64");
    response
        .try_timestamp_window((Some(now_ms), Some(end)))
        .expect("the window is non-empty")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_payment_amount() {
        let price_per_unit = 10u128;
        let rate_limit = 100u64;
        assert_eq!(calculate_payment_amount(rate_limit, price_per_unit), 1000);

        assert_eq!(calculate_payment_amount(600, 5), 3000);
    }

    /// A price that cannot be paid is better than a price that wrapped into
    /// one that can.
    #[test]
    fn calculate_payment_amount_saturates_instead_of_wrapping() {
        assert_eq!(calculate_payment_amount(2, u128::MAX), u128::MAX);
    }

    #[test]
    fn test_compute_registration_leaf() {
        let id_commitment = [1u8; 32];
        let rate_limit = 100u64;

        let leaf = compute_registration_leaf(&id_commitment, rate_limit);

        // Should be deterministic
        let leaf2 = compute_registration_leaf(&id_commitment, rate_limit);
        assert_eq!(leaf, leaf2);

        // Different inputs should produce different leaves
        let leaf3 = compute_registration_leaf(&id_commitment, 200);
        assert_ne!(leaf, leaf3);
    }

    #[test]
    fn test_is_in_grace_period_boundaries() {
        let start_ms = 1_000u64;
        let duration_ms = 100u64;
        assert!(!is_in_grace_period(start_ms, duration_ms, 999));
        assert!(is_in_grace_period(start_ms, duration_ms, 1000));
        assert!(is_in_grace_period(start_ms, duration_ms, 1099));
        assert!(!is_in_grace_period(start_ms, duration_ms, 1100));
        assert!(!is_in_grace_period(start_ms, duration_ms, 5000));
    }

    #[test]
    fn test_is_expired_boundaries() {
        let start_ms = 1_000u64;
        let duration_ms = 100u64;
        assert!(!is_expired(start_ms, duration_ms, 999));
        assert!(!is_expired(start_ms, duration_ms, 1099));
        assert!(is_expired(start_ms, duration_ms, 1100));
        assert!(is_expired(start_ms, duration_ms, 5000));
    }

    #[test]
    fn test_grace_period_zero_duration_transitions_directly_to_expired() {
        let start_ms = 1_000u64;
        assert!(!is_in_grace_period(start_ms, 0, 1_000));
        assert!(is_expired(start_ms, 0, 1_000));
    }

    const T: u64 = 10_000_000;

    /// The window admits the claim itself and anything up to the tolerance
    /// later, and nothing earlier.
    #[test]
    fn time_window_spans_the_claim_and_the_tolerance_after_it() {
        let window = time_window(Response::keep_state(), T).validity.timestamps;
        assert!(!window.is_valid_for(T - 1));
        assert!(window.is_valid_for(T));
        assert!(window.is_valid_for(T + CLOCK_CLAIM_TOLERANCE_MS - 1));
        assert!(!window.is_valid_for(T + CLOCK_CLAIM_TOLERANCE_MS));
        assert_eq!(window.start(), Some(T));
        assert_eq!(window.end(), Some(T + CLOCK_CLAIM_TOLERANCE_MS));
    }

    #[test]
    #[should_panic(expected = "overflows u64")]
    fn time_window_refuses_a_claim_near_the_end_of_time() {
        let _ = time_window(Response::keep_state(), u64::MAX);
    }
}
