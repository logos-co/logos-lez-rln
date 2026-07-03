//! Helpers shared by the SPEL `rln_registration` guest binary.

use crate::hash::{hash_pair, validate_field_element};
use crate::layouts;
use nssa_core::Timestamp;
use nssa_core::account::AccountWithMetadata;

// Re-export rate limit and expiration constants / helpers from shared crate
pub use crate::layouts::{
    MIN_RATE_LIMIT, MAX_RATE_LIMIT,
    CLOCK_50_ACCOUNT_ID_BYTES,
    is_in_grace_period, is_expired,
};

// ============================================================================
// Merkle Tree Account Layout
// ============================================================================

pub use rln_layouts::OFFSET_NEXT_INDEX as TREE_OFFSET_NEXT_INDEX;

// ============================================================================
// Token Operations
// ============================================================================

/// A decoded token-holding account: which token it holds and the balance.
pub struct TokenHolding {
    pub definition_id: [u8; 32],
    pub balance: u128,
}

pub fn parse_token_holding(data: &[u8]) -> TokenHolding {
    let layout = layouts::TokenHoldingLayout::parse(data);
    TokenHolding {
        definition_id: layout.definition_id,
        balance: layout.balance(),
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Validate rate limit is within allowed range.
///
/// # Panics
/// If rate_limit is below MIN_RATE_LIMIT or above MAX_RATE_LIMIT.
pub fn validate_rate_limit(rate_limit: u64) {
    assert!(
        rate_limit >= MIN_RATE_LIMIT,
        "Rate limit {} below minimum {}",
        rate_limit, MIN_RATE_LIMIT
    );
    assert!(
        rate_limit <= MAX_RATE_LIMIT,
        "Rate limit {} above maximum {}",
        rate_limit, MAX_RATE_LIMIT
    );
}

/// Calculate payment amount for a given rate limit.
pub fn calculate_payment_amount(rate_limit: u64, price_per_unit: u128) -> u128 {
    price_per_unit * (rate_limit as u128)
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
// Merkle Tree Helpers
// ============================================================================

/// Read next_index from tree main account data.
pub fn read_tree_next_index(tree_main_data: &[u8]) -> u64 {
    u64::from_le_bytes(
        tree_main_data[TREE_OFFSET_NEXT_INDEX..TREE_OFFSET_NEXT_INDEX + 8].try_into().unwrap()
    )
}

// ============================================================================
// Clock Helpers
// ============================================================================

/// Validate that `clock_account` is the expected CLOCK_50 system account and
/// return its current unix timestamp.
pub fn require_clock(clock_account: &AccountWithMetadata) -> Timestamp {
    assert!(
        *clock_account.account_id.value() == CLOCK_50_ACCOUNT_ID_BYTES,
        "Wrong clock account provided"
    );
    clock_core::ClockAccountData::from_bytes(clock_account.account.data.as_ref()).timestamp
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rate_limit_valid() {
        validate_rate_limit(MIN_RATE_LIMIT);
        validate_rate_limit(MAX_RATE_LIMIT);
        validate_rate_limit(300);
    }

    #[test]
    #[should_panic(expected = "below minimum")]
    fn test_validate_rate_limit_too_low() {
        validate_rate_limit(MIN_RATE_LIMIT - 1);
    }

    #[test]
    #[should_panic(expected = "above maximum")]
    fn test_validate_rate_limit_too_high() {
        validate_rate_limit(MAX_RATE_LIMIT + 1);
    }

    #[test]
    fn test_calculate_payment_amount() {
        let price_per_unit = 10u128;
        let rate_limit = 100u64;
        assert_eq!(calculate_payment_amount(rate_limit, price_per_unit), 1000);

        assert_eq!(calculate_payment_amount(600, 5), 3000);
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
        let start = 1_000u64;
        let duration = 100u32;
        assert!(!is_in_grace_period(start, duration, 999));
        assert!(is_in_grace_period(start, duration, 1000));
        assert!(is_in_grace_period(start, duration, 1099));
        assert!(!is_in_grace_period(start, duration, 1100));
        assert!(!is_in_grace_period(start, duration, 5000));
    }

    #[test]
    fn test_is_expired_boundaries() {
        let start = 1_000u64;
        let duration = 100u32;
        assert!(!is_expired(start, duration, 999));
        assert!(!is_expired(start, duration, 1099));
        assert!(is_expired(start, duration, 1100));
        assert!(is_expired(start, duration, 5000));
    }

    #[test]
    fn test_grace_period_zero_duration_transitions_directly_to_expired() {
        let start = 1_000u64;
        assert!(!is_in_grace_period(start, 0, 1_000));
        assert!(is_expired(start, 0, 1_000));
    }
}
