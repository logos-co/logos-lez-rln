//! Constants for RLN registration.
//!
//! Layout-derived constants are automatically computed from the shared
//! `rln-layouts` crate using `offset_of!` and `size_of` to ensure
//! they stay in sync with the actual struct definitions.

use std::mem::{offset_of, size_of};
use rln_layouts::{ConfigLayout, MembershipLayout};

// Re-export merkle tree constants
pub use crate::merkle_tree::{TREE_DEPTH, SUBTREE_LEAVES};

/// Computes the subtree ID for a given leaf index.
pub fn subtree_id_for_index(leaf_index: u64) -> u32 {
    (leaf_index / SUBTREE_LEAVES as u64) as u32
}

// Re-export from shared crate
pub use rln_layouts::MIN_RATE_LIMIT;
pub use rln_layouts::MAX_RATE_LIMIT;

// ============================================================================
// Config Account Layout (Derived from ConfigLayout)
// ============================================================================

pub const CONFIG_OFFSET_PRICE_PER_UNIT: usize = offset_of!(ConfigLayout, price_per_unit);
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = offset_of!(ConfigLayout, treasury_account_id);
pub const CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT: usize = offset_of!(ConfigLayout, current_total_rate_limit);

// ============================================================================
// Membership Account Layout (Derived from MembershipLayout)
// ============================================================================

pub const MEMBERSHIP_OFFSET_LEAF_INDEX: usize = offset_of!(MembershipLayout, leaf_index);
pub const MEMBERSHIP_OFFSET_RATE_LIMIT: usize = offset_of!(MembershipLayout, rate_limit);
pub const MEMBERSHIP_OFFSET_ID_COMMITMENT: usize = offset_of!(MembershipLayout, id_commitment);
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP: usize =
    offset_of!(MembershipLayout, grace_period_start_timestamp);
pub const MEMBERSHIP_OFFSET_ACTIVE_DURATION: usize = offset_of!(MembershipLayout, active_duration);
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION: usize =
    offset_of!(MembershipLayout, grace_period_duration);
pub const MEMBERSHIP_OFFSET_HOLDER_ACCOUNT_ID: usize =
    offset_of!(MembershipLayout, holder_account_id);
pub const MEMBERSHIP_SIZE: usize = size_of::<MembershipLayout>();

// ============================================================================
// Clock Account
// ============================================================================

pub use rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES;
