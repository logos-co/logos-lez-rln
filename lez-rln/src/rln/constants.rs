//! Byte offsets and sizes for `ConfigState` / `MembershipState` so the host
//! can read individual fields without pulling in Borsh + the full struct decl.
//!
//! Hand-computed: Borsh writes fixed-width primitives in declaration order
//! with no length prefix for fixed-size arrays, so each offset is the running
//! sum of the preceding field sizes. Source of truth for field order is the
//! guest's `#[account_type]` definitions (kept in sync via a size_of assert
//! against `rln_layouts::{ConfigState, MembershipState}`).

pub use crate::merkle_tree::{SUBTREE_LEAVES, TREE_DEPTH};

/// Computes the subtree ID for a given leaf index.
pub fn subtree_id_for_index(leaf_index: u64) -> u32 {
    (leaf_index / SUBTREE_LEAVES as u64) as u32
}

pub use rln_layouts::MAX_RATE_LIMIT;
pub use rln_layouts::MIN_RATE_LIMIT;

// Layout source of truth: `rln_layouts::ConfigState`.
pub const CONFIG_OFFSET_MERKLE_PROGRAM_ID: usize = 0;
pub const CONFIG_OFFSET_TREE_ID: usize = 32;
pub const CONFIG_OFFSET_PAYMENT_TOKEN_ID: usize = 64;
pub const CONFIG_OFFSET_PRICE_PER_UNIT: usize = 128;
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 144;
pub const CONFIG_OFFSET_TOTAL_REGISTRATIONS: usize = 176;
pub const CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT: usize = 192;
// Deployment-policy fields (appended; earlier offsets unchanged):
// token_program_id [u8;32] @208 (no host reader by offset today).
pub const CONFIG_OFFSET_AUTHORIZED_REGISTRAR: usize = 240;
pub const CONFIG_OFFSET_FREE_QUOTA_REMAINING: usize = 272;
pub const CONFIG_OFFSET_FAUCET_CLAIM_CAP: usize = 280;
pub const CONFIG_SIZE: usize = 296;

// Layout source of truth: `rln_layouts::MembershipState`.
pub const MEMBERSHIP_OFFSET_LEAF_INDEX: usize = 0;
pub const MEMBERSHIP_OFFSET_RATE_LIMIT: usize = 8;
pub const MEMBERSHIP_OFFSET_ID_COMMITMENT: usize = 16;
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP: usize = 48;
pub const MEMBERSHIP_OFFSET_ACTIVE_DURATION: usize = 56;
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION: usize = 60;
pub const MEMBERSHIP_SIZE: usize = 64;

pub use rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES;
