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

// ============================================================================
// ConfigState Borsh layout
// ============================================================================
//
// pub struct ConfigState {
//     merkle_program_id: [u8; 32],                       // 0..32
//     tree_id: [u8; 32],                                 // 32..64
//     payment_token_id: [u8; 32],                        // 64..96
//     receipt_token_id: [u8; 32],                        // 96..128
//     price_per_unit: u128,                              // 128..144
//     treasury_account_id: [u8; 32],                     // 144..176
//     total_registrations: u64,                          // 176..184
//     max_total_rate_limit: u64,                         // 184..192
//     current_total_rate_limit: u64,                     // 192..200
//     active_duration_for_new_memberships: u32,          // 200..204
//     grace_period_duration_for_new_memberships: u32,    // 204..208
//     token_program_id: [u8; 32],                        // 208..240
// }

pub const CONFIG_OFFSET_MERKLE_PROGRAM_ID: usize = 0;
pub const CONFIG_OFFSET_TREE_ID: usize = 32;
pub const CONFIG_OFFSET_PAYMENT_TOKEN_ID: usize = 64;
pub const CONFIG_OFFSET_PRICE_PER_UNIT: usize = 128;
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 144;
pub const CONFIG_OFFSET_TOTAL_REGISTRATIONS: usize = 176;
pub const CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT: usize = 192;
pub const CONFIG_SIZE: usize = 240;

// ============================================================================
// MembershipState Borsh layout
// ============================================================================
//
// pub struct MembershipState {
//     leaf_index: u64,                          // 0..8
//     rate_limit: u64,                          // 8..16
//     id_commitment: [u8; 32],                  // 16..48
//     grace_period_start_timestamp: u64,        // 48..56
//     active_duration: u32,                     // 56..60
//     grace_period_duration: u32,               // 60..64
// }

pub const MEMBERSHIP_OFFSET_LEAF_INDEX: usize = 0;
pub const MEMBERSHIP_OFFSET_RATE_LIMIT: usize = 8;
pub const MEMBERSHIP_OFFSET_ID_COMMITMENT: usize = 16;
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP: usize = 48;
pub const MEMBERSHIP_OFFSET_ACTIVE_DURATION: usize = 56;
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION: usize = 60;
pub const MEMBERSHIP_SIZE: usize = 64;

// ============================================================================
// Clock Account
// ============================================================================

pub use rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES;
