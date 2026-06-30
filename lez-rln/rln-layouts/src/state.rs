//! Shared Borsh-encoded state structs for the SPEL `rln_registration` program.
//!
//! These mirror the `#[account_type]` definitions in
//! `methods/guest/src/bin/rln_registration.rs`. The guest binary re-uses
//! these by wrapping them in the `#[account_type]` macro; the host can either
//! deserialize via `borsh::from_slice` or read individual fields by the
//! offset constants in `src/rln/constants.rs` (kept consistent with this
//! struct's field declaration order).

use borsh::{BorshDeserialize, BorshSerialize};

/// Borsh layout for the registration program's config account.
///
/// Fixed size: 240 bytes. Field declaration order matches the byte layout
/// (Borsh encodes fixed-width primitives + fixed arrays in declaration order
/// with no length prefixes).
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct ConfigState {
    pub merkle_program_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub payment_token_id: [u8; 32],
    pub receipt_token_id: [u8; 32],
    pub price_per_unit: u128,
    pub treasury_account_id: [u8; 32],
    pub total_registrations: u64,
    pub max_total_rate_limit: u64,
    pub current_total_rate_limit: u64,
    pub active_duration_for_new_memberships: u32,
    pub grace_period_duration_for_new_memberships: u32,
    pub token_program_id: [u8; 32],
}

/// Borsh layout for a per-member account in the SPEL registration program.
///
/// Fixed size: 64 bytes.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct MembershipState {
    pub leaf_index: u64,
    pub rate_limit: u64,
    pub id_commitment: [u8; 32],
    pub grace_period_start_timestamp: u64,
    pub active_duration: u32,
    pub grace_period_duration: u32,
}
