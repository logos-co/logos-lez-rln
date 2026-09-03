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
/// Fixed size: 264 bytes. Borsh writes fields in declaration order with no
/// length prefixes, so `src/rln/constants.rs` offsets are a running sum of the
/// fields above each one — and `logos-lez-rln-module` duplicates them. Editing
/// anywhere but the tail moves both.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct ConfigState {
    pub merkle_program_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub payment_token_id: [u8; 32],
    pub price_per_unit: u128,
    pub treasury_account_id: [u8; 32],
    pub total_registrations: u64,
    pub max_total_rate_limit: u64,
    pub current_total_rate_limit: u64,
    pub active_duration_for_new_memberships: u32,
    pub grace_period_duration_for_new_memberships: u32,
    pub token_program_id: [u8; 32],
    /// Account allowed to create memberships via `RegisterFree` (all-zero =
    /// no free-quota registrar configured for this deployment).
    pub authorized_registrar: [u8; 32],
    /// Free memberships left for the authorized registrar; decremented per
    /// `RegisterFree`.
    pub free_quota_remaining: u64,
    /// Max payment tokens minted per `ClaimTokens` call. 0 = faucet disabled
    /// (wallet-key deployments); >0 also implies the payment token definition
    /// is this program's `payment` PDA.
    pub faucet_claim_cap: u128,
}

/// Borsh layout for a per-member account in the SPEL registration program.
///
/// Fixed size: 113 bytes.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct MembershipState {
    pub leaf_index: u64,
    pub rate_limit: u64,
    pub id_commitment: [u8; 32],
    pub grace_period_start_timestamp: u64,
    pub active_duration: u32,
    pub grace_period_duration: u32,
    /// The holding that paid the deposit — the only account `erase` refunds.
    /// Free memberships record their registrar here, with a zero deposit.
    pub holder: [u8; 32],
    /// Held in the tree's `escrow` PDA: refunded by `erase`, burned by `slash`.
    pub deposit_amount: u128,
    /// Non-zero once `force_expire` has run; `extend` then refuses.
    pub exiting: u8,
}
