//! Shared layouts for RLN registration.
//!
//! This crate provides `#[repr(C, packed)]` structs for direct memory mapping
//! with `bytemuck`, and a serde-based `Instruction` enum for typed instruction
//! passing between host and guest.
//!
//! # no_std Support
//!
//! This crate is `no_std` compatible. Disable the default `std` feature for
//! embedded or zkVM guest environments:
//!
//! ```toml
//! rln-layouts = { path = "../rln-layouts", default-features = false }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

use bytemuck::{Pod, Zeroable};

pub mod sparse;
pub use sparse::{read_sparse_node, subtree_node_offset};

// ============================================================================
// Instruction Enum
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Instruction {
    Initialize {
        merkle_program_id: [u8; 32],
        tree_id: [u8; 24],
        payment_token_id: [u8; 32],
        price_per_unit: u128,
        treasury_account_id: [u8; 32],
        token_program_id: [u8; 32],
        max_total_rate_limit: u64,
        active_duration_for_new_memberships: u32,
        grace_period_duration_for_new_memberships: u32,
    },
    Register {
        id_commitment: [u8; 32],
        rate_limit: u64,
    },
    BuyCredits {
        amount: u128,
    },
    RegisterWithCredits {
        id_commitment: [u8; 32],
        amount_to_burn: u64,
    },
    Slash {
        identity_secret: [u8; 32],
    },
    /// Renew a membership during its grace period. Only the holder may call this.
    Extend {
        id_commitment: [u8; 32],
    },
    /// Remove a membership. Allowed when the membership is expired (any caller)
    /// or in its grace period (holder only).
    Erase {
        id_commitment: [u8; 32],
    },
}

// ============================================================================
// Rate Limit Constraints
// ============================================================================

/// Minimum allowed rate limit for registration.
pub const MIN_RATE_LIMIT: u64 = 100;

/// Maximum allowed rate limit for registration.
pub const MAX_RATE_LIMIT: u64 = 600;

// ============================================================================
// Clock Account
// ============================================================================

/// Raw bytes of the CLOCK_50 system account ID, updated by the sequencer every
/// 50 blocks. This crate mirrors the constant instead of depending on
/// `clock_core` to stay `no_std`-friendly for the host side.
pub const CLOCK_50_ACCOUNT_ID_BYTES: [u8; 32] = *b"/LEZ/ClockProgramAccount/0000050";

// ============================================================================
// Expiration helpers
// ============================================================================

/// Returns true iff `now` falls inside `[grace_start, grace_start + grace_duration)`.
#[inline]
pub fn is_in_grace_period(grace_start: u64, grace_duration: u32, now: u64) -> bool {
    grace_start <= now && now < grace_start.saturating_add(grace_duration as u64)
}

/// Returns true iff `now >= grace_start + grace_duration`.
#[inline]
pub fn is_expired(grace_start: u64, grace_duration: u32, now: u64) -> bool {
    now >= grace_start.saturating_add(grace_duration as u64)
}

// ============================================================================
// Helper Types for Unaligned Integer Access
// ============================================================================

macro_rules! le_int {
    ($name:ident, $int:ty, $n:expr) => {
        #[repr(C, packed)]
        #[derive(Clone, Copy, Pod, Zeroable, Debug, Default)]
        pub struct $name(pub [u8; $n]);

        impl $name {
            #[inline]
            pub fn get(&self) -> $int {
                <$int>::from_le_bytes(self.0)
            }

            #[inline]
            pub fn set(&mut self, value: $int) {
                self.0 = value.to_le_bytes();
            }

            #[inline]
            pub fn new(value: $int) -> Self {
                Self(value.to_le_bytes())
            }
        }
    };
}

le_int!(U32Le, u32, 4);
le_int!(U64Le, u64, 8);
le_int!(U128Le, u128, 16);

// ============================================================================
// Account Layouts
// ============================================================================

/// Zero-copy layout for config account data (200 bytes).
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       32    merkle_program_id
/// 32      24    tree_id
/// 56      32    payment_token_id
/// 88      32    receipt_token_id (credit token)
/// 120     16    price_per_unit (u128 le)
/// 136     32    treasury_account_id
/// 168     8     total_registrations (u64 le)
/// 176     8     max_total_rate_limit (u64 le)
/// 184     8     current_total_rate_limit (u64 le)
/// 192     4     active_duration_for_new_memberships (u32 le, seconds)
/// 196     4     grace_period_duration_for_new_memberships (u32 le, seconds)
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ConfigLayout {
    pub merkle_program_id: [u8; 32],
    pub tree_id: [u8; 24],
    pub payment_token_id: [u8; 32],
    pub receipt_token_id: [u8; 32],
    pub price_per_unit: U128Le,
    pub treasury_account_id: [u8; 32],
    pub total_registrations: U64Le,
    pub max_total_rate_limit: U64Le,
    pub current_total_rate_limit: U64Le,
    pub active_duration_for_new_memberships: U32Le,
    pub grace_period_duration_for_new_memberships: U32Le,
}

impl ConfigLayout {
    pub const SIZE: usize = 200;

    #[inline] pub fn parse(data: &[u8]) -> &Self { bytemuck::from_bytes(&data[..Self::SIZE]) }
    #[inline] pub fn parse_mut(data: &mut [u8]) -> &mut Self { bytemuck::from_bytes_mut(&mut data[..Self::SIZE]) }

    #[inline] pub fn price_per_unit(&self) -> u128 { self.price_per_unit.get() }
    #[inline] pub fn set_price_per_unit(&mut self, v: u128) { self.price_per_unit.set(v); }
    #[inline] pub fn total_registrations(&self) -> u64 { self.total_registrations.get() }
    #[inline] pub fn set_total_registrations(&mut self, v: u64) { self.total_registrations.set(v); }
    #[inline] pub fn max_total_rate_limit(&self) -> u64 { self.max_total_rate_limit.get() }
    #[inline] pub fn set_max_total_rate_limit(&mut self, v: u64) { self.max_total_rate_limit.set(v); }
    #[inline] pub fn current_total_rate_limit(&self) -> u64 { self.current_total_rate_limit.get() }
    #[inline] pub fn set_current_total_rate_limit(&mut self, v: u64) { self.current_total_rate_limit.set(v); }
    #[inline] pub fn active_duration_for_new_memberships(&self) -> u32 { self.active_duration_for_new_memberships.get() }
    #[inline] pub fn set_active_duration_for_new_memberships(&mut self, v: u32) { self.active_duration_for_new_memberships.set(v); }
    #[inline] pub fn grace_period_duration_for_new_memberships(&self) -> u32 { self.grace_period_duration_for_new_memberships.get() }
    #[inline] pub fn set_grace_period_duration_for_new_memberships(&mut self, v: u32) { self.grace_period_duration_for_new_memberships.set(v); }
}

const _: () = assert!(core::mem::size_of::<ConfigLayout>() == ConfigLayout::SIZE);

/// Zero-copy layout for membership account data (96 bytes).
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       8     leaf_index (u64 le)
/// 8       8     rate_limit (u64 le)
/// 16      32    id_commitment
/// 48      8     grace_period_start_timestamp (u64 le, unix seconds)
/// 56      4     active_duration (u32 le, seconds; snapshot of global at registration)
/// 60      4     grace_period_duration (u32 le, seconds; snapshot of global at registration)
/// 64      32    holder_account_id (account authorized to extend / erase during grace)
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct MembershipLayout {
    pub leaf_index: U64Le,
    pub rate_limit: U64Le,
    pub id_commitment: [u8; 32],
    pub grace_period_start_timestamp: U64Le,
    pub active_duration: U32Le,
    pub grace_period_duration: U32Le,
    pub holder_account_id: [u8; 32],
}

impl MembershipLayout {
    pub const SIZE: usize = 96;

    #[inline] pub fn parse(data: &[u8]) -> &Self { bytemuck::from_bytes(&data[..Self::SIZE]) }
    #[inline] pub fn parse_mut(data: &mut [u8]) -> &mut Self { bytemuck::from_bytes_mut(&mut data[..Self::SIZE]) }

    #[inline] pub fn leaf_index(&self) -> u64 { self.leaf_index.get() }
    #[inline] pub fn set_leaf_index(&mut self, v: u64) { self.leaf_index.set(v); }
    #[inline] pub fn rate_limit(&self) -> u64 { self.rate_limit.get() }
    #[inline] pub fn set_rate_limit(&mut self, v: u64) { self.rate_limit.set(v); }
    #[inline] pub fn grace_period_start_timestamp(&self) -> u64 { self.grace_period_start_timestamp.get() }
    #[inline] pub fn set_grace_period_start_timestamp(&mut self, v: u64) { self.grace_period_start_timestamp.set(v); }
    #[inline] pub fn active_duration(&self) -> u32 { self.active_duration.get() }
    #[inline] pub fn set_active_duration(&mut self, v: u32) { self.active_duration.set(v); }
    #[inline] pub fn grace_period_duration(&self) -> u32 { self.grace_period_duration.get() }
    #[inline] pub fn set_grace_period_duration(&mut self, v: u32) { self.grace_period_duration.set(v); }
}

const _: () = assert!(core::mem::size_of::<MembershipLayout>() == MembershipLayout::SIZE);

/// Zero-copy layout for token holding account (49 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct TokenHoldingLayout {
    pub account_type: u8,
    pub definition_id: [u8; 32],
    pub balance: U128Le,
}

impl TokenHoldingLayout {
    pub const SIZE: usize = 49;

    #[inline] pub fn parse(data: &[u8]) -> &Self { bytemuck::from_bytes(&data[..Self::SIZE]) }
    #[inline] pub fn parse_mut(data: &mut [u8]) -> &mut Self { bytemuck::from_bytes_mut(&mut data[..Self::SIZE]) }

    #[inline] pub fn balance(&self) -> u128 { self.balance.get() }
    #[inline] pub fn set_balance(&mut self, v: u128) { self.balance.set(v); }
}

const _: () = assert!(core::mem::size_of::<TokenHoldingLayout>() == TokenHoldingLayout::SIZE);

/// Zero-copy layout for token definition account (55 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct TokenDefinitionLayout {
    pub account_type: u8,
    pub name: [u8; 6],
    pub total_supply: U128Le,
    pub metadata_id: [u8; 32],
}

impl TokenDefinitionLayout {
    pub const SIZE: usize = 55;

    #[inline] pub fn parse(data: &[u8]) -> &Self { bytemuck::from_bytes(&data[..Self::SIZE]) }
    #[inline] pub fn parse_mut(data: &mut [u8]) -> &mut Self { bytemuck::from_bytes_mut(&mut data[..Self::SIZE]) }

    #[inline] pub fn total_supply(&self) -> u128 { self.total_supply.get() }
    #[inline] pub fn set_total_supply(&mut self, v: u128) { self.total_supply.set(v); }
}

const _: () = assert!(core::mem::size_of::<TokenDefinitionLayout>() == TokenDefinitionLayout::SIZE);

// ============================================================================
// Merkle Tree Constants
// ============================================================================

/// Tree depth (number of levels from root to leaves).
/// A depth of 20 supports up to 2^20 = 1,048,576 leaves.
pub const TREE_DEPTH: usize = 20;

/// Depth of the top tree (levels 0-10).
pub const TOP_DEPTH: usize = 10;

/// Depth of each bottom subtree (levels 11-20, mapped to 0-10 within subtree).
pub const BOTTOM_DEPTH: usize = 10;

/// Number of leaves per bottom subtree (2^10 = 1024).
pub const SUBTREE_LEAVES: usize = 1024;

/// Offset of depth field in main account data (1 byte).
pub const OFFSET_DEPTH: usize = 0;

/// Offset of next_index field in main account data (8 bytes, u64 le).
pub const OFFSET_NEXT_INDEX: usize = 1;

/// Offset of root hash in main account data (32 bytes).
pub const OFFSET_ROOT: usize = 9;

/// Number of previous roots stored in the root history buffer.
pub const ROOT_HISTORY_SIZE: usize = 4;

/// Offset of root history in main account data (4 × 32 = 128 bytes).
pub const OFFSET_ROOT_HISTORY: usize = 41;

/// Offset of cached default hashes in main account data (32 bytes * (depth + 1)).
pub const OFFSET_CACHED_NODES: usize = OFFSET_ROOT_HISTORY + ROOT_HISTORY_SIZE * 32;

/// Offset of top tree sparse data in main account data.
pub const OFFSET_TOP_TREE_DATA: usize = OFFSET_CACHED_NODES + (TREE_DEPTH + 1) * 32;

// ============================================================================
// PDA Seed Construction
// ============================================================================

/// Build the raw 32-byte PDA seed for the tree main account.
pub fn main_seed(tree_id: &[u8; 24]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0..24].copy_from_slice(tree_id);
    seed[24..32].copy_from_slice(b"__main__");
    seed
}

/// Build the raw 32-byte PDA seed for a bottom subtree account.
pub fn subtree_seed(tree_id: &[u8; 24], subtree_id: u32) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0..24].copy_from_slice(tree_id);
    seed[24] = 0xFF;
    seed[25..29].copy_from_slice(&subtree_id.to_le_bytes());
    seed
}

/// Build the raw 32-byte PDA seed for the config account.
pub fn config_seed(tree_id: &[u8; 24]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0..24].copy_from_slice(tree_id);
    seed[24..32].copy_from_slice(b"_config_");
    seed
}

/// Build the raw 32-byte PDA seed for the credit token definition account.
pub fn credit_token_seed(tree_id: &[u8; 24]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0..24].copy_from_slice(tree_id);
    seed[24..32].copy_from_slice(b"_receipt");
    seed
}

/// Build the raw 32-byte PDA seed for the credit supply holder account.
pub fn credit_supply_seed(tree_id: &[u8; 24]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0..24].copy_from_slice(tree_id);
    seed[24..32].copy_from_slice(b"_supply_");
    seed
}

// ============================================================================
// Account Layouts (Tree)
// ============================================================================

/// Zero-copy layout for tree main account header (169 bytes).
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       1     tree_depth
/// 1       8     next_index (u64 le)
/// 9       32    current_root
/// 41      128   root_history (4 × 32 bytes, newest at [0])
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct TreeMainLayout {
    pub tree_depth: u8,
    pub next_index: U64Le,
    pub current_root: [u8; 32],
    pub root_history: [[u8; 32]; 4],
}

impl TreeMainLayout {
    pub const SIZE: usize = 169;

    #[inline] pub fn parse(data: &[u8]) -> &Self { bytemuck::from_bytes(&data[..Self::SIZE]) }

    #[inline] pub fn next_index(&self) -> u64 { self.next_index.get() }
}

const _: () = assert!(core::mem::size_of::<TreeMainLayout>() == TreeMainLayout::SIZE);
