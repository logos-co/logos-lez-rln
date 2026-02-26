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

// ============================================================================
// Instruction Enum
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Instruction {
    Initialize {
        registration_program_id: [u8; 32],
        merkle_program_id: [u8; 32],
        tree_id: [u8; 24],
        payment_token_id: [u8; 32],
        price_per_unit: u128,
        treasury_account_id: [u8; 32],
        token_program_id: [u8; 32],
        max_total_rate_limit: u64,
    },
    Register {
        registration_program_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
    },
    BuyCredits {
        amount: u128,
    },
    RegisterWithCredits {
        registration_program_id: [u8; 32],
        id_commitment: [u8; 32],
        amount_to_burn: u64,
    },
    Slash {
        identity_secret: [u8; 32],
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
// Helper Types for Unaligned Integer Access
// ============================================================================

/// Little-endian u64 stored as bytes (for unaligned access in packed structs).
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable, Debug, Default)]
pub struct U64Le(pub [u8; 8]);

impl U64Le {
    #[inline]
    pub fn get(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    #[inline]
    pub fn set(&mut self, value: u64) {
        self.0 = value.to_le_bytes();
    }

    #[inline]
    pub fn new(value: u64) -> Self {
        Self(value.to_le_bytes())
    }
}

/// Little-endian u128 stored as bytes (for unaligned access in packed structs).
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable, Debug, Default)]
pub struct U128Le(pub [u8; 16]);

impl U128Le {
    #[inline]
    pub fn get(&self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    #[inline]
    pub fn set(&mut self, value: u128) {
        self.0 = value.to_le_bytes();
    }

    #[inline]
    pub fn new(value: u128) -> Self {
        Self(value.to_le_bytes())
    }
}

// ============================================================================
// Account Layouts
// ============================================================================

/// Zero-copy layout for config account data (192 bytes).
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
}

impl ConfigLayout {
    pub const SIZE: usize = 192;

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
}

const _: () = assert!(core::mem::size_of::<ConfigLayout>() == ConfigLayout::SIZE);

/// Zero-copy layout for membership account data (48 bytes).
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       8     leaf_index (u64 le)
/// 8       8     rate_limit (u64 le)
/// 16      32    id_commitment
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct MembershipLayout {
    pub leaf_index: U64Le,
    pub rate_limit: U64Le,
    pub id_commitment: [u8; 32],
}

impl MembershipLayout {
    pub const SIZE: usize = 48;

    #[inline] pub fn parse(data: &[u8]) -> &Self { bytemuck::from_bytes(&data[..Self::SIZE]) }
    #[inline] pub fn parse_mut(data: &mut [u8]) -> &mut Self { bytemuck::from_bytes_mut(&mut data[..Self::SIZE]) }

    #[inline] pub fn leaf_index(&self) -> u64 { self.leaf_index.get() }
    #[inline] pub fn set_leaf_index(&mut self, v: u64) { self.leaf_index.set(v); }
    #[inline] pub fn rate_limit(&self) -> u64 { self.rate_limit.get() }
    #[inline] pub fn set_rate_limit(&mut self, v: u64) { self.rate_limit.set(v); }
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
