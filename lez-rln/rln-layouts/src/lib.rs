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

pub mod spel_pda;
pub use spel_pda::{combine_seeds, label_seed, u32_seed};

pub mod state;
pub use state::{ConfigState, MembershipState};

pub mod instruction;
pub use instruction::Instruction;

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
        }
    };
}

le_int!(U32Le, u32, 4);
le_int!(U64Le, u64, 8);
le_int!(U128Le, u128, 16);

// ============================================================================
// Account Layouts
// ============================================================================

/// Zero-copy layout for config account data (240 bytes, SPEL Borsh-compatible).
///
/// Matches `ConfigState` in `state.rs`. Borsh encodes fixed-size fields in
/// declaration order with no length prefixes, so the byte layout is identical
/// to `#[repr(C, packed)]`.
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       32    merkle_program_id
/// 32      32    tree_id
/// 64      32    payment_token_id
/// 96      32    receipt_token_id (credit token)
/// 128     16    price_per_unit (u128 le)
/// 144     32    treasury_account_id
/// 176     8     total_registrations (u64 le)
/// 184     8     max_total_rate_limit (u64 le)
/// 192     8     current_total_rate_limit (u64 le)
/// 200     4     active_duration_for_new_memberships (u32 le, seconds)
/// 204     4     grace_period_duration_for_new_memberships (u32 le, seconds)
/// 208     32    token_program_id
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ConfigLayout {
    pub merkle_program_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub payment_token_id: [u8; 32],
    pub receipt_token_id: [u8; 32],
    pub price_per_unit: U128Le,
    pub treasury_account_id: [u8; 32],
    pub total_registrations: U64Le,
    pub max_total_rate_limit: U64Le,
    pub current_total_rate_limit: U64Le,
    pub active_duration_for_new_memberships: U32Le,
    pub grace_period_duration_for_new_memberships: U32Le,
    pub token_program_id: [u8; 32],
}

impl ConfigLayout {
    pub const SIZE: usize = 240;

    #[inline] pub fn parse(data: &[u8]) -> &Self { bytemuck::from_bytes(&data[..Self::SIZE]) }
}

const _: () = assert!(core::mem::size_of::<ConfigLayout>() == ConfigLayout::SIZE);

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

    #[inline] pub fn balance(&self) -> u128 { self.balance.get() }
}

const _: () = assert!(core::mem::size_of::<TokenHoldingLayout>() == TokenHoldingLayout::SIZE);

// ============================================================================
// Merkle Tree Opcodes
// ============================================================================

/// Opcodes for the incremental merkle tree program.
///
/// The opcode is the first byte of `instruction_data` passed to the merkle
/// program. Numeric values are part of the cross-program wire format and MUST
/// NOT be changed without coordinated guest+host updates.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleOpcode {
    Initialize = 0,
    Insert = 1,
    Remove = 2,
    Set = 3,
}

impl MerkleOpcode {
    /// Decode an opcode byte. Returns `None` for unknown values.
    #[inline]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Initialize),
            1 => Some(Self::Insert),
            2 => Some(Self::Remove),
            3 => Some(Self::Set),
            _ => None,
        }
    }
}

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
/// SPEL scheme: `combine_seeds([label_seed("main"), tree_id])`.
pub fn main_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
}

/// Build the raw 32-byte PDA seed for a bottom subtree account.
/// SPEL scheme: `combine_seeds([label_seed("subtree"), tree_id, u32_seed(subtree_id)])`.
pub fn subtree_seed(tree_id: &[u8; 32], subtree_id: u32) -> [u8; 32] {
    combine_seeds(&[&label_seed("subtree"), tree_id, &u32_seed(subtree_id)])
}

/// Build the raw 32-byte PDA seed for the config account.
/// SPEL scheme: `combine_seeds([label_seed("config"), tree_id])`.
pub fn config_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("config"), tree_id])
}

/// Build the raw 32-byte PDA seed for a per-member membership account.
/// SPEL scheme: `combine_seeds([label_seed("membership"), tree_id, id_commitment])`.
pub fn membership_seed(tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("membership"), tree_id, id_commitment])
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
