//! Shared layouts for RLN registration.
//!
//! This crate provides `#[repr(C, packed)]` structs for direct memory mapping
//! with `bytemuck`, the Borsh `Instruction` enums of both guest programs, and
//! the merkle shard layout — everything the host and the guests must agree on
//! byte for byte.
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
pub use sparse::{node_offset, read_sparse_node};

pub mod spel_pda;
pub use spel_pda::{combine_seeds, label_seed, u32_seed};

pub mod state;
pub use state::{ConfigState, MembershipState};

pub mod instruction;
pub use instruction::{Instruction, MerkleInstruction};

pub mod exit;

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

/// Prefix `lee_core::AccountId::from_builtin_program_name` hashes ahead of a
/// builtin program's name. Mirrored here so the host tooling and the guests
/// can name a builtin's shard without depending on `lee_core`.
pub const BUILTIN_PROGRAM_NAME_PREFIX: [u8; 32] = *b"/LEE-BuiltinProgram/v1/AccountId";

/// Account id of a builtin program addressed by name:
/// `SHA-256(BUILTIN_PROGRAM_NAME_PREFIX || name)`.
pub fn builtin_program_account_id(name: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(BUILTIN_PROGRAM_NAME_PREFIX);
    h.update(name);
    h.finalize().into()
}

/// The clock program's account id — the shard on `CLOCK_50` that holds
/// `ClockAccountData`.
pub fn clock_program_account_id() -> [u8; 32] {
    builtin_program_account_id(b"clock")
}

pub const MILLIS_PER_SECOND: u64 = 1_000;

#[inline]
pub const fn secs_to_millis(secs: u32) -> u64 {
    secs as u64 * MILLIS_PER_SECOND
}

// ============================================================================
// Expiration helpers
// ============================================================================

/// Returns true iff `now_ms` falls inside
/// `[grace_start_ms, grace_start_ms + grace_duration_ms)`.
#[inline]
pub fn is_in_grace_period(grace_start_ms: u64, grace_duration_ms: u64, now_ms: u64) -> bool {
    grace_start_ms <= now_ms && now_ms < grace_start_ms.saturating_add(grace_duration_ms)
}

/// Returns true iff `now_ms >= grace_start_ms + grace_duration_ms`.
#[inline]
pub fn is_expired(grace_start_ms: u64, grace_duration_ms: u64, now_ms: u64) -> bool {
    now_ms >= grace_start_ms.saturating_add(grace_duration_ms)
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
// Merkle Tree Constants
// ============================================================================

/// Tree depth (number of levels from root to leaves), so the registry holds up
/// to `2^TREE_DEPTH` members.
///
/// Depth is a *cost* decision, not a capacity one. LEZ meters a charged
/// transaction by its declared gas limit at one gas per cycle and caps that at
/// ten million, summed over every plan and apply session the transaction
/// runs, and an insert costs one Poseidon compression — about 902,000
/// cycles — per level. A register transaction spends roughly a million of its
/// budget on the registration guest's own sessions before the insert starts,
/// so the tree can afford nine or ten levels and no more. Depth 20, which this
/// was, costs 18.1M and cannot be included in any block.
pub const TREE_DEPTH: usize = 9;

/// Leaves the tree holds (`2^TREE_DEPTH`).
///
/// `next_index` only ever advances and an erased leaf's index is never reused,
/// so this bounds the registry's lifetime registrations, not its concurrent
/// members.
pub const TREE_LEAVES: u64 = 1 << TREE_DEPTH;

// Sparse node offsets are cast to u16. The largest offset in a tree of depth D
// is 2^(D+1) - 2, so above 15 distinct nodes collapse onto the same slot and
// the tree silently returns a wrong root.
const _: () = assert!(
    TREE_DEPTH <= 15,
    "sparse node offsets are u16, so the tree may not exceed depth 15"
);

/// Number of nodes in the whole tree (`2^(TREE_DEPTH+1) - 1`).
pub const TREE_NODES: usize = (1 << (TREE_DEPTH + 1)) - 1;

/// Bytes one sparse entry occupies: `offset(u16le) || hash(32)`.
pub const SPARSE_ENTRY_LEN: usize = 34;

/// Largest the merkle shard can grow: the header plus every node populated.
pub const TREE_SHARD_MAX_BYTES: usize = OFFSET_TREE_DATA + 2 + TREE_NODES * SPARSE_ENTRY_LEN;

/// `lee_core`'s per-shard data cap (`DATA_MAX_LENGTH`).
pub const SHARD_MAX_BYTES: usize = 100 * 1024;

// The whole tree lives in one shard, so a full tree must fit under the
// protocol's cap or the last inserts fail with a data-length error.
const _: () = assert!(
    TREE_SHARD_MAX_BYTES <= SHARD_MAX_BYTES,
    "a full tree must fit in one shard"
);

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

/// Offset of the whole-tree sparse node map in the merkle shard.
pub const OFFSET_TREE_DATA: usize = OFFSET_CACHED_NODES + (TREE_DEPTH + 1) * 32;

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

    #[inline]
    pub fn parse(data: &[u8]) -> &Self {
        bytemuck::from_bytes(&data[..Self::SIZE])
    }

    #[inline]
    pub fn next_index(&self) -> u64 {
        self.next_index.get()
    }
}

const _: () = assert!(core::mem::size_of::<TreeMainLayout>() == TreeMainLayout::SIZE);
