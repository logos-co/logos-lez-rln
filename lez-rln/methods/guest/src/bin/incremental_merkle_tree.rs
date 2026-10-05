//! Incremental Merkle tree guest program.
//!
//! One account (`tree_main`), one shard, instructions from
//! [`rln_layouts::MerkleInstruction`]:
//!
//! - `Initialize`: empty tree with cached default hashes (one-shot)
//! - `Insert`: add a leaf at `next_index` (sequential)
//! - `Remove`: zero a leaf and recompute the root (`next_index` unchanged)
//! - `Set`: write a leaf into an emptied slot below `next_index`
//!
//! The logic lives in [`logos_lez_rln_guest::merkle_tree`].

use logos_lez_rln_guest::merkle_tree::{self, Effect};
use rln_layouts::MerkleInstruction;

fn main() {
    nssa_core::program::run_program::<MerkleInstruction, Effect, [u8], Vec<u8>>(
        merkle_tree::plan,
        merkle_tree::apply,
    )
}
