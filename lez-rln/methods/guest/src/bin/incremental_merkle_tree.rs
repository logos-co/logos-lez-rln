//! Incremental Merkle tree guest program.
//!
//! One actor (`tree_main`), messages from [`rln_layouts::MerkleMessage`]:
//!
//! - `Initialize`: empty tree with cached default hashes (one-shot)
//! - `Insert`: add a leaf at `next_index` (sequential)
//! - `Remove`: zero a leaf and recompute the root (`next_index` unchanged)
//! - `Set`: write a leaf into an emptied slot below `next_index`
//!
//! The logic lives in [`logos_lez_rln_guest::merkle_tree`].

lee_core::actor_entrypoint!(logos_lez_rln_guest::merkle_tree::handle_message);
