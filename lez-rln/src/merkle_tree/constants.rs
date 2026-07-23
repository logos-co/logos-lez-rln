//! Shared constants for the incremental Merkle tree.
//!
//! All constants are defined in the `rln-layouts` crate and re-exported here.

pub use rln_layouts::{
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_NEXT_INDEX, OFFSET_ROOT, OFFSET_ROOT_HISTORY,
    OFFSET_TOP_TREE_DATA, ROOT_HISTORY_SIZE, SUBTREE_LEAVES, TOP_DEPTH, TREE_DEPTH,
};
