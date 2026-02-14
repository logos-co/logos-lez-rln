//! Shared constants for the incremental Merkle tree.
//!
//! All constants are defined in the `rln-layouts` crate and re-exported here.

pub use rln_layouts::{
    TREE_DEPTH, TOP_DEPTH, SUBTREE_LEAVES,
    OFFSET_DEPTH, OFFSET_NEXT_INDEX, OFFSET_ROOT, OFFSET_CACHED_NODES, OFFSET_TOP_TREE_DATA,
};
