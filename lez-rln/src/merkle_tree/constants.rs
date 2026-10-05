//! Shared constants for the incremental Merkle tree.
//!
//! All constants are defined in the `rln-layouts` crate and re-exported here.

pub use rln_layouts::{
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_NEXT_INDEX, OFFSET_ROOT, OFFSET_ROOT_HISTORY,
    OFFSET_TREE_DATA, ROOT_HISTORY_SIZE, TREE_DEPTH, TREE_LEAVES,
};
