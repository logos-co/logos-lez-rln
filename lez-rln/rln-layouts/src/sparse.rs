//! Sparse node storage used by the top tree and bottom subtrees.
//!
//! Format: `[count(u16le), (offset(u16le), hash(32))...]` sorted by offset so
//! reads are a binary search. Shared by the guest program, the host client,
//! and the C FFI so all three agree on the on-chain encoding.

/// BFS index of a node at `(level, index_within_level)` within its (sub)tree.
#[inline]
pub fn subtree_node_offset(level: usize, index: usize) -> usize {
    ((1 << level) - 1) + index
}

/// Binary-search a sparse entry list for the node at `(level, index)`.
/// Returns `*cached_default` when the entry is absent or the buffer is empty.
pub fn read_sparse_node(
    data: &[u8],
    level: usize,
    index: usize,
    cached_default: &[u8; 32],
) -> [u8; 32] {
    if data.len() < 2 {
        return *cached_default;
    }
    let count = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    if count == 0 {
        return *cached_default;
    }
    let target = subtree_node_offset(level, index) as u16;

    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry_start = 2 + mid * 34;
        let entry_offset =
            u16::from_le_bytes(data[entry_start..entry_start + 2].try_into().unwrap());
        if entry_offset < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if lo < count {
        let entry_start = 2 + lo * 34;
        let entry_offset =
            u16::from_le_bytes(data[entry_start..entry_start + 2].try_into().unwrap());
        if entry_offset == target {
            return data[entry_start + 2..entry_start + 34].try_into().unwrap();
        }
    }

    *cached_default
}
