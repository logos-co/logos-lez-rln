//! Incremental Merkle Tree implementation with subtree-based storage.
//!
//! This module provides the core logic for an incremental Merkle tree that
//! splits the tree at level 10 into a top tree (levels 0-10, stored in the
//! main account) and 1024 bottom subtrees (each a complete depth-10 tree
//! in its own account).
//!
//! # Architecture
//!
//! - **Main account**: Stores tree metadata (depth, next_index, root, cached defaults)
//!   plus top tree nodes in sparse format (grows dynamically)
//! - **Bottom subtree accounts**: Each stores a depth-10 subtree in sparse format
//!
//! Each insert/remove touches exactly 2 accounts: the main account and one
//! bottom subtree account. Sparse storage format: `[count(u16le), (offset(u16le), hash(32))...]`
//!
//! # Key Formulas
//!
//! - `subtree_id = leaf_index / 1024`
//! - `local_index = leaf_index % 1024`
//! - BFS node offset: `(2^level - 1) + index_within_level`
//!
//! # Authorization
//!
//! All operations require `is_authorized = true` on the main account. This
//! ensures only the owning program (via tail call with PDA seeds) can modify
//! the tree.

use crate::hash::{ZERO, compute_default_hashes, hash_pair};
use nssa_core::account::AccountWithMetadata;
use nssa_core::program::{AccountPostState, Claim};
pub use rln_layouts::{
    TREE_DEPTH, TOP_DEPTH, BOTTOM_DEPTH, SUBTREE_LEAVES,
    OFFSET_DEPTH, OFFSET_NEXT_INDEX, OFFSET_ROOT, OFFSET_ROOT_HISTORY, ROOT_HISTORY_SIZE,
    OFFSET_CACHED_NODES, OFFSET_TOP_TREE_DATA,
};

// ============================================================================
// Sparse Node Storage
// ============================================================================

/// Compute the BFS offset for a node at (level, index_within_level).
/// Used as the key in sparse node storage.
#[inline]
fn subtree_node_offset(level: usize, index: usize) -> usize {
    ((1 << level) - 1) + index
}

/// Read a 32-byte hash from sparse tree node storage.
///
/// Format: `[count(u16le), entries...]` where each entry is `[offset(u16le), hash(32)]`.
/// Entries are sorted by offset for binary search. Returns cached_default if not found.
fn read_sparse_node(
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

    // Binary search
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry_start = 2 + mid * 34;
        let entry_offset = u16::from_le_bytes(
            data[entry_start..entry_start + 2].try_into().unwrap(),
        );
        if entry_offset < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if lo < count {
        let entry_start = 2 + lo * 34;
        let entry_offset = u16::from_le_bytes(
            data[entry_start..entry_start + 2].try_into().unwrap(),
        );
        if entry_offset == target {
            return data[entry_start + 2..entry_start + 34].try_into().unwrap();
        }
    }

    *cached_default
}

/// Write a 32-byte hash into sparse tree node storage.
///
/// Format: `[count(u16le), entries...]` where each entry is `[offset(u16le), hash(32)]`.
/// Entries are kept sorted by offset. Updates existing entries in-place, or inserts new ones.
fn write_sparse_node(
    data: &mut Vec<u8>,
    level: usize,
    index: usize,
    hash: &[u8; 32],
) {
    if data.len() < 2 {
        data.resize(2, 0);
    }
    let count = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    let target = subtree_node_offset(level, index) as u16;

    // Binary search for position
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry_start = 2 + mid * 34;
        let entry_offset = u16::from_le_bytes(
            data[entry_start..entry_start + 2].try_into().unwrap(),
        );
        if entry_offset < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let insert_pos = 2 + lo * 34;

    if lo < count {
        let entry_offset = u16::from_le_bytes(
            data[insert_pos..insert_pos + 2].try_into().unwrap(),
        );
        if entry_offset == target {
            // Update existing entry in-place
            data[insert_pos + 2..insert_pos + 34].copy_from_slice(hash);
            return;
        }
    }

    // Insert new entry: shift existing entries right
    let old_len = data.len();
    data.resize(old_len + 34, 0);
    data.copy_within(insert_pos..old_len, insert_pos + 34);
    data[insert_pos..insert_pos + 2].copy_from_slice(&target.to_le_bytes());
    data[insert_pos + 2..insert_pos + 34].copy_from_slice(hash);

    let new_count = (count + 1) as u16;
    data[0..2].copy_from_slice(&new_count.to_le_bytes());
}

// ============================================================================
// Core Operations
// ============================================================================

/// Initialize a new empty Merkle tree.
///
/// Creates the main account with:
/// - depth = TREE_DEPTH
/// - next_index = 0
/// - root = default empty tree root
/// - cached_nodes = precomputed default hashes for each level
/// - top tree data starts empty (grows dynamically on first insert)
///
/// # Arguments
/// * `pre_states` - Must contain exactly one account (the main account)
///
/// # Returns
/// Post states with the initialized main account
///
/// # Panics
/// - If `pre_states[0].is_authorized` is false
pub fn initialize_tree(pre_states: Vec<AccountWithMetadata>) -> Vec<AccountPostState> {
    let main_account = &pre_states[0];

    if !main_account.is_authorized {
        panic!("Authorization required to initialize tree");
    }

    let cached_nodes = compute_default_hashes(TREE_DEPTH);
    let root = cached_nodes[0];

    let mut data = vec![0u8; OFFSET_TOP_TREE_DATA];
    data[OFFSET_DEPTH] = TREE_DEPTH as u8;
    data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&0u64.to_le_bytes());
    data[OFFSET_ROOT..OFFSET_ROOT + 32].copy_from_slice(&root);
    for (i, level_hash) in cached_nodes.iter().enumerate() {
        let start = OFFSET_CACHED_NODES + i * 32;
        data[start..start + 32].copy_from_slice(level_hash);
    }
    // Top tree data starts empty and grows dynamically on first insert

    let mut post_account = main_account.account.clone();
    post_account.data = data.try_into().expect("Data should fit");

    vec![AccountPostState::new_claimed_if_default(post_account, Claim::Authorized)]
}

/// Insert a leaf into the Merkle tree.
///
/// # Arguments
/// * `pre_states` - `[main_account, bottom_subtree]`
/// * `instruction` - `[expected_index(8), leaf_value(32)]`
///
/// # Returns
/// Post states with updated main account and bottom subtree
///
/// # Panics
/// - If `pre_states[0].is_authorized` is false
/// - If expected_index != next_index
pub fn insert_leaf(
    pre_states: Vec<AccountWithMetadata>,
    instruction: &[u8],
) -> Vec<AccountPostState> {
    let main_account = &pre_states[0];

    if !main_account.is_authorized {
        panic!("Authorization required to insert leaf");
    }

    assert!(
        instruction.len() >= 40,
        "Instruction must contain expected_index and leaf value"
    );
    let expected_index = u64::from_le_bytes(instruction[0..8].try_into().unwrap());
    let leaf_value: [u8; 32] = instruction[8..40].try_into().unwrap();

    let main_data = main_account.account.data.as_ref();
    let depth = main_data[OFFSET_DEPTH] as usize;
    let next_index = u64::from_le_bytes(
        main_data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
            .try_into()
            .unwrap(),
    );

    assert!(
        expected_index == next_index,
        "Insert must be sequential: expected index {} but tree next_index is {}",
        expected_index,
        next_index
    );

    let next_index = next_index as usize;

    let cached_nodes = extract_cached_nodes(main_data, depth);
    let mut bottom_data = pre_states[1].account.data.as_ref().to_vec();
    let mut top_tree_data = if main_data.len() > OFFSET_TOP_TREE_DATA {
        main_data[OFFSET_TOP_TREE_DATA..].to_vec()
    } else {
        Vec::new()
    };

    let new_root = compute_root_after_update(
        leaf_value,
        next_index,
        &mut bottom_data,
        &mut top_tree_data,
        &cached_nodes,
    );

    // Build updated main account data
    let mut main_post_data = main_data[..OFFSET_TOP_TREE_DATA].to_vec();
    main_post_data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
        .copy_from_slice(&((next_index + 1) as u64).to_le_bytes());
    push_root_history(&mut main_post_data, &new_root);
    main_post_data.extend_from_slice(&top_tree_data);

    let mut main_post_account = main_account.account.clone();
    main_post_account.data = main_post_data.try_into().expect("Data fits");

    let mut subtree_post_account = pre_states[1].account.clone();
    subtree_post_account.data = bottom_data.try_into().expect("Data fits");

    vec![
        AccountPostState::new(main_post_account),
        AccountPostState::new_claimed_if_default(subtree_post_account, Claim::Authorized),
    ]
}

/// Set a leaf at a specific index (for index reuse after removal).
///
/// # Arguments
/// * `pre_states` - `[main_account, bottom_subtree]`
/// * `instruction` - `[leaf_index(8), leaf_value(32)]`
///
/// # Returns
/// Post states with updated main account and bottom subtree
///
/// # Panics
/// - If `pre_states[0].is_authorized` is false
/// - If leaf_index >= next_index
/// - If the current leaf at leaf_index is not zero
pub fn set_leaf(pre_states: Vec<AccountWithMetadata>, instruction: &[u8]) -> Vec<AccountPostState> {
    let main_account = &pre_states[0];

    if !main_account.is_authorized {
        panic!("Authorization required to set leaf");
    }

    assert!(
        instruction.len() >= 40,
        "Instruction must contain leaf_index and leaf value"
    );
    let leaf_index = u64::from_le_bytes(instruction[0..8].try_into().unwrap());
    let leaf_value: [u8; 32] = instruction[8..40].try_into().unwrap();

    let main_data = main_account.account.data.as_ref();
    let depth = main_data[OFFSET_DEPTH] as usize;
    let next_index = u64::from_le_bytes(
        main_data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
            .try_into()
            .unwrap(),
    );

    assert!(
        leaf_index < next_index,
        "Can only set at index < next_index: index {} >= next_index {}",
        leaf_index,
        next_index
    );

    let leaf_index = leaf_index as usize;

    let cached_nodes = extract_cached_nodes(main_data, depth);
    let bottom_data_ref = pre_states[1].account.data.as_ref();

    // Check that the current leaf at this index is zero
    let local_index = leaf_index % SUBTREE_LEAVES;
    let current_leaf = read_sparse_node(
        bottom_data_ref,
        BOTTOM_DEPTH,
        local_index,
        &cached_nodes[TREE_DEPTH],
    );
    assert!(
        current_leaf == ZERO || current_leaf == cached_nodes[TREE_DEPTH],
        "Can only set at an empty (zeroed) index"
    );

    let mut bottom_data = bottom_data_ref.to_vec();
    let mut top_tree_data = if main_data.len() > OFFSET_TOP_TREE_DATA {
        main_data[OFFSET_TOP_TREE_DATA..].to_vec()
    } else {
        Vec::new()
    };

    let new_root = compute_root_after_update(
        leaf_value,
        leaf_index,
        &mut bottom_data,
        &mut top_tree_data,
        &cached_nodes,
    );

    // Build updated main account data (only root changes, NOT next_index)
    let mut main_post_data = main_data[..OFFSET_TOP_TREE_DATA].to_vec();
    push_root_history(&mut main_post_data, &new_root);
    main_post_data.extend_from_slice(&top_tree_data);

    let mut main_post_account = main_account.account.clone();
    main_post_account.data = main_post_data.try_into().expect("Data fits");

    let mut subtree_post_account = pre_states[1].account.clone();
    subtree_post_account.data = bottom_data.try_into().expect("Data fits");

    vec![
        AccountPostState::new(main_post_account),
        AccountPostState::new(subtree_post_account),
    ]
}

/// Remove a leaf from the Merkle tree by setting it to zero.
///
/// # Arguments
/// * `pre_states` - `[main_account, bottom_subtree]`
/// * `instruction` - `[leaf_index(8)]`
///
/// # Returns
/// Tuple of (post_states, new_root)
///
/// # Panics
/// - If `pre_states[0].is_authorized` is false
/// - If leaf_index >= next_index
pub fn remove_leaf(
    pre_states: Vec<AccountWithMetadata>,
    instruction: &[u8],
) -> (Vec<AccountPostState>, [u8; 32]) {
    let main_account = &pre_states[0];

    if !main_account.is_authorized {
        panic!("Authorization required to remove leaf");
    }

    assert!(
        instruction.len() >= 8,
        "Instruction must contain leaf_index"
    );
    let leaf_index = u64::from_le_bytes(instruction[0..8].try_into().unwrap());

    let main_data = main_account.account.data.as_ref();
    let depth = main_data[OFFSET_DEPTH] as usize;
    let next_index = u64::from_le_bytes(
        main_data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
            .try_into()
            .unwrap(),
    );

    assert!(
        leaf_index < next_index,
        "Cannot remove leaf at index {} when next_index is {}",
        leaf_index,
        next_index
    );

    let leaf_index = leaf_index as usize;

    let cached_nodes = extract_cached_nodes(main_data, depth);
    let mut bottom_data = pre_states[1].account.data.as_ref().to_vec();
    let mut top_tree_data = if main_data.len() > OFFSET_TOP_TREE_DATA {
        main_data[OFFSET_TOP_TREE_DATA..].to_vec()
    } else {
        Vec::new()
    };

    let new_root = compute_root_after_update(
        ZERO,
        leaf_index,
        &mut bottom_data,
        &mut top_tree_data,
        &cached_nodes,
    );

    // Build updated main account data (only root changes, NOT next_index)
    let mut main_post_data = main_data[..OFFSET_TOP_TREE_DATA].to_vec();
    push_root_history(&mut main_post_data, &new_root);
    main_post_data.extend_from_slice(&top_tree_data);

    let mut main_post_account = main_account.account.clone();
    main_post_account.data = main_post_data.try_into().expect("Data fits");

    let mut subtree_post_account = pre_states[1].account.clone();
    subtree_post_account.data = bottom_data.try_into().expect("Data fits");

    let post_states = vec![
        AccountPostState::new(main_post_account),
        AccountPostState::new(subtree_post_account),
    ];

    (post_states, new_root)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Shift root history down and write the new root.
///
/// Copies `history[0..2]` → `history[1..3]` (dropping oldest), moves old
/// `current_root` into `history[0]`, then writes `new_root` as current.
fn push_root_history(data: &mut [u8], new_root: &[u8; 32]) {
    let old_root: [u8; 32] = data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap();
    // Shift history entries down (drop oldest)
    data.copy_within(
        OFFSET_ROOT_HISTORY..OFFSET_ROOT_HISTORY + (ROOT_HISTORY_SIZE - 1) * 32,
        OFFSET_ROOT_HISTORY + 32,
    );
    // Old root becomes newest history entry
    data[OFFSET_ROOT_HISTORY..OFFSET_ROOT_HISTORY + 32].copy_from_slice(&old_root);
    // Write new root
    data[OFFSET_ROOT..OFFSET_ROOT + 32].copy_from_slice(new_root);
}

/// Extract cached default hashes from main account data.
fn extract_cached_nodes(main_data: &[u8], depth: usize) -> Vec<[u8; 32]> {
    (0..=depth)
        .map(|i| {
            let start = OFFSET_CACHED_NODES + i * 32;
            main_data[start..start + 32].try_into().unwrap()
        })
        .collect()
}

/// Compute the new root after updating a leaf value.
///
/// Two-phase approach:
/// 1. **Bottom subtree** (BOTTOM_DEPTH levels): Walk local_index from leaf
///    to subtree root, reading/writing from bottom_tree_data
/// 2. **Top tree** (TOP_DEPTH levels): Walk subtree_id from its position
///    in the top tree to the overall root, reading/writing from top_tree_data
fn compute_root_after_update(
    leaf_value: [u8; 32],
    leaf_index: usize,
    bottom_tree_data: &mut Vec<u8>,
    top_tree_data: &mut Vec<u8>,
    cached_nodes: &[[u8; 32]],
) -> [u8; 32] {
    let subtree_id = leaf_index / SUBTREE_LEAVES;
    let local_index = leaf_index % SUBTREE_LEAVES;

    // Phase 1: Update bottom subtree (levels BOTTOM_DEPTH down to 1, then root at 0)
    let mut current_hash = leaf_value;
    let mut current_index = local_index;

    for bottom_level in (1..=BOTTOM_DEPTH).rev() {
        // The tree level in the full tree is TOP_DEPTH + bottom_level
        let full_level = TOP_DEPTH + bottom_level;

        // Write current node
        write_sparse_node(bottom_tree_data, bottom_level, current_index, &current_hash);

        // Get sibling
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };
        let sibling_hash = read_sparse_node(
            bottom_tree_data,
            bottom_level,
            sibling_index,
            &cached_nodes[full_level],
        );

        // Compute parent
        let (left, right) = if current_index % 2 == 0 {
            (current_hash, sibling_hash)
        } else {
            (sibling_hash, current_hash)
        };
        current_hash = hash_pair(&left, &right);
        current_index /= 2;
    }

    // Write subtree root (level 0 in bottom tree)
    write_sparse_node(bottom_tree_data, 0, 0, &current_hash);

    // Phase 2: Update top tree (the subtree root becomes a leaf in the top tree)
    // The subtree root is at position subtree_id in the leaf level of the top tree
    current_index = subtree_id;

    for top_level in (1..=TOP_DEPTH).rev() {
        // Write current node in top tree
        write_sparse_node(top_tree_data, top_level, current_index, &current_hash);

        // Get sibling
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };
        let sibling_hash = read_sparse_node(
            top_tree_data,
            top_level,
            sibling_index,
            &cached_nodes[top_level],
        );

        // Compute parent
        let (left, right) = if current_index % 2 == 0 {
            (current_hash, sibling_hash)
        } else {
            (sibling_hash, current_hash)
        };
        current_hash = hash_pair(&left, &right);
        current_index /= 2;
    }

    // Write overall root (level 0 in top tree)
    write_sparse_node(top_tree_data, 0, 0, &current_hash);

    current_hash
}

// ============================================================================
// Test Utilities
// ============================================================================

/// Create main account data for an initialized tree.
pub fn create_initialized_main_account_data() -> Vec<u8> {
    let cached_nodes = compute_default_hashes(TREE_DEPTH);
    let root = cached_nodes[0];

    let mut data = vec![0u8; OFFSET_TOP_TREE_DATA];
    data[OFFSET_DEPTH] = TREE_DEPTH as u8;
    data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&0u64.to_le_bytes());
    data[OFFSET_ROOT..OFFSET_ROOT + 32].copy_from_slice(&root);
    for (i, level_hash) in cached_nodes.iter().enumerate() {
        let start = OFFSET_CACHED_NODES + i * 32;
        data[start..start + 32].copy_from_slice(level_hash);
    }
    data
}

/// Create main account data with a specific next_index and root.
pub fn create_main_account_data_with_state(
    next_index: u64,
    root: [u8; 32],
    cached_nodes: &[[u8; 32]],
) -> Vec<u8> {
    let mut data = vec![0u8; OFFSET_TOP_TREE_DATA];
    data[OFFSET_DEPTH] = TREE_DEPTH as u8;
    data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&next_index.to_le_bytes());
    data[OFFSET_ROOT..OFFSET_ROOT + 32].copy_from_slice(&root);
    for (i, level_hash) in cached_nodes.iter().enumerate() {
        let start = OFFSET_CACHED_NODES + i * 32;
        data[start..start + 32].copy_from_slice(level_hash);
    }
    data
}

/// Read next_index from main account data.
pub fn read_next_index(main_data: &[u8]) -> u64 {
    u64::from_le_bytes(
        main_data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
            .try_into()
            .unwrap(),
    )
}

/// Read root hash from main account data.
pub fn read_root(main_data: &[u8]) -> [u8; 32] {
    main_data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ZERO;
    use nssa_core::account::Account;
    use nssa_core::account::AccountId;

    // ========================================================================
    // Test Fixtures
    // ========================================================================

    struct IdForTests;

    impl IdForTests {
        fn main_account_id() -> AccountId {
            AccountId::new([1; 32])
        }

        fn subtree_account_id() -> AccountId {
            let mut bytes = [0u8; 32];
            bytes[0] = 100;
            AccountId::new(bytes)
        }
    }

    struct AccountForTests;

    impl AccountForTests {
        fn main_empty() -> AccountWithMetadata {
            AccountWithMetadata {
                account_id: IdForTests::main_account_id(),
                account: Account::default(),
                is_authorized: true,
            }
        }

        fn main_unauthorized() -> AccountWithMetadata {
            AccountWithMetadata {
                account_id: IdForTests::main_account_id(),
                account: Account::default(),
                is_authorized: false,
            }
        }

        fn main_initialized() -> AccountWithMetadata {
            let data = create_initialized_main_account_data();
            AccountWithMetadata {
                account_id: IdForTests::main_account_id(),
                account: Account {
                    data: data.try_into().unwrap(),
                    ..Default::default()
                },
                is_authorized: true,
            }
        }

        fn main_initialized_unauthorized() -> AccountWithMetadata {
            let mut acc = Self::main_initialized();
            acc.is_authorized = false;
            acc
        }

        fn subtree_empty() -> AccountWithMetadata {
            AccountWithMetadata {
                account_id: IdForTests::subtree_account_id(),
                account: Account::default(),
                is_authorized: true,
            }
        }
    }

    /// Build instruction and pre_states for inserting a leaf at index 0.
    fn build_insert_first_leaf_data(
        main: AccountWithMetadata,
        subtree: AccountWithMetadata,
        leaf_value: [u8; 32],
    ) -> (Vec<AccountWithMetadata>, Vec<u8>) {
        let pre_states = vec![main, subtree];

        let mut instruction = Vec::with_capacity(40);
        instruction.extend_from_slice(&0u64.to_le_bytes()); // expected_index
        instruction.extend_from_slice(&leaf_value);

        (pre_states, instruction)
    }

    /// Build instruction and pre_states for inserting at a given index.
    fn build_insert_leaf_data(
        main: AccountWithMetadata,
        subtree: AccountWithMetadata,
        leaf_value: [u8; 32],
        expected_index: u64,
    ) -> (Vec<AccountWithMetadata>, Vec<u8>) {
        let pre_states = vec![main, subtree];

        let mut instruction = Vec::with_capacity(40);
        instruction.extend_from_slice(&expected_index.to_le_bytes());
        instruction.extend_from_slice(&leaf_value);

        (pre_states, instruction)
    }

    // ========================================================================
    // Authorization Tests
    // ========================================================================

    #[test]
    #[should_panic(expected = "Authorization required to initialize tree")]
    fn test_initialize_requires_authorization() {
        let pre_states = vec![AccountForTests::main_unauthorized()];
        initialize_tree(pre_states);
    }

    #[test]
    #[should_panic(expected = "Authorization required to insert leaf")]
    fn test_insert_requires_authorization() {
        let pre_states = vec![
            AccountForTests::main_initialized_unauthorized(),
            AccountForTests::subtree_empty(),
        ];
        let mut instruction = vec![0u8; 40];
        instruction[0..8].copy_from_slice(&0u64.to_le_bytes());
        insert_leaf(pre_states, &instruction);
    }

    // ========================================================================
    // Initialize Tests
    // ========================================================================

    #[test]
    fn test_initialize_empty_tree() {
        let pre_states = vec![AccountForTests::main_empty()];
        let post_states = initialize_tree(pre_states);

        assert_eq!(post_states.len(), 1);

        let post_data = post_states[0].account().data.as_ref();

        assert_eq!(post_data[OFFSET_DEPTH], TREE_DEPTH as u8);

        let next_index = read_next_index(post_data);
        assert_eq!(next_index, 0);

        let root = read_root(post_data);
        assert_ne!(root, ZERO);

        // Verify main account has metadata (top tree grows dynamically)
        assert!(post_data.len() >= OFFSET_TOP_TREE_DATA);
    }

    #[test]
    fn test_initialize_cached_defaults_correct() {
        let pre_states = vec![AccountForTests::main_empty()];
        let post_states = initialize_tree(pre_states);
        let post_data = post_states[0].account().data.as_ref();

        let mut cached_from_account = Vec::new();
        for i in 0..=TREE_DEPTH {
            let start = OFFSET_CACHED_NODES + i * 32;
            let hash: [u8; 32] = post_data[start..start + 32].try_into().unwrap();
            cached_from_account.push(hash);
        }

        let expected = compute_default_hashes(TREE_DEPTH);
        assert_eq!(cached_from_account, expected);
    }

    #[test]
    fn test_initialize_root_matches_cached_default() {
        let pre_states = vec![AccountForTests::main_empty()];
        let post_states = initialize_tree(pre_states);
        let post_data = post_states[0].account().data.as_ref();

        let root = read_root(post_data);
        let cached_level_0: [u8; 32] = post_data[OFFSET_CACHED_NODES..OFFSET_CACHED_NODES + 32]
            .try_into()
            .unwrap();

        assert_eq!(root, cached_level_0);
    }

    // ========================================================================
    // Insert Tests
    // ========================================================================

    #[test]
    fn test_insert_first_leaf() {
        let leaf_value = [42u8; 32];
        let (pre_states, instruction) = build_insert_first_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            leaf_value,
        );

        let post_states = insert_leaf(pre_states, &instruction);

        // Verify 2 post states (main + subtree)
        assert_eq!(post_states.len(), 2);

        let main_post = post_states[0].account().data.as_ref();
        assert_eq!(read_next_index(main_post), 1);

        let cached_nodes = compute_default_hashes(TREE_DEPTH);
        let old_root = cached_nodes[0];
        let new_root = read_root(main_post);
        assert_ne!(new_root, old_root);

        // Verify subtree has data
        let subtree_post = post_states[1].account().data.as_ref();
        assert!(!subtree_post.is_empty());
    }

    #[test]
    #[should_panic(expected = "Insert must be sequential")]
    fn test_insert_wrong_index_panics() {
        let leaf_value = [42u8; 32];
        let (pre_states, instruction) = build_insert_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            leaf_value,
            1, // WRONG: next_index is 0
        );

        insert_leaf(pre_states, &instruction);
    }

    #[test]
    fn test_insert_two_leaves_sequential() {
        // Insert first leaf
        let leaf1 = [1u8; 32];
        let (pre_states, instruction1) = build_insert_first_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            leaf1,
        );

        let post_states1 = insert_leaf(pre_states, &instruction1);
        let root_after_first = read_root(post_states1[0].account().data.as_ref());

        // Insert second leaf - reuse state from first insert
        let main2 = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: post_states1[0].account().clone(),
            is_authorized: true,
        };
        let subtree2 = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: post_states1[1].account().clone(),
            is_authorized: true,
        };

        let leaf2 = [2u8; 32];
        let (pre_states2, instruction2) = build_insert_leaf_data(main2, subtree2, leaf2, 1);

        let post_states2 = insert_leaf(pre_states2, &instruction2);

        let main_post = post_states2[0].account().data.as_ref();
        assert_eq!(read_next_index(main_post), 2);

        let root_after_second = read_root(main_post);
        assert_ne!(root_after_second, root_after_first);
    }

    // ========================================================================
    // Remove Tests
    // ========================================================================

    fn build_remove_leaf_data(
        main: AccountWithMetadata,
        subtree: AccountWithMetadata,
        leaf_index: u64,
    ) -> (Vec<AccountWithMetadata>, Vec<u8>) {
        let pre_states = vec![main, subtree];
        let instruction = leaf_index.to_le_bytes().to_vec();
        (pre_states, instruction)
    }

    #[test]
    #[should_panic(expected = "Authorization required to remove leaf")]
    fn test_remove_requires_authorization() {
        let pre_states = vec![
            AccountForTests::main_initialized_unauthorized(),
            AccountForTests::subtree_empty(),
        ];
        let instruction = vec![0u8; 8];
        remove_leaf(pre_states, &instruction);
    }

    #[test]
    #[should_panic(expected = "Cannot remove leaf at index 0 when next_index is 0")]
    fn test_remove_nonexistent_leaf_panics() {
        let (pre_states, instruction) = build_remove_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            0,
        );
        remove_leaf(pre_states, &instruction);
    }

    #[test]
    fn test_remove_leaf_updates_root() {
        // Insert a leaf
        let leaf_value = [42u8; 32];
        let (pre_states, instruction) = build_insert_first_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            leaf_value,
        );

        let post_states = insert_leaf(pre_states, &instruction);
        let root_after_insert = read_root(post_states[0].account().data.as_ref());

        // Remove the leaf
        let main_after_insert = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: post_states[0].account().clone(),
            is_authorized: true,
        };
        let subtree_after_insert = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: post_states[1].account().clone(),
            is_authorized: true,
        };

        let (remove_pre_states, remove_instruction) =
            build_remove_leaf_data(main_after_insert, subtree_after_insert, 0);

        let (remove_post_states, new_root) = remove_leaf(remove_pre_states, &remove_instruction);

        let root_after_remove = read_root(remove_post_states[0].account().data.as_ref());
        assert_ne!(root_after_remove, root_after_insert);
        assert_eq!(root_after_remove, new_root);
    }

    #[test]
    fn test_remove_leaf_restores_original_root() {
        let initialized = AccountForTests::main_initialized();
        let empty_root = read_root(initialized.account.data.as_ref());

        // Insert a leaf
        let leaf_value = [42u8; 32];
        let (pre_states, instruction) =
            build_insert_first_leaf_data(initialized, AccountForTests::subtree_empty(), leaf_value);

        let post_states = insert_leaf(pre_states, &instruction);

        // Remove the leaf
        let main_after_insert = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: post_states[0].account().clone(),
            is_authorized: true,
        };
        let subtree_after_insert = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: post_states[1].account().clone(),
            is_authorized: true,
        };

        let (remove_pre_states, remove_instruction) =
            build_remove_leaf_data(main_after_insert, subtree_after_insert, 0);

        let (remove_post_states, _) = remove_leaf(remove_pre_states, &remove_instruction);

        let root_after_remove = read_root(remove_post_states[0].account().data.as_ref());
        assert_eq!(root_after_remove, empty_root);
    }

    #[test]
    fn test_remove_does_not_change_next_index() {
        let leaf_value = [42u8; 32];
        let (pre_states, instruction) = build_insert_first_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            leaf_value,
        );

        let post_states = insert_leaf(pre_states, &instruction);
        assert_eq!(read_next_index(post_states[0].account().data.as_ref()), 1);

        let main_after = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: post_states[0].account().clone(),
            is_authorized: true,
        };
        let subtree_after = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: post_states[1].account().clone(),
            is_authorized: true,
        };

        let (remove_pre_states, remove_instruction) =
            build_remove_leaf_data(main_after, subtree_after, 0);

        let (remove_post_states, _) = remove_leaf(remove_pre_states, &remove_instruction);

        assert_eq!(read_next_index(remove_post_states[0].account().data.as_ref()), 1);
    }

    #[test]
    fn test_remove_second_leaf_of_two() {
        // Insert first leaf
        let leaf1 = [1u8; 32];
        let (pre_states, instruction1) = build_insert_first_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            leaf1,
        );

        let post_states1 = insert_leaf(pre_states, &instruction1);

        // Insert second leaf
        let main2 = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: post_states1[0].account().clone(),
            is_authorized: true,
        };
        let subtree2 = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: post_states1[1].account().clone(),
            is_authorized: true,
        };

        let leaf2 = [2u8; 32];
        let (pre_states2, instruction2) = build_insert_leaf_data(main2, subtree2, leaf2, 1);

        let post_states2 = insert_leaf(pre_states2, &instruction2);
        let root_after_two = read_root(post_states2[0].account().data.as_ref());

        // Remove second leaf (index 1)
        let main_after_two = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: post_states2[0].account().clone(),
            is_authorized: true,
        };
        let subtree_after_two = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: post_states2[1].account().clone(),
            is_authorized: true,
        };

        let (remove_pre_states, remove_instruction) =
            build_remove_leaf_data(main_after_two, subtree_after_two, 1);

        let (remove_post_states, _) = remove_leaf(remove_pre_states, &remove_instruction);

        let root_after_remove = read_root(remove_post_states[0].account().data.as_ref());
        assert_ne!(root_after_remove, root_after_two, "Root should change after removal");
    }

    // ========================================================================
    // Determinism Tests
    // ========================================================================

    #[test]
    fn test_same_insertions_produce_same_root() {
        let run_insertions = || {
            let leaf = [123u8; 32];
            let (pre_states, instruction) = build_insert_first_leaf_data(
                AccountForTests::main_initialized(),
                AccountForTests::subtree_empty(),
                leaf,
            );

            let post_states = insert_leaf(pre_states, &instruction);
            read_root(post_states[0].account().data.as_ref())
        };

        let root1 = run_insertions();
        let root2 = run_insertions();
        assert_eq!(root1, root2);
    }

    // ========================================================================
    // Subtree Node Addressing Tests
    // ========================================================================

    #[test]
    fn test_subtree_node_offset() {
        // Level 0 (root): offset 0
        assert_eq!(subtree_node_offset(0, 0), 0);
        // Level 1: offsets 1, 2
        assert_eq!(subtree_node_offset(1, 0), 1);
        assert_eq!(subtree_node_offset(1, 1), 2);
        // Level 2: offsets 3, 4, 5, 6
        assert_eq!(subtree_node_offset(2, 0), 3);
        assert_eq!(subtree_node_offset(2, 3), 6);
        // Level 10 (leaf level of a depth-10 tree): offset 1023 + index
        assert_eq!(subtree_node_offset(10, 0), 1023);
        assert_eq!(subtree_node_offset(10, 1023), 2046);
    }

    // ========================================================================
    // Capacity / Boundary Tests
    // ========================================================================

    /// Helper: sequentially insert `count` leaves starting from a fresh tree.
    /// Returns (main_account_data, subtree_map) where subtree_map tracks
    /// each subtree's data by subtree_id.
    fn insert_n_leaves(
        count: usize,
    ) -> (Account, std::collections::HashMap<u32, Account>) {
        use std::collections::HashMap;

        // Initialize tree
        let init_post = initialize_tree(vec![AccountForTests::main_empty()]);
        let mut main_account = init_post[0].account().clone();
        let mut subtrees: HashMap<u32, Account> = HashMap::new();

        for i in 0..count {
            let subtree_id = (i / SUBTREE_LEAVES) as u32;

            let subtree_account = subtrees
                .get(&subtree_id)
                .cloned()
                .unwrap_or_default();

            let mut instruction = Vec::with_capacity(40);
            instruction.extend_from_slice(&(i as u64).to_le_bytes());
            // Unique leaf value per index
            let mut leaf = [0u8; 32];
            leaf[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            leaf[8] = 0xAB; // marker
            instruction.extend_from_slice(&leaf);

            let pre_states = vec![
                AccountWithMetadata {
                    account_id: IdForTests::main_account_id(),
                    account: main_account,
                    is_authorized: true,
                },
                AccountWithMetadata {
                    account_id: IdForTests::subtree_account_id(),
                    account: subtree_account,
                    is_authorized: true,
                },
            ];

            let post_states = insert_leaf(pre_states, &instruction);
            main_account = post_states[0].account().clone();
            subtrees.insert(subtree_id, post_states[1].account().clone());
        }

        (main_account, subtrees)
    }

    #[test]
    fn test_fill_complete_subtree() {
        // Fill all 1024 leaves in subtree 0
        let (main_account, subtrees) = insert_n_leaves(SUBTREE_LEAVES);

        let main_data = main_account.data.as_ref();
        assert_eq!(read_next_index(main_data), SUBTREE_LEAVES as u64);

        // Only subtree 0 should exist
        assert_eq!(subtrees.len(), 1);
        assert!(subtrees.contains_key(&0));

        // Root should differ from empty tree
        let empty_root = compute_default_hashes(TREE_DEPTH)[0];
        assert_ne!(read_root(main_data), empty_root);

        // Verify the subtree has non-empty data
        let subtree_data = subtrees[&0].data.as_ref();
        assert!(!subtree_data.is_empty());
    }

    #[test]
    fn test_insert_crosses_subtree_boundary() {
        // Insert 1025 leaves: fills subtree 0 (1024 leaves) + 1 leaf in subtree 1
        let (main_account, subtrees) = insert_n_leaves(SUBTREE_LEAVES + 1);

        let main_data = main_account.data.as_ref();
        assert_eq!(read_next_index(main_data), (SUBTREE_LEAVES + 1) as u64);

        // Two subtrees should exist
        assert_eq!(subtrees.len(), 2);
        assert!(subtrees.contains_key(&0));
        assert!(subtrees.contains_key(&1));
    }

    #[test]
    fn test_insert_at_last_index() {
        // Craft state with next_index = 2^20 - 1 (last valid index)
        let last_index: u64 = (1u64 << TREE_DEPTH) - 1;
        let cached_nodes = compute_default_hashes(TREE_DEPTH);

        let main_data = create_main_account_data_with_state(
            last_index,
            cached_nodes[0], // root doesn't matter for this test
            &cached_nodes,
        );

        let main_account = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: Account {
                data: main_data.try_into().unwrap(),
                ..Default::default()
            },
            is_authorized: true,
        };

        let subtree_account = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: Account::default(),
            is_authorized: true,
        };

        let mut instruction = Vec::with_capacity(40);
        instruction.extend_from_slice(&last_index.to_le_bytes());
        let leaf = [0xFFu8; 32];
        instruction.extend_from_slice(&leaf);

        let post_states = insert_leaf(vec![main_account, subtree_account], &instruction);

        let main_post = post_states[0].account().data.as_ref();
        assert_eq!(read_next_index(main_post), last_index + 1);

        // Root should differ from default (we inserted a non-zero leaf)
        assert_ne!(read_root(main_post), cached_nodes[0]);

        // Verify subtree_id = last_index / 1024 = 1023
        let expected_subtree_id = (last_index / SUBTREE_LEAVES as u64) as u32;
        assert_eq!(expected_subtree_id, 1023);

        // Subtree should have data
        let subtree_post = post_states[1].account().data.as_ref();
        assert!(!subtree_post.is_empty());
    }

    #[test]
    fn test_insert_and_remove_at_last_index() {
        // Insert at last index, then remove — root should restore
        let last_index: u64 = (1u64 << TREE_DEPTH) - 1;
        let cached_nodes = compute_default_hashes(TREE_DEPTH);

        let main_data = create_main_account_data_with_state(
            last_index,
            cached_nodes[0],
            &cached_nodes,
        );

        let main_account = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: Account {
                data: main_data.try_into().unwrap(),
                ..Default::default()
            },
            is_authorized: true,
        };

        let subtree_account = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: Account::default(),
            is_authorized: true,
        };

        // Insert
        let mut insert_instr = Vec::with_capacity(40);
        insert_instr.extend_from_slice(&last_index.to_le_bytes());
        insert_instr.extend_from_slice(&[0xFFu8; 32]);

        let post_insert = insert_leaf(
            vec![main_account, subtree_account],
            &insert_instr,
        );
        let root_after_insert = read_root(post_insert[0].account().data.as_ref());

        // Remove
        let remove_instr = last_index.to_le_bytes().to_vec();
        let main_after = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: post_insert[0].account().clone(),
            is_authorized: true,
        };
        let subtree_after = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: post_insert[1].account().clone(),
            is_authorized: true,
        };

        let (post_remove, _) = remove_leaf(vec![main_after, subtree_after], &remove_instr);

        let root_after_remove = read_root(post_remove[0].account().data.as_ref());
        assert_ne!(root_after_remove, root_after_insert);
        // Should restore to the empty-tree root (since all other leaves are zero)
        assert_eq!(root_after_remove, cached_nodes[0]);
    }

    #[test]
    fn test_multiple_subtrees_independent_roots() {
        // Insert 1 leaf in subtree 0, record root.
        // Insert 1 leaf in subtree 1 (index 1024), record root.
        // They should differ (both leaves are distinct).
        let cached_nodes = compute_default_hashes(TREE_DEPTH);

        // Insert leaf at index 0
        let (pre_states, instr) = build_insert_first_leaf_data(
            AccountForTests::main_initialized(),
            AccountForTests::subtree_empty(),
            [1u8; 32],
        );
        let post1 = insert_leaf(pre_states, &instr);
        let root_one_leaf_subtree0 = read_root(post1[0].account().data.as_ref());

        // Now insert at index 1024 (subtree 1) using a fresh subtree account
        // but carrying forward the main account from above
        let main_data = post1[0].account().data.as_ref();
        // Set next_index to 1024 to skip the rest of subtree 0
        let mut modified_main = main_data.to_vec();
        modified_main[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
            .copy_from_slice(&1024u64.to_le_bytes());

        let main_for_subtree1 = AccountWithMetadata {
            account_id: IdForTests::main_account_id(),
            account: Account {
                data: modified_main.try_into().unwrap(),
                ..Default::default()
            },
            is_authorized: true,
        };
        let fresh_subtree1 = AccountWithMetadata {
            account_id: IdForTests::subtree_account_id(),
            account: Account::default(),
            is_authorized: true,
        };

        let mut instr2 = Vec::with_capacity(40);
        instr2.extend_from_slice(&1024u64.to_le_bytes());
        instr2.extend_from_slice(&[2u8; 32]);

        let post2 = insert_leaf(vec![main_for_subtree1, fresh_subtree1], &instr2);
        let root_two_subtrees = read_root(post2[0].account().data.as_ref());

        // Roots should differ — second insert added a leaf in a different subtree
        assert_ne!(root_one_leaf_subtree0, root_two_subtrees);
        // Both should differ from empty
        assert_ne!(root_one_leaf_subtree0, cached_nodes[0]);
        assert_ne!(root_two_subtrees, cached_nodes[0]);
    }

    #[test]
    fn test_full_subtree_then_remove_all() {
        // Fill subtree 0, then remove all leaves — root should restore to empty
        let cached_nodes = compute_default_hashes(TREE_DEPTH);
        let empty_root = cached_nodes[0];

        let (main_account, subtrees) = insert_n_leaves(SUBTREE_LEAVES);
        let root_after_fill = read_root(main_account.data.as_ref());
        assert_ne!(root_after_fill, empty_root);

        // Remove all 1024 leaves in reverse order
        let mut current_main = main_account;
        let mut current_subtree = subtrees[&0].clone();

        for i in (0..SUBTREE_LEAVES).rev() {
            let remove_instr = (i as u64).to_le_bytes().to_vec();

            let pre_states = vec![
                AccountWithMetadata {
                    account_id: IdForTests::main_account_id(),
                    account: current_main,
                    is_authorized: true,
                },
                AccountWithMetadata {
                    account_id: IdForTests::subtree_account_id(),
                    account: current_subtree,
                    is_authorized: true,
                },
            ];

            let (post_states, _) = remove_leaf(pre_states, &remove_instr);
            current_main = post_states[0].account().clone();
            current_subtree = post_states[1].account().clone();
        }

        let final_root = read_root(current_main.data.as_ref());
        assert_eq!(final_root, empty_root, "Removing all leaves should restore empty root");
        // next_index should still be 1024 (removals don't decrement it)
        assert_eq!(read_next_index(current_main.data.as_ref()), SUBTREE_LEAVES as u64);
    }
}
