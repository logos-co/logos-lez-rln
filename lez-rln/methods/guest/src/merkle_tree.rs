//! Incremental Merkle tree held in a single shard.
//!
//! The tree's one account is its main PDA. The merkle program's shard of that
//! account holds, in order:
//!
//! ```text
//! 0                     TreeMainLayout header (depth, next_index, root, root_history[4])
//! OFFSET_CACHED_NODES   default hash per level, (TREE_DEPTH + 1) * 32, root level first
//! OFFSET_TREE_DATA      sparse node map for the whole tree:
//!                       [count u16le][(node_offset u16le, hash 32)...] sorted by offset
//! ```
//!
//! Node offsets are BFS indices (`rln_layouts::node_offset`): the root is
//! `(0, 0)`, leaves sit at level `TREE_DEPTH`. A node absent from the map holds
//! its level's cached default. A full tree is `TREE_SHARD_MAX_BYTES`.
//!
//! # Plan and apply
//!
//! [`plan`] sees only account metadata; it checks the one declared account and
//! emits one [`Effect`] on the tree's shard. [`apply`] sees the shard bytes and
//! does all the tree math. Every public function below the two entry points is
//! a pure function over shard bytes so the host test suite can drive it
//! without a zkVM.
//!
//! # Authorization
//!
//! Every instruction requires `is_authorized` on the tree account. The tree
//! account is a PDA of the registration program, and a PDA is authorized only
//! when its owning program chains into this one with the PDA's seeds
//! (`with_pda_seeds`) — so only the registration program can drive the tree.
//! Authorization says the caller may write the account, never that it is
//! unclaimed: `Initialize` is one-shot because its apply refuses a non-empty
//! shard.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::program::{Plan, PlanInput};
pub use rln_layouts::{
    MerkleInstruction, OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_NEXT_INDEX, OFFSET_ROOT,
    OFFSET_ROOT_HISTORY, OFFSET_TREE_DATA, ROOT_HISTORY_SIZE, SPARSE_ENTRY_LEN, TREE_DEPTH,
    TREE_LEAVES, node_offset, read_sparse_node,
};

use crate::hash::{ZERO, compute_default_hashes, hash_pair, validate_field_element};

/// What the plan asks the apply session to do to the tree's shard. Mirrors
/// [`MerkleInstruction`] one to one; it is a separate type because it is the
/// program's own plan-to-apply contract, not the wire format callers use.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Initialize,
    Insert { leaf: [u8; 32] },
    Remove { index: u64, leaf: [u8; 32] },
    Set { index: u64, leaf: [u8; 32] },
}

impl From<MerkleInstruction> for Effect {
    fn from(ix: MerkleInstruction) -> Self {
        match ix {
            MerkleInstruction::Initialize => Self::Initialize,
            MerkleInstruction::Insert { leaf } => Self::Insert { leaf },
            MerkleInstruction::Remove { index, leaf } => Self::Remove { index, leaf },
            MerkleInstruction::Set { index, leaf } => Self::Set { index, leaf },
        }
    }
}

// ============================================================================
// Entry points
// ============================================================================

/// Plan phase: exactly one account, the tree's main PDA, authorized and
/// selected on this program's own shard.
pub fn plan(input: &PlanInput, ix: MerkleInstruction) -> Plan {
    let [tree_main] = input.accounts.as_slice() else {
        panic!(
            "merkle program takes exactly one account (tree_main), got {}",
            input.accounts.len()
        );
    };
    assert!(
        tree_main.is_authorized,
        "tree account must be authorized by its owning program's pda_seeds"
    );
    assert_eq!(
        tree_main.program_account_id, input.self_account_id,
        "tree account must be selected on the merkle program's own shard"
    );

    let mut plan = Plan::new(input);
    plan.effect(tree_main, &Effect::from(ix));
    plan
}

/// Apply phase: the new shard bytes. Every effect rewrites the shard.
pub fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    Some(match effect {
        Effect::Initialize => initialize_tree(pre_data),
        Effect::Insert { leaf } => insert_leaf(pre_data, &leaf),
        Effect::Remove { index, leaf } => remove_leaf(pre_data, index, &leaf),
        Effect::Set { index, leaf } => set_leaf(pre_data, index, &leaf),
    })
}

// ============================================================================
// Tree operations
// ============================================================================

/// An empty tree: header, cached defaults, empty node map.
///
/// # Panics
/// If the shard already holds data — replaying `Initialize` against a live
/// tree would reset `next_index` and the root history, invalidating every
/// member's proof while their membership PDAs survive.
pub fn initialize_tree(pre_data: &[u8]) -> Vec<u8> {
    assert!(pre_data.is_empty(), "tree already initialized");
    create_initialized_main_account_data()
}

/// Write `leaf` at `next_index` and advance `next_index`.
///
/// The tree assigns the index: the caller never names one, so two inserts
/// planned against the same tree state land at consecutive indices instead of
/// contending for one.
///
/// # Panics
/// - the tree is full (`next_index >= TREE_LEAVES`)
/// - `leaf` is not a BN254 field element
pub fn insert_leaf(pre_data: &[u8], leaf: &[u8; 32]) -> Vec<u8> {
    check_header(pre_data);
    validate_field_element(leaf);
    let next_index = read_next_index(pre_data);
    // Node offsets are computed with no per-level bound, so an index past the
    // last leaf lands on live nodes of the level below and yields a wrong root
    // without failing.
    assert!(
        next_index < TREE_LEAVES,
        "tree is full: next_index {} is past the last leaf",
        next_index
    );

    let mut data = update_leaf(pre_data, next_index as usize, leaf);
    data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&(next_index + 1).to_le_bytes());
    data
}

/// Zero the leaf at `index`, which must hold `leaf`. `next_index` is
/// unchanged: an erased index is never reused by `Insert`.
///
/// `index` is the caller's hint and `leaf` what makes it safe: the caller
/// cannot read the tree, so the index is checked by content, and naming
/// another member's index (or a rate limit that is not the member's) removes
/// nothing.
///
/// # Panics
/// - `index >= next_index`
/// - the leaf at `index` is not `leaf`
pub fn remove_leaf(pre_data: &[u8], index: u64, leaf: &[u8; 32]) -> Vec<u8> {
    check_header(pre_data);
    let next_index = read_next_index(pre_data);
    assert!(
        index < next_index,
        "Cannot remove leaf at index {} when next_index is {}",
        index,
        next_index
    );
    let cached_nodes = extract_cached_nodes(pre_data);
    let current = read_sparse_node(
        &pre_data[OFFSET_TREE_DATA..],
        TREE_DEPTH,
        index as usize,
        &cached_nodes[TREE_DEPTH],
    );
    assert!(
        current == *leaf,
        "leaf at index {} is not this member's",
        index
    );
    update_leaf(pre_data, index as usize, &ZERO)
}

/// Write `leaf` into an emptied slot below `next_index`. `next_index` is
/// unchanged.
///
/// # Panics
/// - `index >= next_index`
/// - the slot is not empty
/// - `leaf` is not a BN254 field element
pub fn set_leaf(pre_data: &[u8], index: u64, leaf: &[u8; 32]) -> Vec<u8> {
    check_header(pre_data);
    validate_field_element(leaf);
    let next_index = read_next_index(pre_data);
    assert!(
        index < next_index,
        "Can only set at index < next_index: index {} >= next_index {}",
        index,
        next_index
    );

    let cached_nodes = extract_cached_nodes(pre_data);
    let current = read_sparse_node(
        &pre_data[OFFSET_TREE_DATA..],
        TREE_DEPTH,
        index as usize,
        &cached_nodes[TREE_DEPTH],
    );
    assert!(
        current == ZERO || current == cached_nodes[TREE_DEPTH],
        "Can only set at an empty (zeroed) index"
    );

    update_leaf(pre_data, index as usize, leaf)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// The shard holds a tree built to this program's depth.
fn check_header(data: &[u8]) {
    assert!(data.len() >= OFFSET_TREE_DATA, "tree not initialized");
    // The tree records its own depth, but every walk navigates with the
    // compile-time constants. A binary pointed at a tree built to a different
    // depth reads the wrong offsets and returns a wrong root without
    // panicking, so refuse it here instead.
    assert_eq!(
        data[OFFSET_DEPTH] as usize, TREE_DEPTH,
        "tree was built to a different depth than this program"
    );
}

/// Write `leaf` at `leaf_index`, recompute the root and push it into the
/// root history. Leaves `next_index` alone.
fn update_leaf(pre_data: &[u8], leaf_index: usize, leaf: &[u8; 32]) -> Vec<u8> {
    let cached_nodes = extract_cached_nodes(pre_data);
    let mut data = pre_data.to_vec();
    let mut nodes = data.split_off(OFFSET_TREE_DATA);
    let new_root = compute_root_after_update(*leaf, leaf_index, &mut nodes, &cached_nodes);
    push_root_history(&mut data, &new_root);
    data.extend_from_slice(&nodes);
    data
}

/// Write a hash into the sparse node map, keeping entries sorted by offset.
fn write_sparse_node(data: &mut Vec<u8>, level: usize, index: usize, hash: &[u8; 32]) {
    if data.len() < 2 {
        data.resize(2, 0);
    }
    let count = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    let target = node_offset(level, index) as u16;

    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry_start = 2 + mid * SPARSE_ENTRY_LEN;
        let entry_offset =
            u16::from_le_bytes(data[entry_start..entry_start + 2].try_into().unwrap());
        if entry_offset < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let pos = 2 + lo * SPARSE_ENTRY_LEN;

    if lo < count {
        let entry_offset = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
        if entry_offset == target {
            data[pos + 2..pos + SPARSE_ENTRY_LEN].copy_from_slice(hash);
            return;
        }
    }

    let old_len = data.len();
    data.resize(old_len + SPARSE_ENTRY_LEN, 0);
    data.copy_within(pos..old_len, pos + SPARSE_ENTRY_LEN);
    data[pos..pos + 2].copy_from_slice(&target.to_le_bytes());
    data[pos + 2..pos + SPARSE_ENTRY_LEN].copy_from_slice(hash);

    let new_count = (count + 1) as u16;
    data[0..2].copy_from_slice(&new_count.to_le_bytes());
}

/// Shift the root history down one slot (dropping the oldest), move the
/// current root into `history[0]`, and write `new_root` as current.
fn push_root_history(data: &mut [u8], new_root: &[u8; 32]) {
    let old_root: [u8; 32] = data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap();
    data.copy_within(
        OFFSET_ROOT_HISTORY..OFFSET_ROOT_HISTORY + (ROOT_HISTORY_SIZE - 1) * 32,
        OFFSET_ROOT_HISTORY + 32,
    );
    data[OFFSET_ROOT_HISTORY..OFFSET_ROOT_HISTORY + 32].copy_from_slice(&old_root);
    data[OFFSET_ROOT..OFFSET_ROOT + 32].copy_from_slice(new_root);
}

/// Cached default hash per level, indexed by level (0 = root, `TREE_DEPTH` =
/// leaf).
fn extract_cached_nodes(data: &[u8]) -> Vec<[u8; 32]> {
    (0..=TREE_DEPTH)
        .map(|i| {
            let start = OFFSET_CACHED_NODES + i * 32;
            data[start..start + 32].try_into().unwrap()
        })
        .collect()
}

/// Write `leaf_value` at `leaf_index` and every recomputed ancestor, root
/// included, into the node map; return the new root.
fn compute_root_after_update(
    leaf_value: [u8; 32],
    leaf_index: usize,
    nodes: &mut Vec<u8>,
    cached_nodes: &[[u8; 32]],
) -> [u8; 32] {
    let mut current_hash = leaf_value;
    let mut current_index = leaf_index;

    for level in (1..=TREE_DEPTH).rev() {
        write_sparse_node(nodes, level, current_index, &current_hash);

        let sibling_index = current_index ^ 1;
        let sibling_hash = read_sparse_node(nodes, level, sibling_index, &cached_nodes[level]);

        let (left, right) = if current_index.is_multiple_of(2) {
            (current_hash, sibling_hash)
        } else {
            (sibling_hash, current_hash)
        };
        current_hash = hash_pair(&left, &right);
        current_index /= 2;
    }

    write_sparse_node(nodes, 0, 0, &current_hash);
    current_hash
}

// ============================================================================
// Shard constructors and readers
// ============================================================================

/// Shard bytes of an empty, initialized tree.
pub fn create_initialized_main_account_data() -> Vec<u8> {
    let cached_nodes = compute_default_hashes(TREE_DEPTH);
    create_main_account_data_with_state(0, cached_nodes[0], &cached_nodes)
}

/// Shard bytes with the given header state and an empty node map.
pub fn create_main_account_data_with_state(
    next_index: u64,
    root: [u8; 32],
    cached_nodes: &[[u8; 32]],
) -> Vec<u8> {
    let mut data = vec![0u8; OFFSET_TREE_DATA];
    data[OFFSET_DEPTH] = TREE_DEPTH as u8;
    data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&next_index.to_le_bytes());
    data[OFFSET_ROOT..OFFSET_ROOT + 32].copy_from_slice(&root);
    for (i, level_hash) in cached_nodes.iter().enumerate() {
        let start = OFFSET_CACHED_NODES + i * 32;
        data[start..start + 32].copy_from_slice(level_hash);
    }
    data
}

/// `next_index` from shard bytes.
pub fn read_next_index(data: &[u8]) -> u64 {
    u64::from_le_bytes(
        data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
            .try_into()
            .unwrap(),
    )
}

/// Current root from shard bytes.
pub fn read_root(data: &[u8]) -> [u8; 32] {
    data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use nssa_core::{account::AccountId, program::AccountMeta};
    use rln_layouts::{SHARD_MAX_BYTES, TREE_SHARD_MAX_BYTES};

    use super::*;

    fn leaf_for(i: u64) -> [u8; 32] {
        let mut leaf = [0u8; 32];
        leaf[0..8].copy_from_slice(&i.to_le_bytes());
        leaf[8] = 0xAB;
        leaf
    }

    fn initialized() -> Vec<u8> {
        initialize_tree(&[])
    }

    /// A fresh tree with `count` sequential leaves.
    fn insert_n_leaves(count: u64) -> Vec<u8> {
        (0..count).fold(initialized(), |data, i| insert_leaf(&data, &leaf_for(i)))
    }

    // ========================================================================
    // Plan
    // ========================================================================

    fn merkle_program_id() -> AccountId {
        AccountId::new([7; 32])
    }

    fn plan_input(accounts: Vec<AccountMeta>) -> PlanInput {
        PlanInput {
            self_account_id: merkle_program_id(),
            caller_account_id: None,
            accounts,
            instruction_data: Vec::new(),
        }
    }

    fn tree_main(is_authorized: bool) -> AccountMeta {
        AccountMeta::new(AccountId::new([1; 32]), is_authorized, merkle_program_id())
    }

    #[test]
    fn test_plan_emits_one_effect_on_tree_shard() {
        let input = plan_input(vec![tree_main(true)]);
        let ix = MerkleInstruction::Insert { leaf: [5; 32] };
        let plan = plan(&input, ix);
        let effects = &plan.output().effects;
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].selector.account_id, AccountId::new([1; 32]));
        assert_eq!(effects[0].selector.program_account_id, merkle_program_id());
        let effect: Effect = borsh::from_slice(&effects[0].data).unwrap();
        assert_eq!(effect, Effect::Insert { leaf: [5; 32] });
    }

    #[test]
    #[should_panic(expected = "tree account must be authorized")]
    fn test_plan_rejects_unauthorized_tree() {
        let _ = plan(
            &plan_input(vec![tree_main(false)]),
            MerkleInstruction::Initialize,
        );
    }

    #[test]
    #[should_panic(expected = "merkle program's own shard")]
    fn test_plan_rejects_foreign_shard() {
        let foreign = AccountMeta::new(AccountId::new([1; 32]), true, AccountId::new([9; 32]));
        let _ = plan(&plan_input(vec![foreign]), MerkleInstruction::Initialize);
    }

    #[test]
    #[should_panic(expected = "exactly one account")]
    fn test_plan_rejects_extra_accounts() {
        let _ = plan(
            &plan_input(vec![tree_main(true), tree_main(true)]),
            MerkleInstruction::Initialize,
        );
    }

    #[test]
    fn test_apply_dispatches_every_effect() {
        let data = apply(Effect::Initialize, &[]).unwrap();
        let data = apply(Effect::Insert { leaf: [1; 32] }, &data).unwrap();
        assert_eq!(read_next_index(&data), 1);
        let data = apply(
            Effect::Remove {
                index: 0,
                leaf: [1; 32],
            },
            &data,
        )
        .unwrap();
        assert_eq!(read_root(&data), compute_default_hashes(TREE_DEPTH)[0]);
        let data = apply(
            Effect::Set {
                index: 0,
                leaf: [2; 32],
            },
            &data,
        )
        .unwrap();
        assert_eq!(read_next_index(&data), 1);
        assert_ne!(read_root(&data), compute_default_hashes(TREE_DEPTH)[0]);
    }

    // ========================================================================
    // Initialize
    // ========================================================================

    #[test]
    #[should_panic(expected = "tree already initialized")]
    fn test_initialize_rejects_live_tree() {
        // Replaying Initialize against a live tree would reset next_index and
        // the root history, breaking every existing member's proof. Being
        // authorized to write the account is not permission to wipe it.
        let _ = initialize_tree(&initialized());
    }

    #[test]
    fn test_initialize_empty_tree() {
        let data = initialized();
        assert_eq!(data[OFFSET_DEPTH], TREE_DEPTH as u8);
        assert_eq!(read_next_index(&data), 0);
        assert_ne!(read_root(&data), ZERO);
        assert_eq!(data.len(), OFFSET_TREE_DATA);
    }

    #[test]
    fn test_initialize_cached_defaults_correct() {
        assert_eq!(
            extract_cached_nodes(&initialized()),
            compute_default_hashes(TREE_DEPTH)
        );
    }

    #[test]
    fn test_initialize_root_matches_cached_default() {
        let data = initialized();
        let cached_level_0: [u8; 32] = data[OFFSET_CACHED_NODES..OFFSET_CACHED_NODES + 32]
            .try_into()
            .unwrap();
        assert_eq!(read_root(&data), cached_level_0);
    }

    #[test]
    #[should_panic(expected = "tree not initialized")]
    fn test_insert_into_uninitialized_shard_panics() {
        let _ = insert_leaf(&[], &[1; 32]);
    }

    // ========================================================================
    // Insert
    // ========================================================================

    #[test]
    fn test_insert_first_leaf() {
        let pre = initialized();
        let post = insert_leaf(&pre, &[42; 32]);
        assert_eq!(read_next_index(&post), 1);
        assert_ne!(read_root(&post), read_root(&pre));
        assert!(post.len() > OFFSET_TREE_DATA);
        // The previous root moves into history[0].
        assert_eq!(
            &post[OFFSET_ROOT_HISTORY..OFFSET_ROOT_HISTORY + 32],
            &read_root(&pre)
        );
    }

    /// Two inserts planned from the same tree state: the second lands at the
    /// next index, not on top of the first.
    #[test]
    fn test_insert_takes_the_index_from_the_tree() {
        let one = insert_leaf(&initialized(), &[1; 32]);
        let two = insert_leaf(&one, &[2; 32]);
        let nodes = &two[OFFSET_TREE_DATA..];
        let default = compute_default_hashes(TREE_DEPTH)[TREE_DEPTH];
        assert_eq!(read_sparse_node(nodes, TREE_DEPTH, 0, &default), [1; 32]);
        assert_eq!(read_sparse_node(nodes, TREE_DEPTH, 1, &default), [2; 32]);
    }

    #[test]
    #[should_panic(expected = "not a valid BN254 field element")]
    fn test_insert_rejects_non_field_leaf() {
        let _ = insert_leaf(&initialized(), &[0xFF; 32]);
    }

    #[test]
    #[should_panic(expected = "different depth")]
    fn test_insert_rejects_foreign_depth() {
        let mut data = initialized();
        data[OFFSET_DEPTH] = (TREE_DEPTH + 1) as u8;
        let _ = insert_leaf(&data, &[1; 32]);
    }

    #[test]
    fn test_insert_two_leaves_sequential() {
        let one = insert_leaf(&initialized(), &[1; 32]);
        let two = insert_leaf(&one, &[2; 32]);
        assert_eq!(read_next_index(&two), 2);
        assert_ne!(read_root(&two), read_root(&one));
    }

    #[test]
    fn test_root_matches_reference_tree() {
        // Rebuild the root from scratch over the leaf layer and compare.
        let n = 5u64;
        let data = insert_n_leaves(n);
        let defaults = compute_default_hashes(TREE_DEPTH);
        let mut layer: Vec<[u8; 32]> = (0..TREE_LEAVES)
            .map(|i| {
                if i < n {
                    leaf_for(i)
                } else {
                    defaults[TREE_DEPTH]
                }
            })
            .collect();
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
        }
        assert_eq!(read_root(&data), layer[0]);
        assert_eq!(
            read_sparse_node(&data[OFFSET_TREE_DATA..], 0, 0, &defaults[0]),
            layer[0]
        );
    }

    // ========================================================================
    // Remove / Set
    // ========================================================================

    #[test]
    #[should_panic(expected = "Cannot remove leaf at index 0 when next_index is 0")]
    fn test_remove_nonexistent_leaf_panics() {
        let _ = remove_leaf(&initialized(), 0, &[42; 32]);
    }

    #[test]
    fn test_remove_leaf_updates_root() {
        let inserted = insert_leaf(&initialized(), &[42; 32]);
        let removed = remove_leaf(&inserted, 0, &[42; 32]);
        assert_ne!(read_root(&removed), read_root(&inserted));
    }

    #[test]
    fn test_remove_leaf_restores_original_root() {
        let empty = initialized();
        let inserted = insert_leaf(&empty, &[42; 32]);
        let removed = remove_leaf(&inserted, 0, &[42; 32]);
        assert_eq!(read_root(&removed), read_root(&empty));
    }

    #[test]
    fn test_remove_does_not_change_next_index() {
        let inserted = insert_leaf(&initialized(), &[42; 32]);
        assert_eq!(read_next_index(&inserted), 1);
        assert_eq!(read_next_index(&remove_leaf(&inserted, 0, &[42; 32])), 1);
    }

    #[test]
    #[should_panic(expected = "leaf at index 0 is not this member's")]
    fn test_remove_refuses_a_leaf_that_is_not_the_named_one() {
        let two = insert_n_leaves(2);
        let _ = remove_leaf(&two, 0, &leaf_for(1));
    }

    /// A removed leaf reads as zero, so naming it again fails the content
    /// check instead of re-zeroing it.
    #[test]
    #[should_panic(expected = "is not this member's")]
    fn test_remove_refuses_an_already_removed_leaf() {
        let removed = remove_leaf(&insert_n_leaves(1), 0, &leaf_for(0));
        let _ = remove_leaf(&removed, 0, &leaf_for(0));
    }

    #[test]
    fn test_remove_second_leaf_of_two() {
        let two = insert_n_leaves(2);
        let removed = remove_leaf(&two, 1, &leaf_for(1));
        assert_ne!(read_root(&removed), read_root(&two));
        assert_eq!(read_root(&removed), read_root(&insert_n_leaves(1)));
    }

    #[test]
    #[should_panic(expected = "Can only set at an empty (zeroed) index")]
    fn test_set_rejects_occupied_slot() {
        let _ = set_leaf(&insert_n_leaves(1), 0, &[3; 32]);
    }

    #[test]
    #[should_panic(expected = "Can only set at index < next_index")]
    fn test_set_rejects_index_past_next_index() {
        let _ = set_leaf(&initialized(), 0, &[3; 32]);
    }

    #[test]
    fn test_set_after_remove_matches_insert() {
        let inserted = insert_leaf(&initialized(), &[3; 32]);
        let reset = set_leaf(&remove_leaf(&inserted, 0, &[3; 32]), 0, &[3; 32]);
        assert_eq!(read_root(&reset), read_root(&inserted));
        assert_eq!(read_next_index(&reset), 1);
    }

    // ========================================================================
    // Determinism / root history
    // ========================================================================

    #[test]
    fn test_same_insertions_produce_same_root() {
        assert_eq!(
            read_root(&insert_n_leaves(3)),
            read_root(&insert_n_leaves(3))
        );
    }

    #[test]
    fn test_root_history_keeps_last_four_roots() {
        let roots: Vec<[u8; 32]> = (0..=5).map(|n| read_root(&insert_n_leaves(n))).collect();
        let data = insert_n_leaves(5);
        for slot in 0..ROOT_HISTORY_SIZE {
            let start = OFFSET_ROOT_HISTORY + slot * 32;
            assert_eq!(&data[start..start + 32], &roots[4 - slot]);
        }
    }

    // ========================================================================
    // Node addressing
    // ========================================================================

    #[test]
    fn test_node_offset() {
        assert_eq!(node_offset(0, 0), 0);
        assert_eq!(node_offset(1, 0), 1);
        assert_eq!(node_offset(1, 1), 2);
        assert_eq!(node_offset(2, 0), 3);
        assert_eq!(node_offset(2, 3), 6);
        assert_eq!(node_offset(TREE_DEPTH, 0), (1 << TREE_DEPTH) - 1);
        assert_eq!(
            node_offset(TREE_DEPTH, TREE_LEAVES as usize - 1),
            (1 << (TREE_DEPTH + 1)) - 2
        );
    }

    // ========================================================================
    // Capacity / boundary
    // ========================================================================

    #[test]
    fn full_tree_fits_in_one_shard() {
        let data = insert_n_leaves(TREE_LEAVES);
        assert_eq!(read_next_index(&data), TREE_LEAVES);
        // Every node, root included, is in the map once the tree is full.
        assert_eq!(data.len(), TREE_SHARD_MAX_BYTES);
        assert!(data.len() <= SHARD_MAX_BYTES);
    }

    #[test]
    fn test_insert_at_last_index() {
        let last_index = TREE_LEAVES - 1;
        let cached_nodes = compute_default_hashes(TREE_DEPTH);
        let pre = create_main_account_data_with_state(last_index, cached_nodes[0], &cached_nodes);

        let post = insert_leaf(&pre, &[1; 32]);
        assert_eq!(read_next_index(&post), last_index + 1);
        assert_ne!(read_root(&post), cached_nodes[0]);
    }

    #[test]
    fn test_insert_and_remove_at_last_index() {
        let last_index = TREE_LEAVES - 1;
        let cached_nodes = compute_default_hashes(TREE_DEPTH);
        let pre = create_main_account_data_with_state(last_index, cached_nodes[0], &cached_nodes);

        let inserted = insert_leaf(&pre, &[1; 32]);
        let removed = remove_leaf(&inserted, last_index, &[1; 32]);
        assert_ne!(read_root(&removed), read_root(&inserted));
        assert_eq!(read_root(&removed), cached_nodes[0]);
    }

    #[test]
    fn test_first_and_last_leaf_give_different_roots() {
        let cached_nodes = compute_default_hashes(TREE_DEPTH);
        let first = insert_leaf(&initialized(), &[1; 32]);
        let last = insert_leaf(
            &create_main_account_data_with_state(TREE_LEAVES - 1, cached_nodes[0], &cached_nodes),
            &[1; 32],
        );
        assert_ne!(read_root(&first), read_root(&last));
    }

    #[test]
    #[should_panic(expected = "tree is full")]
    fn test_insert_past_the_last_leaf_is_refused() {
        let mut data = insert_leaf(&initialized(), &[1; 32]);
        data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&TREE_LEAVES.to_le_bytes());
        let _ = insert_leaf(&data, &[2; 32]);
    }

    #[test]
    fn test_full_tree_then_remove_all() {
        let empty_root = compute_default_hashes(TREE_DEPTH)[0];
        let full = insert_n_leaves(TREE_LEAVES);
        assert_ne!(read_root(&full), empty_root);

        let emptied = (0..TREE_LEAVES)
            .rev()
            .fold(full, |data, i| remove_leaf(&data, i, &leaf_for(i)));
        assert_eq!(
            read_root(&emptied),
            empty_root,
            "Removing all leaves should restore empty root"
        );
        assert_eq!(read_next_index(&emptied), TREE_LEAVES);
    }
}
