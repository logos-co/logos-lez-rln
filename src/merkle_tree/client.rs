//! Client-side operations for the incremental Merkle tree.
//!
//! This module provides:
//! - Functions for fetching tree state from chain
//! - Merkle proof generation
//!
//! Note: Tree operations (initialize, insert, remove) are performed via chained
//! calls from the RLN registration program, not directly by clients.

use std::time::Duration;

use nssa::program::Program;
use rln::prelude::Fr;
use rln::utils::bytes_le_to_fr;
use tokio::time::sleep;
use wallet::WalletCore;

use super::{
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_NEXT_INDEX, OFFSET_ROOT,
    OFFSET_TOP_TREE_DATA, TREE_DEPTH, TOP_DEPTH,
    derive_main_account, derive_subtree_account,
};

// ============================================================================
// Parsed Tree State
// ============================================================================

/// Parsed tree main account data.
#[derive(Debug, Clone)]
pub struct ParsedTreeMain {
    pub depth: u8,
    pub next_index: u64,
    pub root: [u8; 32],
}

impl ParsedTreeMain {
    /// Parse tree main from account data bytes.
    ///
    /// # Panics
    /// Panics if data is too short.
    pub fn from_bytes(data: &[u8]) -> Self {
        assert!(
            data.len() >= OFFSET_ROOT + 32,
            "Tree main data too short: need at least {} bytes, got {}",
            OFFSET_ROOT + 32,
            data.len()
        );

        Self {
            depth: data[OFFSET_DEPTH],
            next_index: u64::from_le_bytes(
                data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].try_into().unwrap()
            ),
            root: data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap(),
        }
    }
}

// ============================================================================
// Sparse Node Reading
// ============================================================================

/// Computes the BFS offset for a node within a subtree (or the top tree).
/// Used as the key in sparse node storage.
pub fn subtree_node_offset(level: usize, index: usize) -> usize {
    ((1 << level) - 1) + index
}

/// Read a node from sparse tree storage format.
///
/// Format: `[count(u16le), (offset(u16le), hash(32bytes))...]`
/// Entries are sorted by offset. Returns cached_default if not found.
pub fn read_sparse_node(data: &[u8], level: usize, index: usize, cached_default: &[u8; 32]) -> [u8; 32] {
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

// ============================================================================
// Tree State Reading
// ============================================================================

/// Fetches the current next_index from the main tree account.
pub async fn fetch_next_index(
    wallet_core: &WalletCore,
    program: &Program,
    tree_id: &[u8; 24],
) -> u64 {
    let main_account_id = derive_main_account(&program.id(), tree_id);

    let account = wallet_core
        .get_account_public(main_account_id)
        .await
        .expect("Failed to fetch main tree account. Is the tree initialized?");

    ParsedTreeMain::from_bytes(account.data.as_ref()).next_index
}

/// Fetches the current root from the main tree account.
pub async fn fetch_root(
    wallet_core: &WalletCore,
    program: &Program,
    tree_id: &[u8; 24],
) -> [u8; 32] {
    let main_account_id = derive_main_account(&program.id(), tree_id);

    let account = wallet_core
        .get_account_public(main_account_id)
        .await
        .expect("Failed to fetch main tree account");

    ParsedTreeMain::from_bytes(account.data.as_ref()).root
}

/// Fetches the cached default hashes from the main tree account.
pub async fn fetch_cached_defaults(
    wallet_core: &WalletCore,
    program: &Program,
    tree_id: &[u8; 24],
) -> Vec<[u8; 32]> {
    let main_account_id = derive_main_account(&program.id(), tree_id);

    let account = wallet_core
        .get_account_public(main_account_id)
        .await
        .expect("Failed to fetch main tree account");

    let main_data = account.data.as_ref();
    let depth = main_data[OFFSET_DEPTH] as usize;

    (0..=depth)
        .map(|i| {
            let start = OFFSET_CACHED_NODES + i * 32;
            main_data[start..start + 32].try_into().unwrap()
        })
        .collect()
}

/// Fetches a node hash from the tree.
///
/// For the full tree (depth 20), nodes at levels 0-10 are in the top tree
/// (stored in the main account), and nodes at levels 11-20 are in bottom
/// subtree accounts.
///
/// Returns the cached default if the node doesn't exist or is zero.
pub async fn fetch_node_hash(
    wallet_core: &WalletCore,
    program: &Program,
    tree_id: &[u8; 24],
    level: u8,
    node_index: u64,
    cached_defaults: &[[u8; 32]],
) -> [u8; 32] {
    let level = level as usize;

    if level <= TOP_DEPTH {
        // Node is in top tree (sparse format stored in main account after OFFSET_TOP_TREE_DATA)
        let main_account_id = derive_main_account(&program.id(), tree_id);
        match wallet_core.get_account_public(main_account_id).await {
            Ok(account) => {
                let data = account.data.as_ref();
                let top_tree_data = if data.len() > OFFSET_TOP_TREE_DATA {
                    &data[OFFSET_TOP_TREE_DATA..]
                } else {
                    &[]
                };
                read_sparse_node(top_tree_data, level, node_index as usize, &cached_defaults[level])
            }
            Err(_) => cached_defaults[level],
        }
    } else {
        // Node is in a bottom subtree (sparse format)
        let bottom_level = level - TOP_DEPTH;
        let nodes_per_subtree_at_level = 1usize << bottom_level;
        let subtree_id = (node_index as usize / nodes_per_subtree_at_level) as u32;
        let local_index = node_index as usize % nodes_per_subtree_at_level;

        let subtree_account_id = derive_subtree_account(&program.id(), tree_id, subtree_id);
        match wallet_core.get_account_public(subtree_account_id).await {
            Ok(account) => {
                let data = account.data.as_ref();
                read_sparse_node(data, bottom_level, local_index, &cached_defaults[level])
            }
            Err(_) => cached_defaults[level],
        }
    }
}

/// Waits for a leaf to appear on-chain after insertion.
///
/// Polls until the leaf is visible or timeout is reached.
pub async fn wait_for_leaf(
    wallet_core: &WalletCore,
    program: &Program,
    tree_id: &[u8; 24],
    leaf_index: u64,
    expected_leaf: &[u8; 32],
    max_attempts: u32,
    poll_interval: Duration,
) -> bool {
    let cached_defaults = fetch_cached_defaults(wallet_core, program, tree_id).await;

    for _ in 0..max_attempts {
        let stored_leaf = fetch_node_hash(
            wallet_core,
            program,
            tree_id,
            TREE_DEPTH as u8,
            leaf_index,
            &cached_defaults,
        ).await;

        if &stored_leaf == expected_leaf {
            return true;
        }

        sleep(poll_interval).await;
    }

    false
}

// ============================================================================
// Merkle Proofs
// ============================================================================

/// Merkle proof for a leaf in the tree.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf value at the given index
    pub leaf: [u8; 32],
    /// Sibling hashes from leaf level to root (length = depth)
    pub path_elements: Vec<[u8; 32]>,
    /// Path indices: 0 if node is left child, 1 if right child
    pub path_indices: Vec<u8>,
    /// Current merkle root
    pub root: [u8; 32],
    /// Leaf index this proof is for
    pub leaf_index: u64,
}

/// Fetches a Merkle proof for a leaf at the given index.
pub async fn get_merkle_proof(
    wallet_core: &WalletCore,
    program: &Program,
    tree_id: &[u8; 24],
    leaf_index: u64,
) -> MerkleProof {
    let main_account_id = derive_main_account(&program.id(), tree_id);

    // Fetch main account
    let main_account = wallet_core
        .get_account_public(main_account_id)
        .await
        .expect("Failed to fetch main tree account");

    let main_data = main_account.data.as_ref();
    let depth = main_data[OFFSET_DEPTH] as usize;
    let root: [u8; 32] = main_data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap();

    // Extract cached defaults
    let cached_defaults: Vec<[u8; 32]> = (0..=depth)
        .map(|i| {
            let start = OFFSET_CACHED_NODES + i * 32;
            main_data[start..start + 32].try_into().unwrap()
        })
        .collect();

    // Fetch the leaf
    let leaf = fetch_node_hash(
        wallet_core,
        program,
        tree_id,
        depth as u8,
        leaf_index,
        &cached_defaults,
    ).await;

    // Collect sibling hashes
    let mut path_elements: Vec<[u8; 32]> = Vec::with_capacity(depth);
    let mut path_indices: Vec<u8> = Vec::with_capacity(depth);
    let mut current_index = leaf_index;

    for level in (1..=depth).rev() {
        let node_index = current_index;
        let is_right_child = (node_index % 2) as u8;
        path_indices.push(is_right_child);

        let sibling_index = if node_index % 2 == 0 {
            node_index + 1
        } else {
            node_index - 1
        };

        let sibling = fetch_node_hash(
            wallet_core,
            program,
            tree_id,
            level as u8,
            sibling_index,
            &cached_defaults,
        ).await;

        path_elements.push(sibling);
        current_index /= 2;
    }

    MerkleProof {
        leaf,
        path_elements,
        path_indices,
        root,
        leaf_index,
    }
}

pub fn proof_to_fr(proof: &MerkleProof) -> (Vec<Fr>, Vec<u8>, Fr) {
    let path_elements: Vec<Fr> = proof.path_elements
        .iter()
        .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element").0)
        .collect();

    let (root, _) = bytes_le_to_fr(&proof.root).expect("Invalid root");

    (path_elements, proof.path_indices.clone(), root)
}
