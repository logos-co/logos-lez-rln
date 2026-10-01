//! Client-side reads of the incremental Merkle tree.
//!
//! The whole tree is one shard: the merkle program's shard of the
//! registration program's `tree_main` PDA. Its layout (`rln_layouts`):
//! `[0..OFFSET_CACHED_NODES)` the `TreeMainLayout` header,
//! `[OFFSET_CACHED_NODES..OFFSET_TREE_DATA)` the default hash of each level
//! (root level first), then from `OFFSET_TREE_DATA` the sparse node map
//! `[count u16le][(node_offset(level, index) u16le, hash32)…]`. A node absent
//! from the map holds its level's default.
//!
//! Tree writes happen only through the registration program's chained calls;
//! nothing here builds a merkle transaction.

use std::time::Duration;

use nssa::{AccountId, ProgramShardSelector};
use rln::prelude::{Fr, RLNMerkleProof};
pub use rln_layouts::{node_offset, read_sparse_node};
use tokio::time::sleep;
use wallet::WalletCore;

use super::{
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_NEXT_INDEX, OFFSET_ROOT, OFFSET_ROOT_HISTORY,
    OFFSET_TREE_DATA, ROOT_HISTORY_SIZE, TREE_DEPTH, TREE_LEAVES, derive_main_account,
};
use crate::{fr_bytes::bytes_le_to_fr, rln::ProgramIds};

// ============================================================================
// Parsed Tree State
// ============================================================================

/// Parsed tree header.
#[derive(Debug, Clone)]
pub struct ParsedTreeMain {
    pub depth: u8,
    pub next_index: u64,
    pub root: [u8; 32],
    pub root_history: Vec<[u8; 32]>,
}

impl ParsedTreeMain {
    /// Parse the header of a tree shard.
    ///
    /// # Panics
    /// If `data` is not an initialized shard of a depth-`TREE_DEPTH` tree.
    pub fn from_bytes(data: &[u8]) -> Self {
        check_tree_shard(data);
        let root_history = (0..ROOT_HISTORY_SIZE)
            .map(|i| read32(data, OFFSET_ROOT_HISTORY + i * 32))
            .collect();

        Self {
            depth: data[OFFSET_DEPTH],
            next_index: u64::from_le_bytes(
                data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8]
                    .try_into()
                    .unwrap(),
            ),
            root: read32(data, OFFSET_ROOT),
            root_history,
        }
    }
}

fn read32(data: &[u8], at: usize) -> [u8; 32] {
    data[at..at + 32].try_into().unwrap()
}

/// Every offset past the header is a function of `TREE_DEPTH`, so a shard
/// written at another depth would be misread rather than rejected.
fn check_tree_shard(data: &[u8]) {
    assert!(
        data.len() >= OFFSET_TREE_DATA,
        "Tree shard is {} bytes, an initialized tree has at least {OFFSET_TREE_DATA}. \
         Is the tree initialized?",
        data.len()
    );
    assert_eq!(
        data[OFFSET_DEPTH] as usize, TREE_DEPTH,
        "Tree shard has depth {}, this host is built for depth {TREE_DEPTH}",
        data[OFFSET_DEPTH]
    );
}

/// The default hash of each level, root level first.
pub fn cached_defaults(shard: &[u8]) -> Vec<[u8; 32]> {
    check_tree_shard(shard);
    (0..=TREE_DEPTH)
        .map(|level| read32(shard, OFFSET_CACHED_NODES + level * 32))
        .collect()
}

/// The hash of node `(level, index)`; level 0 is the root.
pub fn node_hash(shard: &[u8], level: usize, index: u64) -> [u8; 32] {
    assert!(level <= TREE_DEPTH, "level {level} is below the leaves");
    assert!(index < 1u64 << level, "level {level} has no node {index}");
    let defaults = cached_defaults(shard);
    read_sparse_node(
        &shard[OFFSET_TREE_DATA..],
        level,
        index as usize,
        &defaults[level],
    )
}

/// The inclusion proof of leaf `leaf_index` against the shard's current root.
pub fn merkle_proof(shard: &[u8], leaf_index: u64) -> MerkleProof {
    assert!(
        leaf_index < TREE_LEAVES,
        "leaf {leaf_index} is past the last leaf ({TREE_LEAVES} leaves)"
    );
    let header = ParsedTreeMain::from_bytes(shard);
    let leaf = node_hash(shard, TREE_DEPTH, leaf_index);

    let mut path_elements = Vec::with_capacity(TREE_DEPTH);
    let mut path_indices = Vec::with_capacity(TREE_DEPTH);
    let mut index = leaf_index;
    for level in (1..=TREE_DEPTH).rev() {
        path_indices.push((index % 2) as u8);
        path_elements.push(node_hash(shard, level, index ^ 1));
        index /= 2;
    }

    MerkleProof {
        leaf,
        path_elements,
        path_indices,
        root: header.root,
        leaf_index,
    }
}

// ============================================================================
// Tree State Reading
// ============================================================================

/// The tree's shard selector: the merkle program's shard of `tree_main`.
pub fn tree_shard_selector(programs: &ProgramIds, tree_id: &[u8; 32]) -> ProgramShardSelector {
    ProgramShardSelector::new(tree_main_account(programs, tree_id), programs.merkle)
}

pub fn tree_main_account(programs: &ProgramIds, tree_id: &[u8; 32]) -> AccountId {
    derive_main_account(&programs.registration, tree_id)
}

/// Fetch the tree shard's bytes; empty before the tree is initialized.
pub async fn fetch_tree_shard(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
) -> Vec<u8> {
    let account = wallet_core
        .get_account_view(tree_shard_selector(programs, tree_id))
        .await
        .expect("Failed to fetch the tree main account");
    account.data.shard(programs.merkle).to_vec()
}

/// Fetches the current next_index.
pub async fn fetch_next_index(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
) -> u64 {
    ParsedTreeMain::from_bytes(&fetch_tree_shard(wallet_core, programs, tree_id).await).next_index
}

/// Fetches the current root.
pub async fn fetch_root(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
) -> [u8; 32] {
    ParsedTreeMain::from_bytes(&fetch_tree_shard(wallet_core, programs, tree_id).await).root
}

/// Fetches the current root plus non-zero history entries, newest first:
/// `[current_root, history[0], history[1], ...]`.
pub async fn fetch_root_history(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
) -> Vec<[u8; 32]> {
    let parsed =
        ParsedTreeMain::from_bytes(&fetch_tree_shard(wallet_core, programs, tree_id).await);
    let mut roots = vec![parsed.root];
    roots.extend(
        parsed
            .root_history
            .iter()
            .filter(|entry| **entry != [0u8; 32]),
    );
    roots
}

/// Fetches the default hash of each level, root level first.
pub async fn fetch_cached_defaults(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
) -> Vec<[u8; 32]> {
    cached_defaults(&fetch_tree_shard(wallet_core, programs, tree_id).await)
}

/// Fetches the hash of node `(level, node_index)`; level 0 is the root.
pub async fn fetch_node_hash(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    level: u8,
    node_index: u64,
) -> [u8; 32] {
    node_hash(
        &fetch_tree_shard(wallet_core, programs, tree_id).await,
        level as usize,
        node_index,
    )
}

/// Polls until leaf `leaf_index` holds `expected_leaf` or `max_attempts` run
/// out.
pub async fn wait_for_leaf(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    leaf_index: u64,
    expected_leaf: &[u8; 32],
    max_attempts: u32,
    poll_interval: Duration,
) -> bool {
    for _ in 0..max_attempts {
        let shard = fetch_tree_shard(wallet_core, programs, tree_id).await;
        if shard.len() >= OFFSET_TREE_DATA
            && &node_hash(&shard, TREE_DEPTH, leaf_index) == expected_leaf
        {
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Fetches a Merkle proof for a leaf at the given index. The leaf, siblings
/// and root all come from one read of the shard.
pub async fn get_merkle_proof(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    leaf_index: u64,
) -> MerkleProof {
    merkle_proof(
        &fetch_tree_shard(wallet_core, programs, tree_id).await,
        leaf_index,
    )
}

/// Converts an on-chain [`MerkleProof`] into zerokit's witness inputs: the
/// [`RLNMerkleProof`] plus the root as a field element, both at the TREE's
/// depth. Feed [`proof_to_circuit`] to the prover, not this.
pub fn proof_to_fr(proof: &MerkleProof) -> (RLNMerkleProof, Fr) {
    let path_elements: Vec<Fr> = proof
        .path_elements
        .iter()
        .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
        .collect();

    let root = bytes_le_to_fr(&proof.root).expect("Invalid root");

    (
        RLNMerkleProof::new(path_elements, proof.path_indices.clone()),
        root,
    )
}

/// [`proof_to_fr`] lifted to the circuit's depth: the path is padded with
/// empty-subtree siblings and the root folded up the same way, so the root
/// the circuit derives is the one it is verified against.
pub fn proof_to_circuit(proof: &MerkleProof) -> (RLNMerkleProof, Fr) {
    let mut path_elements: Vec<Fr> = proof
        .path_elements
        .iter()
        .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
        .collect();
    let mut path_indices = proof.path_indices.clone();
    crate::proof_circuit::pad_path(&mut path_elements, &mut path_indices);
    let root = crate::proof_circuit::fold_root(bytes_le_to_fr(&proof.root).expect("Invalid root"));
    (RLNMerkleProof::new(path_elements, path_indices), root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_at(level: usize) -> [u8; 32] {
        [0xD0 | level as u8; 32]
    }

    /// A freshly initialized shard: header, defaults, empty sparse map.
    fn empty_shard() -> Vec<u8> {
        let mut shard = vec![0u8; OFFSET_TREE_DATA];
        shard[OFFSET_DEPTH] = TREE_DEPTH as u8;
        shard[OFFSET_ROOT..OFFSET_ROOT + 32].copy_from_slice(&default_at(0));
        for level in 0..=TREE_DEPTH {
            let at = OFFSET_CACHED_NODES + level * 32;
            shard[at..at + 32].copy_from_slice(&default_at(level));
        }
        shard
    }

    /// Append a sparse map holding `nodes`, which must be sorted by offset.
    fn with_nodes(mut shard: Vec<u8>, nodes: &[(usize, u64, [u8; 32])]) -> Vec<u8> {
        shard.extend_from_slice(&(nodes.len() as u16).to_le_bytes());
        for (level, index, hash) in nodes {
            shard.extend_from_slice(&(node_offset(*level, *index as usize) as u16).to_le_bytes());
            shard.extend_from_slice(hash);
        }
        shard
    }

    #[test]
    fn a_fresh_shard_is_the_header_and_defaults() {
        assert_eq!(OFFSET_TREE_DATA, 489);
        let shard = empty_shard();
        assert_eq!(ParsedTreeMain::from_bytes(&shard).next_index, 0);
        assert_eq!(node_hash(&shard, TREE_DEPTH, 7), default_at(TREE_DEPTH));
        assert_eq!(node_hash(&shard, 0, 0), default_at(0));
    }

    #[test]
    fn a_stored_leaf_is_read_at_its_node_offset() {
        let shard = with_nodes(empty_shard(), &[(TREE_DEPTH, 3, [0x33; 32])]);
        assert_eq!(node_hash(&shard, TREE_DEPTH, 3), [0x33; 32]);
        assert_eq!(node_hash(&shard, TREE_DEPTH, 2), default_at(TREE_DEPTH));
    }

    #[test]
    fn a_proof_takes_each_sibling_from_its_own_level() {
        // Leaf 2's path: sibling leaf 3, then node 0 at depth-1, then defaults.
        let nodes = [
            (TREE_DEPTH - 1, 0, [0x10; 32]),
            (TREE_DEPTH, 2, [0x22; 32]),
            (TREE_DEPTH, 3, [0x33; 32]),
        ];
        let shard = with_nodes(empty_shard(), &nodes);
        let proof = merkle_proof(&shard, 2);

        assert_eq!(proof.leaf, [0x22; 32]);
        assert_eq!(proof.path_elements.len(), TREE_DEPTH);
        assert_eq!(proof.path_elements[0], [0x33; 32]);
        assert_eq!(proof.path_elements[1], [0x10; 32]);
        for (i, sibling) in proof.path_elements.iter().enumerate().skip(2) {
            assert_eq!(*sibling, default_at(TREE_DEPTH - i));
        }
        assert_eq!(proof.path_indices[..2], [0, 1]);
        assert!(proof.path_indices[2..].iter().all(|bit| *bit == 0));
    }

    #[test]
    #[should_panic(expected = "past the last leaf")]
    fn a_proof_past_the_last_leaf_is_refused() {
        merkle_proof(&empty_shard(), TREE_LEAVES);
    }

    #[test]
    #[should_panic(expected = "Is the tree initialized")]
    fn an_empty_shard_is_refused() {
        ParsedTreeMain::from_bytes(&[]);
    }

    #[test]
    #[should_panic(expected = "this host is built for depth")]
    fn a_shard_of_another_depth_is_refused() {
        let mut shard = empty_shard();
        shard[OFFSET_DEPTH] = 20;
        ParsedTreeMain::from_bytes(&shard);
    }
}
