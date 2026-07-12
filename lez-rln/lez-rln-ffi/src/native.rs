//! Safe, Rust-native API backing the C FFI layer in `lib.rs`.
//!
//! Every `rln_ffi_*` extern "C" function is a thin shim over one of the
//! functions here. Rust consumers should call these directly:
//! `use lez_rln_ffi::native::*;`

use borsh::BorshDeserialize;
use rln_layouts::{
    combine_seeds, label_seed,
    MembershipState, TreeMainLayout, ROOT_HISTORY_SIZE,
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_ROOT, OFFSET_TOP_TREE_DATA,
    TOP_DEPTH, TREE_DEPTH, SUBTREE_LEAVES,
    read_sparse_node,
};
use serde::Serialize;
use sha2::{Sha256, Digest};

use crate::{MerkleProofsPlan, RlnMerkleProof, RlnRegisterPlan, MAX_SUBTREES_PER_CALL};

/// `rln_layouts::ConfigState` field offsets (borsh: fixed-width fields in
/// declaration order, no prefixes). The layout is APPEND-ONLY, so these are
/// stable across config versions; reading by offset keeps this crate working
/// against both pre-policy (240-byte) and policy (296-byte) deployments,
/// where an exact-size borsh decode would reject the other version.
pub const CONFIG_OFFSET_TREE_ID: usize = 32;
pub const CONFIG_OFFSET_PAYMENT_TOKEN_ID: usize = 64;
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 144;
pub const CONFIG_OFFSET_TOKEN_PROGRAM_ID: usize = 208;
/// Minimum (pre-policy) ConfigState size — the precheck floor. NOT the full
/// policy-era size (296, the host's `CONFIG_SIZE`); accepting 240 is what
/// keeps this crate working against pre-policy deployments.
pub const CONFIG_STATE_MIN_SIZE: usize = 240;

/// Read a 32-byte field out of raw config-account bytes by offset.
pub fn config_field_32(config_data: &[u8], offset: usize) -> [u8; 32] {
    config_data[offset..offset + 32]
        .try_into()
        .expect("32-byte config field")
}

/// Borsh size of the on-chain `MembershipState` (8+8+32+8+4+4 bytes).
pub const MEMBERSHIP_STATE_SIZE: usize = 64;

/// Errors surfaced by the safe Rust-native API.
///
/// Mirrors the C `Error` enum minus `Success` (encoded as `Ok`) and
/// `NullPointer` (a pointer-level concern handled by the FFI shims).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlnError {
    DataTooShort,
    InvalidConfig,
    InvalidLeafIndex,
    SerializationError,
    KeygenFailed,
    HashFailed,
    TransactionBuildFailed,
}

impl core::fmt::Display for RlnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            RlnError::DataTooShort => "account data too short",
            RlnError::InvalidConfig => "invalid config account data",
            RlnError::InvalidLeafIndex => "invalid leaf index",
            RlnError::SerializationError => "serialization error",
            RlnError::KeygenFailed => "keygen failed",
            RlnError::HashFailed => "hash failed",
            RlnError::TransactionBuildFailed => "transaction build failed",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for RlnError {}

const PDA_PREFIX: &[u8; 32] = b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00";

pub(crate) fn derive_pda(program_id: &[u8; 32], pda_seed: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 96];
    input[0..32].copy_from_slice(PDA_PREFIX);
    input[32..64].copy_from_slice(program_id);
    input[64..96].copy_from_slice(pda_seed);

    let hash = Sha256::digest(&input);
    hash.into()
}

/// Parse tree-main account data and return the valid roots.
///
/// Index 0 = current root. Indices 1..N = non-zero history entries.
/// Returns 1..=(1 + ROOT_HISTORY_SIZE) roots.
pub fn get_valid_roots(data: &[u8]) -> Result<Vec<[u8; 32]>, RlnError> {
    if data.len() < TreeMainLayout::SIZE {
        return Err(RlnError::DataTooShort);
    }

    let header = TreeMainLayout::parse(data);

    let mut roots = Vec::with_capacity(1 + ROOT_HISTORY_SIZE);
    roots.push(header.current_root);

    let zero = [0u8; 32];
    for entry in &header.root_history {
        if *entry != zero {
            roots.push(*entry);
        }
    }

    Ok(roots)
}

/// Build a merkle proof for a single leaf given pre-fetched main + subtree data.
///
/// `main_data`: raw bytes of the tree main account.
/// `subtree_data`: raw bytes of the subtree account for this leaf
///   (subtree_id = leaf_index / SUBTREE_LEAVES); may be empty.
/// `leaf_index`: the leaf position in the tree.
pub fn build_merkle_proof(
    main_data: &[u8],
    subtree_data: &[u8],
    leaf_index: u64,
) -> Result<RlnMerkleProof, RlnError> {
    let min_main_len = OFFSET_CACHED_NODES + (TREE_DEPTH + 1) * 32;
    if main_data.len() < min_main_len {
        return Err(RlnError::DataTooShort);
    }

    let depth = main_data[OFFSET_DEPTH] as usize;
    if depth == 0 || depth > TREE_DEPTH {
        return Err(RlnError::DataTooShort);
    }

    let max_leaves = 1u64 << depth;
    if leaf_index >= max_leaves {
        return Err(RlnError::InvalidLeafIndex);
    }

    let root: [u8; 32] = main_data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap();

    let cached_defaults: Vec<[u8; 32]> = (0..=depth)
        .map(|i| {
            let start = OFFSET_CACHED_NODES + i * 32;
            main_data[start..start + 32].try_into().unwrap()
        })
        .collect();

    let top_tree_data = if main_data.len() > OFFSET_TOP_TREE_DATA {
        &main_data[OFFSET_TOP_TREE_DATA..]
    } else {
        &[]
    };

    let fetch_node = |level: usize, node_index: u64| -> [u8; 32] {
        if level <= TOP_DEPTH {
            read_sparse_node(top_tree_data, level, node_index as usize, &cached_defaults[level])
        } else {
            let bottom_level = level - TOP_DEPTH;
            let nodes_per_subtree = 1usize << bottom_level;
            let local_index = node_index as usize % nodes_per_subtree;
            read_sparse_node(subtree_data, bottom_level, local_index, &cached_defaults[level])
        }
    };

    let leaf = fetch_node(depth, leaf_index);

    let mut path_elements = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices = [0u8; TREE_DEPTH];
    let mut current_index = leaf_index;

    for i in 0..depth {
        let level = depth - i;
        let is_right = (current_index % 2) as u8;
        path_indices[i] = is_right;

        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        path_elements[i] = fetch_node(level, sibling_index);
        current_index /= 2;
    }

    Ok(RlnMerkleProof {
        leaf,
        root,
        leaf_index,
        depth: depth as u32,
        path_elements,
        path_indices,
    })
}

/// Phase 1: Given config data, program owner, and leaf indices, compute which
/// accounts the caller needs to fetch.
///
/// `program_owner`: 32-byte registration program ID (from config account's
/// `program_owner`). Tree main and subtree accounts are PDAs of this program,
/// NOT the merkle program.
///
/// Returns a `MerkleProofsPlan` with the main account ID and unique subtree
/// account IDs.
pub fn merkle_proofs_plan(
    config_data: &[u8],
    program_owner: &[u8; 32],
    leaf_indices: &[u64],
) -> Result<MerkleProofsPlan, RlnError> {
    if config_data.len() < CONFIG_STATE_MIN_SIZE {
        return Err(RlnError::InvalidConfig);
    }

    // Tree PDAs derive from the registration program, not the merkle program.
    let tree_id: &[u8; 32] = &config_field_32(config_data, CONFIG_OFFSET_TREE_ID);
    let main_account_id =
        derive_pda(program_owner, &combine_seeds(&[&label_seed("main"), tree_id]));

    let mut unique_ids: Vec<u32> = leaf_indices
        .iter()
        .map(|&idx| (idx / SUBTREE_LEAVES as u64) as u32)
        .collect();
    unique_ids.sort_unstable();
    unique_ids.dedup();

    if unique_ids.len() > MAX_SUBTREES_PER_CALL {
        return Err(RlnError::InvalidLeafIndex);
    }

    let mut plan = MerkleProofsPlan {
        main_account_id,
        subtree_account_ids: [[0u8; 32]; MAX_SUBTREES_PER_CALL],
        subtree_ids: [0u32; MAX_SUBTREES_PER_CALL],
        subtree_count: unique_ids.len() as u32,
    };

    for (i, &subtree_id) in unique_ids.iter().enumerate() {
        let mut subtree_id_seed = [0u8; 32];
        subtree_id_seed[..4].copy_from_slice(&subtree_id.to_le_bytes());
        plan.subtree_account_ids[i] = derive_pda(
            program_owner,
            &combine_seeds(&[&label_seed("subtree"), tree_id, &subtree_id_seed]),
        );
        plan.subtree_ids[i] = subtree_id;
    }

    Ok(plan)
}

#[derive(Serialize)]
struct ProofJson {
    leaf: String,
    root: String,
    leaf_index: u64,
    depth: u32,
    path_elements: Vec<String>,
    path_indices: Vec<u8>,
}

fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Phase 2: Given fetched account data and leaf indices, build all proofs and
/// return them as a JSON array string.
///
/// `subtrees`: (subtree_id, raw subtree account data) pairs. Leaves whose
/// subtree is absent fall back to cached default nodes.
pub fn merkle_proofs_exec(
    main_data: &[u8],
    subtrees: &[(u32, &[u8])],
    leaf_indices: &[u64],
) -> Result<String, RlnError> {
    let mut proofs = Vec::with_capacity(leaf_indices.len());

    for &leaf_index in leaf_indices {
        let subtree_id = (leaf_index / SUBTREE_LEAVES as u64) as u32;

        let subtree_data: &[u8] = subtrees
            .iter()
            .find(|(id, _)| *id == subtree_id)
            .map(|(_, data)| *data)
            .unwrap_or(&[]);

        let proof = build_merkle_proof(main_data, subtree_data, leaf_index)?;

        let depth = proof.depth as usize;
        proofs.push(ProofJson {
            leaf: bytes_to_hex(&proof.leaf),
            root: bytes_to_hex(&proof.root),
            leaf_index: proof.leaf_index,
            depth: proof.depth,
            path_elements: proof.path_elements[..depth]
                .iter()
                .map(|e| bytes_to_hex(e))
                .collect(),
            path_indices: proof.path_indices[..depth].to_vec(),
        });
    }

    serde_json::to_string(&proofs).map_err(|_| RlnError::SerializationError)
}

/// Generate an RLN identity from a 32-byte seed.
///
/// Uses zerokit's seeded_keygen to derive identity_secret and id_commitment.
/// The seed should be derived from a wallet signing key or similar entropy source.
///
/// Returns `(id_commitment, id_secret_hash)`.
pub fn generate_identity(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let (identity_secret_fr, id_commitment_fr) = rln::prelude::seeded_keygen(seed);

    let mut id_commitment = [0u8; 32];
    id_commitment.copy_from_slice(&rln::utils::fr_to_bytes_le(&id_commitment_fr));

    let mut id_secret_hash = [0u8; 32];
    id_secret_hash.copy_from_slice(&rln::utils::fr_to_bytes_le(&identity_secret_fr));

    (id_commitment, id_secret_hash)
}

/// Compute rate_commitment = poseidon(id_commitment, rate_limit).
///
/// This is the leaf value stored in the merkle tree for rate-limited membership.
pub fn compute_rate_commitment(
    id_commitment: &[u8; 32],
    rate_limit: u64,
) -> Result<[u8; 32], RlnError> {
    let (id_commitment_fr, _) =
        rln::utils::bytes_le_to_fr(id_commitment).map_err(|_| RlnError::HashFailed)?;

    let rate_limit_fr = rln::prelude::Fr::from(rate_limit);

    let rate_commitment_fr = rln::hashers::poseidon_hash(&[id_commitment_fr, rate_limit_fr]);

    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&rln::utils::fr_to_bytes_le(&rate_commitment_fr));

    Ok(leaf)
}

/// Plan a registration transaction by deriving all required account IDs.
///
/// `config_data`: raw bytes of config account (tree_id is read from here)
/// `tree_main_data`: raw bytes of tree main account (for next_leaf_index)
/// `program_owner`: 32-byte registration program ID
/// `id_commitment`: 32-byte id_commitment (used to derive the membership PDA)
pub fn register_plan(
    config_data: &[u8],
    tree_main_data: &[u8],
    program_owner: &[u8; 32],
    id_commitment: &[u8; 32],
) -> Result<RlnRegisterPlan, RlnError> {
    if config_data.len() < CONFIG_STATE_MIN_SIZE {
        return Err(RlnError::InvalidConfig);
    }
    if tree_main_data.len() < TreeMainLayout::SIZE {
        return Err(RlnError::DataTooShort);
    }

    // Offset reads (version-agnostic; see the CONFIG_OFFSET_* comment).
    let tree_main = TreeMainLayout::parse(tree_main_data);
    let tree_id: &[u8; 32] = &config_field_32(config_data, CONFIG_OFFSET_TREE_ID);

    let config_account_id =
        derive_pda(program_owner, &combine_seeds(&[&label_seed("config"), tree_id]));
    let tree_main_account_id =
        derive_pda(program_owner, &combine_seeds(&[&label_seed("main"), tree_id]));

    let next_leaf_index = tree_main.next_index();
    let subtree_id = (next_leaf_index / SUBTREE_LEAVES as u64) as u32;
    let subtree_id_seed = {
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(&subtree_id.to_le_bytes());
        s
    };
    let subtree_account_id = derive_pda(
        program_owner,
        &combine_seeds(&[&label_seed("subtree"), tree_id, &subtree_id_seed]),
    );

    let membership_account_id = derive_pda(
        program_owner,
        &combine_seeds(&[&label_seed("membership"), tree_id, id_commitment]),
    );

    Ok(RlnRegisterPlan {
        config_account_id,
        tree_main_account_id,
        treasury_account_id: config_field_32(config_data, CONFIG_OFFSET_TREASURY_ACCOUNT_ID),
        subtree_account_id,
        clock_account_id: rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES,
        membership_account_id,
        subtree_id,
        next_leaf_index,
    })
}

/// Build the serialized instruction data for a Register transaction.
///
/// Returns a serialized SPEL `Instruction::Register` payload (risc0-serde),
/// suitable for the registration program's #[lez_program] handler.
///
/// `tree_id`: 32-byte tree_id (same as in ConfigState)
/// `id_commitment`: 32-byte id_commitment
/// `rate_limit`: the user's rate limit
/// `subtree_id`: which bottom subtree the leaf will land in (= next_leaf_index / SUBTREE_LEAVES)
pub fn register_build_instruction(
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    rate_limit: u64,
    subtree_id: u32,
) -> Result<Vec<u8>, RlnError> {
    let instruction = rln_layouts::Instruction::Register {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        rate_limit,
        subtree_id,
    };

    // risc0 serde — matches the on-chain program's wire format.
    let u32_vec =
        risc0_zkvm::serde::to_vec(&instruction).map_err(|_| RlnError::SerializationError)?;

    let mut bytes: Vec<u8> = Vec::with_capacity(u32_vec.len() * 4);
    for word in &u32_vec {
        bytes.extend_from_slice(&word.to_le_bytes());
    }

    Ok(bytes)
}

/// Decode a fetched membership PDA's account data.
///
/// Used by callers (e.g. logos_rln_module) to check whether a given
/// id_commitment already has an on-chain membership before submitting a
/// Register tx (idempotency / restart recovery / retry-after-tx-loss).
///
/// Returns `DataTooShort` if the buffer is too small; `SerializationError`
/// if borsh decode fails (account exists but isn't a valid MembershipState —
/// caller should treat as "not a membership PDA").
pub fn decode_membership(account_data: &[u8]) -> Result<MembershipState, RlnError> {
    if account_data.len() < MEMBERSHIP_STATE_SIZE {
        return Err(RlnError::DataTooShort);
    }
    MembershipState::try_from_slice(&account_data[..MEMBERSHIP_STATE_SIZE])
        .map_err(|_| RlnError::SerializationError)
}
