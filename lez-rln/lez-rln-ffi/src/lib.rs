#![allow(
    unsafe_code,
    reason = "C ABI boundary: extern \"C\" entry points and raw-pointer interop"
)]

use borsh::BorshDeserialize;
use rln_layouts::{
    combine_seeds, label_seed,
    MembershipState, TreeMainLayout, ROOT_HISTORY_SIZE,
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_ROOT, OFFSET_TOP_TREE_DATA,
    TOP_DEPTH, TREE_DEPTH, SUBTREE_LEAVES,
    read_sparse_node,
};

/// `rln_layouts::ConfigState` field offsets (borsh: fixed-width fields in
/// declaration order, no prefixes). The layout is APPEND-ONLY, so these are
/// stable across config versions; reading by offset keeps this FFI working
/// against both pre-policy (240-byte) and policy (296-byte) deployments,
/// where an exact-size borsh decode would reject the other version.
const CONFIG_OFFSET_TREE_ID: usize = 32;
const CONFIG_OFFSET_PAYMENT_TOKEN_ID: usize = 64;
const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 144;
const CONFIG_OFFSET_TOKEN_PROGRAM_ID: usize = 208;
/// Minimum (pre-policy) ConfigState size — the precheck floor. NOT the full
/// policy-era size (296, the host's `CONFIG_SIZE`); accepting 240 is what
/// keeps this FFI working against pre-policy deployments.
const CONFIG_STATE_MIN_SIZE: usize = 240;

fn config_field_32(config_data: &[u8], offset: usize) -> [u8; 32] {
    config_data[offset..offset + 32]
        .try_into()
        .expect("32-byte config field")
}
use serde::Serialize;
use sha2::{Sha256, Digest};

#[repr(C)]
pub enum Error {
    Success = 0,
    NullPointer = 1,
    DataTooShort = 2,
    InvalidConfig = 3,
    InvalidLeafIndex = 4,
    SerializationError = 5,
    KeygenFailed = 6,
    HashFailed = 7,
    TransactionBuildFailed = 8,
}

/// Maximum tree depth for proof arrays.
pub const RLN_TREE_DEPTH: usize = 20;

#[repr(C)]
pub struct RlnMerkleProof {
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    pub leaf_index: u64,
    pub depth: u32,
    pub path_elements: [[u8; 32]; RLN_TREE_DEPTH],
    pub path_indices: [u8; RLN_TREE_DEPTH],
}

pub const MAX_SUBTREES_PER_CALL: usize = 64;

#[repr(C)]
pub struct MerkleProofsPlan {
    pub main_account_id: [u8; 32],
    pub subtree_account_ids: [[u8; 32]; MAX_SUBTREES_PER_CALL],
    pub subtree_ids: [u32; MAX_SUBTREES_PER_CALL],
    pub subtree_count: u32,
}

#[repr(C)]
pub struct SubtreeEntry {
    pub subtree_id: u32,
    pub data_ptr: *const u8,
    pub data_len: usize,
}

/// Serialize an instruction with risc0-serde (the deployed programs' wire
/// format: u32 words, LE bytes) into a heap buffer whose ownership passes to
/// the caller side of the C ABI. Free with `rln_ffi_free_string`.
///
/// SAFETY: `out_data_ptr` and `out_data_len` must be valid, writable,
/// non-null pointers. On any non-`Success` return they are left untouched.
unsafe fn leak_instruction_bytes<T: Serialize>(
    instruction: &T,
    out_data_ptr: *mut *mut u8,
    out_data_len: *mut usize,
) -> Error {
    let u32_vec = match risc0_zkvm::serde::to_vec(instruction) {
        Ok(v) => v,
        Err(_) => return Error::SerializationError,
    };
    let mut bytes: Vec<u8> = Vec::with_capacity(u32_vec.len() * 4);
    for word in &u32_vec {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.shrink_to_fit();
    let ptr = bytes.as_mut_ptr();
    let len = bytes.len();
    core::mem::forget(bytes);

    unsafe {
        *out_data_ptr = ptr;
        *out_data_len = len;
    }
    Error::Success
}

/// Parse a C-side decimal string (e.g. a token amount) into a `u128`.
///
/// SAFETY: `ptr` must point to `len` readable bytes.
unsafe fn parse_amount_u128(ptr: *const u8, len: usize) -> Result<u128, Error> {
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or(Error::SerializationError)
}

const PDA_PREFIX: &[u8; 32] = b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00";

fn derive_pda(program_id: &[u8; 32], pda_seed: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 96];
    input[0..32].copy_from_slice(PDA_PREFIX);
    input[32..64].copy_from_slice(program_id);
    input[64..96].copy_from_slice(pda_seed);

    let hash = Sha256::digest(&input);
    hash.into()
}


/// Parse tree-main account data and write valid roots into `out_roots`.
///
/// `out_roots`: caller buffer, at least 160 bytes (5 x 32).
/// `out_count`: set to number of valid roots written (1..=5).
///
/// Slot 0 = current root. Slots 1..N = non-zero history entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_get_valid_roots(
    data_ptr: *const u8,
    data_len: usize,
    out_roots: *mut u8,
    out_count: *mut u32,
) -> Error {
    if data_ptr.is_null() || out_roots.is_null() || out_count.is_null() {
        return Error::NullPointer;
    }
    if data_len < TreeMainLayout::SIZE {
        return Error::DataTooShort;
    }

    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };
    let header = TreeMainLayout::parse(data);

    let out = unsafe { core::slice::from_raw_parts_mut(out_roots, (1 + ROOT_HISTORY_SIZE) * 32) };
    out[0..32].copy_from_slice(&header.current_root);
    let mut count: u32 = 1;

    let zero = [0u8; 32];
    for entry in &header.root_history {
        if *entry != zero {
            let off = (count as usize) * 32;
            out[off..off + 32].copy_from_slice(entry);
            count += 1;
        }
    }

    unsafe { *out_count = count };
    Error::Success
}

/// Safe-Rust proof builder shared by `rln_ffi_build_merkle_proof` and the
/// batch `rln_ffi_merkle_proofs_exec`.
fn build_merkle_proof_inner(
    main_data: &[u8],
    subtree_data: &[u8],
    leaf_index: u64,
    out_proof: &mut RlnMerkleProof,
) -> Error {
    let min_main_len = OFFSET_CACHED_NODES + (TREE_DEPTH + 1) * 32;
    if main_data.len() < min_main_len {
        return Error::DataTooShort;
    }

    let depth = main_data[OFFSET_DEPTH] as usize;
    if depth == 0 || depth > TREE_DEPTH {
        return Error::DataTooShort;
    }

    let max_leaves = 1u64 << depth;
    if leaf_index >= max_leaves {
        return Error::InvalidLeafIndex;
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

    out_proof.leaf = leaf;
    out_proof.root = root;
    out_proof.leaf_index = leaf_index;
    out_proof.depth = depth as u32;
    out_proof.path_elements = path_elements;
    out_proof.path_indices = path_indices;

    Error::Success
}

/// Build a merkle proof for a single leaf given pre-fetched main + subtree data.
///
/// `main_data`/`main_len`: raw bytes of the tree main account.
/// `subtree_data`/`subtree_len`: raw bytes of the subtree account for this leaf.
///   (subtree_id = leaf_index / SUBTREE_LEAVES)
/// `leaf_index`: the leaf position in the tree.
/// `out_proof`: pointer to caller-allocated `RlnMerkleProof`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_build_merkle_proof(
    main_data_ptr: *const u8,
    main_data_len: usize,
    subtree_data_ptr: *const u8,
    subtree_data_len: usize,
    leaf_index: u64,
    out_proof: *mut RlnMerkleProof,
) -> Error {
    if main_data_ptr.is_null() || out_proof.is_null() {
        return Error::NullPointer;
    }

    let main_data = unsafe { core::slice::from_raw_parts(main_data_ptr, main_data_len) };
    let subtree_data = if !subtree_data_ptr.is_null() && subtree_data_len > 0 {
        unsafe { core::slice::from_raw_parts(subtree_data_ptr, subtree_data_len) }
    } else {
        &[]
    };

    build_merkle_proof_inner(main_data, subtree_data, leaf_index, unsafe { &mut *out_proof })
}

/// Phase 1: Given config data, program owner, and leaf indices, compute which accounts
/// C++ needs to fetch.
///
/// `program_owner_ptr`: 32-byte registration program ID (from config account's `program_owner`).
/// Tree main and subtree accounts are PDAs of this program, NOT the merkle program.
///
/// Returns a `MerkleProofsPlan` with the main account ID and unique subtree account IDs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_merkle_proofs_plan(
    config_data_ptr: *const u8,
    config_data_len: usize,
    program_owner_ptr: *const u8,
    leaf_indices_ptr: *const u64,
    leaf_indices_count: usize,
    out_plan: *mut MerkleProofsPlan,
) -> Error {
    if config_data_ptr.is_null() || program_owner_ptr.is_null() || out_plan.is_null() {
        return Error::NullPointer;
    }
    if leaf_indices_count > 0 && leaf_indices_ptr.is_null() {
        return Error::NullPointer;
    }
    if config_data_len < CONFIG_STATE_MIN_SIZE {
        return Error::InvalidConfig;
    }

    let config_data = unsafe { core::slice::from_raw_parts(config_data_ptr, config_data_len) };
    let program_owner = unsafe { &*(program_owner_ptr as *const [u8; 32]) };
    let leaf_indices: &[u64] = if leaf_indices_count == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(leaf_indices_ptr, leaf_indices_count) }
    };

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
        return Error::InvalidLeafIndex;
    }

    let plan = unsafe { &mut *out_plan };
    plan.main_account_id = main_account_id;
    plan.subtree_count = unique_ids.len() as u32;

    for (i, &subtree_id) in unique_ids.iter().enumerate() {
        let mut subtree_id_seed = [0u8; 32];
        subtree_id_seed[..4].copy_from_slice(&subtree_id.to_le_bytes());
        plan.subtree_account_ids[i] = derive_pda(
            program_owner,
            &combine_seeds(&[&label_seed("subtree"), tree_id, &subtree_id_seed]),
        );
        plan.subtree_ids[i] = subtree_id;
    }

    Error::Success
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

/// Phase 2: Given fetched account data and leaf indices, build all proofs and return JSON.
///
/// `out_json_ptr` and `out_json_len` receive a heap-allocated UTF-8 string.
/// Caller must free it with `rln_ffi_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_merkle_proofs_exec(
    main_data_ptr: *const u8,
    main_data_len: usize,
    subtrees_ptr: *const SubtreeEntry,
    subtrees_count: usize,
    leaf_indices_ptr: *const u64,
    leaf_indices_count: usize,
    out_json_ptr: *mut *mut u8,
    out_json_len: *mut usize,
) -> Error {
    if main_data_ptr.is_null()
        || leaf_indices_ptr.is_null()
        || out_json_ptr.is_null()
        || out_json_len.is_null()
    {
        return Error::NullPointer;
    }

    let main_data = unsafe { core::slice::from_raw_parts(main_data_ptr, main_data_len) };
    let leaf_indices = unsafe { core::slice::from_raw_parts(leaf_indices_ptr, leaf_indices_count) };
    let subtrees = if !subtrees_ptr.is_null() && subtrees_count > 0 {
        unsafe { core::slice::from_raw_parts(subtrees_ptr, subtrees_count) }
    } else {
        &[]
    };

    let mut proofs = Vec::with_capacity(leaf_indices.len());

    for &leaf_index in leaf_indices {
        let subtree_id = (leaf_index / SUBTREE_LEAVES as u64) as u32;

        let subtree_data: &[u8] = subtrees
            .iter()
            .find(|s| s.subtree_id == subtree_id)
            .map(|s| {
                if s.data_ptr.is_null() || s.data_len == 0 {
                    &[] as &[u8]
                } else {
                    unsafe { core::slice::from_raw_parts(s.data_ptr, s.data_len) }
                }
            })
            .unwrap_or(&[]);

        let mut proof = RlnMerkleProof {
            leaf: [0u8; 32],
            root: [0u8; 32],
            leaf_index: 0,
            depth: 0,
            path_elements: [[0u8; 32]; RLN_TREE_DEPTH],
            path_indices: [0u8; RLN_TREE_DEPTH],
        };

        let err = build_merkle_proof_inner(main_data, subtree_data, leaf_index, &mut proof);

        if !matches!(err, Error::Success) {
            return err;
        }

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

    let json = match serde_json::to_string(&proofs) {
        Ok(s) => s,
        Err(_) => return Error::SerializationError,
    };

    let mut bytes = json.into_bytes();
    bytes.shrink_to_fit();
    let ptr = bytes.as_mut_ptr();
    let len = bytes.len();
    core::mem::forget(bytes);

    unsafe {
        *out_json_ptr = ptr;
        *out_json_len = len;
    }

    Error::Success
}

/// Free a string previously returned by `rln_ffi_merkle_proofs_exec`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_free_string(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, len, len));
        }
    }
}

// ============================================================================
// Registration Support
// ============================================================================

/// Plan for a registration transaction, containing derived account IDs.
#[repr(C)]
pub struct RlnRegisterPlan {
    pub config_account_id: [u8; 32],
    pub tree_main_account_id: [u8; 32],
    pub treasury_account_id: [u8; 32],
    pub subtree_account_id: [u8; 32],
    pub clock_account_id: [u8; 32],
    /// Membership PDA from (program_owner, tree_id, id_commitment).
    /// Required by the `Register` instruction's `init`-marked membership account.
    pub membership_account_id: [u8; 32],
    pub subtree_id: u32,
    pub next_leaf_index: u64,
}

/// Generate an RLN identity from a 32-byte seed.
///
/// Uses zerokit's seeded_keygen to derive identity_secret and id_commitment.
/// The seed should be derived from a wallet signing key or similar entropy source.
///
/// `seed_ptr`: 32-byte input seed
/// `out_id_commitment`: 32-byte output (the public commitment)
/// `out_id_secret_hash`: 32-byte output (the secret, needed for RLN proofs)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_generate_identity(
    seed_ptr: *const u8,
    out_id_commitment: *mut u8,
    out_id_secret_hash: *mut u8,
) -> Error {
    if seed_ptr.is_null() || out_id_commitment.is_null() || out_id_secret_hash.is_null() {
        return Error::NullPointer;
    }

    let seed = unsafe { &*(seed_ptr as *const [u8; 32]) };

    let (identity_secret_fr, id_commitment_fr) = rln::prelude::seeded_keygen(seed);

    let id_commitment_bytes = rln::utils::fr_to_bytes_le(&id_commitment_fr);
    let id_secret_hash_bytes = rln::utils::fr_to_bytes_le(&identity_secret_fr);

    let out_commit = unsafe { core::slice::from_raw_parts_mut(out_id_commitment, 32) };
    out_commit.copy_from_slice(&id_commitment_bytes);

    let out_secret = unsafe { core::slice::from_raw_parts_mut(out_id_secret_hash, 32) };
    out_secret.copy_from_slice(&id_secret_hash_bytes);

    Error::Success
}

/// Compute rate_commitment = poseidon(id_commitment, rate_limit).
///
/// This is the leaf value stored in the merkle tree for rate-limited membership.
///
/// `id_commitment_ptr`: 32-byte id_commitment
/// `rate_limit`: the user's rate limit (message limit)
/// `out_leaf`: 32-byte output (the rate commitment / leaf value)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_compute_rate_commitment(
    id_commitment_ptr: *const u8,
    rate_limit: u64,
    out_leaf: *mut u8,
) -> Error {
    if id_commitment_ptr.is_null() || out_leaf.is_null() {
        return Error::NullPointer;
    }

    let id_commitment = unsafe { &*(id_commitment_ptr as *const [u8; 32]) };

    let (id_commitment_fr, _) = match rln::utils::bytes_le_to_fr(id_commitment) {
        Ok(result) => result,
        Err(_) => return Error::HashFailed,
    };

    let rate_limit_fr = rln::prelude::Fr::from(rate_limit);

    let rate_commitment_fr = rln::hashers::poseidon_hash(&[id_commitment_fr, rate_limit_fr]);

    let leaf_bytes = rln::utils::fr_to_bytes_le(&rate_commitment_fr);

    let out = unsafe { core::slice::from_raw_parts_mut(out_leaf, 32) };
    out.copy_from_slice(&leaf_bytes);

    Error::Success
}

/// Plan a registration transaction by deriving all required account IDs.
///
/// `config_data_ptr`/`config_data_len`: raw bytes of config account (tree_id is read from here)
/// `tree_main_data_ptr`/`tree_main_data_len`: raw bytes of tree main account (for next_leaf_index)
/// `program_owner_ptr`: 32-byte registration program ID
/// `id_commitment_ptr`: 32-byte id_commitment (used to derive the membership PDA)
/// `out_plan`: pointer to caller-allocated RlnRegisterPlan
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_register_plan(
    config_data_ptr: *const u8,
    config_data_len: usize,
    tree_main_data_ptr: *const u8,
    tree_main_data_len: usize,
    program_owner_ptr: *const u8,
    id_commitment_ptr: *const u8,
    out_plan: *mut RlnRegisterPlan,
) -> Error {
    if config_data_ptr.is_null()
        || tree_main_data_ptr.is_null()
        || program_owner_ptr.is_null()
        || id_commitment_ptr.is_null()
        || out_plan.is_null()
    {
        return Error::NullPointer;
    }
    if config_data_len < CONFIG_STATE_MIN_SIZE {
        return Error::InvalidConfig;
    }
    if tree_main_data_len < TreeMainLayout::SIZE {
        return Error::DataTooShort;
    }

    let config_data = unsafe { core::slice::from_raw_parts(config_data_ptr, config_data_len) };
    let tree_main_data = unsafe { core::slice::from_raw_parts(tree_main_data_ptr, tree_main_data_len) };
    let program_owner = unsafe { &*(program_owner_ptr as *const [u8; 32]) };
    let id_commitment = unsafe { &*(id_commitment_ptr as *const [u8; 32]) };

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

    let plan = unsafe { &mut *out_plan };
    plan.config_account_id = config_account_id;
    plan.tree_main_account_id = tree_main_account_id;
    plan.treasury_account_id = config_field_32(config_data, CONFIG_OFFSET_TREASURY_ACCOUNT_ID);
    plan.subtree_account_id = subtree_account_id;
    plan.clock_account_id = rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES;
    plan.membership_account_id = membership_account_id;
    plan.subtree_id = subtree_id;
    plan.next_leaf_index = next_leaf_index;

    Error::Success
}

/// Build the serialized instruction data for a Register transaction.
///
/// Returns a serialized SPEL `Instruction::Register` payload (risc0-serde),
/// suitable for the registration program's #[lez_program] handler.
///
/// `tree_id_ptr`: 32-byte tree_id (same as in ConfigState)
/// `id_commitment_ptr`: 32-byte id_commitment
/// `rate_limit`: the user's rate limit
/// `subtree_id`: which bottom subtree the leaf will land in (= next_leaf_index / SUBTREE_LEAVES)
/// `out_data_ptr` and `out_data_len`: receive heap-allocated serialized data
/// Caller must free with `rln_ffi_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_register_build_instruction(
    tree_id_ptr: *const u8,
    id_commitment_ptr: *const u8,
    rate_limit: u64,
    subtree_id: u32,
    out_data_ptr: *mut *mut u8,
    out_data_len: *mut usize,
) -> Error {
    if tree_id_ptr.is_null()
        || id_commitment_ptr.is_null()
        || out_data_ptr.is_null()
        || out_data_len.is_null()
    {
        return Error::NullPointer;
    }

    let tree_id = unsafe { *(tree_id_ptr as *const [u8; 32]) };
    let id_commitment = unsafe { *(id_commitment_ptr as *const [u8; 32]) };

    let instruction = rln_layouts::Instruction::Register {
        tree_id,
        id_commitment,
        rate_limit,
        subtree_id,
    };

    // risc0 serde — matches the on-chain program's wire format.
    unsafe { leak_instruction_bytes(&instruction, out_data_ptr, out_data_len) }
}

/// Decode a fetched membership PDA's account data into its scalar fields.
///
/// Used by callers (e.g. logos_rln_module) to check whether a given
/// id_commitment already has an on-chain membership before submitting a
/// Register tx (idempotency / restart recovery / retry-after-tx-loss).
///
/// `account_data_ptr` / `account_data_len`: raw account.data bytes from the
/// wallet. Must be at least 64 bytes (MembershipState borsh size).
/// `out_leaf_index` / `out_rate_limit`: receive the corresponding fields.
/// `out_id_commitment_ptr`: caller-allocated 32-byte buffer for id_commitment.
///
/// Returns `DataTooShort` if the buffer is too small; `SerializationError`
/// if borsh decode fails (account exists but isn't a valid MembershipState —
/// caller should treat as "not a membership PDA").
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_decode_membership(
    account_data_ptr: *const u8,
    account_data_len: usize,
    out_leaf_index: *mut u64,
    out_rate_limit: *mut u64,
    out_id_commitment_ptr: *mut u8,
) -> Error {
    if account_data_ptr.is_null()
        || out_leaf_index.is_null()
        || out_rate_limit.is_null()
        || out_id_commitment_ptr.is_null()
    {
        return Error::NullPointer;
    }
    // MembershipState is 8+8+32+8+4+4 = 64 bytes borsh.
    if account_data_len < 64 {
        return Error::DataTooShort;
    }
    let bytes = unsafe { core::slice::from_raw_parts(account_data_ptr, account_data_len) };
    let state = match MembershipState::try_from_slice(&bytes[..64]) {
        Ok(s) => s,
        Err(_) => return Error::SerializationError,
    };
    unsafe {
        *out_leaf_index = state.leaf_index;
        *out_rate_limit = state.rate_limit;
        core::ptr::copy_nonoverlapping(
            state.id_commitment.as_ptr(),
            out_id_commitment_ptr,
            32,
        );
    }
    Error::Success
}

/// Parse a Token-program holding account (borsh `TokenHolding`).
///
/// Used by the mint-on-demand funding path: any fungible holding's data
/// yields its token-definition account id and balance.
///
/// `data_ptr`/`data_len`: raw token-holding account bytes.
/// `out_definition_id`: caller-allocated 32-byte buffer.
/// `out_balance_str`/`balance_cap`/`out_balance_len`: caller buffer receiving
/// the balance as a decimal string (u128 needs up to 39 chars; pass >= 40 —
/// a string keeps the full u128 range across the C ABI).
///
/// Returns `InvalidConfig` for NFT holdings, `SerializationError` if the
/// data is not a valid `TokenHolding`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_token_holding_info(
    data_ptr: *const u8,
    data_len: usize,
    out_definition_id: *mut u8,
    out_balance_str: *mut u8,
    balance_cap: usize,
    out_balance_len: *mut usize,
) -> Error {
    if data_ptr.is_null()
        || out_definition_id.is_null()
        || out_balance_str.is_null()
        || out_balance_len.is_null()
    {
        return Error::NullPointer;
    }
    let mut bytes = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };
    // `deserialize` (not try_from_slice) tolerates trailing bytes in the
    // account data.
    let holding = match token_core::TokenHolding::deserialize(&mut bytes) {
        Ok(h) => h,
        Err(_) => return Error::SerializationError,
    };
    let (definition_id, balance) = match holding {
        token_core::TokenHolding::Fungible {
            definition_id,
            balance,
        } => (definition_id, balance),
        token_core::TokenHolding::NftMaster { .. }
        | token_core::TokenHolding::NftPrintedCopy { .. } => return Error::InvalidConfig,
    };
    let s = balance.to_string();
    if s.len() > balance_cap {
        return Error::DataTooShort;
    }
    unsafe {
        core::slice::from_raw_parts_mut(out_definition_id, 32)
            .copy_from_slice(definition_id.value());
        core::slice::from_raw_parts_mut(out_balance_str, s.len()).copy_from_slice(s.as_bytes());
        *out_balance_len = s.len();
    }
    Error::Success
}

/// Plan a Token-program `Mint` transaction from the RLN config account.
///
/// The RLN `ConfigState` already records the payment token's definition
/// account (`payment_token_id` — the mint authority, whose signing key lives
/// in the deployment wallet) and the Token program id, so the caller only
/// needs the config account it already holds.
///
/// `config_data_ptr`/`config_data_len`: raw config account bytes.
/// `amount_str_ptr`/`amount_str_len`: mint amount as a decimal u128 string.
/// `out_definition_id` / `out_token_program_id`: 32-byte buffers — the two
/// tx accounts are `[definition (signer), destination holder]` per the Token
/// program's `Mint` contract (holder may be a fresh, uninitialized account —
/// the program zero-initializes the holding from the definition).
/// `out_data_ptr`/`out_data_len`: heap-allocated instruction words
/// (risc0-serde u32 words serialized LE — the deployed built-in Token
/// program's wire format, same convention as
/// `rln_ffi_register_build_instruction`). Free with `rln_ffi_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_token_mint_plan(
    config_data_ptr: *const u8,
    config_data_len: usize,
    amount_str_ptr: *const u8,
    amount_str_len: usize,
    out_definition_id: *mut u8,
    out_token_program_id: *mut u8,
    out_data_ptr: *mut *mut u8,
    out_data_len: *mut usize,
) -> Error {
    if config_data_ptr.is_null()
        || amount_str_ptr.is_null()
        || out_definition_id.is_null()
        || out_token_program_id.is_null()
        || out_data_ptr.is_null()
        || out_data_len.is_null()
    {
        return Error::NullPointer;
    }
    if config_data_len < CONFIG_STATE_MIN_SIZE {
        return Error::InvalidConfig;
    }

    let config_data = unsafe { core::slice::from_raw_parts(config_data_ptr, config_data_len) };

    let amount = match unsafe { parse_amount_u128(amount_str_ptr, amount_str_len) } {
        Ok(a) => a,
        Err(e) => return e,
    };

    let instruction = token_core::Instruction::Mint {
        amount_to_mint: amount,
    };
    let err = unsafe { leak_instruction_bytes(&instruction, out_data_ptr, out_data_len) };
    if !matches!(err, Error::Success) {
        return err;
    }

    unsafe {
        core::slice::from_raw_parts_mut(out_definition_id, 32)
            .copy_from_slice(&config_field_32(config_data, CONFIG_OFFSET_PAYMENT_TOKEN_ID));
        core::slice::from_raw_parts_mut(out_token_program_id, 32)
            .copy_from_slice(&config_field_32(config_data, CONFIG_OFFSET_TOKEN_PROGRAM_ID));
    }

    Error::Success
}

/// Plan a faucet `ClaimTokens` transaction (faucet-funded deployments: the
/// payment token definition is the registration program's `payment` PDA and
/// the mint is program-authorized — no human key).
///
/// `config_data_ptr`/`config_data_len`: raw config account bytes (tree_id is
/// read by offset).
/// `program_owner_ptr`: 32-byte REGISTRATION program id (the config account's
/// `program_owner` — the claim tx targets this program, not the token program).
/// `amount_str_ptr`/`amount_str_len`: claim amount as a decimal u128 string.
/// `out_payment_def_id`: 32-byte buffer — tx account order is
/// `[config, payment_def, dest (signer)]`; dest co-signs (fresh holdings are
/// claimed `Claim::Authorized` by the token program).
/// `out_data_ptr`/`out_data_len`: heap-allocated risc0-serde instruction
/// words, LE bytes. Free with `rln_ffi_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_claim_plan(
    config_data_ptr: *const u8,
    config_data_len: usize,
    program_owner_ptr: *const u8,
    amount_str_ptr: *const u8,
    amount_str_len: usize,
    out_payment_def_id: *mut u8,
    out_data_ptr: *mut *mut u8,
    out_data_len: *mut usize,
) -> Error {
    if config_data_ptr.is_null()
        || program_owner_ptr.is_null()
        || amount_str_ptr.is_null()
        || out_payment_def_id.is_null()
        || out_data_ptr.is_null()
        || out_data_len.is_null()
    {
        return Error::NullPointer;
    }
    if config_data_len < CONFIG_STATE_MIN_SIZE {
        return Error::InvalidConfig;
    }

    let config_data = unsafe { core::slice::from_raw_parts(config_data_ptr, config_data_len) };
    let program_owner = unsafe { &*(program_owner_ptr as *const [u8; 32]) };

    let amount = match unsafe { parse_amount_u128(amount_str_ptr, amount_str_len) } {
        Ok(a) => a,
        Err(e) => return e,
    };

    let tree_id = config_field_32(config_data, CONFIG_OFFSET_TREE_ID);
    let payment_def_id = derive_pda(
        program_owner,
        &combine_seeds(&[&label_seed("payment"), &tree_id]),
    );

    let instruction = rln_layouts::Instruction::ClaimTokens { tree_id, amount };
    let err = unsafe { leak_instruction_bytes(&instruction, out_data_ptr, out_data_len) };
    if !matches!(err, Error::Success) {
        return err;
    }

    unsafe {
        core::slice::from_raw_parts_mut(out_payment_def_id, 32).copy_from_slice(&payment_def_id);
    }

    Error::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use rln_layouts::ConfigState;

    fn make_config_state() -> Vec<u8> {
        let cfg = ConfigState {
            merkle_program_id: [0x11; 32],
            tree_id: [0x42; 32],
            payment_token_id: [0x22; 32],
            receipt_token_id: [0x23; 32],
            price_per_unit: 1,
            treasury_account_id: [0x33; 32],
            total_registrations: 0,
            max_total_rate_limit: 1_000_000,
            current_total_rate_limit: 0,
            active_duration_for_new_memberships: 100,
            grace_period_duration_for_new_memberships: 10,
            token_program_id: [0x44; 32],
            authorized_registrar: [0x55; 32],
            free_quota_remaining: 3,
            faucet_claim_cap: 1_000_000,
        };
        borsh::to_vec(&cfg).unwrap()
    }

    #[test]
    fn plan_derives_correct_ids_with_program_owner() {
        let config_data = make_config_state();
        let program_owner: [u8; 32] = [0xAA; 32];
        let tree_id: [u8; 32] = [0x42; 32];

        let expected_main_id =
            derive_pda(&program_owner, &combine_seeds(&[&label_seed("main"), &tree_id]));

        let leaf_indices: Vec<u64> = vec![0, 1, 1025];
        let mut plan = MerkleProofsPlan {
            main_account_id: [0u8; 32],
            subtree_account_ids: [[0u8; 32]; MAX_SUBTREES_PER_CALL],
            subtree_ids: [0u32; MAX_SUBTREES_PER_CALL],
            subtree_count: 0,
        };
        let err = unsafe {
            rln_ffi_merkle_proofs_plan(
                config_data.as_ptr(), config_data.len(),
                program_owner.as_ptr(),
                leaf_indices.as_ptr(), leaf_indices.len(),
                &mut plan,
            )
        };
        assert!(matches!(err, Error::Success));

        assert_eq!(expected_main_id, plan.main_account_id);

        assert_eq!(plan.subtree_count, 2);
        assert_eq!(plan.subtree_ids[0], 0);
        assert_eq!(plan.subtree_ids[1], 1);

        for i in 0..plan.subtree_count as usize {
            let mut subtree_id_seed = [0u8; 32];
            subtree_id_seed[..4].copy_from_slice(&plan.subtree_ids[i].to_le_bytes());
            let expected = derive_pda(
                &program_owner,
                &combine_seeds(&[&label_seed("subtree"), &tree_id, &subtree_id_seed]),
            );
            assert_eq!(expected, plan.subtree_account_ids[i],
                "subtree {} account ID mismatch!", plan.subtree_ids[i]);
        }
    }

    // Pins the local CONFIG_OFFSET_* consts to rln_layouts::ConfigState's
    // Borsh layout: each offset read must recover exactly its field's bytes
    // (make_config_state uses distinct per-field values, so any offset drift
    // or field reorder fails). Also states the compat contract: the offsets
    // this FFI relies on all end at or before the 240-byte pre-policy floor,
    // which every config version (240 legacy, 296 policy) satisfies.
    #[test]
    fn config_offsets_match_shared_layout() {
        let bytes = make_config_state();

        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TREE_ID), [0x42; 32]);
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_PAYMENT_TOKEN_ID), [0x22; 32]);
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TREASURY_ACCOUNT_ID), [0x33; 32]);
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TOKEN_PROGRAM_ID), [0x44; 32]);

        assert_eq!(
            CONFIG_OFFSET_TOKEN_PROGRAM_ID + 32,
            CONFIG_STATE_MIN_SIZE,
            "last offset-read field must fit within the pre-policy floor"
        );
        assert!(
            bytes.len() >= CONFIG_STATE_MIN_SIZE,
            "policy-era ConfigState must still satisfy the precheck floor"
        );
    }
}
