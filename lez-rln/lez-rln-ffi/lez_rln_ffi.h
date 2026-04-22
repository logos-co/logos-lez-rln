#ifndef LEZ_RLN_FFI_H
#define LEZ_RLN_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Maximum tree depth for proof arrays.
 */
#define RlnFfiRLN_TREE_DEPTH 20

#define RlnFfiMAX_SUBTREES_PER_CALL 64

typedef enum RlnFfiError {
  RLN_FFI_ERROR_SUCCESS = 0,
  RLN_FFI_ERROR_NULL_POINTER = 1,
  RLN_FFI_ERROR_DATA_TOO_SHORT = 2,
  RLN_FFI_ERROR_INVALID_CONFIG = 3,
  RLN_FFI_ERROR_INVALID_LEAF_INDEX = 4,
  RLN_FFI_ERROR_SERIALIZATION_ERROR = 5,
  RLN_FFI_ERROR_KEYGEN_FAILED = 6,
  RLN_FFI_ERROR_HASH_FAILED = 7,
  RLN_FFI_ERROR_TRANSACTION_BUILD_FAILED = 8,
} RlnFfiError;

typedef struct RlnFfiRlnMerkleProof {
  uint8_t leaf[32];
  uint8_t root[32];
  uint64_t leaf_index;
  uint32_t depth;
  uint8_t path_elements[RlnFfiRLN_TREE_DEPTH][32];
  uint8_t path_indices[RlnFfiRLN_TREE_DEPTH];
} RlnFfiRlnMerkleProof;

typedef struct RlnFfiMerkleProofsPlan {
  uint8_t main_account_id[32];
  uint8_t subtree_account_ids[RlnFfiMAX_SUBTREES_PER_CALL][32];
  uint32_t subtree_ids[RlnFfiMAX_SUBTREES_PER_CALL];
  uint32_t subtree_count;
} RlnFfiMerkleProofsPlan;

typedef struct RlnFfiSubtreeEntry {
  uint32_t subtree_id;
  const uint8_t *data_ptr;
  uintptr_t data_len;
} RlnFfiSubtreeEntry;

/**
 * Plan for a registration transaction, containing derived account IDs.
 */
typedef struct RlnFfiRlnRegisterPlan {
  uint8_t config_account_id[32];
  uint8_t tree_main_account_id[32];
  uint8_t treasury_account_id[32];
  uint8_t subtree_account_id[32];
  uint32_t subtree_id;
  uint64_t next_leaf_index;
} RlnFfiRlnRegisterPlan;

/**
 * Parse tree-main account data and write valid roots into `out_roots`.
 *
 * `out_roots`: caller buffer, at least 160 bytes (5 x 32).
 * `out_count`: set to number of valid roots written (1..=5).
 *
 * Slot 0 = current root. Slots 1..N = non-zero history entries.
 */
enum RlnFfiError rln_ffi_get_valid_roots(const uint8_t *data_ptr,
                                         uintptr_t data_len,
                                         uint8_t *out_roots,
                                         uint32_t *out_count);

/**
 * Build a merkle proof for a single leaf given pre-fetched main + subtree data.
 *
 * `main_data`/`main_len`: raw bytes of the tree main account.
 * `subtree_data`/`subtree_len`: raw bytes of the subtree account for this leaf.
 *   (subtree_id = leaf_index / SUBTREE_LEAVES)
 * `leaf_index`: the leaf position in the tree.
 * `out_proof`: pointer to caller-allocated `RlnMerkleProof`.
 */
enum RlnFfiError rln_ffi_build_merkle_proof(const uint8_t *main_data_ptr,
                                            uintptr_t main_data_len,
                                            const uint8_t *subtree_data_ptr,
                                            uintptr_t subtree_data_len,
                                            uint64_t leaf_index,
                                            struct RlnFfiRlnMerkleProof *out_proof);

/**
 * Phase 1: Given config data, program owner, and leaf indices, compute which accounts
 * C++ needs to fetch.
 *
 * `program_owner_ptr`: 32-byte registration program ID (from config account's `program_owner`).
 * Tree main and subtree accounts are PDAs of this program, NOT the merkle program.
 *
 * Returns a `MerkleProofsPlan` with the main account ID and unique subtree account IDs.
 */
enum RlnFfiError rln_ffi_merkle_proofs_plan(const uint8_t *config_data_ptr,
                                            uintptr_t config_data_len,
                                            const uint8_t *program_owner_ptr,
                                            const uint64_t *leaf_indices_ptr,
                                            uintptr_t leaf_indices_count,
                                            struct RlnFfiMerkleProofsPlan *out_plan);

/**
 * Phase 2: Given fetched account data and leaf indices, build all proofs and return JSON.
 *
 * `out_json_ptr` and `out_json_len` receive a heap-allocated UTF-8 string.
 * Caller must free it with `rln_ffi_free_string`.
 */
enum RlnFfiError rln_ffi_merkle_proofs_exec(const uint8_t *main_data_ptr,
                                            uintptr_t main_data_len,
                                            const struct RlnFfiSubtreeEntry *subtrees_ptr,
                                            uintptr_t subtrees_count,
                                            const uint64_t *leaf_indices_ptr,
                                            uintptr_t leaf_indices_count,
                                            uint8_t **out_json_ptr,
                                            uintptr_t *out_json_len);

/**
 * Free a string previously returned by `rln_ffi_merkle_proofs_exec`.
 */
void rln_ffi_free_string(uint8_t *ptr, uintptr_t len);

/**
 * Generate an RLN identity from a 32-byte seed.
 *
 * Uses zerokit's seeded_keygen to derive identity_secret and id_commitment.
 * The seed should be derived from a wallet signing key or similar entropy source.
 *
 * `seed_ptr`: 32-byte input seed
 * `out_id_commitment`: 32-byte output (the public commitment)
 * `out_id_secret_hash`: 32-byte output (the secret, needed for RLN proofs)
 */
enum RlnFfiError rln_ffi_generate_identity(const uint8_t *seed_ptr,
                                           uint8_t *out_id_commitment,
                                           uint8_t *out_id_secret_hash);

/**
 * Compute rate_commitment = poseidon(id_commitment, rate_limit).
 *
 * This is the leaf value stored in the merkle tree for rate-limited membership.
 *
 * `id_commitment_ptr`: 32-byte id_commitment
 * `rate_limit`: the user's rate limit (message limit)
 * `out_leaf`: 32-byte output (the rate commitment / leaf value)
 */
enum RlnFfiError rln_ffi_compute_rate_commitment(const uint8_t *id_commitment_ptr,
                                                 uint64_t rate_limit,
                                                 uint8_t *out_leaf);

/**
 * Plan a registration transaction by deriving all required account IDs.
 *
 * `config_data_ptr`/`config_data_len`: raw bytes of config account (tree_id is read from here)
 * `tree_main_data_ptr`/`tree_main_data_len`: raw bytes of tree main account (for next_leaf_index)
 * `program_owner_ptr`: 32-byte registration program ID
 * `out_plan`: pointer to caller-allocated RlnRegisterPlan
 */
enum RlnFfiError rln_ffi_register_plan(const uint8_t *config_data_ptr,
                                       uintptr_t config_data_len,
                                       const uint8_t *tree_main_data_ptr,
                                       uintptr_t tree_main_data_len,
                                       const uint8_t *program_owner_ptr,
                                       struct RlnFfiRlnRegisterPlan *out_plan);

/**
 * Build the serialized instruction data for a Register transaction.
 *
 * Returns a borsh-serialized instruction payload that can be used
 * to construct the transaction message.
 *
 * `id_commitment_ptr`: 32-byte id_commitment
 * `rate_limit`: the user's rate limit
 * `out_data_ptr` and `out_data_len`: receive heap-allocated serialized data
 * Caller must free with `rln_ffi_free_string`.
 */
enum RlnFfiError rln_ffi_register_build_instruction(const uint8_t *id_commitment_ptr,
                                                    uint64_t rate_limit,
                                                    uint8_t **out_data_ptr,
                                                    uintptr_t *out_data_len);

#endif  /* LEZ_RLN_FFI_H */
