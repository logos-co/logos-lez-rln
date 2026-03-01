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
 * Deprecated: superseded by `rln_ffi_merkle_proofs_plan` which handles config parsing internally.
 * Extract merkle_program_id (32 bytes) and tree_id (24 bytes) from config account data.
 */
enum RlnFfiError rln_ffi_parse_config(const uint8_t *data_ptr,
                                      uintptr_t data_len,
                                      uint8_t *out_merkle_program_id,
                                      uint8_t *out_tree_id);

/**
 * Deprecated: superseded by `rln_ffi_merkle_proofs_plan` which derives accounts internally.
 * WARNING: the first parameter should be the registration program ID (the config account's
 * `program_owner`), NOT the merkle_program_id from config data. Tree accounts are PDAs of
 * the registration program.
 */
enum RlnFfiError rln_ffi_derive_main_account_id(const uint8_t *registration_program_id,
                                                const uint8_t *tree_id,
                                                uint8_t *out_account_id);

/**
 * Deprecated: superseded by `rln_ffi_merkle_proofs_plan` which derives accounts internally.
 * WARNING: the first parameter should be the registration program ID, NOT the merkle_program_id.
 */
enum RlnFfiError rln_ffi_derive_subtree_account_id(const uint8_t *registration_program_id,
                                                   const uint8_t *tree_id,
                                                   uint32_t subtree_id,
                                                   uint8_t *out_account_id);

/**
 * Build a merkle proof for a single leaf given pre-fetched main + subtree data.
 *
 * `main_data`/`main_len`: raw bytes of the tree main account.
 * `subtree_data`/`subtree_len`: raw bytes of the subtree account for this leaf.
 *   (subtree_id = leaf_index / 1024)
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

#endif  /* LEZ_RLN_FFI_H */
