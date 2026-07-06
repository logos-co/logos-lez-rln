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
  uint8_t clock_account_id[32];
  /**
   * Membership PDA from (program_owner, tree_id, id_commitment).
   * Required by the `Register` instruction's `init`-marked membership account.
   */
  uint8_t membership_account_id[32];
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
 * `id_commitment_ptr`: 32-byte id_commitment (used to derive the membership PDA)
 * `out_plan`: pointer to caller-allocated RlnRegisterPlan
 */
enum RlnFfiError rln_ffi_register_plan(const uint8_t *config_data_ptr,
                                       uintptr_t config_data_len,
                                       const uint8_t *tree_main_data_ptr,
                                       uintptr_t tree_main_data_len,
                                       const uint8_t *program_owner_ptr,
                                       const uint8_t *id_commitment_ptr,
                                       struct RlnFfiRlnRegisterPlan *out_plan);

/**
 * Build the serialized instruction data for a Register transaction.
 *
 * Returns a serialized SPEL `Instruction::Register` payload (risc0-serde),
 * suitable for the registration program's #[lez_program] handler.
 *
 * `tree_id_ptr`: 32-byte tree_id (same as in ConfigState)
 * `id_commitment_ptr`: 32-byte id_commitment
 * `rate_limit`: the user's rate limit
 * `subtree_id`: which bottom subtree the leaf will land in (= next_leaf_index / SUBTREE_LEAVES)
 * `out_data_ptr` and `out_data_len`: receive heap-allocated serialized data
 * Caller must free with `rln_ffi_free_string`.
 */
enum RlnFfiError rln_ffi_register_build_instruction(const uint8_t *tree_id_ptr,
                                                    const uint8_t *id_commitment_ptr,
                                                    uint64_t rate_limit,
                                                    uint32_t subtree_id,
                                                    uint8_t **out_data_ptr,
                                                    uintptr_t *out_data_len);

/**
 * Decode a fetched membership PDA's account data into its scalar fields.
 *
 * Used by callers (e.g. logos_rln_module) to check whether a given
 * id_commitment already has an on-chain membership before submitting a
 * Register tx (idempotency / restart recovery / retry-after-tx-loss).
 *
 * `account_data_ptr` / `account_data_len`: raw account.data bytes from the
 * wallet. Must be at least 64 bytes (MembershipState borsh size).
 * `out_leaf_index` / `out_rate_limit`: receive the corresponding fields.
 * `out_id_commitment_ptr`: caller-allocated 32-byte buffer for id_commitment.
 *
 * Returns `DataTooShort` if the buffer is too small; `SerializationError`
 * if borsh decode fails (account exists but isn't a valid MembershipState —
 * caller should treat as "not a membership PDA").
 */
enum RlnFfiError rln_ffi_decode_membership(const uint8_t *account_data_ptr,
                                           uintptr_t account_data_len,
                                           uint64_t *out_leaf_index,
                                           uint64_t *out_rate_limit,
                                           uint8_t *out_id_commitment_ptr);

/**
 * Parse a Token-program holding account (borsh `TokenHolding`).
 *
 * Used by the mint-on-demand funding path: any fungible holding's data
 * yields its token-definition account id and balance.
 *
 * `data_ptr`/`data_len`: raw token-holding account bytes.
 * `out_definition_id`: caller-allocated 32-byte buffer.
 * `out_balance_str`/`balance_cap`/`out_balance_len`: caller buffer receiving
 * the balance as a decimal string (u128 needs up to 39 chars; pass >= 40 —
 * a string keeps the full u128 range across the C ABI).
 *
 * Returns `InvalidConfig` for NFT holdings, `SerializationError` if the
 * data is not a valid `TokenHolding`.
 */
enum RlnFfiError rln_ffi_token_holding_info(const uint8_t *data_ptr,
                                            uintptr_t data_len,
                                            uint8_t *out_definition_id,
                                            uint8_t *out_balance_str,
                                            uintptr_t balance_cap,
                                            uintptr_t *out_balance_len);

/**
 * Plan a Token-program `Mint` transaction from the RLN config account.
 *
 * The RLN `ConfigState` already records the payment token's definition
 * account (`payment_token_id` — the mint authority, whose signing key lives
 * in the deployment wallet) and the Token program id, so the caller only
 * needs the config account it already holds.
 *
 * `config_data_ptr`/`config_data_len`: raw config account bytes.
 * `amount_str_ptr`/`amount_str_len`: mint amount as a decimal u128 string.
 * `out_definition_id` / `out_token_program_id`: 32-byte buffers — the two
 * tx accounts are `[definition (signer), destination holder]` per the Token
 * program's `Mint` contract (holder may be a fresh, uninitialized account —
 * the program zero-initializes the holding from the definition).
 * `out_data_ptr`/`out_data_len`: heap-allocated instruction words
 * (risc0-serde u32 words serialized LE — the deployed built-in Token
 * program's wire format, same convention as
 * `rln_ffi_register_build_instruction`). Free with `rln_ffi_free_string`.
 */
enum RlnFfiError rln_ffi_token_mint_plan(const uint8_t *config_data_ptr,
                                         uintptr_t config_data_len,
                                         const uint8_t *amount_str_ptr,
                                         uintptr_t amount_str_len,
                                         uint8_t *out_definition_id,
                                         uint8_t *out_token_program_id,
                                         uint8_t **out_data_ptr,
                                         uintptr_t *out_data_len);

#endif  /* LEZ_RLN_FFI_H */
