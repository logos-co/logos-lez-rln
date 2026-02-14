# logos-lez-rln

This repository contains the LEZ program for the RLN (Rate-Limiting Nullifiers) membership registry.

## Prerequisites

- Rust
```bash
# Install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add nightly toolchain (required for guest unit tests)
rustup toolchain install nightly
```
- [RISC Zero toolchain](https://dev.risczero.com/api/zkvm/install)
- Docker (for guest program compilation)

## Usage
### Build

```bash
# Build client library
cargo build

# Build programs for risc0
cargo risczero build --manifest-path methods/guest/Cargo.toml
```

### Test

```bash
# Run state/integration tests (requires guest programs built first)
RISC0_DEV_MODE=1 cargo test --lib state_tests

# Run guest program unit tests (requires nightly)
cargo +nightly test -p logos_lez_rln_guest
```

## Structure

- `rln-layouts/` - Shared zero-copy layouts, constants, and PDA seed construction (no_std, used by both host and guest)
- `methods/guest/` - zkVM guest programs (rln_registration, incremental_merkle_tree)
- `src/rln/` - RLN client library (PDA derivation)
- `src/merkle_tree/` - Merkle tree client library
- `src/bin/` - CLI tools

## Merkle Tree Program

The incremental Merkle tree (depth 20, ~1M leaves) is split across multiple on-chain accounts to keep each operation's data footprint small.

### Storage Layout

The tree is divided at level 10 into a **top tree** and **1024 bottom subtrees**:

```
           [root]              <- top tree (levels 0-10)
          /      \                stored in main account
        ...      ...
       / \ ... / \
      S0  S1  ... S1023        <- subtree roots
     /\   /\      /\           <- bottom subtrees (levels 11-20)
    ...  ...     ...              each in its own PDA account
```

- **Main account** (`tree_id + "__main__"`): Tree metadata (depth, next_index, root, 21 cached default hashes) + top tree nodes in sparse format. Starts at 713 bytes, grows as nodes are added.
- **Subtree accounts** (`tree_id + 0xFF + subtree_id`): Each stores a depth-10 subtree in sparse format.

Each insert or remove touches exactly **2 accounts**: the main account and one bottom subtree.

### Sparse Node Storage

Both the top tree and subtrees use a compact sparse format instead of storing all 2^11 - 1 nodes:

```
[count: u16le] [offset: u16le, hash: 32 bytes] [offset: u16le, hash: 32 bytes] ...
```

Entries are sorted by BFS offset (`(2^level - 1) + index_within_level`) for binary search. Only modified nodes are stored; unmodified nodes use cached default hashes.

### Operations

| Operation  | Accounts              | Instruction data             |
|------------|-----------------------|------------------------------|
| Initialize | main                  | (none)                       |
| Insert     | main + subtree        | expected_index(8) + leaf(32) |
| Remove     | main + subtree        | leaf_index(8)                |

The merkle tree program is never called directly by clients. The RLN registration program calls it via **chained calls** with PDA authorization.

## RLN Registration Program

The registration program controls access to the merkle tree and manages membership. It is the only entity that can insert or remove leaves, enforced via PDA authorization on the tree accounts.

### Accounts

All accounts are PDAs derived from the registration program's ID and a 24-byte `tree_id`:

| Account          | Seed suffix      | Contents                                              |
|------------------|------------------|-------------------------------------------------------|
| Config           | `_config_`       | Merkle program ID, tree ID, payment/credit token IDs, price, treasury, rate limit tracking |
| Tree main        | `__main__`       | Merkle tree metadata + top tree (see above)           |
| Subtrees         | `0xFF` + id      | Bottom subtrees (see above)                           |
| Credit token def | `_receipt`       | Fungible credit token definition                      |
| Credit supply    | `_supply_`       | Credit token supply holder                            |
| Membership       | `hash(tree_id, id_commitment)` | Maps id_commitment to (leaf_index, rate_limit) |

### Instructions

Instructions are passed as a serde `Instruction` enum (defined in `rln-layouts`).

**Initialize** — Sets up a new registration instance. Derives config, credit token, and tree main accounts internally (zero-account pattern). Chains to the token program to create the credit token and to the merkle program to initialize the tree. No external accounts needed.

**Register** (direct flow) — Atomic payment + registration. Transfers `rate_limit * price_per_unit` from the user's payment holding to treasury, computes `leaf = hash(id_commitment, rate_limit)`, creates a membership PDA, and chains to the merkle program to insert the leaf.

**BuyCredits** — Transfers payment tokens to treasury and mints an equal amount of credits to the user. Chains to the token program for both transfer and mint.

**RegisterWithCredits** — Burns credits from the user's credit holding (rate_limit = amount burned), creates a membership PDA, and chains to the merkle program to insert the leaf. Separating payment from registration allows unlinkable registration via private credit transfers.

**Slash** — Anyone can remove a spammer by providing their `identity_secret`. The program verifies `id_commitment = hash(identity_secret)`, looks up the membership, and chains to the merkle program to remove the leaf. Frees the consumed rate limit.

### Rate Limits

Each registration consumes rate limit from a global pool (`current_total_rate_limit` in config). Rate limit per member must be between 100 and 600. Slashing returns the member's rate limit to the pool.
