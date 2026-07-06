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

The Rust toolchain is pinned via `rust-toolchain.toml`. The LEZ framework
(`lssa` / `logos-execution-zone`) and the SPEL macro framework (`spel`) are
consumed as **git dependencies pinned by tag/rev** in `lez-rln/Cargo.toml` and
`lez-rln/methods/guest/Cargo.toml` — a fresh clone builds with no sibling
checkouts to place by hand.

## Usage
### Build

```bash
cd lez-rln
cargo build
cargo risczero build --manifest-path methods/guest/Cargo.toml
```

### Test

```bash
cd lez-rln
cargo +nightly test -p logos_lez_rln_guest
cargo test --lib -- --skip state_tests
RISC0_DEV_MODE=1 cargo test --lib state_tests
```

### Run end-to-end against a sequencer

Terminal 1:

```bash
./dev.sh   # fetches the pinned sequencer source into a cache on first run, then starts it
```

Terminal 2:

```bash
source dev/env.sh
cd lez-rln
cargo run --bin run_setup        # deploys programs, creates payment token
cargo run --bin register_member  # registers a single identity (--count N to batch)
cargo run --bin run_rln_proof    # generate + verify RLN proof against on-chain root
```

`run_rln_proof` is the canonical end-to-end smoke test: it registers an identity, fetches the merkle proof from the chain, generates an RLN proof via zerokit, and verifies it. Pass = the on-chain Poseidon merkle root matches what zerokit computes.

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

- **Main account** (seeds `["main", tree_id]`): Tree metadata (depth, next_index, root, 4 previous roots, 21 cached default hashes) + top tree nodes in sparse format. Starts at 841 bytes, grows as nodes are added.
- **Subtree accounts** (seeds `["subtree", tree_id, subtree_id]`): Each stores a depth-10 subtree in sparse format.

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

All accounts are PDAs derived from the registration program's ID and a 32-byte
`tree_id`. Each PDA's address is `compute_pda(SHA-256(seed_1 || seed_2 || ...))`
where each seed is zero-padded to 32 bytes (string labels), little-endian-prefixed
(`u32` args), or passed through (32-byte args).

| Account          | Seeds                                       | Contents                                              |
|------------------|---------------------------------------------|-------------------------------------------------------|
| Config           | `["config", tree_id]`                       | Merkle program ID, tree ID, payment/credit token IDs, price, treasury, rate limit tracking |
| Tree main        | `["main", tree_id]`                         | Merkle tree metadata + top tree (see above)           |
| Subtrees         | `["subtree", tree_id, subtree_id]`          | Bottom subtrees (see above)                           |
| Credit token def | `["receipt", tree_id]`                      | Fungible credit token definition                      |
| Credit supply    | `["supply", tree_id]`                       | Credit token supply holder                            |
| Membership       | `["membership", tree_id, id_commitment]`    | Per-identity (leaf_index, rate_limit, expiry timestamps) |

### Instructions

Instructions are passed as a serde `Instruction` enum. The host-side mirror is in `src/rln/instruction.rs`; the on-chain shape is generated by the SPEL macro in `methods/guest/src/bin/rln_registration.rs` and the two must agree variant-by-variant.

**Initialize** — Sets up a new registration instance. Derives config, credit token, and tree main accounts internally (zero-account pattern). Chains to the token program to create the credit token and to the merkle program to initialize the tree. No external accounts needed.

**Register** (direct flow) — Atomic payment + registration. Transfers `rate_limit * price_per_unit` from the user's payment holding to treasury, computes `leaf = hash(id_commitment, rate_limit)`, creates a membership PDA, and chains to the merkle program to insert the leaf.

**BuyCredits** — Transfers payment tokens to treasury and mints an equal amount of credits to the user. Chains to the token program for both transfer and mint.

**RegisterWithCredits** — Burns credits from the user's credit holding (rate_limit = amount burned), creates a membership PDA, and chains to the merkle program to insert the leaf. Separating payment from registration allows unlinkable registration via private credit transfers.

**Slash** — Anyone can remove a spammer by providing their `identity_secret`. The program verifies `id_commitment = hash(identity_secret)`, looks up the membership, and chains to the merkle program to remove the leaf. Frees the consumed rate limit.

### Rate Limits

Each registration consumes rate limit from a global pool (`current_total_rate_limit` in config). Rate limit per member must be between 100 and 600. Slashing returns the member's rate limit to the pool.

## Reproducibility on testnet

The submodule ships seed artifacts for the canonical testnet deployment so a fresh clone can reuse it without redeploying:

- `testnet/storage.json.seed` — wallet seed containing the **full post-deploy state**: public + private roots, the 3 deploy-created public accounts (token definition, supply holding, treasury, plus any intermediate-depth accounts), the shared funded payment account, and the 4 preconfigured initial accounts the wallet expects at startup.
- `testnet/supply_holding.txt` — the supply holding's `AccountId`, in the same single-line format `create_funded_user` writes to `~/.logos-lez-rln/supply_holding_<tree>.txt`.
- `testnet/payment_account.txt` — the shared pre-funded payment account's `AccountId`. Used only by **slim mode** (see below); the default `run_setup` flow creates a fresh per-dev payment account each run.
- `testnet/config_account.txt` — the deployed registration program's `config` PDA `AccountId`. Used only by **slim mode** as a substitute for parsing `run_setup`'s output.

**Slim mode (opt-in):** set `SIM_SLIM=1` (in `mix_lez_chat/run_simulation.sh`) to skip `run_setup` on testnet — the sim reuses the shipped `config_account.txt` and `payment_account.txt`. Useful for fresh-clone devs who don't want to build `lez-rln/run_setup` (which pulls in the `lssa` nested submodule via `wallet-ffi`). The shared payment account holds ~100M RLNTOK (~1M Register txs), enough for many runs across many devs.

**Concurrency caveat:** slim mode has all devs sharing one payment account on chain, so two concurrent sim runs would race on its nonce / leaf-index space. Use serially. Default mode avoids this by giving each run a fresh per-dev account.

**Why the full post-deploy state, not just supply:** the deploy populates several chain_indices (token_def, supply, treasury, etc.). If the seed omits them, the wallet's `find_next_slot_layered` re-picks one of those slots when creating a new user payment account, derives a key that matches the on-chain account, and the funding transfer ends up writing the user_holding to e.g. the token-definition account (which has a 28-byte definition layout, not a 49-byte TokenHoldingLayout). The subsequent `Register` tx then panics inside the registration program guest with `range end index 49 out of range for slice of length 28`. Shipping the full deploy-state lets the wallet skip those occupied slots and derive a truly fresh user account.

A consumer (e.g. `simulations/mix_lez_chat/run_simulation.sh` when invoked with `SIM_NETWORK=testnet`) is responsible for bootstrapping the dev's working copy: if `testnet/storage.json` is missing, copy from `testnet/storage.json.seed`; if `~/.logos-lez-rln/supply_holding_<tree>.txt` is missing, copy from `testnet/supply_holding.txt`. After that, `run_setup` sees `is_initialized == true` for the shared `TREE_ID` and short-circuits to `create_funded_user`, which draws a fresh per-dev payment account from the shared supply.

**Security note:** the supply signing key (and the signing keys of token_def/treasury) is in `storage.json.seed` and therefore in the repo. This is acceptable here because the testnet sequencer does not charge gas and the tokens involved are test tokens with no real value. Do not reuse this pattern for any environment with real value.

**Rotating the deployment:**
1. Bump `TREE_ID` (in `lez-rln/src/rln/client.rs` *and* any consumer that hardcodes the hex form).
2. Wipe `testnet/storage.json`, `testnet/supply_holding.txt`, and any `~/.logos-lez-rln/supply_holding_<tree>.txt` / `payment_account_<tree>.txt` caches.
3. Run `cargo run --bin run_setup` against testnet — this does the full deploy (creates programs + token + treasury, mints supply, funds an initial per-dev payment account).
4. Regenerate the seed from the resulting `testnet/storage.json`, dropping the per-dev payment account (whichever account_id matches `~/.logos-lez-rln/payment_account_<tree>.txt`) and keeping everything else.
5. Update `testnet/supply_holding.txt` with the new supply `AccountId`.
