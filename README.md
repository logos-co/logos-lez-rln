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
cargo risczero build --manifest-path methods/guest/Cargo.toml   # reproducible deploy guest bins
cargo build                                                     # host + strips the deploy bins under the per-tx cap
```

Order matters: `cargo risczero build` produces the deploy artifacts under
`methods/guest/target/.../docker/`, and the subsequent `cargo build` runs
`methods/build.rs`, which strips them (and the local build) so the deploy tx
fits the sequencer's per-tx size cap. Re-run `cargo build` after any
`cargo risczero build`.

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
| Config           | `["config", tree_id]`                       | Merkle program ID, tree ID, payment/credit token IDs, price, treasury, rate limit tracking, deployment policy (registrar, free quota, faucet cap) |
| Tree main        | `["main", tree_id]`                         | Merkle tree metadata + top tree (see above)           |
| Subtrees         | `["subtree", tree_id, subtree_id]`          | Bottom subtrees (see above)                           |
| Credit token def | `["receipt", tree_id]`                      | Fungible credit token definition                      |
| Credit supply    | `["supply", tree_id]`                       | Credit token supply holder                            |
| Payment def      | `["payment", tree_id]`                      | Payment token (RLNTOK) definition — faucet deployments only |
| Payment supply   | `["payment_supply", tree_id]`               | Payment token supply holder — faucet deployments only |
| Membership       | `["membership", tree_id, id_commitment]`    | Per-identity (leaf_index, rate_limit, expiry timestamps) |

### Instructions

Instructions are passed as a serde `Instruction` enum defined in `rln-layouts/src/instruction.rs` (re-exported to the host via `src/rln/mod.rs`); the on-chain shape is generated by the SPEL macro in `methods/guest/src/program.rs` (entry point `methods/guest/src/bin/rln_registration.rs`) and the two must agree variant-by-variant.

**Initialize** — Writes the config PDA: token/merkle program IDs, payment token, price, treasury, rate-limit caps, membership durations, and the deployment policy (authorized registrar, free quota, faucet claim cap). Setup is split across separate transactions (a fused init exceeds the 32M per-session cycle cap): `InitializeCreditToken` chains to the token program to create the credit token; `InitializeMerkleTree` chains to the merkle program to initialize the tree; faucet deployments add `InitializePaymentToken`, which creates RLNTOK as a program-owned PDA definition (the program itself is the mint authority — no human key).

**Register** (direct flow) — Atomic payment + registration. Transfers `rate_limit * price_per_unit` from the user's payment holding to treasury, computes `leaf = hash(id_commitment, rate_limit)`, creates a membership PDA, and chains to the merkle program to insert the leaf.

**BuyCredits** — Transfers payment tokens to treasury and mints an equal amount of credits to the user. Chains to the token program for both transfer and mint.

**RegisterWithCredits** — Burns credits from the user's credit holding (rate_limit = amount burned), creates a membership PDA, and chains to the merkle program to insert the leaf. Separating payment from registration allows unlinkable registration via private credit transfers.

**Slash** — Anyone can remove a spammer by providing their `identity_secret`. The program verifies `id_commitment = hash(identity_secret)`, looks up the membership, and chains to the merkle program to remove the leaf. Frees the consumed rate limit.

**Extend** — Renews an existing membership's active period from the current clock (a membership in its grace period can be extended rather than re-registered). Anyone may call it, including on someone else's behalf, but it costs the same as registering that membership's rate limit — free renewal would let a third party pin an abandoned membership's share of the rate-limit budget indefinitely.

**Erase** — Removes an expired membership and chains to the merkle program to remove its leaf, returning the member's rate limit to the pool.

**ClaimTokens** — The faucet: mints up to `faucet_claim_cap` payment tokens per call into the (co-signing) destination holding, PDA-authorized — rejected on deployments initialized with cap 0.

**RegisterFree** — Creates a membership without payment. Only the config's `authorized_registrar` may call it (must sign), and only while `free_quota_remaining > 0`; each call decrements the quota. Additive: the paid `Register` path works unchanged alongside.

The funding model (program-PDA faucet vs. wallet-key supply) is fixed per
deployment at `Initialize`; see `tools/deployments/README.md` for the policy
knobs and profile workflow.

### Rate Limits

Each registration consumes rate limit from a global pool (`current_total_rate_limit` in config). Rate limit per member must be between 100 and 600. Slashing returns the member's rate limit to the pool.

## Testnet deployments

Reusable on-chain deployments (one RLN tree + its wallet) are captured as
**deployment profiles** under `deployments/<name>/` and managed by the shared
tooling in [`tools/deployments/`](tools/deployments/README.md):
`provision.sh` deploys a fresh tree (faucet funding by default; the legacy
wallet-key funding mode remains fully supported via `--funding wallet-key`),
`stage.sh` stages an existing profile into the flat files consumers expect,
and `verify.sh` guards against guest drift. See that README for the profile
format, deployment-policy knobs (funding mode, faucet claim cap, free-quota
registrar), and the run-against-existing / redeploy-fresh workflows.

**Security note:** a profile's `storage.json` contains signing keys (for
wallet-key profiles, including the payment token's mint key) and may be
committed to a repo. This is acceptable only because the testnet sequencer
does not charge gas and the tokens involved are test tokens with no real
value. Do not reuse this pattern for any environment with real value.
