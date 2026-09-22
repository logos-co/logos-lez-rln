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
cargo run --bin run_setup        # deploys programs, initializes the registry
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

The incremental Merkle tree (depth 9, 512 leaves) is split across multiple on-chain accounts to keep each operation's data footprint small. Depth is a cost decision, not a capacity one: an insert costs one Poseidon compression per level, and a register transaction has room for nine.

### Storage Layout

The tree is divided at level 4 into a **top tree** and **16 bottom subtrees** of 32 leaves each:

```
           [root]              <- top tree (levels 0-4)
          /      \                stored in main account
        ...      ...
       / \ ... / \
      S0  S1  ...  S15         <- subtree roots
     /\   /\      /\           <- bottom subtrees (levels 5-9)
    ...  ...     ...              each in its own PDA account
```

- **Main account** (seeds `["main", tree_id]`): Tree metadata (depth, next_index, root, 4 previous roots, 10 cached default hashes) + top tree nodes in sparse format. Starts at 489 bytes, grows as nodes are added.
- **Subtree accounts** (seeds `["subtree", tree_id, subtree_id]`): Each stores a depth-5 subtree in sparse format.

Each insert or remove touches exactly **2 accounts**: the main account and one bottom subtree.

### Sparse Node Storage

Both the top tree and subtrees use a compact sparse format instead of storing every node:

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
| Config           | `["config", tree_id]`                       | Merkle program ID, tree ID, price, treasury, rate limit tracking, membership durations |
| Tree main        | `["main", tree_id]`                         | Merkle tree metadata + top tree (see above)           |
| Subtrees         | `["subtree", tree_id, subtree_id]`          | Bottom subtrees (see above)                           |
| Escrow           | `["escrow", tree_id]`                       | Holds every membership's deposit for this tree         |
| Membership       | `["membership", tree_id, id_commitment]`    | Per-identity (leaf_index, rate_limit, expiry timestamps, holder, deposit) |

The treasury is deliberately **not** a PDA: it only accrues, and whoever holds it
spends it by signing. The escrow is the opposite case — it has to be spendable by
the *program*, and a PDA is the only account that can be, through a chained call
carrying its seed. `Erase` and `Slash` are the instructions that issue one.

### Instructions

Instructions are passed as a serde `Instruction` enum defined in `rln-layouts/src/instruction.rs` (re-exported to the host via `src/rln/mod.rs`); the on-chain shape is generated by the SPEL macro in `methods/guest/src/program.rs` (entry point `methods/guest/src/bin/rln_registration.rs`) and the two must agree variant-by-variant.

**Initialize** — Writes the config PDA: merkle program ID, tree ID, price, treasury, rate-limit cap and membership durations. Setup is still split across two transactions (a fused init exceeds the 32M per-session cycle cap): `InitializeMerkleTree` chains to the merkle program to initialize the tree.

**Register** — Atomic deposit + registration, in one asset. Debits `rate_limit * price_per_unit` of **native** balance from the signing account into the tree's `escrow` PDA, records that account as the membership's `holder` with the amount, computes `leaf = hash(id_commitment, rate_limit)`, creates a membership PDA, and chains to the merkle program to insert the leaf. The signer is also the transaction's fee payer, so one account and one balance cover the whole thing. The deposit is collateral, not revenue: `Erase` returns it and `Slash` forfeits it.

The balance move is a field assignment rather than a chained call: the SPEL macro derives each account's `BalanceDiff` from the post-account a handler returns. The protocol then enforces what the old token-holding asserts stood in for — only an authorized account can be debited, the guest cannot misreport a pre-state, and credits must equal debits across the diff. The one thing it does not decide is where the credit lands; for the escrow that is the macro's `pda` constraint, and for `Extend`'s fee it is the treasury-id assert.

Paying a deposit back is not symmetric with taking one. A credit needs no authorization, but a debit needs the account authorized — and a program's own PDA is authorized only as the callee of a chained call naming its seed. So `Erase` and `Slash` each carry a chained `authenticated_transfer` out of the escrow, which is the one place the deposit model costs an extra guest execution (about 25k cycles).

Unlinkable registration does not need a credit token: LEZ privacy is transparent to guest logic, so the paying account may itself be **private** — `pre_states` carries `is_authorized` either way, and a private account proves it through its nullifier secret key.

**Slash** — Anyone can remove a spammer by providing their `identity_secret`. The program verifies `id_commitment = hash(identity_secret)`, looks up the membership, chains to the merkle program to remove the leaf, and forfeits the escrowed deposit to the treasury. Frees the consumed rate limit. Forfeited rather than burned: a diff's credits must equal its debits, so native balance cannot be destroyed.

**Extend** — Renews an existing membership from inside its grace period, at the same price as registering that rate limit, paid to the treasury and not refundable. Anyone may call it, including on someone else's behalf — free renewal would let a third party pin an abandoned membership's share of the rate-limit budget indefinitely. Refused once the holder has called `ForceExpire`.

**ForceExpire** — Brings a membership's grace period forward to now (`min(grace_start, now)`, so it can never postpone expiry) and marks it exiting. Holder only. This is the counterweight to renewal being permissionless: without it a third party could keep a stranger's membership alive, and their deposit escrowed, indefinitely. The leaf stays in the tree until `Erase`, so the wind-down window is also the interval in which `Slash` can still forfeit the deposit — an exit that released funds immediately would outrun slashing.

**Erase** — Removes an expired membership, chains to the merkle program to remove its leaf, returns the rate limit to the pool, and refunds the escrowed deposit to the recorded `holder`. Permissionless; the caller names the destination but the program rejects any account that is not the one that paid.

There is no faucet and no free-registration path. A faucet is not expressible
for the native asset — no program can mint it — so balance arrives only at
genesis, over the L1 bridge, or by transfer. See
`tools/deployments/README.md` for the profile workflow.

### Rate Limits

Each registration consumes rate limit from a global pool (`current_total_rate_limit` in config). Rate limit per member must be between 100 and 600. Slashing returns the member's rate limit to the pool.

## Testnet deployments

Reusable on-chain deployments (one RLN tree + its wallet) are captured as
**deployment profiles** under `deployments/<name>/` and managed by the shared
tooling in [`tools/deployments/`](tools/deployments/README.md):
`provision.sh` deploys a fresh tree (`--payer` is required — it pays the deploy
fees and becomes the deployment's `payer_account`), `stage.sh` stages an
existing profile into the flat files consumers expect, and `verify.sh` guards
against guest drift. See that README for the profile format and the
run-against-existing / redeploy-fresh workflows.

**Security note:** a profile's `storage.json` contains signing keys and may be
committed to a repo. That warning is stronger now than it was: the key it
carries no longer unlocks test tokens with no value, it unlocks an account
holding **native** balance — the same asset that pays every fee on the chain.
Treat any key in a committed profile as public, fund it only with what a run
needs, and do not reuse this pattern for any environment with real value.
