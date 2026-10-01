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

The Rust toolchain is pinned via `rust-toolchain.toml`. LEZ
(`logos-execution-zone`) is consumed as **git dependencies pinned by tag** in
`lez-rln/Cargo.toml` and `lez-rln/methods/guest/Cargo.toml` — a fresh clone
builds with no sibling checkouts to place by hand. `dev.sh` pins the same tag
in `LEZ_REF`; move all three together.

## Usage
### Build

```bash
cd lez-rln
cargo risczero build --manifest-path methods/guest/Cargo.toml   # reproducible deploy guest bins
cargo build                                                     # host + strips the deploy bins' user ELF
```

Order matters: `cargo risczero build` produces the deploy artifacts under
`methods/guest/target/.../docker/`, and the subsequent `cargo build` runs
`methods/build.rs`, which strips the user ELF inside them (and the local
build). The kernel ELF is left untouched — the program loader only accepts the
canonical `risc0_zkos_v1compat` kernel. Re-run `cargo build` after any
`cargo risczero build`.

### Test

```bash
cd lez-rln
(cd methods/guest && cargo +nightly test --lib)          # guest unit tests
cargo test                                                # host unit tests
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true RISC0_DEV_MODE=1 \
  cargo test --release --features rc5-state-tests         # in-process state tests + cycle harness
bash ../tools/e2e-local.sh                                # lifecycle against a local sequencer
```

`tools/e2e-local.sh` boots the pinned sequencer with `dev.sh`, funds a payer at
genesis, and runs `lez-rln/tests/local_sequencer.rs`: deploy, init, three
registrations, an RLN proof against the on-chain root, a refused duplicate,
slash, extend and erase. It stamps memberships with second-long durations so
the two time-gated steps clear within a few `CLOCK_50` ticks; expect it to take
a few minutes. On macOS the state tests need
`DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Frameworks`
(see `lez-rln/CLAUDE.md`).

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

## Execution model

LEZ runs a program in two phases. **Plan** sees only account ids and
authorization flags plus the instruction, and emits *effects* (one per shard it
touches) and chained calls. **Apply** runs once per effect, sees exactly one
shard's bytes, and returns that shard's new bytes. Every value a handler needs
from an account — the clock's timestamp, the config's price and merkle program
id, a membership's rate limit — therefore travels in the instruction as a
**claim**, and the apply that can see the account asserts it. Effects are
applied before the plan's chained calls run, so a false claim fails the
transaction before anything downstream executes.

The leaf index is not a claim. The merkle program assigns it on insert (its own
`next_index`), so two registrations built from the same chain state both land,
at consecutive indices. No account records it: clients find a member's leaf by
scanning the tree for `hash(id_commitment, rate_limit)`
(`merkle_tree::find_leaf_index`).

Each account is a map of per-program **shards**. Registration state lives in
the registration program's shard of its PDAs, the tree in the merkle program's
shard of `tree_main`, balances in the native shard, and the clock in the clock
program's shard of `CLOCK_50`. A program can write only its own shards.

## Merkle Tree Program

The incremental Merkle tree (depth 9, 512 leaves) lives in one account. Depth is
a cost decision, not a capacity one: an insert costs one Poseidon compression
per level, and a register transaction's 10M-gas budget has room for nine.

### Storage Layout

The merkle program's shard of the **main account** (seeds `["main", tree_id]`)
holds tree metadata (depth, `next_index`, root, 4 previous roots, 10 cached
default hashes) followed by every populated node of the tree in sparse format.
A full tree is under 35 KB, inside the 100 KiB per-shard cap (asserted at
build time via `TREE_SHARD_MAX_BYTES`).

### Sparse Node Storage

```
[count: u16le] [offset: u16le, hash: 32 bytes] [offset: u16le, hash: 32 bytes] ...
```

Entries are sorted by BFS offset (`(2^level - 1) + index_within_level`) for
binary search. Only modified nodes are stored; unmodified nodes use cached
default hashes.

### Operations

`rln_layouts::MerkleInstruction` (Borsh) is the chained-call payload:

| Operation  | Accounts | Payload                        |
|------------|----------|--------------------------------|
| Initialize | main     |                                |
| Insert     | main     | `leaf` (index = tree's `next_index`) |
| Remove     | main     | `index: u64, leaf` (leaf at `index` must equal `leaf`) |

The merkle tree program is never called directly by clients. The RLN
registration program calls it via **chained calls** carrying the `main` PDA
seed, which is what authorizes the tree write.

## RLN Registration Program

The registration program controls access to the merkle tree and manages
membership. It is the only entity that can insert or remove leaves, enforced
via PDA authorization on the tree account.

### Accounts

All accounts are PDAs derived from the registration program's account id — the
header account the deployer created, recorded in the deployment descriptor —
and a 32-byte `tree_id`. Each PDA's address is
`for_public_pda(program, SHA-256(seed_1 || seed_2 || ...))` where each seed is
zero-padded to 32 bytes (string labels) or passed through (32-byte args).

| Account          | Seeds                                       | Contents                                              |
|------------------|---------------------------------------------|-------------------------------------------------------|
| Config           | `["config", tree_id]`                       | Merkle program ID, tree ID, price, treasury, rate limit tracking, membership durations |
| Tree main        | `["main", tree_id]`                         | The whole merkle tree (merkle program's shard)        |
| Membership       | `["membership", tree_id, id_commitment]`    | Per-identity (rate_limit, expiry timestamps) |

The treasury is deliberately **not** a PDA. A PDA is spendable only through a
chained call carrying its seeds, issued by its owning program, and this program
has no instruction that would issue one — so a PDA treasury would accrue revenue
nothing could ever move. It is a plain account named in the config instead.

### Instructions

Instructions are the Borsh `Instruction` enum in `rln-layouts/src/instruction.rs`,
shared by the guest (`methods/guest/src/program.rs`, entry point
`methods/guest/src/bin/rln_registration.rs`) and the host. The doc comment
there lists which fields are claims and which apply asserts each one.

**Initialize** — Writes the config PDA: merkle program ID, tree ID, price,
treasury, rate-limit cap and membership durations. `InitializeMerkleTree` then
chains to the merkle program to initialize the tree; the config apply asserts
the claimed merkle program id against the stored one before the chained call
is handed the `main` PDA seed.

**Register** — Atomic payment + registration, in one asset. Chains a native
transfer of `rate_limit * price_per_unit` from the signing account to the
treasury, computes `leaf = hash(id_commitment, rate_limit)`, creates a
membership PDA (apply refuses a non-empty shard, which is what makes an
`id_commitment` unique), and chains to the merkle program to append the leaf
at the tree's `next_index` (the tree picks the index; the instruction names
none). The clock
timestamp is claimed and guarded by a read-only effect on `CLOCK_50`. The
signer is also the transaction's fee payer, so one account and one balance
cover the whole thing.

**Slash** — Anyone can remove a spammer by providing their `identity_secret`.
The program verifies `id_commitment = hash(identity_secret)`, the membership
apply checks the claimed rate limit, and a chained call removes the leaf at the
caller's leaf-index hint, which the merkle apply refuses unless that leaf is
`hash(id_commitment, rate_limit)`. Frees the consumed rate limit.

**Extend** — Renews an existing membership's active period from the current
clock (a membership in its grace period can be extended rather than
re-registered). Anyone may call it, including on someone else's behalf, but it
costs the same as registering that membership's rate limit — free renewal would
let a third party pin an abandoned membership's share of the rate-limit budget
indefinitely.

**Erase** — Removes an expired membership and chains to the merkle program to
remove its leaf (index checked by content, as for Slash), returning the
member's rate limit to the pool.

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
