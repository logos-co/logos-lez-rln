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
the two time-gated steps clear within a minute of chain time; expect it to
take a few minutes. On macOS the state tests need
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

### Wallets

The host tools open a `WalletCore` from `LEE_WALLET_HOME_DIR`
(`wallet_config.json` + `storage.json`). A storage may be sealed with a
password: the tools read `LEE_WALLET_PASSWORD` and never prompt, and an unset
or empty variable means an unencrypted file (the default for every throwaway
wallet here). A storage written by a wallet before LEZ v0.4.0 no longer parses
— its private-account entries changed shape — so re-mint such wallets.

`mint_payer` prints two lines, the payer's account id and its public key.
`dev.sh` funds the payer at genesis from the **public key**
(`LEZ_RLN_GENESIS_FUND=<64 hex>`); `run_setup` and the registration tools take
the **account id** (`LEZ_RLN_PAYER`).

## Structure

- `rln-layouts/` - Shared zero-copy layouts, constants, and PDA seed construction (no_std, used by both host and guest)
- `methods/guest/` - zkVM guest programs (rln_registration, incremental_merkle_tree)
- `src/rln/` - RLN client library (PDA derivation)
- `src/merkle_tree/` - Merkle tree client library
- `src/bin/` - CLI tools

## Execution model

LEZ runs a program as **actors**: one `(account, program)` pair per message
delivery, each a zkVM session that sees only that actor's own state and the
message, and returns its new state plus the messages it sends on. A
transaction submits one root message to one actor and declares every actor
the program will touch. Sync messages run in emission order, each to
completion before the next; a panic anywhere fails the whole transaction.

An actor reads what it owns and asks for the rest: the config knows its price,
treasury, merkle program and rate bounds; a membership knows its rate limit
and dates. Nothing is claimed. What one actor tells another is accepted only
from the actor it must come from — a `Release` from anyone but the member's
own membership, or an `InitMembership` from anyone but the tree's config, is
refused — because the protocol lets any transaction message any actor.

Authorization is per account: a signer, or a PDA whose owning program sends
to it with the PDA's seed. The merkle program writes the tree only when the
registration program's config actor messages it with the `main` seed. An
actor that does not exist yet (a new config or membership PDA) is admitted by
that seed as **evidence** in the transaction, or by the seed on the message
that reaches it; a declared account that neither exists, signs, nor is
seeded fails the transaction.

Chain time is the including block's timestamp. A time-dependent message
carries `now_ms`, the submitter's reading of it, and pins the transaction to
blocks whose timestamp lies in `[now_ms, now_ms + CLOCK_CLAIM_TOLERANCE_MS)`;
a claim behind chain time only shortens the member's own window, and one
ahead is never included.

The leaf index is never sent for a registration. The merkle program assigns
it on insert (its own `next_index`), so two registrations built from the same
chain state both land, at consecutive indices. No account records it: clients
find a member's leaf by scanning the tree for `hash(id_commitment, rate_limit)`
(`merkle_tree::find_leaf_index`).

Each account holds one state per program. Registration state lives in the
registration program's state of its PDAs, the tree in the merkle program's
state of `tree_main`, balances in the native program's. A program can write
only its own states.

## Merkle Tree Program

The incremental Merkle tree (depth 9, 512 leaves) lives in one account. Depth is
a cost decision, not a capacity one: an insert costs one Poseidon compression
per level, and a register transaction's 10M-gas budget has room for nine.

### Storage Layout

The merkle program's state at the **main account** (seeds `["main", tree_id]`)
holds tree metadata (depth, `next_index`, root, 4 previous roots, 10 cached
default hashes) followed by every populated node of the tree in sparse format.
A full tree is under 35 KB (asserted at build time via `TREE_SHARD_MAX_BYTES`);
every merkle session reads and rewrites the whole state, which is what bounds
its size now that the protocol no longer caps it.

### Sparse Node Storage

```
[count: u16le] [offset: u16le, hash: 32 bytes] [offset: u16le, hash: 32 bytes] ...
```

Entries are sorted by BFS offset (`(2^level - 1) + index_within_level`) for
binary search. Only modified nodes are stored; unmodified nodes use cached
default hashes.

### Operations

`rln_layouts::MerkleMessage` (Borsh) is what the tree actor receives:

| Message    | Actor | Payload                        |
|------------|-------|--------------------------------|
| Initialize | main  |                                |
| Insert     | main  | `leaf` (index = tree's `next_index`) |
| Remove     | main  | `index: u64, leaf` (leaf at `index` must equal `leaf`) |

The merkle tree program is never messaged directly by clients. The RLN
registration program's config actor messages it carrying the `main` PDA seed,
which is what authorizes the tree write.

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
| Tree main        | `["main", tree_id]`                         | The whole merkle tree (merkle program's state)        |
| Membership       | `["membership", tree_id, id_commitment]`    | Per-identity (rate_limit, expiry timestamps) |

The treasury is deliberately **not** a PDA. A PDA is spendable only by its
owning program, and this program has no message that would spend it — so a
PDA treasury would accrue revenue nothing could ever move. It is a plain
account named in the config instead. A registration declares the treasury's
native actor (the price is credited to it in the same transaction), and a
declared account must exist on chain: `run_setup` moves one unit into the
treasury so that every later transaction can name it.

### Messages

Messages are the Borsh `Message` enum in `rln-layouts/src/instruction.rs`,
shared by the guest (`methods/guest/src/program.rs`, entry point
`methods/guest/src/bin/rln_registration.rs`) and the host. The doc comment
there says which actor each entry message is for and which messages are
internal to the program's own actors.

**Initialize** (to the config) — Writes the config PDA: merkle program ID,
tree ID, price, treasury, rate-limit cap and bounds, membership durations.
One-shot: a non-empty state is refused. **InitializeMerkleTree** (to the
config) — the config messages the merkle program it stores to initialize the
tree, granting it the `main` PDA seed.

**Register** (to the config) — Atomic payment + registration, in one asset.
The config checks the rate against its bounds and capacity, computes
`leaf = hash(id_commitment, rate_limit)`, then sends in order: a native
transfer of `rate_limit * price_per_unit` from the paying account to the
treasury; `InitMembership` to the new membership PDA (refused on a non-empty
state, which is what makes an `id_commitment` unique); `Insert` to the merkle
program to append the leaf at the tree's `next_index` (the tree picks the
index; the message names none). The payer signs the transaction and is also
its fee payer, so one account and one balance cover the whole thing, and
`now_ms` dates the membership and pins the validity window.

**Slash** (to the membership) — Anyone can remove a spammer by providing their
`identity_secret`. The membership verifies `id_commitment =
hash(identity_secret)`, clears itself, and sends `Release` to the config,
which uncounts the rate limit and has the merkle program remove the leaf at
the caller's leaf-index hint — refused unless that leaf is
`hash(id_commitment, rate_limit)` with the membership's own rate limit.

**Extend** (to the membership) — Renews an existing membership's active
period (a membership in its grace period can be extended rather than
re-registered), then sends `ChargeRenewal` to the config, which moves the
registration price from the payer to the treasury. Anyone may call it,
including on someone else's behalf, but it costs the same as registering that
membership's rate limit — free renewal would let a third party pin an
abandoned membership's share of the rate-limit budget indefinitely.

**Erase** (to the membership) — Removes an expired membership and, through
`Release`, has the merkle program remove its leaf (index checked by content,
as for Slash), returning the member's rate limit to the pool.

There is no faucet and no free-registration path. A faucet is not expressible
for the native asset — no program can mint it — so balance arrives only at
genesis, over the L1 bridge, or by transfer. See
`tools/deployments/README.md` for the profile workflow.

### Rate Limits

Each registration consumes rate limit from a global pool (`current_total_rate_limit` in config). The rate limit per member must lie within the registry's own bounds, set at `Initialize` (`min_rate_limit..=max_rate_limit`; `run_setup` defaults to 100..=600, `LEZ_RLN_MIN_RATE_LIMIT` / `LEZ_RLN_MAX_RATE_LIMIT` override). Slashing returns the member's rate limit to the pool.

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
