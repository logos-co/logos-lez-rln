# lez-rln — non-obvious facts (measured at commit 0780862, 2026-08)

## Guest binaries: two stale-binary traps
- Building or testing the host crate NEVER rebuilds the guest — lez-rln has
  no cargo dependency on `methods/`. Edits to `methods/guest/src/` silently
  keep executing the old ELF until you build inside `methods/` yourself
  (observed: a July 6 `.bin` serving July 31 source edits, tests "passing"
  against unfixed code).
- The deploy host reads `methods/guest/target/riscv32im-risc0-zkvm-elf/docker/*.bin`
  (`REGISTRATION_BINARY`, client.rs:124), but a local `cargo build` in
  `methods/` writes to
  `methods/target/riscv-guest/.../riscv32im-risc0-zkvm-elf/release/`.
  build.rs strips both dirs but copies nothing between them — copy the fresh
  release `.bin`s into the `docker/` dir before provisioning, or you deploy
  stale code with no error.
- Known-good force rebuild: `rm -rf methods/target/riscv-guest && touch
  methods/build.rs && (cd methods && cargo build --release)`, then copy the
  two `.bin`s. Docker is NOT required — build.rs builds the guest locally
  (docker mode cannot resolve the sibling lssa/spel path deps; see the
  build.rs header).
- Builds are reproducible but LINE-SENSITIVE: panic `Location` metadata
  embeds file:line, so adding a blank line or editing a comment in the guest
  produces a different program id — and therefore different PDAs and a dead
  deployment. Proven by controlled experiment. Consequence: finish guest
  comment churn BEFORE provisioning, never after.

## Running state_tests.rs
Plain `cargo test` prints "0 passed, N filtered out" and exits 0 — it ran
nothing. The suite is feature-gated, and on macOS PyO3 needs the framework
path or tests die in dyld with SIGABRT
("Library not loaded: @rpath/Python3.framework"):

    RISC0_DEV_MODE=1 \
    DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Frameworks \
    cargo test --release --features rc5-state-tests

## Init handlers must carry `init`
Public transactions need no signature (`build_public_tx` passes empty nonces
and keys), so any instruction that writes a PDA is submittable by anyone.
`#[account(init, pda = ...)]` — which expands to an `Account::default()`
check — is what makes an initializer one-shot; a bare `pda` constraint is
not an authorization. Authorization (`is_authorized`) only says the caller
may write the account, never that the account is unclaimed.

`initialize_merkle_tree` shipped with a bare `pda` constraint and the merkle
program's `initialize_tree` checked only authorization, so replaying
`InitializeMerkleTree` against a live tree reset `next_index` and the root
history — invalidating every member's proof while their membership PDAs
survived, leaving them unable to re-register. Regressions:
`test_initialize_merkle_tree_cannot_reset_a_live_tree` (state) and
`merkle_tree::tests::test_initialize_rejects_live_tree` (guest unit). Note
`test_registration_init_prevents_reinit` does NOT cover this: it replays the
whole init batch and short-circuits on the first tx.

When adding a program that owns accounts, give it the same
`Account::default()` check.

## Chained-call targets come from config, never from instruction args
The same rule the token-holding convention below states, generalized: a
`ChainedCall::program_id` must be read from `config_state`, because these
handlers attach `pda_seeds` that authorize the callee to claim the
registration program's own PDAs (`main`, and the subtrees under it). A
caller-named program id would be handed those seeds.

`InitializeMerkleTree` originally took `merkle_program_id` as an instruction
arg and never loaded config. It now declares the config PDA and reads the
target from it via `require_config` (which also binds `tree_id`), and the arg
is gone from `rln_layouts::Instruction` entirely — the wire cannot express the
attack. This makes config a prerequisite, satisfied because `Initialize` runs
first. Regression: `test_init_merkle_uses_config_program_not_caller_arg`.

The registry takes the native asset only, so it chains to nothing but the
merkle program.

## Unowned accounts holding only a balance are fine
v0.2.2's rule 7 (`NonDefaultAccountWithDefaultOwner`), which rejected any
DEFAULT-owned account in a program's output that was no longer
`Account::default()`, is GONE in v0.2.5. Its successor
`DataBearingUnownedAccount` fires only on an unowned account carrying DATA.

So a plain unowned account that has already transacted — the treasury, a fee
payer, any wallet — can be declared repeatedly without the program breaking on
its second use. Ownership gates DATA writes only; a balance decrease is gated
separately on the account's own authorization. The note this replaces was
written against rule 7 and described `register_free` and `claim_tokens`, none
of which exist.

## Renewal is priced, not permissioned
`extend` deliberately does not check caller identity — `MembershipState`
records no owner, and a third party paying for someone's renewal is
harmless. The griefing vector was that renewal was FREE: `erase` reclaims a
membership's `rate_limit` only once it expires, so anyone could keep
abandoned memberships alive one cheap tx per grace window and pin
`current_total_rate_limit` at `max_total_rate_limit`, blocking all new
registrations. `extend` now charges `rate_limit * price_per_unit` — the same
as registering — which also gives `active_duration` economic force.

With a REFUNDABLE deposit, that same permissionless renewal also freezes a
stranger's funds, which the charge does not fix. `force_expire` is the
counterweight: the holder pulls `grace_period_start_timestamp_ms` forward via
`min` (never postponing expiry) and sets `exiting`, which `extend` then refuses.
It does NOT release the deposit — the leaf stays in the tree until `erase`, so
the wind-down window is also the interval in which `slash` can still forfeit it.
Releasing on request would let a spammer register, spam and withdraw before
anyone reconstructed their secret.

## A debit needs authorization; a credit needs nothing
v0.2.5 rule 2 gates a `BalanceDiff::Sub` on `pre.is_authorized` — NOT on
ownership, which is what v0.2.2 gated it on. Credits are unrestricted, and rule
5 requires a diff's credits to equal its debits, so native balance can be
neither minted nor burned.

Three consequences this program is built on:
- Taking a deposit is a field assignment (`escrow.account.balance += x`), because
  crediting needs no authorization.
- Paying one back is NOT. A program's own PDA is authorized only as the callee
  of a chained call naming its seed (`compute_public_authorized_pdas` returns
  empty when there is no caller, and the top-level call has none), so `erase`
  and `slash` each carry an `authenticated_transfer::custody_transfer`. That
  program is a genesis builtin; the registry does not deploy it, but
  `state_with_programs` must seed it or every erase fails.
- `slash` FORFEITS the deposit to the treasury rather than burning it, because
  burning is not expressible.

## Gas, not binary size, is the binding limit
v0.2.5 meters a charged transaction at one gas per cycle and caps it at
`MAX_GAS_EXEC` = 10M; the whole chained-call chain shares one budget. Measured
on this tree (depth 9): register 9.09M (91%), slash 8.81M (88%), erase 8.20M
(82%). A refund leg costs ~25k, so the margin that matters is the ~900k above
register, not the ~200KB of binary headroom. `register_transaction_fits_the_gas_ceiling`
and the two `*_fits_the_gas_ceiling` tests beside it print the numbers — read
them before adding work to any instruction.

## The tree holds 512 leaves, and that is a lifetime count
`next_index` only advances and an erased leaf's index is never reused, so
`TREE_LEAVES` bounds total registrations over the tree's life, not concurrent
members. Past it the top-tree walk addresses nodes by a compile-time BFS offset
with no per-level bound, so an insert aliases live nodes of other subtrees and
returns a wrong root WITHOUT failing — every member's proof then stops
verifying, and `config`/`tree_main` are `init`-guarded, so the deployment
cannot be repaired. `insert_leaf` and `register` both assert the bound.
`MerkleOpcode::Set` exists with no callers and is the only index-reuse path if
capacity ever has to grow.

## Testnet operations

- A program-deploy tx larger than the sequencer's max_block_size is deferred
  in the mempool FOREVER with zero client feedback (submission returns a
  hash; the tx never includes). Measured on testnet 2026-08-05: the ~266KB
  merkle deploy included, the ~459KB registration deploy never did — the
  operative cap sits somewhere between, while local debug configs allow
  1 MiB, so local provisioning hides the problem. Downstream symptom: the
  one-shot InitializeConfig then fails the execution check ("program
  missing", visible only in the sequencer's own log) and is silently left
  out of the block, so run_setup times out waiting for the config account.
  Check the deploy landed (scan recent blocks for a ~600KB base64 getBlock
  result) before believing any InitializeConfig diagnosis.
- register_member's "Timeout waiting for leaf N" panic is often a FALSE
  negative: `wait_for_leaf` polls a hardcoded 30 × 500 ms
  (register_member.rs:66) and testnet confirmation regularly exceeds 15 s.
  Measured: the panic fired while the registration had actually landed
  (tree `next_index` and config `total_registrations` both advanced).
- Do NOT blindly re-run after that panic. The tx was submitted (and paid)
  before the poll; a re-run mints a fresh identity + payer and registers a
  SECOND distinct member at a second full payment. Worse, the first
  membership's IDENTITY_SECRET_HASH is lost — it prints only after the
  panic point (register_member.rs:71 vs :76). Recoverable in principle (the
  wallet account persists; `seeded_keygen` is deterministic) but no tool
  does that recovery. Check on-chain state first.
- Resubmitting the SAME id_commitment fails cleanly
  (`AccountAlreadyInitialized`, no payment, no leaf) — but that uniqueness
  is enforced SOLELY by the `#[account(init, pda = ...)]` attribute on the
  membership PDA (program.rs:224). The register handler has no duplicate
  check and the merkle insert doesn't dedupe; weaken that attribute and
  re-registration silently overwrites. Regression:
  `test_register_same_commitment_twice_fails`.
- Deploying new program instances to https://testnet.lez.logos.co/ is
  normal, routine development practice (`tools/deployments/provision.sh`).
- `state_tests` reads the guest `.bin`s from the same `docker/` dir the
  deploy host uses, which is also the record of what is live. Set
  `LEZ_RLN_GUEST_DIR` to a fresh build's `release/` dir to test guest changes
  without overwriting the artifacts `verify.sh` compares against.
- Wallet sync is only required for tree insertion (registration); claims and
  reads work against an unsynced wallet (measured pre-0780862).
