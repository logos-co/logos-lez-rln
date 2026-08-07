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

## Running state_tests.rs
Plain `cargo test` prints "0 passed, N filtered out" and exits 0 — it ran
nothing. The suite is feature-gated, and on macOS PyO3 needs the framework
path or tests die in dyld with SIGABRT
("Library not loaded: @rpath/Python3.framework"):

    RISC0_DEV_MODE=1 \
    DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Frameworks \
    cargo test --release --features rc5-state-tests

## Handler security convention
`account.program_owner` on caller-supplied accounts is attacker-controllable
(anyone can pre-insert an account owned by an arbitrary program carrying
forged balance data). Any handler touching token holdings must take the
token program from `config_state.token_program_id`, assert the holding's
owner equals it, and use the config value as the ChainedCall target — never
`account.program_owner`. Regression tests:
`test_*_rejects_*foreign_program` in state_tests.rs (added at 0780862).

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

The token initializers are covered by `token_core::new_fungible_definition`,
which asserts both accounts are `Account::default()` — the merkle program
had no equivalent. When adding a program that owns accounts, give it one.

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
- The registration program recorded in `deployments/shared-faucet` predates
  the merkle-init fix above, so the live tree can still be reset by anyone
  until it is redeployed (blocked on the block-size cap). Treat that
  deployment as demo-only and do not point anything durable at it.
- `state_tests` reads the guest `.bin`s from the same `docker/` dir the
  deploy host uses, which is also the record of what is live. Set
  `LEZ_RLN_GUEST_DIR` to a fresh build's `release/` dir to test guest changes
  without overwriting the artifacts `verify.sh` compares against.
- Wallet sync is only required for tree insertion (registration); claims and
  reads work against an unsynced wallet (measured pre-0780862).
