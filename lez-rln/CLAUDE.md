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

## Testnet operations

- Provisioning can silently lose InitializeConfig to a deploy race: run_setup
  submits it after a fixed seal wait (`LEZ_RLN_BLOCK_SEAL_SECS`, default 90s),
  but a ~460KB program-deploy tx can take several testnet blocks to be
  included. If InitializeConfig executes before the deploy lands, the v0.2.2
  sequencer drops it from the block ("failed execution check", visible only
  in the sequencer's own log — the client just times out waiting for the
  config account) and NOTHING resubmits it. Provision testnet with
  `LEZ_RLN_BLOCK_SEAL_SECS=240` (or rerun on timeout); local dev sequencers
  (~15s blocks) never hit this.
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
- Wallet sync is only required for tree insertion (registration); claims and
  reads work against an unsynced wallet (measured pre-0780862).
