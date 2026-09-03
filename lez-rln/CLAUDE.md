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

The token initializers are additionally covered by
`token_core::new_fungible_definition`, which asserts both accounts are
`Account::default()` — the merkle program had no equivalent. When adding a
program that owns accounts, give it one.

## Chained-call targets come from config, never from instruction args
The same rule the token-holding convention below states, generalized: a
`ChainedCall::program_id` must be read from `config_state`, because these
handlers attach `pda_seeds` that authorize the callee to claim the
registration program's own PDAs (`main`, `escrow`, `payment`,
`payment_supply`). A caller-named program id would be handed those seeds.

`InitializeMerkleTree` / `InitializePaymentToken` originally took
`merkle_program_id` / `token_program_id` as instruction args and never loaded
config. They now declare the config PDA and read the target
from it via `require_config` (which also binds `tree_id`), and the args are
gone from `rln_layouts::Instruction` entirely — the wire cannot express the
attack. This makes config a prerequisite for those instructions, which is satisfied
because `Initialize` runs first. Regression:
`test_init_merkle_uses_config_program_not_caller_arg`.

## A declared plain-wallet account breaks the program on its second use
LEZ rule 7 (`NonDefaultAccountWithDefaultOwner`) rejects any account in a
program's output that is DEFAULT-owned and no longer `Account::default()`.
Every declared account IS echoed into the output — v0.2.2's
`DeclaredAccountMissingFromOutput` leaves no way to omit one, and the
rc6-era spel filter that used to strip these echoes was deleted for exactly
that reason. Signing increments the nonce, so a declared plain-wallet signer
works ONCE and is then rejected forever, with the reason visible only in the
sequencer's log.

`register_free`'s registrar is the case in point, and it now asserts the
registrar is program-owned so the misconfiguration fails loudly on the first
call instead. Deployments must seed the registrar (e.g. claim tokens into it)
before its first registration. Regressions:
`test_register_free_works_repeatedly_for_one_registrar` and
`test_register_free_rejects_a_plain_wallet_registrar` — note that
`test_register_free_quota_exhaustion` CANNOT catch this, since its second tx
dies on the quota assert before validation runs.

`claim_tokens`' `dest_holding` is the benign version: its first claim needs a
pristine account anyway, and the token program then owns it, so rule 7 is
skipped from then on. Only a plain wallet that has already transacted is
permanently unusable as a claim destination.

## Renewal is priced, not permissioned
`extend` deliberately does not check caller identity — a third party paying
for someone's renewal is harmless. FREE renewal is not: `erase` reclaims a
membership's `rate_limit` only once it expires, so anyone could keep abandoned
memberships alive one cheap tx per grace window and pin
`current_total_rate_limit` at `max_total_rate_limit`. Hence the non-refundable
`rate_limit * price_per_unit` to treasury. Both payment accounts are
token-owned, so this is rule-7 safe.

With a REFUNDABLE deposit, that same permissionless renewal also freezes a
stranger's funds. `force_expire` is the counterweight: the holder pulls
`grace_period_start` forward via `min` (never postponing expiry) and sets
`exiting`, which `extend` refuses. It does NOT release the deposit — the leaf
stays in the tree until `erase`, so the wind-down window is also the interval
in which `slash` can still burn it. Releasing on request would let a spammer
register, spam, and withdraw before anyone reconstructed their secret.

## A chained call's pre-state must match the previous call's output
`ValidatedStateDiff` threads a `state_diff` across the call chain and checks
every chained call's declared `pre_states` against it
(`validated_state_diff/mod.rs:143-152`, `InconsistentAccountPreState`), so
touching one account in two chained calls means computing what the first did
to it. Fine for a balance: `register_replacing` credits then debits the escrow,
and `escrow_after_credit` patches 16 bytes at
`TokenHoldingLayout::BALANCE_OFFSET`. Impossible for a merkle root without
duplicating the merkle guest — which is why replacing a membership is ONE
`MerkleOpcode::Replace` (overwrite in place), not Remove-then-Insert, and why
the new leaf lands on the displaced one's index. Index reuse is a consequence,
not the goal.

Any future instruction wanting two merkle ops in one tx therefore needs an
opcode doing both internally, within one 32M-cycle execution.
`merkle_replace_cycles_under_budget` measures it: Replace 18.76M (55.9%),
essentially Insert.

## Any source line shift changes the program id
Guest builds are reproducible — identical source gives a byte-identical `.bin`
— but they are line-sensitive: adding a single blank line to
`methods/guest/src/merkle_tree.rs` changes the stripped `.bin` and therefore
the program id (measured 2026-09-03, `08e29a49…` -> `92dccba2…`). Panic
`Location` metadata embeds file:line, so a comment edit that shifts following
lines is not a no-op to the artifact.

Consequences: reformatting or re-commenting a guest invalidates every
deployment of it (`verify.sh` on the profile starts failing, and the merkle
program id recorded in a live config no longer resolves), and a doc-only commit
still needs a redeploy before its profile is usable. Batch comment churn ahead
of provisioning, not after.

## Testnet operations

- A program-deploy tx larger than the sequencer's max_block_size is deferred
  in the mempool FOREVER with zero client feedback (submission returns a
  hash; the tx never includes). Local debug configs allow 1 MiB, so local
  provisioning hides the problem entirely. Downstream symptom: the one-shot
  InitializeConfig then fails the execution check ("program missing",
  visible only in the sequencer's own log) and is silently left out of the
  block, so run_setup times out waiting for the config account.
  Measured deploys: ~266 KB ✓ and ~459 KB ✗ (2026-08-05), 404,720 B ✓
  (2026-08-13), 415,080 B ✓ (2026-09-02, profile
  `testnet-replace-on-register`). Cap is >415,080 and <=~459,000 — NOT the
  512,000 B `wait_for_block_seal`'s doc still asserts.
  DO NOT believe run_setup's diagnosis either way; it cannot tell "never
  included" from "still confirming". Decide from chain state: `getAccount` on
  the config PDA (`derive_accounts` prints it). Data there proves the deploy
  landed — InitializeConfig cannot execute against a missing program — and its
  LENGTH identifies the live ConfigState layout (264 B current).
  `getTransaction` returns null even on success, so it proves nothing.
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
- `deployments/shared-faucet` records a DEAD deployment: the chain it was
  provisioned against no longer exists, and its program predates both
  security fixes above. Its ids (registry, tree, program) are stale — expect
  to re-provision from scratch rather than to verify against it.
- `state_tests` reads the guest `.bin`s from the same `docker/` dir the
  deploy host uses, which is also the record of what is live. Set
  `LEZ_RLN_GUEST_DIR` to a fresh build's `release/` dir to test guest changes
  without overwriting the artifacts `verify.sh` compares against.
- Wallet sync is only required for tree insertion (registration); claims and
  reads work against an unsynced wallet (measured pre-0780862).
