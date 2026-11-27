# lez-rln — non-obvious facts (LEZ v0.4.0)

## Guest binaries: two stale-binary traps
- Building or testing the host crate NEVER rebuilds the guest — lez-rln has
  no cargo dependency on `methods/`. Edits to `methods/guest/src/` silently
  keep executing the old ELF until you build inside `methods/` yourself
  (observed: a July 6 `.bin` serving July 31 source edits, tests "passing"
  against unfixed code).
- The deploy host reads `methods/guest/target/riscv32im-risc0-zkvm-elf/docker/*.bin`
  (`REGISTRATION_BINARY`), but a local `cargo build` in `methods/` writes to
  `methods/target/riscv-guest/.../riscv32im-risc0-zkvm-elf/release/`.
  build.rs strips both dirs but copies nothing between them — copy the fresh
  release `.bin`s into the `docker/` dir before provisioning, or you deploy
  stale code with no error.
- Known-good force rebuild: `rm -rf methods/target/riscv-guest && touch
  methods/build.rs && (cd methods && cargo build --release)`, then copy the
  two `.bin`s. Docker is NOT required — build.rs builds the guest locally.
- build.rs strips the USER ELF only. The kernel ELF inside the R0BF `.bin`
  must stay byte-identical to `risc0_zkos_v1compat::V1COMPAT_ELF`: the
  program loader refuses any other kernel, and only the user ELF is uploaded
  (96 KiB segments, at most 20), so stripping the kernel buys nothing and
  bricks the deploy.
- Builds are reproducible but LINE-SENSITIVE: panic `Location` metadata
  embeds file:line, so adding a blank line or editing a comment in the guest
  produces a different image id. The program's ACCOUNT id (and so every PDA)
  is the deployer-chosen header account, not the image id — but the tools
  deploy every header IMMUTABLE (`deploy_program` passes `immutable = true`,
  and the loader refuses `UpdateHeader` on an immutable header), so a rebuilt
  guest cannot replace a deployed one: it needs a new header account, hence
  new ids. Finish guest comment churn BEFORE provisioning.
- The docker CONTEXT directory is part of the image id: the same metadata
  embeds each source file's path below it (`/src/lez-rln/rln-layouts/src/…`
  from the repo root, `/src/rln-layouts/src/…` from `lez-rln/`). CI and the
  deployed programs are built from the repo root (`cargo risczero build
  --manifest-path lez-rln/methods/guest/Cargo.toml`); from `lez-rln/` the
  same commit gives two other image ids. `strings` on a `.bin` shows which.
- The strip step alone: `(cd methods && touch build.rs && RISC0_SKIP_BUILD=1
  cargo build --release)`. `RISC0_SKIP_BUILD` skips the local guest build
  and `build.rs` still strips; without `touch` cargo may not rerun it. The
  `llvm-strip` of the 1.91.1 and 1.97.0 risc0 toolchains give the same bytes.
- A build from an export of the commit (`git archive <commit> | tar -x`)
  reproduces the binaries of a checkout and keeps untracked files (the
  `dev/` wallet) out of the docker context.
- The same metadata embeds the cargo git-checkout path of every dependency,
  which contains the pinned commit hash. Bumping the LEZ tag therefore changes
  both image ids even when `lee_core` and `clock_core` are byte-identical
  across the tags (v0.3.0 -> v0.3.1: no source change, both bins differ), so
  every dependency bump is a redeploy.

## Execution model: actors and messages, one session per delivery
- A program runs as actors: one `(account, program)` pair per delivered
  message (`lee_core::actor_entrypoint!`, `ReceiveInput { receiver, from,
  grants, pre_state, message }` → `Response { post_state,
  sync_messages, async_messages, validity, .. }`). A handler sees its own
  state and nothing else; there is no account list and no claim. What it
  needs from another actor it asks for by message (`rln_layouts::Message`:
  entry variants to the config or a membership, internal `InitMembership` /
  `Release` / `ChargeRenewal` between the program's own actors).
- ANY transaction can root-message ANY actor with any message. Internal
  variants therefore check `from`: `InitMembership` only from the tree's
  config actor, `Release` / `ChargeRenewal` only from the member's own
  membership actor (`require_from`). Every message names its tree (and
  member), and the receiver re-derives its own PDA from that and refuses a
  mismatch (`require_receiver`), so a message for another tree lands nowhere.
- Authorization is per actor and explicit, nothing is inherited. A signature
  authorizes only the actors the transaction declares as signers of its root
  call. A called actor is authorized only by a grant: the sender attaches
  grants to a sync message (`SyncMessage.grants`, each over an actor whose
  grant the sender holds in `ReceiveInput.grants`; `with_lent_grant` passes
  on the one over the destination), or the message carries the PDA seed of
  the destination (`for_public_pda(sender.program, seed) == receiver`). The
  merkle program asserts `is_authorized()`. At a registry's tree account (the
  PDA of the registration program and `main_seed(tree_id)`) only that tree's
  config actor can produce it (it sends with the `main` seed, and only to the
  merkle program its config stores — "callee targets come from config"
  survives as: the config is the only emitter). At any other account the
  grant can come from elsewhere: a signer can build a tree at an account they
  sign for, and a program at its own PDA. A reader of a registry's tree
  therefore derives that address and checks the config's
  `merkle_program_id`. A payment is a sync
  `native_token::Message::Transfer` to the PAYER's native actor; the native
  program debits it only if the message carries a grant over the payer, which
  needs the payer to be a declared signer and the sending handler to attach
  the grant, and credits the treasury by an async `Credit` that lands in the same
  transaction only because the treasury's native actor is declared. The
  handlers attach the payer's grant only when the delivery holds it
  (`payer_grant`): for a payer that did not sign, the native program then
  refuses as `UnauthorizedSender`, where an unconditional attach would fail
  the transaction as `UnheldGrant`, a fault of our program. `Extend` carries
  the grant two hops: membership to config (`ChargeRenewal`), config to the
  payment.
- Every actor a transaction touches must be declared (`public_actors`) and
  admitted: exist on chain, sign, be reached by a sync message carrying its
  PDA seed, or carry `admission_evidence` (`Pda { program, seed }` /
  `Key(pk)`). The host declares config, membership, tree_main, payer-native
  and treasury-native, with `Pda` evidence for a membership PDA that does not
  exist yet (and for the config at `Initialize`, though the program's own
  forward carries the seed and admits it). The treasury is a plain
  keyed account nobody but the deployer holds the key of, so `run_setup`
  seeds it with one unit: from then on it exists and needs no evidence. An
  undeclared actor, an unadmitted one, or an async credit to an undeclared
  recipient fails the transaction (charged).
- Sync messages run in emission order, each subtree to completion
  (`execution_state.rs` LIFO stack); the fee transfer runs after the root
  subtree. Register emits payment, `InitMembership`, merkle `Insert` in that
  order so a duplicate (exit 14) costs the config session and nothing more.
- Time: no clock account. A time-dependent root message carries `now_ms`
  (the host reads the head block's timestamp) and `time_window` pins the
  transaction to blocks in `[now_ms, now_ms + CLOCK_CLAIM_TOLERANCE_MS)`
  (`Response::try_timestamp_window`); a violated window is `OutOfValidityWindow`
  after execution and is charged the full budget, so do not sit on a built
  transaction. Memberships are dated by the claim, which the host reads
  as the head block's timestamp less 5 s (`CHAIN_TIME_SLACK_MS`): block
  timestamps are the sequencer's wall clock and may step back a little
  before inclusion. Nothing in this repo reads a clock account any more.
- The leaf index is never sent for a registration: the merkle `Insert` takes
  it from the tree's own `next_index`, so two registrations built from the
  same state compose (`same_block_registrations_compose`). Slash/erase send
  the index as a hint and the merkle `Remove` checks the leaf there equals
  `H(id_commitment, rate_limit)` with the membership's OWN rate limit
  (`remove_refuses_a_wrong_index`). Clients locate a leaf by scanning the
  tree (`merkle_tree::find_leaf_index`); no account stores it.
- Each actor's state belongs to one program: registration data in the
  registration program's state of its PDAs, the tree in the merkle program's
  state of `tree_main`, balances in the native program's (`[0;32]`). A
  program can write only its own actor's state. `ActorState` is unbounded —
  nothing caps the tree's 35 KB but the session that reads and rewrites it.
- Every delivery is a separate zkVM session, and the transaction's gas
  (`≤ MAX_GAS_EXEC = 10M`, one gas per cycle) is the SUM. Measured on
  v0.4.0 with the docker guests (image `r0.1.88.0`; RISC0_DEV_MODE,
  `cycle_harness`, a tree holding one leaf): register = config 927,176 (one
  Poseidon for the leaf) + membership 16,000 + merkle Insert 8,326,989 (nine
  Poseidons) = 9,270,165, 92.7% of the ceiling; the merkle Initialize
  transaction 27,700. Poseidon is the budget, which is why the tree is depth
  9 and a tenth level (+~0.9M) does not fit. Re-measure with `cycle_harness`
  and `register_transaction_fits_the_gas_ceiling` after any guest change.
- The builder's rustc is part of the cost: the same merkle source built with
  1.91.1 runs about 152,000 cycles cheaper per session (1.88 inlines the
  Poseidon pair hash into `update_leaf`). The figures this file used to give
  for v0.4.0-rc3 (register 9,112,101, slash 9,717,891) were of a local
  1.91.1 build; the docker-built rc3 merkle program costs what this one does.
- Slash is the tightest transaction: the membership session hashes the
  identity secret AND the member's leaf before the nine-Poseidon root update
  — membership 1,525,137 + config 21,175 + merkle Remove 8,324,380 =
  9,870,692, 98.7% of the ceiling
  (`slash_and_erase_transactions_fit_the_gas_ceiling`). Any guest change that
  adds a hash to slash does not fit.
- Those figures are of a tree with ONE leaf. A merkle session also pays about
  10 cycles per byte of tree state, and a removed leaf's nodes stay in the
  state, so cost follows the registrations a tree has had in its LIFE.
  Measured on these binaries through the in-process chain, with real Register
  transactions and a 10M budget per transaction: slash is first refused at
  185 lifetime registrations and always from 196 (`OutOfGas`, the declared
  gas charged, state unchanged); register is refused at leaves 384, 448 and
  480, the leaves that open a new subtree, and since the next index only
  advances, a tree takes no registration from leaf 384 on; erase always fits
  (9,623,711 at most). The gas-ceiling tests and `cycle_harness` measure the
  one-leaf tree, and `TestSetup::apply` runs at a 32M budget, so neither
  shows this.
- A guest PANIC is charged the transaction's full declared gas; a guest that
  halts with `env::exit(code != 0)` is charged the cycles it ran
  (`ProgramExitedWithCode`, `validated_state_diff::from_public_transaction_metered`,
  `ExecutionCharge.revert` set). Checks an honest client fails only because
  the chain moved after it read it use `ensure!(cond, EXIT_*, ..)`
  (`methods/guest/src/fail.rs`, codes in `rln_layouts::exit`: 13/14/15/17/18
  in the registration program, 19/20 in the merkle one); malformed-input
  checks stay `assert!`s and keep the full charge. Measured: a duplicate
  registration costs 935,645 cycles (the config session's Poseidon, then exit
  14 in the membership session) vs 10,000,000 for a malformed one
  (`a_stale_view_is_charged_measured_cycles`).

## Init guards are empty-state checks
Public transactions need no signature for PDA rows, so any message that
writes a PDA is submittable by anyone. What makes an initializer one-shot is
the handler asserting `pre_state.is_empty()` before writing (`Initialize`,
`InitMembership`, merkle `Initialize`). Authorization (`is_authorized`) only
says the sender may write the account, never that the account is unclaimed.
Do not use `lee_core::program::write_once` for these: it tolerates an
identical rewrite.

## A registry has an owner, and the tree id is the owner's
One-shot is not enough for `Initialize`: an unsigned one let whoever knew a
tree id initialize it first, with a treasury and a merkle program of their
own. A handler learns that its RECEIVER signed from the grant over it
(`is_authorized()`), and a config is a PDA nobody signs for, so `Initialize`
enters at the owner's own keyed account (root message, `from == None`,
`is_authorized()`, the owner's actor declared a signer), where the tree
id is computed as `owner_tree_id(owner, tree_label)`, and is forwarded to
that tree's config, which takes it only from this program's actor at the
owner (`from_own_program`, and the PDA re-derived from `from.account_id`).
A tree id is therefore never an input to setup: `run_setup` prints it,
`LEZ_RLN_TREE_LABEL` picks among one owner's registries, and a
`LEZ_RLN_TREE_ID_HEX` naming another tree is refused before anything is
sent. The `Initialize` variant kept its position and byte layout (the
32-byte `tree_id` became `tree_label`), and no other message or state layout
changed, so clients built against the earlier `rln-layouts` still register
against the new program. Regressions:
`an_unsigned_initialize_at_the_config_is_refused`,
`another_account_cannot_take_the_owners_tree`.

History: `initialize_merkle_tree` once shipped with authorization only, so
replaying it against a live tree reset `next_index` and the root history —
invalidating every member's proof while their membership PDAs survived.
Regressions: `test_initialize_merkle_tree_cannot_reset_a_live_tree` (state)
and `merkle_tree::tests::test_initialize_rejects_live_tree` (guest unit).
Duplicate registration is refused SOLELY by the membership init guard
(`InitMembership`, exit 14) — the register handler has no duplicate check and
the merkle insert doesn't dedupe. Regression:
`test_register_same_commitment_twice_fails`.

## Wallets: passwords and the v0.4.0 storage
- `WalletCore` is `WalletCore<SequencerClient>` here (`rln::client::Wallet`)
  and opens a storage with a password. The tools read `LEE_WALLET_PASSWORD`
  (`rln::client::wallet_password`) and never prompt; unset or empty means an
  unencrypted file, which every throwaway wallet is. An encrypted storage
  (top-level `ciphertext`) without the variable fails at open; `stage.sh`
  and `provision.sh` refuse it outright because they read the file with jq.
- A storage written by a wallet before v0.4.0 does not work here. Before
  v0.4.0-rc3 its private entries carry `shards` and `Regular(Identifier)` and
  it no longer parses. A v0.4.0-rc3 storage parses no better: its public
  entries carry `ssk` / `pub_sign_key` where v0.4.0 stores `{secret, cci}`
  and `{account_id, secret}`. Every old wallet — `dev/storage.json`, every
  consumer profile — must be re-minted. `provision.sh`/`stage.sh` refuse a
  storage containing `"shards"`, `"ssk"` or `"pub_sign_key"`.
- A private key file or wallet entry holds an account SECRET (64 hex): the
  same 64 hex name a different account on v0.4.0 than on rc3, so a payer key
  file funded on an rc3 chain is another, unfunded account here.
- Genesis funds an INITIAL KEY, not an account id: the key type byte `00`
  followed by the account's 32-byte key commitment, 66 hex characters, the
  text a genesis file takes in `identified.key`. `mint_payer` prints the id
  on line 1 and the key on line 2 (`--public-key` prints only the key), and
  `dev.sh` takes the key in `LEZ_RLN_GENESIS_FUND` (it refuses a base58 id
  and a 64-hex key). `run_setup` prints the payer's and the treasury's
  keys, and `provision.sh` records them in `deployment.json`
  (`payer_public_key`, `treasury_public_key`: the names stayed, the values are
  initial keys): a credit to an account that has never existed needs the key
  (`fund_account --to-public-key`).

## Program ids are deployment state
`CreateHeader` requires an `is_authorized` target, so a program lives at a
keypair account the deployer created and signed — there is no bytecode-derived
address. `run_setup` creates the two header accounts and records them; every
PDA hangs off those ids, and every tool must be told them (deployment
descriptor, `~/.logos-lez-rln/programs_<tree_hex>.json`, or `LEZ_RLN_REGISTRATION_PROGRAM_ID` / `LEZ_RLN_MERKLE_PROGRAM_ID`), never derive them from the `.bin`. The `.bin`
still determines the IMAGE id the header must carry.

They can be fixed in advance, though: with `LEZ_RLN_DEPLOY_SECRET_FILE` and
`LEZ_RLN_DEPLOY_NAME` the header, segment, owner and treasury keys derive
from a secret (`rln::deploy_keys`), so every id is known before the chain
exists (`plan_deployment`, `deploy_plan`, `tools/deployments/plan.sh` and
`deploy.sh`). No address depends on the chain, and none on the image.
- The payer is the one key that need not come from that secret:
  `LEZ_RLN_PAYER_KEY_FILE` (`--payer-key-file`) holds an account secret as it
  is, 64 hex, nothing derived. So `deploy_plan` does not hold a plan file to
  the secret's payer (`differences` skips `payer_*`), and resolves the key
  of `LEZ_RLN_PAYER` itself: the key file, else the secret's payer, else the
  wallet. `run_setup` and `deploy_programs` do not read the key file.
- The key-chain path cannot do this: it takes the next account whose loader
  shard is empty, which depends on the wallet's history and on how many
  segments the guest uploads as.
- The wallet's `[profile.dev]` here comes from a cargo config ABOVE the
  checkout (`~/Waku/Logos/.cargo/config.toml` on the machine these notes
  were written on). A worktree outside that folder builds another profile
  and shares nothing with the checkout's `target/`: pass
  `CARGO_PROFILE_DEV_DEBUG=line-tables-only
  CARGO_PROFILE_DEV_SPLIT_DEBUGINFO=unpacked` to reuse it.
- A local guest build takes the rzup DEFAULT rust toolchain, and
  `rust-poseidon-bn254-pure` at the pinned rev does not compile with 1.97:
  build with 1.91.1 or the docker builder (1.88).

## Renewal is priced, not permissioned
`extend` deliberately does not check caller identity — `MembershipState`
records no owner, and a third party paying for someone's renewal is
harmless. What is not harmless is renewal being FREE: `erase` reclaims a
membership's `rate_limit` only once it expires, so anyone could keep
abandoned memberships alive one cheap tx per grace window and pin
`current_total_rate_limit` at `max_total_rate_limit`, blocking all new
registrations. `extend` charges `rate_limit * price_per_unit` — the same as
registering — which also gives `active_duration` economic force.

## The tree holds 512 leaves, and that is a lifetime count
`next_index` only advances and an erased leaf's index is never reused, so
`TREE_LEAVES` bounds total registrations over the tree's life, not concurrent
members. The whole tree is one sparse node map in one actor state (u16 BFS
offsets, `TREE_SHARD_MAX_BYTES` under this crate's own 100 KiB bound, asserted
at build time); an index past the last leaf would alias live nodes and return
a wrong root WITHOUT failing, so `insert_leaf` asserts the bound (the
registration program cannot: it never sees `next_index`). `MerkleMessage::Set` exists with no callers
and is the only index-reuse path if capacity ever has to grow.

## Running state_tests.rs
Plain `cargo test` prints "0 passed, N filtered out" and exits 0 — it ran
nothing. The suite is feature-gated, and on macOS PyO3 needs the framework
path or tests die in dyld with SIGABRT
("Library not loaded: @rpath/Python3.framework"):

    CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
    RISC0_DEV_MODE=1 \
    DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Frameworks \
    cargo test --release --features rc5-state-tests

`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true` is not optional: lee's
`test-utils` feature (which the `nssa` dev-dependency enables) is a
`compile_error!` in a release profile without debug assertions.

`state_tests` reads the guest `.bin`s from the same `docker/` dir the deploy
host uses, which is also the record of what is live. Set `LEZ_RLN_GUEST_DIR`
to a fresh build's `release/` dir to test guest changes without overwriting
the artifacts `verify.sh` compares against.

The in-process suite never touches a sequencer. `bash tools/e2e-local.sh`
runs `lez-rln/tests/local_sequencer.rs` — the whole lifecycle including slash,
extend and erase — against a `dev.sh` sequencer at the pinned tag, with
second-long membership durations (`LEZ_RLN_ACTIVE_DURATION_SECS` /
`LEZ_RLN_GRACE_PERIOD_DURATION_SECS`). ~5 minutes, most of it waiting for
chain time to pass. The test is a no-op without `LEZ_RLN_LOCAL_SEQUENCER`.

## dev.sh on v0.4.0
- The sequencer CLI is `setup <home> --config <file> --funding-public-key
  <hex> --create-channel`, then `start <home> --rpc-listen-address
  127.0.0.1:<port> --metrics-listen-address <addr>`; the config template is
  `lez/sequencer/service/networks/local.json` (schema is
  `deny_unknown_fields`; genesis is `{channel_params, actions:[..]}`). `setup`
  refuses a home that already holds `sequencer_config.json`, so dev.sh wipes
  the whole home every start. Do NOT pass `--config` to `start`: without
  `--create-channel` it drops the genesis, and the payer's balance with it.
- `LEZ_RLN_PORT`, `LEZ_RLN_SEQUENCER_HOME`, `LEZ_RLN_METRICS_ADDR`,
  `LEZ_RLN_SEQUENCER_SRC` (keyed by `LEZ_REF`) and `LEZ_RLN_SEQUENCER_ARGS`
  keep their meanings; the release workspace's `rln up lez` drives dev.sh
  through them. Metrics default to port+6060, so a `--metrics-address` in
  `LEZ_RLN_SEQUENCER_ARGS` duplicates the flag and the sequencer never
  starts. The sequencer answers RPC with error -31902 while it bootstraps;
  `tools/e2e-local.sh` retries until it answers.
- Executing a guest needs the r0vm of the pinned risc0-zkvm (3.1.0). The
  scripts that execute guests export `RISC0_SERVER_PATH` from
  `~/.risc0/extensions/v3.1.0-cargo-risczero-*/r0vm` when it is unset; a
  `cargo test` run by hand needs it set the same way on a machine whose
  default r0vm is older.

## Testnet operations
- register_member's "Timeout waiting for leaf N" panic is often a FALSE
  negative: `wait_for_leaf` polls a hardcoded 30 × 500 ms and testnet
  confirmation regularly exceeds 15 s. Measured: the panic fired while the
  registration had actually landed (tree `next_index` and config
  `total_registrations` both advanced).
- Do NOT blindly re-run after that panic. The tx was submitted (and paid)
  before the poll; a re-run mints a fresh identity + payer and registers a
  SECOND distinct member at a second full payment. Worse, the first
  membership's IDENTITY_SECRET_HASH is lost — it prints only after the
  panic point. Recoverable in principle (the wallet account persists;
  `seeded_keygen` is deterministic) but no tool does that recovery. Check
  on-chain state first.
- A transaction whose action fails on chain is still INCLUDED and charged:
  `getTransaction` finds it, and the block's `body.reverted` lists its
  position (`rln::client::tx_outcome` → `Reverted`; `await_outcome` is the
  one wait every tool uses, and a failed block read is `Pending`, never a
  verdict). The concrete reason
  appears only in the sequencer's own log. Run a local sequencer (`dev.sh`)
  and read its log before believing any client-side diagnosis. Only a
  malformed submission (`InvalidInput`, an unknown root program) is rejected
  for free.
- Deploying new program instances to https://testnet.lez.logos.co/ is
  normal, routine development practice (`tools/deployments/provision.sh`).
- The wallet's own send path (program deploys, inits, native transfers) simulates
  each transaction within `WalletConfig.gas_limit` (default 10M, the block cap) and declares
  the measured cycles + `public_gas_margin_percent` (25), capped at that
  limit, so the payer's reserve covers the measured gas, not the limit. A
  send whose simulation reverts is refused before submission
  (`ExecutionFailureKind::SimulatedRevert`) and costs nothing.
  `send_metered_tx` (register/extend/erase/slash) sends through the same
  wallet but sets `FeeParams { gas_limit, max_fee }` for the one send and
  clears them after: `LEZ_RLN_GAS_LIMIT` (default the 10M cap) and the fee
  reserve. With both set the wallet does not simulate, so a transaction that
  will revert is still sent and charged. Fee params are wallet state, not a
  send argument: anything left set applies to every later send.
- A registration needs no admission evidence for the new membership: the
  config's sync `InitMembership` carries the PDA seed
  (`register_admits_the_membership_without_evidence`). The host still mentions
  it as a PDA.
- Loader actor states are a tagged `LoaderEntry` (`Header` / `Segment`;
  `ProgramHeader::from_loader_actor_state`), so a header written by an rc1
  loader does not decode. `WriteSegment` needs an authorized target like the
  header writes do: segment accounts must be keyed accounts the deployer
  signs for. The loader charges one cycle per byte of loader state it reads,
  so `CreateHeader` over a full chain costs up to ~1.9M gas.
- Wallet sync is only required for tree insertion (registration); claims and
  reads work against an unsynced wallet.
