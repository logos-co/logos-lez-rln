# logos-rln-module — the RLN module (Rust)

`liblogos_rln_module`, built on logos-rust-sdk / logos-module-builder. It is
wire-compatible with the C++/Qt module it replaced — same module name, same
11 methods (register/proof/identity + the funding methods
`mint_tokens`/`claim_tokens`/`get_token_balance`), same two broadcast events —
so existing consumers (delivery module, sim) work unchanged. The RLN
register / proof / funding logic lives in-crate (`rust-lib/src/rln_core.rs`,
plain Rust); there is no C ABI. Acceptance gate: the mix_lez_chat sim (see
"Sim acceptance" below).

## Layout

- `metadata.json` — module manifest: `codegen.rust` drives logos-module-builder
  (lidl scaffold + typed `logos_execution_zone` client + Qt cdylib glue).
- `rust-lib/liblogos_rln_module.lidl` — the module contract (13 methods + 2
  events): the 11 C++-wire-compatible methods plus the additive v1.1
  `get_membership` / `get_registry_bounds`.
- `rust-lib/deps/logos_execution_zone.lidl` — hand-maintained dependency
  contract for the wallet module, wired via `dependency_overrides`.
- `rust-lib/src/lib.rs` — the provider implementation (wallet lp client + the
  11 handlers).
- `rust-lib/src/rln_core.rs` — the RLN core (tree/proof/register/funding logic),
  depending only on the shared `rln-layouts` crate.
- `rust-lib/generated/provider_gen.rs` — checked-in scaffold for local
  `cargo check`/tests; the nix build regenerates it. Regenerate manually with:
  `logos-lidl-gen rust-lib/liblogos_rln_module.lidl --provider \
   --dep logos_execution_zone=rust-lib/deps/logos_execution_zone.lidl \
   -o rust-lib/generated/provider_gen.rs`

## Staged sources (not committed)

mkLogosModule's `rustCrateSrc` stages only the crate dir (plus
`logos-rust-sdk-src`) into the nix sandbox, so path-deps must live inside the
module tree. Two staged copies are required and are NOT in git:

- `logos-rust-sdk-src/` — logos-co/logos-rust-sdk at the rev pinned in
  `stage-sources.sh` (the rev the builder's codegen comes from).
- `rust-lib/lez-rln-src/rln-layouts/` — a copy of `../lez-rln/rln-layouts`
  (rln_core depends on it).

Refresh both — rsync plus a diff verification that fails on drift — with:

```sh
./stage-sources.sh
```

The committed `rust-lib/lez-rln-src/Cargo.toml` is a synthetic workspace root
for the staged `rln-layouts` crate (upstream it declares `[lints] workspace =
true`); keep its `[workspace.lints.*]` tables in sync with `lez-rln/Cargo.toml`
when refreshing the staged copy.

## Build

```sh
nix build 'path:.#default'   # path: scheme — the dir is untracked in-repo
# plugin: result/lib/liblogos_rln_module_plugin.dylib
nix build 'path:.#lgx'       # .lgx bundle for RLN_LGX
```

## Live-registry tests (testnet)

`src/testnet_tests.rs` validates rln_core's chain-facing logic — ConfigState
offsets, PDA derivation, valid roots, merkle-proof construction (recomputed
via poseidon), clock decode, membership reads — against a DEPLOYED
registration program. Read-only, off by default (each test skips unless
gated), no new crate deps (`curl` subprocess speaks the sequencer's
JSON-RPC `getAccount` — the same read the wallet serves this module at
runtime):

```sh
LEZ_RLN_TESTNET_TESTS=1 cargo test testnet_ -- --nocapture
# registry selection (default shared-faucet):
LEZ_RLN_TESTNET_DEPLOYMENT=shared-5ade-v2 LEZ_RLN_TESTNET_TESTS=1 cargo test testnet_
```

The registry comes from `../deployments/<name>/deployment.json`. These
catch what unit pins can't: layout drift against the pinned guest image,
PDA-derivation divergence, tree-encoding drift, chain-clock unit changes.

## Sim acceptance

This is the default RLN module in the mix_lez_chat sim (the parent
`flake.nix` `logos-rln-module` attr resolves to it). Run the sim per its
README — `ALL 15 CHECKS PASSED` on local and testnet (faucet). To force a
specific build via env: `RLN_LGX=<lgx>/logos-rln-module.lgx
RLN_PLUGIN_OVERRIDE=$PWD/result/lib/liblogos_rln_module_plugin.dylib`.

## Design constraints (read before changing)

- **`concurrency` is `single`, deliberately.** The delivery module's pinned
  logos-cpp-sdk predates the deferred-result sentinel (`resolveDeferred` /
  `__logos_call_complete__`), so multi-concurrency provider replies read as
  instant failures there. Flip to multi only after the delivery module's SDK
  pin is bumped — acceptance: sim still 15/15 with `concurrency: "multi"`.
- **The wallet lp client is created in `on_context_ready` (main Qt thread)**
  and never lazily in handlers: the creating thread owns the client and must
  run a Qt event loop (lp owner-thread contract). `wallet_call` picks sync
  `lp_invoke` on the owner thread and `lp_invoke_async` + channel from
  broadcast threads.
- **`REG_IN_FLIGHT` dedup in `register_member`**: the delivery module fires
  register_member twice ~2s apart (sync selfRegisterRln + async rln_fetcher).
  An on-chain idempotency pre-check cannot see a tx that is still confirming
  (60-90s on testnet), and the double submit reuses the payer nonce — the
  second tx is silently dropped and, on a virgin tree, poisoned the gifter.
  The in-session (config_account, id_commitment) map returns the first
  submission's reply to duplicates.
- **Funding methods** (`mint_tokens`/`claim_tokens`/`get_token_balance`) mirror
  the tx-account order + signing flags of the deployed programs exactly:
  mint `[definition(signer), dest(signer)]` under the Token program; claim
  `[config, payment_def, dest(signer)]` under the registration program;
  `get_token_balance` is tri-state (`""`=error, `{exists:false}`=absent,
  `{exists:true,…}`=present) so the faucet poller can distinguish "unreachable"
  from "not credited yet".
- lidl `void` methods must return `true` (`Value::Null` reads as
  METHOD_FAILED through the Qt glue).
