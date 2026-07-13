# lez-rln-module-rs — the RLN module (Rust)

`liblogos_rln_module`, built on logos-rust-sdk / logos-module-builder. This is
**the** RLN module — it replaces the removed hand-written C++/Qt
`logos-rln-module`, with the same module name, the same 11 methods
(register/proof/identity + the funding methods `mint_tokens`/`claim_tokens`/
`get_token_balance`) and the same two broadcast events, byte-level wire parity
verified against the old C++ module. The RLN register / proof / funding logic
lives in-crate (`rust-lib/src/rln_core.rs`, plain Rust) — there is no C ABI and
no separate `lez-rln-ffi` crate. Gated by the mix_lez_chat sim at 15/15 on
local and the public testnet (faucet funding).

## Layout

- `metadata.json` — module manifest: `codegen.rust` drives logos-module-builder
  (lidl scaffold + typed `logos_execution_zone` client + Qt cdylib glue).
- `rust-lib/liblogos_rln_module.lidl` — the module contract (11 methods + 2 events).
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

```sh
# 1. The SDK (logos-co/logos-rust-sdk @ e288fb0 or later):
git clone https://github.com/logos-co/logos-rust-sdk /tmp/logos-rust-sdk
rsync -a --delete --exclude .git --exclude target --exclude doctests \
    --exclude result /tmp/logos-rust-sdk/ logos-rust-sdk-src/

# 2. The shared borsh-layout crate (from this repo — rln_core depends on it):
rsync -a --delete --exclude target --exclude .git \
    ../lez-rln/rln-layouts/ rust-lib/lez-rln-src/rln-layouts/
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
