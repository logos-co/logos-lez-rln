# logos-rln-membership-module — RLN Membership Management (Rust)

`liblogos_rln_membership_module`, built on logos-rust-sdk /
logos-module-builder. Implements the RLN-MEMBERSHIP-MANAGEMENT spec
(logos-lips `docs/anoncomms/raw/rln-membership-management.md`): a
registry-agnostic API for registering, storing, and selecting RLN
memberships on behalf of consuming services — CAIP-10 registry ids,
encrypted keystore storage, a bounded Pending confirmation window, and
per-scope membership selection.

The lez-rln registry provider (the `logos` CAIP-10 namespace) is a wire
client of the sibling [`../logos-rln-module`](../logos-rln-module): all
chain knowledge (PDA derivation, clock reads, tx submission) stays there;
this crate holds only registry-agnostic logic. No rln-layouts / risc0 /
zerokit dependencies.

## Layout

- `metadata.json` — module manifest: `codegen.rust` drives
  logos-module-builder (lidl scaffold + typed `liblogos_rln_module` client
  + Qt cdylib glue).
- `rust-lib/liblogos_rln_membership_module.lidl` — the module contract
  (11 methods; reply/error conventions documented in the header).
- `rust-lib/deps/liblogos_rln_module.lidl` — hand-maintained dependency
  contract (the consumed subset of the sibling's wire), wired via
  `dependency_overrides`. Same repo: update both files in the same PR.
- `rust-lib/src/lib.rs` — module impl: dispatch glue, error envelope.
- `rust-lib/src/registry_id.rs` — CAIP-10 parse/canonicalize +
  `membership_hash` (the spec's SHA256 construction; frozen test vector).
- `rust-lib/src/keystore.rs` — WAKU-RLN-KEYSTORE-format encrypted store:
  PBKDF2-HMAC-SHA256, AES-128-CTR, **keccak256** MAC (the construction the
  spec's own test vector actually uses — its prose says SHA256; the pinned
  `spec_test_vector_decrypts` keeps us honest), atomic tmp+rename saves.
- `rust-lib/src/store.rs` — runtime store: unlock state, lifecycle state
  machine (pending→active/failed, erased inference), merged-state view,
  load-time tamper quarantine.
- `rust-lib/src/provider.rs` — the spec's Registry Provider Interface as a
  trait + namespace routing; the lez-rln provider is a raw `lp_*` wire
  client of the sibling module (owner-thread-bound, explicit per-call
  timeouts; fire-and-record async registration).
- `rust-lib/src/poller.rs` — confirmation + lifecycle poller: 15s-tick
  detached thread; pending→active with authoritative leaf/rate re-read, or
  pending→failed past the 300s window; 60s non-terminal state refresh with
  erased inference.
- `rust-lib/src/select.rs` — spec `select()`: active/grace_period
  candidates only, by_hash / highest_rate_limit / round_robin (rotation
  state per (registry_id, rln_identifier) scope).
- `rust-lib/src/wallet_home.rs` — `provision_wallet_home()`: stakes out
  `<instance_persistence_path>/wallet-home/` with a write-once
  wallet_config.json (stage.sh's exact shape) so sandboxed UIs get wallet
  files without touching the filesystem; storage.json creation stays the
  wallet module's job.
- `rust-lib/src/keychain.rs` — `unlock_keystore_auto()` /
  `remember_keystore_password()`: macOS-Keychain-backed silent unlock via
  the `security` CLI (stdin batch writes — the secret never hits argv;
  a missing item over existing credentials never invents a secret).
  Injectable backend seam; cargo tests never touch the live keychain.
- `rust-lib/generated/provider_gen.rs` — checked-in scaffold for local
  `cargo check`/tests; the nix build regenerates it. Regenerate manually with:
  `logos-lidl-gen rust-lib/liblogos_rln_membership_module.lidl --provider \
   --dep liblogos_rln_module=rust-lib/deps/liblogos_rln_module.lidl \
   -o rust-lib/generated/provider_gen.rs`

## Design constraints

- **Persistence path is mandatory.** The keystore lives at
  `<instance_persistence_path>/rln_keystore.json`. If the host provides no
  path, keystore ops fail with an `internal` error — there is deliberately
  no cwd fallback (a keystore in an unknown directory is worse than a hard
  error).
- **Unlock model.** Reads and lifecycle polling never need the password
  (sidecar metadata is plaintext-safe). `unlock_keystore` is required to
  register (writes a credential) and to `select_membership` (releases one).
  With zero stored credentials any password unlocks and becomes the
  encryption password at first write — the keystore format has no
  keystore-level verifier; later unlocks verify against the first stored
  envelope's MAC.
- **Wire conventions.** Every reply is a compact JSON object (alphabetical
  keys); failures are `{"error":{"kind":…,"message":…}}`. The sibling
  module's `""`-on-error convention is NOT used here.
- **Provisional leaf_index.** `register` returns the provider's pre-submit
  estimate; the authoritative value is re-read from the registry at the
  pending→active transition (spec MUST). Consumers needing the leaf for
  proofs should read it after the membership reports `active`.

## Staged sources (not committed)

mkLogosModule's `rustCrateSrc` stages only the crate dir plus
`logos-rust-sdk-src` into the nix sandbox:

- `logos-rust-sdk-src/` — logos-co/logos-rust-sdk at the rev pinned in
  `stage-sources.sh`. Keep the pin identical to
  `../logos-rln-module/stage-sources.sh`.

Refresh with:

```sh
./stage-sources.sh
```

## Build

```sh
nix build 'path:.#default'   # plugin: result/lib/liblogos_rln_membership_module_plugin.dylib
nix build 'path:.#lgx'       # .lgx bundle
```

## Tests

```sh
cd rust-lib && cargo test
```

### End-to-end registration in logos-core (testnet)

`tests/e2e_register_testnet.sh` loads the real module stack into a
logoscore daemon (wallet → rln → membership) and drives a PAID registration
against the deployed testnet registry — faucet-funded `Register`, not the
gifter's `RegisterFree`: open/sync wallet → fresh holding → `claim_tokens`
→ `generate_identity` → `unlock_keystore` → `register` → poll
`get_membership_state` to `active` → `select_membership` →
`get_merkle_proof` → cross-check via the sibling's `get_membership`.

```sh
bash tests/e2e_register_testnet.sh          # ~3-6 min, burns ~1M RLNTOK (faucet)
E2E_DEPLOYMENT=<name> …                      # descriptor under ../deployments
E2E_KEEP=1 …                                 # keep the daemon + state dir
```

First verified pass (2026-07-14, shared-faucet): leaf 5, ~60s confirmation.
This run is also the acceptance for two architecture assumptions: raw lp_*
calls INTO a Rust module work (the lez-rln provider transport), and
logoscore stamps `instance_persistence_path` (the keystore location) — the
script diagnoses both explicitly if they regress.

Covers: CAIP-10 canonicalization vectors, the frozen membership_hash
vector, keystore roundtrip/tamper/wrong-password plus the WAKU-RLN-KEYSTORE
spec test vector (password `sup3rsecure`), the merged-state matrix, and
metadata-tamper quarantine. The PBKDF2 tests run ~1M rounds each, so the
suite takes ~30–40s.
