# Deployment profiles (shared tooling)

Canonical home for the RLN deployment layer. Every sim that vendors `logos-lez-rln`
(mix_lez_chat, mixnet-logos-core, the dst-libp2p Docker pipeline, …) calls these
scripts instead of re-implementing staging.

A **deployment** = one on-chain RLN instance, fully captured by two files:

```
deployments/<name>/
  deployment.json   # tree_id + sequencer + program_ids + derived config + payment/supply
  storage.json      # the wallet (holds payment/supply/token/treasury keypairs)
```

`tree_id` is the single source of truth: `config`/`tree_main`/`escrow` are **derived**
PDAs of `(registration_program_id, tree_id)`; `payment`/`supply` are **pointers into the
wallet**. Nothing to keep in sync by hand — and a stale `config` can't silently disagree
with the tree. All scripts are bash+jq (no Python) so they run in-sim and in image builds.

## Deployment policy (immutable per tree — a policy change = a new tree)

Policy is set at `Initialize` and recorded in `deployment.json`:

- **`"funding": "faucet"`** (default for new deployments) — the payment token's
  definition is the registration program's own `payment` PDA: **no human mint
  key exists**. Anyone funds an account with the rln module's
  `claim_tokens(config, dest, amount)` (or host-side `claim_payment_tokens`),
  capped per call by the deployment's `--claim-cap` (default 10M). The cap is
  per-call only — repeat claims are unbounded by design (test tokens).
- **`"funding": "wallet-key"`** (and every pre-policy descriptor) — the legacy
  model: fixed pre-minted supply, definition keypair in the wallet, funding via
  wallet transfers (the rln module's `mint_tokens` wire method was removed in
  its v2.0.0 contract). These profiles stay self-replenishing because the
  wallet carries the mint key.
- **`"membership": {"mode": "free-quota", "registrar": <hex>, "quota": N}`**
  (optional, additive) — the registrar account may create up to N memberships
  without paying via the `RegisterFree` instruction; the normal paid path keeps
  working alongside.

`get_token_balance(account)` works in both funding modes.

## Consumer contract

```bash
bash tools/deployments/stage.sh <deployment_dir> <out_dir>
```

Emits the flat files `run_setup`/`register_member`/node daemons already expect
(`storage.json.seed`, `wallet_config.json`, `config_account.txt`,
`payment_account.txt`, `supply_holding.txt`, `funding.txt`, `env.sh`). Asserts the wallet is rc6
(`key_chain.accounts`) and that it actually contains the descriptor's payment account
(+ the supply account on wallet-key deployments; a faucet deployment's supply holder is
a program PDA no wallet holds) — a mismatched wallet fails at stage time, not at runtime.

## Workflows

**Run against an existing deployment** — drop a `deployments/<name>/` in and `stage.sh` it.

**Redeploy fresh** (needs `run_setup` + `derive_accounts` built):
```bash
(cd lez-rln && PYO3_PYTHON=$(command -v python3) cargo build --release --bin run_setup --bin derive_accounts)

# fresh tree + fresh wallet (faucet funding by default):
bash tools/deployments/provision.sh --name my-run

# legacy wallet-key funding, or a free-membership quota for one account:
bash tools/deployments/provision.sh --name legacy --funding wallet-key
bash tools/deployments/provision.sh --name gifted --registrar <64hex> --quota 100

# reuse another sim's wallet (shared accounts), specific tree, write into a consumer repo:
bash tools/deployments/provision.sh --name shared --tree <64hex> \
     --adopt-wallet /path/to/other/storage.json --outdir /path/to/consumer/deployments
```

## verify.sh — guest-drift guard

```bash
bash tools/deployments/verify.sh deployments/<name>
```

Re-derives `program_id`/`config` from the **current** guest binaries (via `derive_accounts`,
reusing the real PDA math) and diffs the descriptor. If the guest changed
(different `program_id`), the same `tree_id` derives a different `config` and this fails
with "guest changed; re-run provision" — surfacing drift instead of a mystery tree bug.
Staging itself trusts the descriptor's cached `config` (so it needs no toolchain);
`verify.sh` is the dev/CI gate that keeps that cache honest.

Note: `lssa` is fetched by the flake (`fetchFromGitHub`, rev `v0.2.0-rc6`); a host
`cargo build` of the bins needs a plain sibling clone at `lssa/` (same rev).
