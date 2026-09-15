# Deployment profiles (shared tooling)

Canonical home for the RLN deployment layer. Every sim that vendors `logos-lez-rln`
(mix_lez_chat, mixnet-logos-core, the dst-libp2p Docker pipeline, …) calls these
scripts instead of re-implementing staging.

A **deployment** = one on-chain RLN instance, fully captured by two files:

```
deployments/<name>/
  deployment.json   # tree_id + sequencer + program_ids + derived config + payer/treasury
  storage.json      # the wallet (holds the payer's keypair)
```

`tree_id` is the single source of truth: `config` and `tree_main` are **derived** PDAs of
`(registration_program_id, tree_id)`; `payer_account` is a **pointer into the wallet**.
`treasury_account` is neither — it is a plain account created at provisioning time, so the
descriptor is the only record of where a registry's revenue accrues. Nothing to keep in
sync by hand, and a stale `config` can't silently disagree with the tree. All scripts are
bash+jq (no Python) so they run in-sim and in image builds.

## Paying for a membership

There is one asset and one way to pay. A membership costs
`rate_limit x price_per_unit` of **native** balance, debited from the account that
signs the `Register` transaction — which is also that transaction's fee payer.
One account, one balance, no holding to derive and nothing to claim first.

That account is `payer_account`, and it must already hold native balance:
**no program can mint native**, so it arrives at genesis (`mint_payer` prints an
id, `dev.sh`'s `LEZ_RLN_GENESIS_FUND` funds it), over the L1 bridge, or by a
transfer from something already funded. Budget roughly
`rate_limit x price_per_unit + 6.5e8` per registration — the fee reserve dwarfs
the price, so an account sized only for the price cannot transact at all.

There is no funding policy to choose any more, and no free-registration quota:
the RLNTOK payment token, the RLNREC credit token, the faucet and `RegisterFree`
were all removed together. A descriptor carrying `funding`, `supply_holding` or
`payment_account` predates that change and is not merely stale — its config
account belongs to a program that no longer exists, and every offset in it
decodes to something plausible and wrong. `stage.sh` refuses it.

## Consumer contract

```bash
bash tools/deployments/stage.sh <deployment_dir> <out_dir>
```

Emits the flat files `run_setup`/`register_member`/node daemons already expect
(`storage.json.seed`, `wallet_config.json`, `config_account.txt`,
`payer_account.txt`, `treasury_account.txt`, `env.sh`). Asserts the wallet is rc6
(`key_chain.accounts`) and that it actually contains the descriptor's payer account —
a mismatched wallet fails at stage time, not at runtime. The treasury is only ever
credited, so no wallet need hold it.

## Workflows

**Run against an existing deployment** — drop a `deployments/<name>/` in and `stage.sh` it.

**Redeploy fresh** (needs `run_setup` + `derive_accounts` built):
```bash
(cd lez-rln && PYO3_PYTHON=$(command -v python3) cargo build --release --bin run_setup --bin derive_accounts)

# fresh tree + fresh wallet. --payer is required: it pays the deploy fees and
# becomes the deployment's payer_account.
bash tools/deployments/provision.sh --name my-run --payer <account-id>

# reuse another sim's wallet (shared accounts), specific tree, write into a consumer repo:
bash tools/deployments/provision.sh --name shared --payer <account-id> --tree <64hex> \
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
