# Deployment profiles (shared tooling)

Canonical home for the RLN deployment layer. Every sim that vendors `logos-lez-rln`
(mix_lez_chat, mixnet-logos-core, the dst-libp2p Docker pipeline, …) calls these
scripts instead of re-implementing staging.

A **deployment** = one on-chain RLN instance, fully captured by two files:

```
deployments/<name>/
  deployment.json   # tree_id + sequencer + both program ids + derived config + payer/treasury
  storage.json      # the wallet (holds the payer's keypair); unencrypted, written by a v0.4 wallet
```

`deployment.json`:

```json
{
  "name": "<name>",
  "tree_id": "<64 hex>",
  "sequencer": "<url>",
  "registration_program_id": "<64 hex>",
  "merkle_program_id": "<64 hex>",
  "config_account": "<base58>",
  "payer_account": "<base58>",
  "treasury_account": "<base58>",
  "min_rate_limit": 100,
  "max_rate_limit": 600,
  "payer_public_key": "<64 hex>",
  "treasury_public_key": "<64 hex>",
  "owner_account": "<base58>",
  "tree_label": "<label>"
}
```

A descriptor written by `plan.sh` / `deploy.sh` also carries `registry_id`
(`logos:<network>:<64 hex of the config account>`, what a network preset
names) and, until it is deployed, `"planned": true`.

**A tree id is not chosen.** A registry belongs to the account that signed its
`Initialize` (`owner_account`), and its tree id is what the registration
program makes of that account and a label:
`SHA-256("tree" ‖ owner ‖ label)`, label zero-padded to 32 bytes. Nobody else
can initialize that registry, and the same owner and label always name the
same one. Descriptors from before this rule name neither field; they describe
registries of the earlier program.

**Program ids are recorded, not derived.** A program's account id is the header account its
deployer created and signed in `run_setup`; it is not a function of the guest `.bin`.
`run_setup` writes both ids to `~/.logos-lez-rln/programs_<tree_hex>.json`, `provision.sh`
copies them into `registration_program_id` / `merkle_program_id`, and `stage.sh`'s `env.sh`
exports them as `LEZ_RLN_REGISTRATION_PROGRAM_ID` / `LEZ_RLN_MERKLE_PROGRAM_ID`, which every
tool reads in preference to the record.

`tree_id` and the registration program id together determine `config` and `tree_main`, which
are **derived** PDAs of `(registration_program_id, tree_id)`; `payer_account` is a **pointer
into the wallet**. `treasury_account` is neither — it is a plain account created at
provisioning time, so the descriptor is the only record of where a registry's revenue
accrues. A stale `config` can't silently disagree with the ids (`verify.sh`). All scripts are
bash+jq (no Python) so they run in-sim and in image builds.

## Paying for a membership

There is one asset and one way to pay. A membership costs
`rate_limit x price_per_unit` of **native** balance, debited from the account that
signs the `Register` transaction — which is also that transaction's fee payer.
One account, one balance, no holding to derive and nothing to claim first.

That account is `payer_account`, and it must already hold native balance:
**no program can mint native**, so it arrives at genesis (`mint_payer` prints the
payer's id and public key; `dev.sh`'s `LEZ_RLN_GENESIS_FUND` takes the public
key), over the L1 bridge, or by a transfer from something already funded
(`fund_account`; an account that has never existed on chain is credited by
`--to-public-key`). Budget roughly
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
`payer_account.txt`, `treasury_account.txt`, `env.sh`). `env.sh` exports
`LEE_WALLET_HOME_DIR`, `LEZ_RLN_TREE_ID_HEX`, `LEZ_RLN_PAYER` and both program ids.
Requires both program ids as 64-hex fields, asserts the wallet has
`key_chain.accounts`, and that it actually contains the descriptor's payer account —
a mismatched wallet fails at stage time, not at runtime. The treasury is only ever
credited, so no wallet need hold it.

## Workflows

**Run against an existing deployment** — drop a `deployments/<name>/` in and `stage.sh` it.

**Redeploy fresh** (needs `run_setup` + `derive_accounts` built):
```bash
(cd lez-rln && PYO3_PYTHON=$(command -v python3) cargo build --release --bin run_setup --bin derive_accounts)

# fresh wallet. --payer is required: it pays the deploy fees, becomes the
# deployment's payer_account and, unless LEZ_RLN_REGISTRY_OWNER names another
# account of the wallet, owns the registry. Deploy and init transactions declare
# their simulated gas plus 25%, so the payer's balance must cover that x base fee.
# The registry's label defaults to the name; the tree id is read back.
bash tools/deployments/provision.sh --name my-run --payer <account-id>

# reuse programs already on the chain: export their header ids first.
LEZ_RLN_REGISTRATION_PROGRAM_ID=<64hex> LEZ_RLN_MERKLE_PROGRAM_ID=<64hex> \
  bash tools/deployments/provision.sh --name my-run --payer <account-id>

# a registry with its own rate-limit range (config state, per registry; the
# defaults are 100..=600). deployment.json records it as min_rate_limit /
# max_rate_limit.
LEZ_RLN_MIN_RATE_LIMIT=20 LEZ_RLN_MAX_RATE_LIMIT=100 \
  bash tools/deployments/provision.sh --name mix --payer <account-id>

# reuse another sim's wallet (shared accounts), a label of its own, write into a consumer repo:
bash tools/deployments/provision.sh --name shared --payer <account-id> --label shared-2 \
     --adopt-wallet /path/to/other/storage.json --outdir /path/to/consumer/deployments
```

## Planned deployments — ids known before the chain exists

`provision.sh` learns a deployment's ids by deploying it. `plan.sh` computes
them first, from a secret, and `deploy.sh` then makes a chain hold exactly
that plan. This is how a network preset can name a registry before the
network is up.

```bash
(cd lez-rln && PYO3_PYTHON=$(command -v python3) cargo build --release \
   --bin plan_deployment --bin deploy_plan --bin derive_accounts)

# once: the deployment secret. Keep it; never commit it.
(umask 077; openssl rand -hex 32 > ~/secrets/testnet-x.secret)
# optional: a payer key of its own (see "Two files" below)
(umask 077; openssl rand -hex 32 > ~/secrets/testnet-x.payer)

# any time, no chain needed: every id, as public descriptors
bash tools/deployments/plan.sh --secret-file ~/secrets/testnet-x.secret \
     --payer-key-file ~/secrets/testnet-x.payer \
     --name testnet-x --reference <network> --sequencer <url> \
     --registry relay:100:600 --registry mix:20:100

# when the chain is up and the payer is funded
bash tools/deployments/deploy.sh --plan-dir deployments/testnet-x \
     --secret-file ~/secrets/testnet-x.secret \
     --payer-key-file ~/secrets/testnet-x.payer --check    # checks only
bash tools/deployments/deploy.sh --plan-dir deployments/testnet-x \
     --secret-file ~/secrets/testnet-x.secret \
     --payer-key-file ~/secrets/testnet-x.payer
```

`plan.sh` writes `deployments/<name>/plan.json` and one planned descriptor per
registry, `deployments/<name>-<label>/deployment.json`, with the `registry_id`
a preset needs. `deploy.sh` turns each into a deployed
`{deployment.json, storage.json}`.

**Two files.** `--secret-file` is the deployment secret: the program header
keys, the registries' owner and the treasuries derive from it, and with them
every id. `--payer-key-file` is optional and holds the private key of the
account that pays, 64 hex characters like the secret, but the key itself:
nothing is derived from it, so it can be the key of an account that is
already funded. Without it the payer is one more key the deployment secret
derives. The ids are the same either way; the plan only names another
`payer_account` / `payer_public_key` to fund, and `deploy.sh` needs the same
file to sign with. The two files must differ: the payer's key is stored in
the deployed `storage.json`.

**Where the ids come from.** Every key derives from the secret, the name and
a role (`lez-rln/src/rln/deploy_keys.rs`). A program lives at the account its
header key signs for, the registries' owner is another derived key, and a
tree id is the owner's under the registry's label. So:

```
registry id = PDA(registration program, "config", tree id)
            = f(secret, name, label)
```

Nothing of the chain goes into it — no chain id, genesis or block — and
nothing of the code: a program's id is its header account, whatever image is
deployed there.

**What to know before relying on a plan.**

- *The secret is the deployment.* Lost before the deploy, the planned ids can
  never be reached. Leaked before the deploy, someone else can deploy their
  code at your program accounts or initialize your registries. After the
  deploy the header keys are spent (the programs are immutable), and the
  owner key can only make further registries of its own.
- *Mistakes are permanent.* A program is deployed immutable and `Initialize`
  is one-shot. `deploy.sh` therefore checks every planned account before it
  sends anything and refuses to continue past anything unexpected; use
  `--check` first. A program fix after launch means a new name, new ids and a
  new preset.
- *A header key signs only its own deploy.* The tools never use it for
  anything else, and neither should you: a signature authorizes every actor on
  the account for the whole transaction.
- *Parameters are not part of the id.* Rate bounds, durations, price and
  treasury are in `plan.json`, and `deploy.sh` initializes with exactly those
  and reads them back; changing them does not change the id. A preset's rate
  limit has to lie inside the planned bounds.
- *The code is not part of the id.* `plan.json` records the image ids of the
  guest binaries present when it was made, and `deploy.sh` refuses others
  unless told `--allow-image-change`.
- *A name is one deployment.* The name is part of every key the secret
  derives, so a rehearsal under another name shares no account with the real
  one. Use that: a LEZ transaction names no chain, so one signed on a
  rehearsal chain could be replayed where the same accounts are funded. A
  payer key of its own is one account under every name: fund it on one chain
  only, or its rehearsal transactions can be replayed at its expense.
- *A reset chain reproduces the same ids,* which keeps presets valid but
  leaves every keystore holding memberships the new chain does not have.
  Clear them, or plan the reset under a new name.
- *The ids hold for the pinned LEZ* (`plan.json`'s `lez`): a LEZ that derives
  account ids, PDAs or program addresses differently gives other ids.
  `deploy.sh` recomputes the plan with the build it runs and refuses a
  `plan.json` that differs.
- *Funding.* The plan names a payer and its public key, for a genesis to
  fund: the key in `--payer-key-file`, else one derived from the secret. Any
  other funded account can pay instead: name it with `--payer` and give its
  key as a key file (`--payer-key-file`) or in a wallet (`--adopt-wallet`).
  No id depends on who pays, and `deploy.sh` refuses a payer it holds no key
  for before it sends anything.
- *One sender per payer.* A transaction names its payer's nonce, read from
  the chain when it is sent. A payer key that something else sends from
  during the deploy (a relay, another deploy) can lose a transaction to it;
  the run stops, and running `deploy.sh` again finishes it.

## verify.sh — descriptor consistency guard

```bash
bash tools/deployments/verify.sh deployments/<name>
```

Re-derives `config_account` from the descriptor's `registration_program_id` and `tree_id`
(via `derive_accounts`, reusing the real PDA math) and diffs the descriptor's cache. When
the descriptor names `owner_account` and `tree_label`, the tree id must be the one that
owner holds under that label. A planned descriptor passes without a wallet. If
`~/.logos-lez-rln/programs_<tree_hex>.json` exists it must name the descriptor's two
program ids; otherwise that cross-check is skipped and says so. Then it runs `stage.sh`'s
wallet binding. Program ids cannot be re-derived from the guest binaries, so this does not
detect a rebuilt guest: `run_setup` checks that each program header carries the local
binary's image id when it deploys or reuses a program.
Staging itself trusts the descriptor (so it needs no toolchain); `verify.sh` is the
dev/CI gate that keeps the cached `config` honest.
