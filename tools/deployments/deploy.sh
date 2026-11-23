#!/usr/bin/env bash
# Deploy a planned deployment: the chain ends up holding exactly what plan.sh wrote.
# FEATURE: deployment-profile tooling — the planned (deterministic) entry point.
#
#   bash deploy.sh --plan-dir <outdir>/<name> --secret-file <file>
#                  [--payer <account-id> --adopt-wallet <storage.json>] [--check]
#                  [--allow-image-change]
#
# Runs deploy_plan in a throwaway wallet home: it recomputes the plan from the
# secret and refuses a plan.json these keys do not derive, checks every
# planned account on the chain before sending anything, deploys both programs
# immutable at the planned accounts, initializes each registry (signed by the
# deployment's owner), and reads it all back. Then it turns each planned
# descriptor into a deployed one, {deployment.json, storage.json}, and runs
# verify.sh on it.
#
# Programs are immutable and Initialize is one-shot, so a mistake at a
# planned account cannot be taken back and spends the ids. Hence the order:
# every check first, and `--check` to stop there. A run that was interrupted
# is finished by running again; a run against a chain that already holds the
# plan sends nothing.
#
# Who pays. By default the deployment's own payer: plan.json's payer_account,
# whose key comes from the secret, funded at genesis by its public key. To
# pay from another funded account, pass its wallet and its id
# (--adopt-wallet, --payer). No id depends on the payer.
#
# The code. plan.json records the image ids of the guest binaries it was made
# beside, and a deploy of other binaries is refused: the ids would be the
# plan's, the code would not. --allow-image-change deploys them anyway.
#
# The sequencer is plan.json's. LEE_WALLET_PASSWORD seals the wallet if set.
set -euo pipefail

usage(){ echo "usage: deploy.sh --plan-dir <outdir>/<name> --secret-file <file> [--payer <account-id> --adopt-wallet <storage.json>] [--check] [--allow-image-change]" >&2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"                    # logos-lez-rln root
LEZ="$REPO/lez-rln"
PLAN_DIR=""; SECRET=""; PAYER=""; ADOPT=""; CHECK=""; IMAGES=""
while [ $# -gt 0 ]; do case "$1" in
  --plan-dir) PLAN_DIR="$2"; shift 2;;
  --secret-file) SECRET="$2"; shift 2;;
  --payer) PAYER="$2"; shift 2;;
  --adopt-wallet) ADOPT="$2"; shift 2;;
  --check) CHECK="--check"; shift;;
  --allow-image-change) IMAGES="--allow-image-change"; shift;;
  -h|--help) usage; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 1;;
esac; done
[ -n "$PLAN_DIR" ] && [ -n "$SECRET" ] || { usage; exit 1; }
PLAN="$PLAN_DIR/plan.json"
[ -f "$PLAN" ] || { echo "deploy: FAIL: no plan at $PLAN (plan.sh writes it)" >&2; exit 1; }
[ -f "$SECRET" ] || { echo "deploy: FAIL: no secret file at $SECRET" >&2; exit 1; }
command -v jq >/dev/null || { echo "deploy: FAIL: jq not found" >&2; exit 1; }
PLAN_DIR="$(cd "$PLAN_DIR" && pwd)"; PLAN="$PLAN_DIR/plan.json"
SECRET="$(cd "$(dirname "$SECRET")" && pwd)/$(basename "$SECRET")"
OUTROOT="$(dirname "$PLAN_DIR")"
NAME=$(jq -re .name "$PLAN"); SEQUENCER=$(jq -re .sequencer "$PLAN")
[ "$(basename "$PLAN_DIR")" = "$NAME" ] || { echo "deploy: FAIL: $PLAN is the plan of '$NAME', not of $(basename "$PLAN_DIR")" >&2; exit 1; }
if [ -n "$PAYER" ] && [ -z "$ADOPT" ]; then
  echo "deploy: FAIL: --payer names an account of another wallet; pass that wallet with --adopt-wallet" >&2; exit 1
fi
[ -n "$PAYER" ] || PAYER=$(jq -re .payer_account "$PLAN")

BIN_DIR="${LEZ_RLN_BIN_DIR:-$LEZ/target/release}"
DEPLOY_BIN="$BIN_DIR/deploy_plan"
for b in "$DEPLOY_BIN" "$BIN_DIR/derive_accounts"; do [ -x "$b" ] || { echo "deploy: FAIL: missing $b — build: (cd $LEZ && PYO3_PYTHON=\$(command -v python3) cargo build --release --bin deploy_plan --bin derive_accounts)" >&2; exit 1; }; done

WS=$(mktemp -d); trap 'rm -rf "$WS"' EXIT
if [ -n "$ADOPT" ]; then
  [ -f "$ADOPT" ] || { echo "deploy: FAIL: adopt wallet not found: $ADOPT" >&2; exit 1; }
  cp "$ADOPT" "$WS/storage.json"; echo "deploy: adopting wallet $ADOPT"
fi
# The wallet config provision.sh writes; see there for each field.
jq -n --arg s "$SEQUENCER" '{sequencer_addr:$s, sequencer:{sequencer_addr:$s}, sequencers:[{sequencer_addr:$s}], seq_poll_timeout:"30s", seq_tx_poll_max_blocks:15, seq_poll_max_retries:10, seq_block_poll_max_amount:100, gas_limit:10000000, multi_sequencer_client_config:{distribution_limit:1, calibration_limit:3}}' > "$WS/wallet_config.json"

echo "deploy: deployment=$NAME sequencer=$SEQUENCER payer=$PAYER"
export HOME="$WS" LEE_WALLET_HOME_DIR="$WS"
export LEE_WALLET_PASSWORD="${LEE_WALLET_PASSWORD:-}"
export LEZ_RLN_DEPLOY_SECRET_FILE="$SECRET" LEZ_RLN_PAYER="$PAYER" RISC0_DEV_MODE=1
export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}"
# From lez-rln/: the guest binaries are read by a relative path.
( cd "$LEZ" && "$DEPLOY_BIN" --plan "$PLAN" --out "$WS/deployed.json" $CHECK $IMAGES )
if [ -n "$CHECK" ]; then echo "deploy: checked only; nothing sent."; exit 0; fi

[ -f "$WS/deployed.json" ] || { echo "deploy: FAIL: deploy_plan wrote no result" >&2; exit 1; }
cp "$WS/deployed.json" "$PLAN_DIR/deployed.json"
COUNT=$(jq '.registries | length' "$PLAN_DIR/deployed.json")
for ((i = 0; i < COUNT; i++)); do
  LABEL=$(jq -r --argjson i "$i" '.registries[$i].label' "$PLAN_DIR/deployed.json")
  DEP_DIR="$OUTROOT/$NAME-$LABEL"; mkdir -p "$DEP_DIR"
  jq --argjson i "$i" '.registries[$i] as $r | {
      name: (.name + "-" + $r.label),
      tree_id: $r.tree_id, sequencer: .sequencer,
      registration_program_id: .registration_program_id, merkle_program_id: .merkle_program_id,
      config_account: $r.config_account,
      payer_account: .payer_account, treasury_account: $r.treasury_account,
      min_rate_limit: $r.min_rate_limit, max_rate_limit: $r.max_rate_limit,
      payer_public_key: .payer_public_key, treasury_public_key: $r.treasury_public_key,
      owner_account: .owner_account, tree_label: $r.label,
      registry_id: ("logos:" + .reference + ":" + $r.config_account_hex)
    }' "$PLAN_DIR/deployed.json" > "$DEP_DIR/deployment.json"
  # The wallet holds the payer, the owner, the treasuries and the program
  # headers: a key file, like every deployment's storage.json.
  cp "$WS/storage.json" "$DEP_DIR/storage.json"
  LEZ_RLN_BIN_DIR="$BIN_DIR" bash "$HERE/verify.sh" "$DEP_DIR"
  echo "deploy: $(jq -r .registry_id "$DEP_DIR/deployment.json") is live  ($DEP_DIR)"
done
echo "deploy: DONE — deployment '$NAME' holds its plan."
