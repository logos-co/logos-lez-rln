#!/usr/bin/env bash
# Pre-generate a deployment: every id it will have, before any of it is on chain.
# FEATURE: deployment-profile tooling — the planned (deterministic) entry point.
#
#   bash plan.sh --secret-file <file> --name <deployment> --reference <network> \
#                --sequencer <url> --registry <label>[:<min rate>:<max rate>] \
#                [--registry ...] [--outdir <dir>]
#
# The ids are a function of three things: the deployment secret (a file of 64
# hex characters, `openssl rand -hex 32`), the deployment's name, and each
# registry's label. Nothing is read from a chain or a wallet, so this runs
# before the network exists and gives the same answer every time.
#
# Writes, under <outdir> (default: this repo's deployments/):
#
#   <name>/plan.json               the whole plan; deploy.sh deploys exactly it
#   <name>-<label>/deployment.json one planned descriptor per registry
#
# A planned descriptor has the fields of a deployed one plus
# `"planned": true`, `registry_id` (logos:<reference>:<64 hex>, what a network
# preset names), `owner_account` and `tree_label`. Everything written is
# public: account ids and public keys. The secret never leaves its file.
#
# What a plan fixes, and what it does not:
#   - The program ids, tree ids and config accounts are fixed. Nobody else can
#     deploy at those program accounts (the header keys come from the secret)
#     or initialize those registries (the registration program takes the tree
#     id from the account that signed Initialize).
#   - The registry parameters (rate bounds, durations, price, treasury) are
#     recorded here and deploy.sh initializes with them; the ids do not
#     depend on them.
#   - The code is not part of any id. plan.json records the image ids of the
#     guest binaries present when it was made, and deploy.sh refuses others.
#   - The ids hold for a LEZ that derives addresses as the pinned one does
#     (plan.json's `lez`).
#
# The name is part of every key: give a rehearsal on another chain another
# name, and it shares no account with the real deployment.
set -euo pipefail

usage(){ echo "usage: plan.sh --secret-file <file> --name <deployment> --reference <network> --sequencer <url> --registry <label>[:<min>:<max>] [--registry ...] [--outdir <dir>]" >&2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"                    # logos-lez-rln root
LEZ="$REPO/lez-rln"
SECRET=""; NAME=""; REFERENCE=""; SEQUENCER=""; OUTROOT="$REPO/deployments"; REGISTRIES=()
while [ $# -gt 0 ]; do case "$1" in
  --secret-file) SECRET="$2"; shift 2;;
  --name) NAME="$2"; shift 2;;
  --reference) REFERENCE="$2"; shift 2;;
  --sequencer) SEQUENCER="$2"; shift 2;;
  --registry) REGISTRIES+=("$2"); shift 2;;
  --outdir) OUTROOT="$2"; shift 2;;
  -h|--help) usage; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 1;;
esac; done
[ -n "$SECRET" ] && [ -n "$NAME" ] && [ -n "$REFERENCE" ] && [ -n "$SEQUENCER" ] && [ ${#REGISTRIES[@]} -gt 0 ] || { usage; exit 1; }
[ -f "$SECRET" ] || { echo "plan: FAIL: no secret file at $SECRET (make one: (umask 077; openssl rand -hex 32 > $SECRET))" >&2; exit 1; }
# The reference becomes part of every registry id, and keystores file
# memberships under that id: the lez module's table takes this alphabet.
[[ "$REFERENCE" =~ ^[-_a-z0-9]{1,32}$ ]] || { echo "plan: FAIL: --reference must match [-_a-z0-9]{1,32}: $REFERENCE" >&2; exit 1; }
command -v jq >/dev/null || { echo "plan: FAIL: jq not found" >&2; exit 1; }

BIN_DIR="${LEZ_RLN_BIN_DIR:-$LEZ/target/release}"
PLAN_BIN="$BIN_DIR/plan_deployment"
[ -x "$PLAN_BIN" ] || { echo "plan: FAIL: missing $PLAN_BIN — build: (cd $LEZ && PYO3_PYTHON=\$(command -v python3) cargo build --release --bin plan_deployment)" >&2; exit 1; }

SECRET="$(cd "$(dirname "$SECRET")" && pwd)/$(basename "$SECRET")"
ARGS=(); for r in "${REGISTRIES[@]}"; do ARGS+=(--registry "$r"); done
export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}"
# From lez-rln/, so the guest binaries are found and their image ids recorded.
RAW=$(cd "$LEZ" && LEZ_RLN_DEPLOY_SECRET_FILE="$SECRET" LEZ_RLN_DEPLOY_NAME="$NAME" "$PLAN_BIN" "${ARGS[@]}")

SEQUENCER="${SEQUENCER%/}/"
PLAN_DIR="$OUTROOT/$NAME"; mkdir -p "$PLAN_DIR"
echo "$RAW" | jq --arg ref "$REFERENCE" --arg seq "$SEQUENCER" '. + {reference:$ref, sequencer:$seq}' > "$PLAN_DIR/plan.json"

COUNT=$(jq '.registries | length' "$PLAN_DIR/plan.json")
for ((i = 0; i < COUNT; i++)); do
  LABEL=$(jq -r --argjson i "$i" '.registries[$i].label' "$PLAN_DIR/plan.json")
  DEP_DIR="$OUTROOT/$NAME-$LABEL"; mkdir -p "$DEP_DIR"
  if [ -f "$DEP_DIR/deployment.json" ] && ! jq -e '.planned == true' "$DEP_DIR/deployment.json" >/dev/null; then
    echo "plan: FAIL: $DEP_DIR/deployment.json describes a deployed registry; not overwriting it" >&2; exit 1
  fi
  jq --argjson i "$i" '.registries[$i] as $r | {
      name: (.name + "-" + $r.label), planned: true,
      tree_id: $r.tree_id, sequencer: .sequencer,
      registration_program_id: .registration_program_id, merkle_program_id: .merkle_program_id,
      config_account: $r.config_account,
      payer_account: .payer_account, treasury_account: $r.treasury_account,
      min_rate_limit: $r.min_rate_limit, max_rate_limit: $r.max_rate_limit,
      payer_public_key: .payer_public_key, treasury_public_key: $r.treasury_public_key,
      owner_account: .owner_account, tree_label: $r.label,
      registry_id: ("logos:" + .reference + ":" + $r.config_account_hex)
    }' "$PLAN_DIR/plan.json" > "$DEP_DIR/deployment.json"
  echo "plan: $(jq -r .registry_id "$DEP_DIR/deployment.json")  ($DEP_DIR/deployment.json)"
done

echo "plan: registration program $(jq -r .registration_program_id "$PLAN_DIR/plan.json")"
echo "plan: merkle program       $(jq -r .merkle_program_id "$PLAN_DIR/plan.json")"
echo "plan: fund at genesis      public key $(jq -r .payer_public_key "$PLAN_DIR/plan.json") (account $(jq -r .payer_account "$PLAN_DIR/plan.json")), or pay from another account: deploy.sh --payer"
if jq -e '.registration_image_id == null' "$PLAN_DIR/plan.json" >/dev/null; then
  echo "plan: no guest binaries found, so the plan holds a deploy to no particular image"
fi
echo "plan: DONE — $PLAN_DIR/plan.json; deploy with: bash $HERE/deploy.sh --plan-dir $PLAN_DIR --secret-file <file>"
