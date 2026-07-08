#!/usr/bin/env bash
# Provision an RLN deployment on a sequencer and capture it as a deployment profile.
# FEATURE: deployment-profile tooling — the fresh/adopt entry point.
#
#   bash provision.sh --name <name> [--tree <64hex>] [--adopt-wallet <storage.json>]
#                     [--sequencer <url>] [--outdir <dir>]
#                     [--funding faucet|wallet-key] [--claim-cap <u128>]
#                     [--registrar <64hex>] [--quota <u64>]
#
# tree_id is the single knob: --tree targets/redeploys a specific tree, omit for a
# fresh random one. --adopt-wallet reuses an existing wallet (its seed, hence account
# ids) so multiple sims share accounts. --outdir writes deployments/<name>/ somewhere
# other than this repo's deployments/ (e.g. a consumer's build context). Writes
# {deployment.json, storage.json} and runs verify.sh.
#
# Deployment policy (immutable after init — a policy change = a new tree):
#   --funding faucet (default): the payment token is a program-owned PDA;
#     anyone claims up to --claim-cap per ClaimTokens call — no human mint key.
#   --funding wallet-key: legacy fixed pre-minted supply; the definition key
#     lives in the wallet.
#   --registrar/--quota: authorize one account for N free (unpaid) memberships
#     via RegisterFree, alongside the normal paid path.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"                    # logos-lez-rln root
NAME=""; TREE=""; ADOPT=""; SEQUENCER="https://testnet.lez.logos.co/"; OUTROOT="$REPO/deployments"
FUNDING="faucet"; CLAIM_CAP=""; REGISTRAR=""; QUOTA="0"
while [ $# -gt 0 ]; do case "$1" in
  --name) NAME="$2"; shift 2;;
  --tree) TREE="$2"; shift 2;;
  --adopt-wallet) ADOPT="$2"; shift 2;;
  --sequencer) SEQUENCER="$2"; shift 2;;
  --outdir) OUTROOT="$2"; shift 2;;
  --funding) FUNDING="$2"; shift 2;;
  --claim-cap) CLAIM_CAP="$2"; shift 2;;
  --registrar) REGISTRAR="$2"; shift 2;;
  --quota) QUOTA="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 1;;
esac; done
case "$FUNDING" in faucet|wallet-key) ;; *) echo "--funding must be faucet|wallet-key" >&2; exit 1;; esac
[ -z "$REGISTRAR" ] || [[ "$REGISTRAR" =~ ^[0-9a-f]{64}$ ]] || { echo "--registrar must be 64 hex chars" >&2; exit 1; }
[[ "$QUOTA" =~ ^[0-9]+$ ]] || { echo "--quota must be a non-negative integer, got '$QUOTA'" >&2; exit 1; }
[ -z "$CLAIM_CAP" ] || [[ "$CLAIM_CAP" =~ ^[0-9]+$ ]] || { echo "--claim-cap must be a non-negative integer, got '$CLAIM_CAP'" >&2; exit 1; }
[ -n "$NAME" ] || { echo "usage: provision.sh --name <name> [--tree H] [--adopt-wallet P] [--sequencer U] [--outdir D] [--funding faucet|wallet-key] [--claim-cap N] [--registrar H] [--quota N]" >&2; exit 1; }
[ -n "$TREE" ] || TREE=$(python3 -c "import secrets;print(secrets.token_hex(32))")
[[ "$TREE" =~ ^[0-9a-f]{64}$ ]] || { echo "--tree must be 64 hex chars" >&2; exit 1; }

LEZ="$REPO/lez-rln"
RUN_SETUP="$LEZ/target/release/run_setup"
DERIVE="$LEZ/target/release/derive_accounts"
for b in "$RUN_SETUP" "$DERIVE"; do [ -x "$b" ] || { echo "missing $b — build: (cd $LEZ && PYO3_PYTHON=\$(command -v python3) cargo build --release --bin run_setup --bin derive_accounts)" >&2; exit 1; }; done

WS=$(mktemp -d); trap 'rm -rf "$WS"' EXIT
if [ -n "$ADOPT" ]; then
  [ -f "$ADOPT" ] || { echo "adopt wallet not found: $ADOPT" >&2; exit 1; }
  cp "$ADOPT" "$WS/storage.json"; echo "provision: adopting wallet $ADOPT"
fi
jq -n --arg s "$SEQUENCER" '{sequencer_addr:$s, seq_poll_timeout:"30s", seq_tx_poll_max_blocks:15, seq_poll_max_retries:10, seq_block_poll_max_amount:100}' > "$WS/wallet_config.json"

echo "provision: tree=$TREE sequencer=$SEQUENCER funding=$FUNDING (deploying via run_setup — several min)"
export HOME="$WS" LEE_WALLET_HOME_DIR="$WS" NSSA_WALLET_HOME_DIR="$WS"
export LEZ_RLN_TREE_ID_HEX="$TREE" RISC0_DEV_MODE=1
export LEZ_RLN_FUNDING="$FUNDING" LEZ_RLN_FREE_QUOTA="$QUOTA"
[ -z "$CLAIM_CAP" ] || export LEZ_RLN_FAUCET_CLAIM_CAP="$CLAIM_CAP"
[ -z "$REGISTRAR" ] || export LEZ_RLN_REGISTRAR="$REGISTRAR"
export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}"
LOG="$WS/run_setup.log"
( cd "$LEZ" && "$RUN_SETUP" ) | tee "$LOG"
CFG=$(grep -E "^Config account:" "$LOG" | awk '{print $NF}')
PAY=$(tr -d '\n\r' < "$WS/.logos-lez-rln/payment_account_${TREE}.txt")
SUP=$(tr -d '\n\r' < "$WS/.logos-lez-rln/supply_holding_${TREE}.txt")

DERIVED=$(cd "$LEZ" && "$DERIVE")
dget(){ echo "$DERIVED" | jq -r ".$1"; }
[ "$(dget config_account)" = "$CFG" ] || { echo "provision: FAIL: derived config != run_setup config" >&2; exit 1; }

DEP_DIR="$OUTROOT/$NAME"; mkdir -p "$DEP_DIR"
cp "$WS/storage.json" "$DEP_DIR/storage.json"
jq -n \
  --arg name "$NAME" --arg tree "$TREE" --arg seq "$SEQUENCER" \
  --arg reg "$(dget registration_program_id)" --arg mrk "$(dget merkle_program_id)" \
  --arg cfg "$CFG" --arg pay "$PAY" --arg sup "$SUP" \
  --arg fund "$FUNDING" --arg registrar "$REGISTRAR" --argjson quota "$QUOTA" \
  '{name:$name, tree_id:$tree, sequencer:$seq, registration_program_id:$reg, merkle_program_id:$mrk, config_account:$cfg, payment_account:$pay, supply_holding:$sup, funding:$fund}
   + (if $registrar != "" then {membership:{mode:"free-quota", registrar:$registrar, quota:$quota}} else {} end)' \
  > "$DEP_DIR/deployment.json"

echo "provision: wrote $DEP_DIR/{deployment.json,storage.json}"
bash "$HERE/verify.sh" "$DEP_DIR"
echo "provision: DONE — deployment '$NAME' ready."
