#!/usr/bin/env bash
# Provision an RLN deployment on a sequencer and capture it as a deployment profile.
# FEATURE: deployment-profile tooling — the fresh/adopt entry point.
#
#   bash provision.sh --name <name> --payer <account-id> [--tree <64hex>]
#                     [--adopt-wallet <storage.json>] [--sequencer <url>]
#                     [--outdir <dir>]
#
# tree_id is the single knob: --tree targets/redeploys a specific tree, omit for a
# fresh random one. --adopt-wallet reuses an existing wallet (its seed, hence account
# ids) so multiple sims share accounts. --outdir writes deployments/<name>/ somewhere
# other than this repo's deployments/ (e.g. a consumer's build context). Writes
# {deployment.json, storage.json} and runs verify.sh.
#
# There is no funding policy left to choose. A membership is paid for in the
# NATIVE asset by the account that signs the Register transaction, which is
# also its fee payer — one account, one balance. No program can mint native, so
# there is no faucet to enable and no pre-minted supply to deploy.
#
# --payer is therefore REQUIRED and names that account. It pays every deploy
# and init fee here, and it is the account recorded as payer_account for runs
# against this deployment. It must already hold native balance: on a local
# chain that means genesis (mint_payer prints an id, dev.sh's
# LEZ_RLN_GENESIS_FUND funds it), otherwise the bridge or a transfer.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"                    # logos-lez-rln root
NAME=""; TREE=""; ADOPT=""; SEQUENCER="https://testnet.lez.logos.co/"; OUTROOT="$REPO/deployments"
PAYER=""
while [ $# -gt 0 ]; do case "$1" in
  --name) NAME="$2"; shift 2;;
  --tree) TREE="$2"; shift 2;;
  --adopt-wallet) ADOPT="$2"; shift 2;;
  --sequencer) SEQUENCER="$2"; shift 2;;
  --outdir) OUTROOT="$2"; shift 2;;
  --payer) PAYER="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 1;;
esac; done
[ -n "$NAME" ] || { echo "usage: provision.sh --name <name> --payer <account-id> [--tree H] [--adopt-wallet P] [--sequencer U] [--outdir D]" >&2; exit 1; }
# Not a warning any more: every deploy, init and registration transaction is
# charged, and a deployment whose payer is unknown cannot be registered against.
[ -n "$PAYER" ] || { echo "provision.sh: --payer is required — it pays the deploy fees and is recorded as the deployment's payer_account" >&2; exit 1; }
[ -n "$TREE" ] || TREE=$(python3 -c "import secrets;print(secrets.token_hex(32))")
[[ "$TREE" =~ ^[0-9a-f]{64}$ ]] || { echo "--tree must be 64 hex chars" >&2; exit 1; }

LEZ="$REPO/lez-rln"
RUN_SETUP="$LEZ/target/release/run_setup"
DERIVE="$LEZ/target/release/derive_accounts"
MINT_PAYER="$LEZ/target/release/mint_payer"
for b in "$RUN_SETUP" "$DERIVE" "$MINT_PAYER"; do [ -x "$b" ] || { echo "missing $b — build: (cd $LEZ && PYO3_PYTHON=\$(command -v python3) cargo build --release --bin run_setup --bin derive_accounts --bin mint_payer)" >&2; exit 1; }; done

WS=$(mktemp -d); trap 'rm -rf "$WS"' EXIT
if [ -n "$ADOPT" ]; then
  [ -f "$ADOPT" ] || { echo "adopt wallet not found: $ADOPT" >&2; exit 1; }
  cp "$ADOPT" "$WS/storage.json"; echo "provision: adopting wallet $ADOPT"
fi
# Dual-shape sequencer field — see stage.sh: `sequencers` for lez >= v0.2.1,
# flat `sequencer_addr` for the rc6-era wallet module. calibration_limit: see
# stage.sh — v0.2.2 open probes calibration_limit times (default 100).
# gas_limit: the wallet's own default is 2,000,000, and a registration costs
# about 9.1M — an on-chain merkle insert is one Poseidon compression, roughly
# 902,000 cycles, per level of tree depth, and gas is cycles. A wallet that
# declares too little has its transaction refused for running out of gas, with
# nothing in the reply naming the limit it hit. MAX_GAS_EXEC (10M) is the
# ceiling the protocol enforces; declaring more is refused outright.
jq -n --arg s "$SEQUENCER" '{sequencer_addr:$s, sequencers:[{sequencer_addr:$s}], seq_poll_timeout:"30s", seq_tx_poll_max_blocks:15, seq_poll_max_retries:10, seq_block_poll_max_amount:100, gas_limit:10000000, multi_sequencer_client_config:{distribution_limit:1, calibration_limit:3}}' > "$WS/wallet_config.json"

echo "provision: tree=$TREE sequencer=$SEQUENCER payer=$PAYER (deploying via run_setup — several min)"
export HOME="$WS" LEE_WALLET_HOME_DIR="$WS" NSSA_WALLET_HOME_DIR="$WS"
export LEZ_RLN_TREE_ID_HEX="$TREE" RISC0_DEV_MODE=1
export LEZ_RLN_PAYER="$PAYER"
export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}"
LOG="$WS/run_setup.log"
( cd "$LEZ" && "$RUN_SETUP" ) | tee "$LOG"
CFG=$(grep -E "^Config account:" "$LOG" | awk '{print $NF}')
PAY=$(tr -d '\n\r' < "$WS/.logos-lez-rln/payment_account_${TREE}.txt")
# The treasury is created during setup and is not derivable — it is a plain
# wallet account, not a PDA — so the descriptor is the only record of where a
# registry's revenue accrues.
TREASURY=$(grep -E "^  Treasury:" "$LOG" | awk '{print $NF}')
[ -n "$TREASURY" ] || { echo "provision: FAIL: run_setup printed no treasury account" >&2; exit 1; }

DERIVED=$(cd "$LEZ" && "$DERIVE")
dget(){ echo "$DERIVED" | jq -r ".$1"; }
[ "$(dget config_account)" = "$CFG" ] || { echo "provision: FAIL: derived config != run_setup config" >&2; exit 1; }

DEP_DIR="$OUTROOT/$NAME"; mkdir -p "$DEP_DIR"
cp "$WS/storage.json" "$DEP_DIR/storage.json"
jq -n \
  --arg name "$NAME" --arg tree "$TREE" --arg seq "$SEQUENCER" \
  --arg reg "$(dget registration_program_id)" --arg mrk "$(dget merkle_program_id)" \
  --arg cfg "$CFG" --arg pay "$PAY" --arg treasury "$TREASURY" \
  '{name:$name, tree_id:$tree, sequencer:$seq, registration_program_id:$reg, merkle_program_id:$mrk, config_account:$cfg, payer_account:$pay, treasury_account:$treasury}' \
  > "$DEP_DIR/deployment.json"

echo "provision: wrote $DEP_DIR/{deployment.json,storage.json}"
bash "$HERE/verify.sh" "$DEP_DIR"
echo "provision: DONE — deployment '$NAME' ready."
