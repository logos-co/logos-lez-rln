#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Keep this in sync with the logos-execution-zone git dep pin in
# lez-rln/Cargo.toml and lez-rln/methods/guest/Cargo.toml.
LEZ_REF="v0.2.5-rc2"
LEZ_REPO="https://github.com/logos-blockchain/logos-execution-zone.git"
SEQ_SRC="${LEZ_RLN_SEQUENCER_SRC:-${XDG_CACHE_HOME:-$HOME/.cache}/logos-lez-rln/sequencer-src}"

# --- Prerequisites ---
if ! command -v cargo &>/dev/null; then
  echo "Error: cargo not found. Install Rust: https://rustup.rs"
  exit 1
fi

# --- Provision the pinned sequencer source (clone-and-go, no manual placement) ---
if [ -d "$SEQ_SRC/.git" ] && ! git -C "$SEQ_SRC" describe --tags --exact-match 2>/dev/null | grep -qx "$LEZ_REF"; then
  echo "Cached sequencer at $SEQ_SRC is not $LEZ_REF — refreshing..."
  rm -rf "$SEQ_SRC"
fi
if [ ! -d "$SEQ_SRC/.git" ]; then
  echo "Fetching sequencer source ($LEZ_REF) into $SEQ_SRC ..."
  rm -rf "$SEQ_SRC"
  mkdir -p "$(dirname "$SEQ_SRC")"
  git clone --depth 1 --branch "$LEZ_REF" "$LEZ_REPO" "$SEQ_SRC"
fi

# Locate the debug sequencer config within the tree (layout-agnostic: rc6 nests
# it under lez/, older tags keep it top-level).
CONFIG="$(cd "$SEQ_SRC" && find . -path '*sequencer/service/configs/debug/sequencer_config.json' | head -1)"
if [ -z "$CONFIG" ]; then
  echo "Error: could not find a debug sequencer_config.json under $SEQ_SRC"
  exit 1
fi

# --- Fund a payer at genesis ---
# Public transactions now carry a fee, and the faucet program only runs in the
# genesis block, so nothing a fresh wallet creates can ever hold native balance.
# Provisioning therefore mints its payer first and names it here, and the chain
# starts owing that account a balance. The stock supply accounts in the shipped
# config belong to whoever generated them, so their keys are no use to us.
#
# The edited config is written beside the checkout rather than into it, so a
# refresh of the pinned source never has to reconcile a local change.
if [ -n "${LEZ_RLN_GENESIS_FUND:-}" ]; then
  FUNDED_CONFIG="$SEQ_SRC/../sequencer_config.funded.json"
  BALANCE="${LEZ_RLN_GENESIS_BALANCE:-10000000000000}"
  python3 - "$SEQ_SRC/$CONFIG" "$FUNDED_CONFIG" "$LEZ_RLN_GENESIS_FUND" "$BALANCE" <<'PY'
import json, sys
src, dst, account_id, balance = sys.argv[1:5]
cfg = json.load(open(src))
cfg["genesis"] = [
    entry for entry in cfg["genesis"]
    if entry.get("supply_account", {}).get("account_id") != account_id
]
cfg["genesis"].append(
    {"supply_account": {"account_id": account_id, "balance": int(balance)}}
)
json.dump(cfg, open(dst, "w"), indent=2)
PY
  CONFIG="$FUNDED_CONFIG"
  echo "Genesis funds $LEZ_RLN_GENESIS_FUND with $BALANCE"
fi

# --- Check port is free ---
if nc -z 127.0.0.1 3040 2>/dev/null; then
  OLD_PID=$(lsof -ti tcp:3040 2>/dev/null || true)
  if [ -n "$OLD_PID" ]; then
    echo "Port 3040 in use by PID $OLD_PID. Killing..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
fi

# --- Clean stale state ---
# The state directory is named after the bedrock channel the sequencer serves,
# so it is `rocksdb-<channel_id>` rather than a bare `rocksdb`. Wiping the wrong
# path is silent: the chain simply keeps the genesis it already had, and a
# config change appears to have no effect.
rm -rf "$SEQ_SRC"/rocksdb "$SEQ_SRC"/rocksdb-*

# --- Start sequencer ---
echo ""
echo "Starting standalone sequencer on port 3040..."
echo "In another terminal: source dev/env.sh && cargo run --bin run_rln_proof"
echo ""

cd "$SEQ_SRC"
exec env RUST_LOG=info cargo run --features standalone -p sequencer_service -- "$CONFIG"
