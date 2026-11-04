#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Keep this in sync with the logos-execution-zone git dep pin in
# lez-rln/Cargo.toml and lez-rln/methods/guest/Cargo.toml.
LEZ_REF="v0.4.0-rc1"
LEZ_REPO="https://github.com/logos-blockchain/logos-execution-zone.git"
# The source checkout is keyed by LEZ_REF so two checkouts of this repo on
# different tags stop re-cloning over each other; it is immutable and shared.
# Per-instance state (RocksDB, the channel signing key, the patched config)
# lives in SEQ_HOME, the sequencer's home, so several sequencers can run from
# one source tree on different ports.
SEQ_SRC="${LEZ_RLN_SEQUENCER_SRC:-${XDG_CACHE_HOME:-$HOME/.cache}/logos-lez-rln/sequencer-src-$LEZ_REF}"
PORT="${LEZ_RLN_PORT:-3040}"
METRICS_ADDR="${LEZ_RLN_METRICS_ADDR:-127.0.0.1:$((PORT + 6060))}"
SEQ_HOME="${LEZ_RLN_SEQUENCER_HOME:-$SEQ_SRC/../home-$PORT}"
# The bedrock funding key `setup` records. Standalone mode mocks bedrock, so
# any well-formed key serves; this is the one LEZ's own Justfile uses.
FUNDING_PK="${LEZ_RLN_BEDROCK_FUNDING_PUBLIC_KEY:-2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26}"

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

# The shipped local-network config: the template every devnet starts from.
CONFIG="$SEQ_SRC/lez/sequencer/service/networks/local.json"
if [ ! -f "$CONFIG" ]; then
  echo "Error: $CONFIG is missing; $LEZ_REF does not ship a local network config"
  exit 1
fi

# --- Patch the shipped config ---
# Two edits, written into the sequencer's home rather than the checkout, so a
# refresh of the pinned source never has to reconcile a local change.
#
# 1. Fund a payer at genesis. Public transactions carry a fee, and no program
#    can mint native balance, so nothing a fresh wallet creates can ever hold
#    any. Provisioning therefore mints its payer first and names its PUBLIC
#    KEY here (genesis credits a key, not an account id — `mint_payer` prints
#    both), and the chain starts owing that account a balance. The stock
#    supply accounts in the shipped config belong to whoever generated them,
#    so their keys are no use to us.
#
# 2. Shorten the block interval. The shipped cadence is a testnet one; a
#    devnet's confirmation waits, and the block timestamps every
#    time-dependent message is pinned to, move with it.
mkdir -p "$SEQ_HOME"
PATCHED_CONFIG="$SEQ_HOME/sequencer_config.patched.json"
BLOCK_TIME="${LEZ_RLN_BLOCK_TIME:-1s}"
BALANCE="${LEZ_RLN_GENESIS_BALANCE:-10000000000000}"
python3 - "$CONFIG" "$PATCHED_CONFIG" "${LEZ_RLN_GENESIS_FUND:-}" "$BALANCE" "$BLOCK_TIME" <<'PY'
import json, re, sys
src, dst, public_key, balance, block_time = sys.argv[1:6]
cfg = json.load(open(src))
if public_key:
    if not re.fullmatch(r"[0-9a-f]{64}", public_key):
        sys.exit(
            "LEZ_RLN_GENESIS_FUND must be the payer's PUBLIC KEY (64 hex chars), not its "
            f"account id: got {public_key!r}. mint_payer prints the key on its second line."
        )
    actions = cfg.setdefault("genesis", {}).setdefault("actions", [])
    actions[:] = [
        entry for entry in actions
        if entry.get("supply_account", {}).get("recipient", {}).get("identified", {}).get("key")
        != public_key
    ]
    actions.append(
        {"supply_account": {"recipient": {"identified": {"key": public_key}}, "balance": int(balance)}}
    )
cfg["block_create_timeout"] = block_time
json.dump(cfg, open(dst, "w"), indent=2)
PY
echo "Block interval $BLOCK_TIME"
if [ -n "${LEZ_RLN_GENESIS_FUND:-}" ]; then
  echo "Genesis funds the account of public key $LEZ_RLN_GENESIS_FUND with $BALANCE"
fi

# --- Check port is free ---
if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  # Listeners only: lsof also lists clients connected to the port. One pid
  # per line; a hung sequencer ignores TERM.
  OLD_PID=$(lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null || true)
  if [ -n "$OLD_PID" ]; then
    echo "Port $PORT in use by PID $OLD_PID. Killing..."
    kill $OLD_PID 2>/dev/null || true
    sleep 1
    kill -9 $(lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null) 2>/dev/null || true
  fi
fi

# --- Clean stale state ---
# The database is named after the bedrock channel the sequencer serves, so it
# is `rocksdb-<channel_id>` rather than a bare `rocksdb`. `setup` also refuses
# a home that already holds a sequencer_config.json, so the whole home is
# reset: every start is a fresh chain from the patched genesis.
rm -rf "$SEQ_HOME"/rocksdb "$SEQ_HOME"/rocksdb-* \
  "$SEQ_HOME"/sequencer_config.json "$SEQ_HOME"/channel_signing_key \
  "$SEQ_HOME"/bedrock_funding_public_key "$SEQ_HOME"/sequencer_stake_signing_key

# --- Set up, then start ---
# `setup` writes the home (config, channel signing key, funding key) and, with
# --create-channel, keeps the config's genesis; `start` then runs it. The
# config is NOT passed to `start`: with an explicit config and no
# --create-channel the genesis — and the payer's balance with it — is dropped.
echo ""
echo "Setting up the sequencer home $SEQ_HOME..."
cd "$SEQ_SRC"
cargo run --features standalone -p sequencer_service -- setup "$SEQ_HOME" \
  --config "$PATCHED_CONFIG" --funding-public-key "$FUNDING_PK" --create-channel

echo ""
echo "Starting standalone sequencer on port $PORT (home $SEQ_HOME, metrics $METRICS_ADDR)..."
echo "In another terminal: source dev/env.sh && cargo run --bin run_rln_proof"
echo ""

# LEZ_RLN_SEQUENCER_ARGS: extra sequencer flags appended after the standard ones.
# shellcheck disable=SC2086
exec env RUST_LOG=info cargo run --features standalone -p sequencer_service -- start "$SEQ_HOME" \
  --rpc-listen-address "127.0.0.1:$PORT" --metrics-listen-address "$METRICS_ADDR" ${LEZ_RLN_SEQUENCER_ARGS:-}
