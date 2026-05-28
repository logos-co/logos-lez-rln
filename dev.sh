#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Prerequisites ---
if ! command -v cargo &>/dev/null; then
  echo "Error: cargo not found. Install Rust: https://rustup.rs"
  exit 1
fi

# --- Ensure lssa is present ---
# Best-effort: if lssa is a registered submodule (.gitmodules), init it; otherwise
# expect it to already exist as a sibling working directory at lssa/.
if [ -f .gitmodules ] && grep -q "submodule \"lssa\"" .gitmodules 2>/dev/null; then
  echo "Initializing lssa submodule..."
  git submodule update --init lssa
elif [ ! -d lssa ]; then
  echo "Error: lssa/ not found. Either register it as a submodule or clone it as a sibling working dir."
  exit 1
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
rm -rf lssa/rocksdb

# --- Start sequencer ---
echo ""
echo "Starting standalone sequencer on port 3040..."
echo "In another terminal: source dev/env.sh && cargo run --bin run_rln_proof"
echo ""

cd lssa
exec env RUST_LOG=info cargo run --features standalone -p sequencer_service -- sequencer/service/configs/debug/sequencer_config.json
