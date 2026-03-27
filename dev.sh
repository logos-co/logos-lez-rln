#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Prerequisites ---
if ! command -v cargo &>/dev/null; then
  echo "Error: cargo not found. Install Rust: https://rustup.rs"
  exit 1
fi

# --- Init submodule ---
echo "Initializing lssa submodule..."
git submodule update --init lssa

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
exec env RUST_LOG=info cargo run --features standalone -p sequencer_runner -- sequencer_runner/configs/debug
