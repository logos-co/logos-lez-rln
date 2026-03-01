#!/usr/bin/env bash
# End-to-end test: register memberships → fetch merkle proofs via RLN module → verify.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export RISC0_DEV_MODE=1

SEQUENCER_PID=""
INDICES_FILE=""
cleanup() {
    [ -n "$INDICES_FILE" ] && rm -f "$INDICES_FILE"
    if [ -n "$SEQUENCER_PID" ]; then
        echo "Cleaning up sequencer (PID $SEQUENCER_PID)..."
        kill "$SEQUENCER_PID" 2>/dev/null || true
        wait "$SEQUENCER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== E2E Test: Merkle Proofs via RLN Module ==="

# ---- Step 1: Start sequencer ----
echo "[1/6] Starting sequencer..."

git submodule update --init lssa

if nc -z 127.0.0.1 3040 2>/dev/null; then
    OLD_PID=$(lsof -ti tcp:3040 2>/dev/null || true)
    if [ -n "$OLD_PID" ]; then
        echo "  Port 3040 in use by PID $OLD_PID. Killing..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
fi

rm -rf lssa/rocksdb

(cd lssa && env RUST_LOG=info cargo run --features standalone -p sequencer_runner -- sequencer_runner/configs/debug) >/dev/null 2>&1 &
SEQUENCER_PID=$!

echo "  Waiting for sequencer on port 3040..."
for i in $(seq 1 120); do
    if nc -z 127.0.0.1 3040 2>/dev/null; then
        echo "  Sequencer ready."
        break
    fi
    if ! kill -0 "$SEQUENCER_PID" 2>/dev/null; then
        echo "  ERROR: Sequencer process exited unexpectedly."
        exit 1
    fi
    sleep 1
done
if ! nc -z 127.0.0.1 3040 2>/dev/null; then
    echo "  ERROR: Sequencer did not start within 120s."
    exit 1
fi

# ---- Set environment ----
export NSSA_WALLET_HOME_DIR="$SCRIPT_DIR/dev"
export WALLET_CONFIG="$NSSA_WALLET_HOME_DIR/wallet_config.json"
export WALLET_STORAGE="$NSSA_WALLET_HOME_DIR/storage.json"

# ---- Step 2: Run setup ----
echo "[2/6] Running setup..."
cargo run --bin run_setup 2>&1 | tail -5
echo "  Setup complete."

# ---- Step 3: Build RLN module ----
if [ "${SKIP_BUILD:-0}" = "1" ] && [ -e logos-rln-module/result ]; then
    echo "[3/6] Skipping build (SKIP_BUILD=1, result exists)"
else
    echo "[3/6] Building RLN module..."
    (cd logos-rln-module && nix build --override-input logos-lez-rln path:../)
    echo "  RLN module built."
fi

# Helper: call a logoscore method and extract the result line.
# logoscore is a Qt app that never exits, so we run it in background,
# watch the output for the final result, then kill it.
run_module_call() {
    local call_expr="$1"
    local tmpfile
    tmpfile=$(mktemp)

    # Run logoscore in background; it won't exit on its own.
    logos-rln-module/run.sh -c "$call_expr" </dev/null >"$tmpfile" 2>&1 &
    local pid=$!

    # Wait for the get_merkle_proofs result to appear (second "Method call" line).
    # The first "Method call successful" is from wallet.open().
    local count=0
    local max_wait=60
    local found=0
    while [ $count -lt $max_wait ]; do
        # Count how many "Method call successful" lines exist so far.
        # We need 2: one for wallet.open(), one for get_merkle_proofs().
        local n=0
        if [ -f "$tmpfile" ]; then
            n=$({ grep '^Method call successful' "$tmpfile" || true; } | wc -l | tr -d ' ')
        fi
        if [ "$n" -ge 2 ]; then
            found=1
            break
        fi
        sleep 0.5
        count=$((count + 1))
    done

    # Kill logoscore regardless
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    if [ "$found" -eq 0 ]; then
        echo "ERROR: Timed out waiting for logoscore result:" >&2
        grep -v '^Debug:' "$tmpfile" >&2
        rm -f "$tmpfile"
        return 1
    fi

    # Extract the last result (the get_merkle_proofs one)
    local result
    result=$({ grep '^Method call successful\. Result:' "$tmpfile" || true; } | tail -1 | sed 's/^Method call successful\. Result: *//')

    if [ -z "$result" ]; then
        echo "ERROR: get_merkle_proofs returned empty result. Logoscore warnings:" >&2
        { grep -i 'Warning:\|failed\|error' "$tmpfile" || true; } | head -20 >&2
        rm -f "$tmpfile"
        return 1
    fi

    rm -f "$tmpfile"
    echo "$result"
}

# ---- Step 4: Register member 1 ----
echo "[4/6] Registering member 1..."
REG1_OUTPUT=$(cargo run --bin register_member 2>&1)
CONFIG_ACCOUNT=$(echo "$REG1_OUTPUT" | grep '^CONFIG_ACCOUNT=' | cut -d= -f2)
LEAF_INDEX_1=$(echo "$REG1_OUTPUT" | grep '^LEAF_INDEX=' | cut -d= -f2)

if [ -z "$CONFIG_ACCOUNT" ] || [ -z "$LEAF_INDEX_1" ]; then
    echo "  ERROR: Failed to parse register_member output:"
    echo "$REG1_OUTPUT"
    exit 1
fi
echo "  Config account: $CONFIG_ACCOUNT"
echo "  Leaf index: $LEAF_INDEX_1"

# ---- Step 5: Get merkle proof (1 member) ----
echo "[5/6] Getting merkle proof (1 member)..."

# Verify sequencer is still alive
if ! kill -0 "$SEQUENCER_PID" 2>/dev/null; then
    echo "  ERROR: Sequencer died before proof query"
    exit 1
fi

INDICES_FILE=$(mktemp)
echo "[$LEAF_INDEX_1]" > "$INDICES_FILE"
PROOF1_JSON=$(run_module_call "liblogos_rln_module.get_merkle_proofs($CONFIG_ACCOUNT, @$INDICES_FILE)")
rm -f "$INDICES_FILE"

ROOT1=$(python3 -c "
import json, sys
proofs = json.loads(sys.argv[1])
if not isinstance(proofs, list) or len(proofs) == 0:
    print('ERROR: no proofs returned', file=sys.stderr)
    sys.exit(1)
print(proofs[0]['root'])
" "$PROOF1_JSON")
echo "  Root: $ROOT1"

# ---- Step 6: Register member 2 ----
echo "[6/6] Registering member 2..."
REG2_OUTPUT=$(cargo run --bin register_member 2>&1)
LEAF_INDEX_2=$(echo "$REG2_OUTPUT" | grep '^LEAF_INDEX=' | cut -d= -f2)

if [ -z "$LEAF_INDEX_2" ]; then
    echo "  ERROR: Failed to parse register_member output:"
    echo "$REG2_OUTPUT"
    exit 1
fi
echo "  Leaf index: $LEAF_INDEX_2"

# ---- Get merkle proofs (2 members) ----
echo "  Getting merkle proofs (2 members)..."
INDICES_FILE=$(mktemp)
echo "[$LEAF_INDEX_1,$LEAF_INDEX_2]" > "$INDICES_FILE"
PROOF2_JSON=$(run_module_call "liblogos_rln_module.get_merkle_proofs($CONFIG_ACCOUNT, @$INDICES_FILE)")
rm -f "$INDICES_FILE"

# ---- Verify results ----
python3 -c "
import json, sys

proofs = json.loads(sys.argv[1])
root1 = sys.argv[2]

# Check proof count
if len(proofs) != 2:
    print(f'  FAIL: expected 2 proofs, got {len(proofs)}')
    sys.exit(1)
print(f'  Proof count: {len(proofs)} ✓')

# Check root changed
root2 = proofs[0]['root']
if root2 == root1:
    print(f'  FAIL: root did not change after 2nd registration')
    print(f'    root1: {root1}')
    print(f'    root2: {root2}')
    sys.exit(1)
print(f'  Root changed: YES ✓')
print(f'    Before: {root1}')
print(f'    After:  {root2}')

# Check path_elements length (should be tree depth = 20)
for i, p in enumerate(proofs):
    n = len(p['path_elements'])
    if n != 20:
        print(f'  FAIL: proof[{i}] path_elements has {n} entries, expected 20')
        sys.exit(1)
print(f'  Path elements: 20 each ✓')

# Check leaves are non-zero
zero = '0' * 64
for i, p in enumerate(proofs):
    if p['leaf'] == zero:
        print(f'  FAIL: proof[{i}] leaf is zero')
        sys.exit(1)
print(f'  Leaves non-zero: YES ✓')
" "$PROOF2_JSON" "$ROOT1"

echo "=== PASS ==="
