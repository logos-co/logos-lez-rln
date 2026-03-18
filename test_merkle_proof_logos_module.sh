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

echo "=== E2E Test: Merkle Proofs & Delivery Event Subscription ==="

# Kill orphaned logos_host processes from previous runs
pkill -f 'logos_host --name' 2>/dev/null || true

# ---- Step 1: Start sequencer ----
echo "[1/12] Starting sequencer..."

git submodule update --init lssa
git submodule update --init --recursive logos-delivery

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
echo "[2/12] Running setup..."
cargo run --bin run_setup 2>&1 | tail -5
echo "  Setup complete."

# ---- Step 3: Build RLN module ----
if [ "${SKIP_BUILD:-0}" = "1" ] && [ -e logos-rln-module/result ]; then
    echo "[3/12] Skipping RLN build (SKIP_BUILD=1, result exists)"
else
    echo "[3/12] Building RLN module..."
    (cd logos-rln-module && nix build --override-input logos-lez-rln path:../)
    echo "  RLN module built."
fi

# ---- Step 3b: Build delivery module ----
if [ "${SKIP_BUILD:-0}" = "1" ] && [ -e logos-delivery-module/result ]; then
    echo "  Skipping delivery build (SKIP_BUILD=1, result exists)"
else
    echo "  Building delivery module..."
    (cd logos-delivery-module && nix build --override-input logos-delivery path:../logos-delivery)
    echo "  Delivery module built."
fi

# --- Platform ---
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM="darwin-arm64"; EXT="dylib";;
  Linux-x86_64) PLATFORM="linux-x86_64"; EXT="so";;
  Linux-aarch64) PLATFORM="linux-aarch64"; EXT="so";;
  *) echo "Unsupported platform"; exit 1;;
esac

LOGOSCORE_PATH="$(nix build github:logos-co/logos-liblogos --no-link --print-out-paths)"
LOGOSCORE="$LOGOSCORE_PATH/bin/logoscore"

WALLET_MODULE_RESULT="${WALLET_MODULE_RESULT:-logos-rln-module/result-wallet}"
WALLET_MODULE="$WALLET_MODULE_RESULT/lib/liblogos_execution_zone_wallet_module.$EXT"

[ -f "$WALLET_MODULE" ] || { echo "Wallet module not found at $WALLET_MODULE"; exit 1; }

# stage_modules [--with-delivery]
# Creates a temp directory with wallet, RLN, and optionally delivery modules for logoscore.
# Capability module is bundled with logoscore and should NOT be staged separately.
stage_modules() {
    local with_delivery=0
    [ "${1:-}" = "--with-delivery" ] && with_delivery=1

    local mdir
    mdir=$(mktemp -d)

    local RLN_MODULE="logos-rln-module/result-rln/lib/liblogos_rln_module.$EXT"

    # NOTE: capability_module is NOT staged — logoscore bundles it from the nix store.

    # Wallet module
    local wallet_dir="$mdir/liblogos_execution_zone_wallet_module"
    mkdir -p "$wallet_dir"
    cp -L "$WALLET_MODULE" "$wallet_dir/"
    [ -f "$WALLET_MODULE_RESULT/lib/libwallet_ffi.$EXT" ] && \
      cp -L "$WALLET_MODULE_RESULT/lib/libwallet_ffi.$EXT" "$wallet_dir/"
    cat > "$wallet_dir/manifest.json" <<MEOF
{"name":"liblogos_execution_zone_wallet_module","version":"1.0.0","type":"core","main":{"$PLATFORM":"liblogos_execution_zone_wallet_module.$EXT"},"dependencies":[],"capabilities":[]}
MEOF

    # RLN module
    local rln_dir="$mdir/liblogos_rln_module"
    mkdir -p "$rln_dir"
    cp -L "$RLN_MODULE" "$rln_dir/"
    local rln_lib_dir
    rln_lib_dir="$(dirname "$RLN_MODULE")"
    [ -f "$rln_lib_dir/liblez_rln_ffi.$EXT" ] && \
      cp -L "$rln_lib_dir/liblez_rln_ffi.$EXT" "$rln_dir/"
    cat > "$rln_dir/manifest.json" <<MEOF
{"name":"liblogos_rln_module","version":"1.0.0","type":"core","main":{"$PLATFORM":"liblogos_rln_module.$EXT"},"dependencies":["liblogos_execution_zone_wallet_module"],"capabilities":[]}
MEOF

    local load_order="liblogos_execution_zone_wallet_module,liblogos_rln_module"

    # Delivery module (optional)
    if [ "$with_delivery" -eq 1 ]; then
        local del_dir="$mdir/delivery_module"
        mkdir -p "$del_dir"
        local del_result="logos-delivery-module/result/lib"
        cp -L "$del_result/delivery_module_plugin.$EXT" "$del_dir/"
        [ -f "$del_result/liblogosdelivery.$EXT" ] && cp -L "$del_result/liblogosdelivery.$EXT" "$del_dir/"
        for pq in "$del_result"/libpq*; do
            [ -f "$pq" ] && cp -L "$pq" "$del_dir/"
        done
        cat > "$del_dir/manifest.json" <<MEOF
{"name":"delivery_module","version":"1.0.0","type":"core","main":{"$PLATFORM":"delivery_module_plugin.$EXT"},"dependencies":["liblogos_rln_module"],"capabilities":[]}
MEOF
        load_order="$load_order,delivery_module"
    fi

    echo "$mdir"
    echo "$load_order"
}

# run_logoscore expected_count [--with-delivery] -c "call1" [-c "call2" ...]
# Runs logoscore with staged modules, waits for expected_count "Method call successful" lines,
# then kills the process. Prints the result of the LAST successful method call.
run_logoscore() {
    local expected_count="$1"; shift
    local with_delivery=""
    if [ "${1:-}" = "--with-delivery" ]; then
        with_delivery="--with-delivery"; shift
    fi

    local stage_output
    stage_output=$(stage_modules $with_delivery)
    local modules_dir
    modules_dir=$(echo "$stage_output" | head -1)
    local load_order
    load_order=$(echo "$stage_output" | tail -1)

    local tmpfile
    tmpfile=$(mktemp)

    local wallet_call="liblogos_execution_zone_wallet_module.open($WALLET_CONFIG,$WALLET_STORAGE)"

    # Use /tmp for Qt Remote Objects sockets to avoid macOS 104-char path limit
    TMPDIR=/tmp "$LOGOSCORE" -m "$modules_dir" -l "$load_order" -c "$wallet_call" "$@" </dev/null >"$tmpfile" 2>&1 &
    local pid=$!

    local count=0
    local max_wait=60
    local found=0
    while [ $count -lt $max_wait ]; do
        local n=0
        if [ -f "$tmpfile" ]; then
            n=$({ grep '^Method call successful' "$tmpfile" || true; } | wc -l | tr -d ' ')
        fi
        if [ "$n" -ge "$expected_count" ]; then
            found=1
            break
        fi
        sleep 0.5
        count=$((count + 1))
    done

    # Kill logoscore and its child processes (logos_host workers)
    local children
    children=$(pgrep -P "$pid" 2>/dev/null || true)
    kill "$pid" $children 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -rf "$modules_dir"

    if [ "$found" -eq 0 ]; then
        echo "ERROR: Timed out waiting for logoscore (expected $expected_count results):" >&2
        grep -v '^Debug:' "$tmpfile" >&2
        rm -f "$tmpfile"
        return 1
    fi

    local result
    result=$({ grep '^Method call successful\. Result:' "$tmpfile" || true; } | tail -1 | sed 's/^Method call successful\. Result: *//')

    rm -f "$tmpfile"
    echo "$result"
}

# Convenience: run a single RLN module call (wallet.open + 1 call = 2 expected).
run_module_call() {
    run_logoscore 2 -c "$1"
}

# ---- Step 4: Register member 1 ----
echo "[4/12] Registering member 1..."
REG1_OUTPUT=$(cargo run --bin register_member 2>&1)
CONFIG_ACCOUNT=$(echo "$REG1_OUTPUT" | grep '^CONFIG_ACCOUNT=' | cut -d= -f2)
LEAF_INDEX_1=$(echo "$REG1_OUTPUT" | grep '^LEAF_INDEX=' | cut -d= -f2)
IDENTITY_SECRET_HASH=$(echo "$REG1_OUTPUT" | grep '^IDENTITY_SECRET_HASH=' | cut -d= -f2)

if [ -z "$CONFIG_ACCOUNT" ] || [ -z "$LEAF_INDEX_1" ] || [ -z "$IDENTITY_SECRET_HASH" ]; then
    echo "  ERROR: Failed to parse register_member output:"
    echo "$REG1_OUTPUT"
    exit 1
fi
echo "  Config account: $CONFIG_ACCOUNT"
echo "  Leaf index: $LEAF_INDEX_1"
echo "  Identity secret hash: ${IDENTITY_SECRET_HASH:0:16}..."

# ---- Step 5: Get merkle proof (1 member) ----
echo "[5/12] Getting merkle proof (1 member)..."

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
echo "[6/12] Registering member 2..."
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

echo ""
echo "=== Merkle Proof Tests: PASS ==="
echo ""

# ---- Step 7: Verify delivery module receives RLN root events ----
echo "[7/12] Testing delivery module event subscription..."

if ! kill -0 "$SEQUENCER_PID" 2>/dev/null; then
    echo "  ERROR: Sequencer died before delivery test"
    exit 1
fi

# Run logoscore with delivery module: subscribe → broadcast → getNimCachedRoots.
# Expected 5 "Method call successful" lines:
#   1) wallet.open
#   2) delivery_module.subscribeToRlnRoots  (returns bool true)
#   3) liblogos_rln_module.start_root_broadcast  (fires event synchronously)
#   4) delivery_module.getValidRoots  (returns C++ cached roots)
#   5) delivery_module.getNimCachedRoots  (returns Nim cached roots via FFI)
ROOTS_RESULT=$(run_logoscore 5 --with-delivery \
    -c "delivery_module.subscribeToRlnRoots()" \
    -c "liblogos_rln_module.start_root_broadcast($CONFIG_ACCOUNT)" \
    -c "delivery_module.getValidRoots()" \
    -c "delivery_module.getNimCachedRoots()")

echo "  getNimCachedRoots result: $ROOTS_RESULT"

# ---- Step 8: Verify Nim library received valid roots ----
echo "[8/12] Verifying Nim library received valid roots..."

python3 -c "
import json, sys

raw = sys.argv[1].strip()
if not raw:
    print('  FAIL: getNimCachedRoots returned empty string')
    sys.exit(1)

roots = json.loads(raw)
if not isinstance(roots, list) or len(roots) == 0:
    print(f'  FAIL: expected non-empty array, got: {raw[:100]}')
    sys.exit(1)
print(f'  Root count: {len(roots)} (expected 1-5)')

for i, r in enumerate(roots):
    if not isinstance(r, str) or len(r) != 64:
        print(f'  FAIL: root[{i}] is not a 64-char hex string: {r}')
        sys.exit(1)
print(f'  All roots are valid 64-char hex strings')
print(f'  Latest root: {roots[0]}')
print(f'  Nim library confirmed receiving roots via FFI push')
" "$ROOTS_RESULT"

echo ""

# ---- Step 9: Verify delivery module receives merkle proof events ----
echo "[9/12] Testing delivery module merkle proof subscription..."

if ! kill -0 "$SEQUENCER_PID" 2>/dev/null; then
    echo "  ERROR: Sequencer died before proof subscription test"
    exit 1
fi

# Run logoscore with delivery module: subscribe to proofs → broadcast → getNimCachedProof.
# Expected 5 "Method call successful" lines:
#   1) wallet.open
#   2) delivery_module.subscribeToMerkleProofs  (triggers start_merkle_proof_broadcast)
#   3) liblogos_rln_module.start_root_broadcast  (needed so roots are also available)
#   4) delivery_module.getNimCachedRoots  (verify roots still work)
#   5) delivery_module.getNimCachedProof  (verify proof was pushed to Nim)
PROOF_RESULT=$(run_logoscore 5 --with-delivery \
    -c "delivery_module.subscribeToMerkleProofs($CONFIG_ACCOUNT,$LEAF_INDEX_1)" \
    -c "liblogos_rln_module.start_root_broadcast($CONFIG_ACCOUNT)" \
    -c "delivery_module.getNimCachedRoots()" \
    -c "delivery_module.getNimCachedProof()")

echo "  getNimCachedProof result: $PROOF_RESULT"

# ---- Step 10: Verify Nim library received merkle proof ----
echo "[10/12] Verifying Nim library received merkle proof..."

python3 -c "
import json, sys

raw = sys.argv[1].strip()
if not raw:
    print('  FAIL: getNimCachedProof returned empty string')
    sys.exit(1)

proof = json.loads(raw)
if not isinstance(proof, dict):
    print(f'  FAIL: expected JSON object, got: {raw[:100]}')
    sys.exit(1)

# Verify required fields
for field in ['root', 'leaf', 'leaf_index', 'depth', 'path_elements', 'path_indices']:
    if field not in proof:
        print(f'  FAIL: missing field: {field}')
        sys.exit(1)
print(f'  All required fields present')

# Verify root is 64-char hex
root = proof['root']
if not isinstance(root, str) or len(root) != 64:
    print(f'  FAIL: root is not a 64-char hex string: {root}')
    sys.exit(1)
print(f'  Root: {root}')

# Verify path_elements length (should be tree depth = 20)
n = len(proof['path_elements'])
if n != 20:
    print(f'  FAIL: path_elements has {n} entries, expected 20')
    sys.exit(1)
print(f'  Path elements: {n}')

print(f'  Nim library confirmed receiving merkle proof via FFI push')
" "$PROOF_RESULT"

echo ""
echo "=== Merkle Proof Subscription Tests: PASS ==="
echo ""

# ---- Step 11: Generate RLN proof using pushed data ----
echo "[11/12] Generating RLN proof via delivery module..."

if ! kill -0 "$SEQUENCER_PID" 2>/dev/null; then
    echo "  ERROR: Sequencer died before proof generation test"
    exit 1
fi

# Run logoscore with delivery module:
#   1) wallet.open
#   2) delivery_module.subscribeToRlnRoots  (register for root events)
#   3) delivery_module.subscribeToMerkleProofs  (register for proof events + start broadcast)
#   4) liblogos_rln_module.start_root_broadcast  (push roots to Nim)
#   5) delivery_module.testGenerateRlnProof  (generate proof from cached data)
PROOF_HEX=$(run_logoscore 5 --with-delivery \
    -c "delivery_module.subscribeToRlnRoots()" \
    -c "delivery_module.subscribeToMerkleProofs($CONFIG_ACCOUNT,$LEAF_INDEX_1)" \
    -c "liblogos_rln_module.start_root_broadcast($CONFIG_ACCOUNT)" \
    -c "delivery_module.testGenerateRlnProof($IDENTITY_SECRET_HASH,$LEAF_INDEX_1,100,deadbeef)")

echo "  Proof result length: ${#PROOF_HEX}"

# ---- Step 12: Verify RLN proof ----
echo "[12/12] Verifying RLN proof..."

python3 -c "
import sys

proof_hex = sys.argv[1].strip()
if not proof_hex:
    print('  FAIL: testGenerateRlnProof returned empty string')
    sys.exit(1)

try:
    proof_bytes = bytes.fromhex(proof_hex)
except ValueError as e:
    print(f'  FAIL: proof is not valid hex: {e}')
    sys.exit(1)

# RateLimitProof serialized: 128 proof + 32*5 fields = 288 bytes minimum
if len(proof_bytes) < 288:
    print(f'  FAIL: proof too short: {len(proof_bytes)} bytes (expected >= 288)')
    sys.exit(1)

print(f'  RLN proof generated: {len(proof_bytes)} bytes')
print(f'  Proof hex (first 64 chars): {proof_hex[:64]}...')
print(f'  RLN proof generation via delivery module: PASS')
" "$PROOF_HEX"

echo ""
echo "=== ALL TESTS PASS ==="
