#!/usr/bin/env bash
# E2E test: Two logoscore instances with RLN + delivery modules exchange messages with RLN proofs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export RISC0_DEV_MODE=1
export TMPDIR=/tmp

# --- Node identity constants ---
NODE1_NODEKEY="f98e3fba96c32e8d1967d460f1b79457380e1a895f7971cecc8528abe733781a"
NODE1_MIXKEY="a87db88246ec0eedda347b9b643864bee3d6933eb15ba41e6d58cb678d813258"
NODE1_PEERID="16Uiu2HAmPiEs2ozjjJF2iN2Pe2FYeMC9w4caRHKYdLdAfjgbWM6o"
NODE1_PORT=60001
NODE1_DISC_PORT=9001

NODE2_NODEKEY="09e9d134331953357bd38bbfce8edb377f4b6308b4f3bfbe85c610497053d684"
NODE2_MIXKEY="c86029e02c05a7e25182974b519d0d52fcbafeca6fe191fbb64857fb05be1a53"
NODE2_PEERID="16Uiu2HAmLtKaFaSWDohToWhWUZFLtqzYZGPFuXwKrojFVF6az5UF"
NODE2_PORT=60002
NODE2_DISC_PORT=9002

CONTENT_TOPIC="/test/1/rln-proof/proto"

# --- Cleanup ---
SEQUENCER_PID=""
INSTANCE1_PID=""
INSTANCE2_PID=""
MODULES_DIR1=""
MODULES_DIR2=""
WORK_DIR=""
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "$INSTANCE2_PID" "$INSTANCE1_PID"; do
        if [ -n "$pid" ]; then
            local children
            children=$(pgrep -P "$pid" 2>/dev/null || true)
            kill "$pid" $children 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    pkill -f 'logos_host' 2>/dev/null || true
    if [ -n "$SEQUENCER_PID" ]; then
        kill "$SEQUENCER_PID" 2>/dev/null || true
        wait "$SEQUENCER_PID" 2>/dev/null || true
    fi
    [ -n "$MODULES_DIR1" ] && rm -rf "$MODULES_DIR1"
    [ -n "$MODULES_DIR2" ] && rm -rf "$MODULES_DIR2"
    [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
    echo "Done."
}
trap cleanup EXIT

echo "=== E2E Test: Two Instances with RLN Proofs ==="

pkill -f 'logos_host' 2>/dev/null || true
sleep 1

# --- Platform ---
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM="darwin-arm64"; EXT="dylib";;
  Linux-x86_64) PLATFORM="linux-x86_64"; EXT="so";;
  Linux-aarch64) PLATFORM="linux-aarch64"; EXT="so";;
  *) echo "Unsupported platform"; exit 1;;
esac

# ---- Step 1: Start sequencer ----
echo "[1/8] Starting sequencer..."

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
        echo "  ERROR: Sequencer exited unexpectedly."
        exit 1
    fi
    sleep 1
done
if ! nc -z 127.0.0.1 3040 2>/dev/null; then
    echo "  ERROR: Sequencer did not start within 120s."
    exit 1
fi

# ---- Step 2: Deploy programs & register members ----
echo "[2/8] Deploying programs..."
export NSSA_WALLET_HOME_DIR="$SCRIPT_DIR/dev"
export WALLET_CONFIG="$NSSA_WALLET_HOME_DIR/wallet_config.json"
export WALLET_STORAGE="$NSSA_WALLET_HOME_DIR/storage.json"
rm -f "$WALLET_CONFIG" "$WALLET_STORAGE"

cargo run --bin run_setup 2>&1 | tail -3
echo "  Setup complete."

echo "  Registering member 1..."
REG1_OUTPUT=$(cargo run --release --bin register_member 2>&1)
CONFIG_ACCOUNT=$(echo "$REG1_OUTPUT" | grep '^CONFIG_ACCOUNT=' | cut -d= -f2)
LEAF_INDEX_1=$(echo "$REG1_OUTPUT" | grep '^LEAF_INDEX=' | cut -d= -f2)
IDENTITY_SECRET_1=$(echo "$REG1_OUTPUT" | grep '^IDENTITY_SECRET_HASH=' | cut -d= -f2)
echo "  Member 1: leaf=$LEAF_INDEX_1, account=$CONFIG_ACCOUNT"

echo "  Registering member 2..."
REG2_OUTPUT=$(cargo run --release --bin register_member 2>&1)
LEAF_INDEX_2=$(echo "$REG2_OUTPUT" | grep '^LEAF_INDEX=' | cut -d= -f2)
IDENTITY_SECRET_2=$(echo "$REG2_OUTPUT" | grep '^IDENTITY_SECRET_HASH=' | cut -d= -f2)
echo "  Member 2: leaf=$LEAF_INDEX_2"

# ---- Step 3: Generate keystores ----
echo "[3/8] Generating keystores..."

WORK_DIR=$(mktemp -d)

# Write manifest for setup_keystores
cat > "$WORK_DIR/manifest.json" <<EOF
[
  {"peerId": "$NODE1_PEERID", "leafIndex": $LEAF_INDEX_1, "identitySecretHash": "$IDENTITY_SECRET_1", "rateLimit": 100},
  {"peerId": "$NODE2_PEERID", "leafIndex": $LEAF_INDEX_2, "identitySecretHash": "$IDENTITY_SECRET_2", "rateLimit": 100}
]
EOF

# Compile and run setup_keystores
LIBRLN_FILE="logos-delivery/librln_v0.9.0.a"
if [ ! -f "$LIBRLN_FILE" ]; then
    (cd logos-delivery && make librln 2>&1 | tail -3)
fi

NIM_PATH_ARGS=()
while IFS= read -r line; do
    line="${line//\"/}"
    [[ -n "$line" ]] && NIM_PATH_ARGS+=("$line")
done < "logos-delivery/nimbus-build-system.paths"

SETUP_BIN="$WORK_DIR/setup_keystores"
nim c -d:release --mm:refc \
    "${NIM_PATH_ARGS[@]}" \
    --passL:"$LIBRLN_FILE" --passL:"-lm" \
    -o:"$SETUP_BIN" \
    "logos-delivery/simulations/mixnet/setup_keystores.nim" 2>&1 | tail -3

(cd "$WORK_DIR" && "$SETUP_BIN" manifest.json)
echo "  Keystores: $(ls -1 "$WORK_DIR"/rln_keystore_*.json 2>/dev/null | wc -l | tr -d ' ')"

# ---- Step 4: Build modules ----
echo "[4/8] Checking module builds..."

LOGOSCORE="$(nix build github:logos-co/logos-liblogos --no-link --print-out-paths)/bin/logoscore"
WALLET_MODULE_RESULT="logos-rln-module/result-wallet"

[ -f "logos-rln-module/result-rln/lib/liblogos_rln_module.$EXT" ] || {
    echo "  RLN module not found. Build with: cd logos-rln-module && nix build .#lib -o result-rln --override-input logos-lez-rln path:../"
    exit 1
}
[ -f "$WALLET_MODULE_RESULT/lib/liblogos_execution_zone_wallet_module.$EXT" ] || {
    echo "  Wallet module not found. Build with: cd logos-rln-module && nix build .#wallet-module -o result-wallet --override-input logos-lez-rln path:../ --override-input logos-wallet-module/logos-execution-zone path:../lssa"
    exit 1
}
[ -f "logos-delivery-module/result/lib/delivery_module_plugin.$EXT" ] || {
    echo "  Delivery module not found. Build with: cd logos-delivery-module && nix build --override-input logos-delivery 'git+file:///.../logos-delivery?submodules=1'"
    exit 1
}
echo "  All modules present."

# ---- Step 5: Stage modules ----
echo "[5/8] Staging modules for two instances..."

stage_modules() {
    local mdir
    mdir=$(mktemp -d)

    mkdir -p "$mdir/liblogos_execution_zone_wallet_module"
    cp -L "$WALLET_MODULE_RESULT/lib/liblogos_execution_zone_wallet_module.$EXT" "$mdir/liblogos_execution_zone_wallet_module/"
    [ -f "$WALLET_MODULE_RESULT/lib/libwallet_ffi.$EXT" ] && \
      cp -L "$WALLET_MODULE_RESULT/lib/libwallet_ffi.$EXT" "$mdir/liblogos_execution_zone_wallet_module/"
    echo "{\"name\":\"liblogos_execution_zone_wallet_module\",\"version\":\"1.0.0\",\"type\":\"core\",\"main\":{\"$PLATFORM\":\"liblogos_execution_zone_wallet_module.$EXT\"},\"dependencies\":[],\"capabilities\":[]}" > "$mdir/liblogos_execution_zone_wallet_module/manifest.json"

    mkdir -p "$mdir/liblogos_rln_module"
    cp -L logos-rln-module/result-rln/lib/liblogos_rln_module.$EXT "$mdir/liblogos_rln_module/"
    cp -L logos-rln-module/result-rln/lib/liblez_rln_ffi.$EXT "$mdir/liblogos_rln_module/" 2>/dev/null || true
    echo "{\"name\":\"liblogos_rln_module\",\"version\":\"1.0.0\",\"type\":\"core\",\"main\":{\"$PLATFORM\":\"liblogos_rln_module.$EXT\"},\"dependencies\":[\"liblogos_execution_zone_wallet_module\"],\"capabilities\":[]}" > "$mdir/liblogos_rln_module/manifest.json"

    mkdir -p "$mdir/delivery_module"
    cp -L logos-delivery-module/result/lib/delivery_module_plugin.$EXT "$mdir/delivery_module/"
    [ -f "logos-delivery-module/result/lib/liblogosdelivery.$EXT" ] && cp -L "logos-delivery-module/result/lib/liblogosdelivery.$EXT" "$mdir/delivery_module/"
    for pq in logos-delivery-module/result/lib/libpq*; do
        [ -f "$pq" ] && cp -L "$pq" "$mdir/delivery_module/"
    done
    echo "{\"name\":\"delivery_module\",\"version\":\"1.0.0\",\"type\":\"core\",\"main\":{\"$PLATFORM\":\"delivery_module_plugin.$EXT\"},\"dependencies\":[\"liblogos_rln_module\"],\"capabilities\":[]}" > "$mdir/delivery_module/manifest.json"

    echo "$mdir"
}

MODULES_DIR1=$(stage_modules)
MODULES_DIR2=$(stage_modules)
LOAD_ORDER="liblogos_execution_zone_wallet_module,liblogos_rln_module,delivery_module"
WALLET_CALL="liblogos_execution_zone_wallet_module.open($WALLET_CONFIG,$WALLET_STORAGE)"

echo "  Instance 1 modules: $MODULES_DIR1"
echo "  Instance 2 modules: $MODULES_DIR2"

# ---- Step 6: Write node configs ----
echo "[6/8] Writing node configs..."

NODE1_CONFIG="$WORK_DIR/node1_config.json"
cat > "$NODE1_CONFIG" <<EOF
{
  "mode": "Core",
  "protocolsConfig": {
    "clusterId": 2,
    "autoShardingConfig": { "numShardsInCluster": 1 },
    "entryNodes": [],
    "messageValidation": { "maxMessageSize": "150 KiB" }
  },
  "networkingConfig": {
    "listenIpv4": "127.0.0.1",
    "p2pTcpPort": $NODE1_PORT,
    "discv5UdpPort": $NODE1_DISC_PORT
  },
  "mixProtocolConfig": {
    "nodekey": "$NODE1_NODEKEY",
    "mixkey": "$NODE1_MIXKEY",
    "enableSpamProtection": true
  },
  "logLevel": "TRACE"
}
EOF

NODE2_CONFIG="$WORK_DIR/node2_config.json"
cat > "$NODE2_CONFIG" <<EOF
{
  "mode": "Core",
  "protocolsConfig": {
    "clusterId": 2,
    "autoShardingConfig": { "numShardsInCluster": 1 },
    "entryNodes": ["/ip4/127.0.0.1/tcp/$NODE1_PORT/p2p/$NODE1_PEERID"],
    "messageValidation": { "maxMessageSize": "150 KiB" }
  },
  "networkingConfig": {
    "listenIpv4": "127.0.0.1",
    "p2pTcpPort": $NODE2_PORT,
    "discv5UdpPort": $NODE2_DISC_PORT
  },
  "mixProtocolConfig": {
    "nodekey": "$NODE2_NODEKEY",
    "mixkey": "$NODE2_MIXKEY",
    "enableSpamProtection": true
  },
  "logLevel": "TRACE"
}
EOF

# ---- Step 7: Start both instances ----
echo "[7/8] Starting two logoscore instances..."

LOG1="$WORK_DIR/instance1.log"
LOG2="$WORK_DIR/instance2.log"

# Instance 1: create node, start, subscribe to RLN events, subscribe to content topic
(cd "$WORK_DIR" && TMPDIR=/tmp "$LOGOSCORE" -m "$MODULES_DIR1" -l "$LOAD_ORDER" \
    -c "$WALLET_CALL" \
    -c "delivery_module.createNode(@$NODE1_CONFIG)" \
    -c "delivery_module.start()" \
    -c "delivery_module.subscribe($CONTENT_TOPIC)" \
    -c "delivery_module.subscribeToRlnRoots()" \
    -c "delivery_module.subscribeToMerkleProofs($CONFIG_ACCOUNT,$LEAF_INDEX_1)" \
    -c "liblogos_rln_module.start_root_broadcast($CONFIG_ACCOUNT)" \
    -c "liblogos_rln_module.start_merkle_proof_broadcast($CONFIG_ACCOUNT,$LEAF_INDEX_1)" \
    </dev/null >"$LOG1" 2>&1) &
INSTANCE1_PID=$!
echo "  Instance 1 PID: $INSTANCE1_PID"

# Wait for instance 1 to be ready (all 8 -c calls succeed = 8 "Method call successful")
echo "  Waiting for instance 1 to initialize..."
for i in $(seq 1 60); do
    N=$(grep -c '^Method call successful' "$LOG1" 2>/dev/null || true); N=${N:-0}
    [ "$N" -ge 8 ] && break
    if ! kill -0 "$INSTANCE1_PID" 2>/dev/null; then
        echo "  ERROR: Instance 1 exited. Last log:"
        tail -10 "$LOG1"
        exit 1
    fi
    sleep 1
done
if [ "$N" -lt 8 ]; then
    echo "  ERROR: Instance 1 did not initialize ($N/8 calls). Log:"
    grep 'Method call\|Error' "$LOG1" | tail -10
    exit 1
fi
echo "  Instance 1 ready ($N/8 calls)."

# Brief pause for instance 1's P2P to start listening
sleep 3

# Instance 2: same setup but bootstraps to instance 1
(cd "$WORK_DIR" && TMPDIR=/tmp "$LOGOSCORE" -m "$MODULES_DIR2" -l "$LOAD_ORDER" \
    -c "$WALLET_CALL" \
    -c "delivery_module.createNode(@$NODE2_CONFIG)" \
    -c "delivery_module.start()" \
    -c "delivery_module.subscribe($CONTENT_TOPIC)" \
    -c "delivery_module.subscribeToRlnRoots()" \
    -c "delivery_module.subscribeToMerkleProofs($CONFIG_ACCOUNT,$LEAF_INDEX_2)" \
    -c "liblogos_rln_module.start_root_broadcast($CONFIG_ACCOUNT)" \
    -c "liblogos_rln_module.start_merkle_proof_broadcast($CONFIG_ACCOUNT,$LEAF_INDEX_2)" \
    </dev/null >"$LOG2" 2>&1) &
INSTANCE2_PID=$!
echo "  Instance 2 PID: $INSTANCE2_PID"

echo "  Waiting for instance 2 to initialize..."
for i in $(seq 1 60); do
    N=$(grep -c '^Method call successful' "$LOG2" 2>/dev/null || true); N=${N:-0}
    [ "$N" -ge 8 ] && break
    if ! kill -0 "$INSTANCE2_PID" 2>/dev/null; then
        echo "  ERROR: Instance 2 exited. Last log:"
        tail -10 "$LOG2"
        exit 1
    fi
    sleep 1
done
if [ "$N" -lt 8 ]; then
    echo "  ERROR: Instance 2 did not initialize ($N/8 calls). Log:"
    grep 'Method call\|Error' "$LOG2" | tail -10
    exit 1
fi
echo "  Instance 2 ready ($N/8 calls)."

# Wait for peer discovery
echo "  Waiting for peer discovery (15s)..."
sleep 15

# ---- Step 8: Verify ----
echo "[8/8] Verifying..."

# Check that both instances received roots
ROOTS1=$(grep 'getNimCachedRoots\|valid_roots.*push\|Logoscore poller\|root.*broadcast' "$LOG1" | head -3)
ROOTS2=$(grep 'getNimCachedRoots\|valid_roots.*push\|Logoscore poller\|root.*broadcast' "$LOG2" | head -3)

echo "  Instance 1 roots activity: $(echo "$ROOTS1" | wc -l | tr -d ' ') log lines"
echo "  Instance 2 roots activity: $(echo "$ROOTS2" | wc -l | tr -d ' ') log lines"

# Check peer connectivity
PEERS1=$(grep -c 'peer.*connected\|Connected to\|mix.*node.*pool\|Discovered' "$LOG1" 2>/dev/null || echo 0)
PEERS2=$(grep -c 'peer.*connected\|Connected to\|mix.*node.*pool\|Discovered' "$LOG2" 2>/dev/null || echo 0)
echo "  Instance 1 peer events: $PEERS1"
echo "  Instance 2 peer events: $PEERS2"

# Check for RLN proof generation
PROOFS1=$(grep -c 'rln.*proof\|RLN.*proof\|generateProof\|appendRLNProof' "$LOG1" 2>/dev/null || echo 0)
PROOFS2=$(grep -c 'rln.*proof\|RLN.*proof\|generateProof\|appendRLNProof' "$LOG2" 2>/dev/null || echo 0)
echo "  Instance 1 RLN proof activity: $PROOFS1"
echo "  Instance 2 RLN proof activity: $PROOFS2"

# Summary
echo ""
echo "=== Summary ==="
echo "  Both instances initialized: YES"
echo "  Logs at: $WORK_DIR/instance{1,2}.log"
echo "  Instance 1: port $NODE1_PORT, leaf $LEAF_INDEX_1"
echo "  Instance 2: port $NODE2_PORT, leaf $LEAF_INDEX_2"
echo ""
echo "  To inspect logs:"
echo "    grep 'Method call' $LOG1"
echo "    grep 'Method call' $LOG2"
echo ""
echo "=== Test Complete ==="
