#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) EXT="dylib";;
  Linux-x86_64)  EXT="so";;
  Linux-aarch64) EXT="so";;
  *) echo "Unsupported platform"; exit 1;;
esac

FORCE="${1:-}"

need_build() {
    [ "$FORCE" = "--force" ] && return 0
    [ ! -f "$1" ] && return 0
    return 1
}

echo "=== Building logoscore modules ==="
echo ""

# Initialize submodules needed by builds
git submodule update --init lssa logos-delivery logos-delivery-module

PIDS=()
LOGS=()
NAMES=()
FAILED=0
IDX=0

start_build() {
    local name=$1 log
    log=$(mktemp)
    NAMES[$IDX]="$name"
    LOGS[$IDX]="$log"
    echo "$log"
}

finish_build() {
    PIDS[$IDX]=$1
    IDX=$((IDX + 1))
}

# --- RLN module ---
if need_build "logos-rln-module/result-rln/lib/liblogos_rln_module.$EXT"; then
    echo "[1/4] Building RLN module..."
    LOG=$(start_build "RLN module")
    (nix build .#logos-rln-module -o logos-rln-module/result-rln > "$LOG" 2>&1) &
    finish_build $!
else
    echo "[1/4] RLN module: already built"
fi

# --- Wallet module ---
if need_build "logos-rln-module/result-wallet/lib/liblogos_execution_zone_wallet_module.$EXT"; then
    echo "[2/4] Building wallet module..."
    LSSA_PATH="$(cd lssa && pwd)"
    LOG=$(start_build "Wallet module")
    (nix build .#wallet-module -o logos-rln-module/result-wallet \
        --override-input logos-wallet-module/logos-execution-zone "git+file://$LSSA_PATH" \
        > "$LOG" 2>&1) &
    finish_build $!
else
    echo "[2/4] Wallet module: already built"
fi

# --- Delivery module ---
if need_build "logos-delivery-module/result/lib/delivery_module_plugin.$EXT"; then
    echo "[3/4] Building delivery module..."
    DELIVERY_PATH="$(cd logos-delivery && pwd)"
    LOG=$(start_build "Delivery module")
    (cd logos-delivery-module && nix build -o result \
        --override-input logos-delivery "git+file://$DELIVERY_PATH?submodules=1" \
        > "$LOG" 2>&1) &
    finish_build $!
else
    echo "[3/4] Delivery module: already built"
fi

# --- Mix simulation module ---
if need_build "mix-simulation-module/result/lib/libmix_simulation_module.$EXT"; then
    echo "[4/4] Building mix simulation module..."
    LOG=$(start_build "Mix simulation module")
    (cd mix-simulation-module && nix build -o result > "$LOG" 2>&1) &
    finish_build $!
else
    echo "[4/4] Mix simulation module: already built"
fi

# Wait for all parallel builds
set +u  # bash 3 compat: array access with -u is unreliable
if [ "${#PIDS[@]}" -gt 0 ]; then
    echo ""
    echo "Waiting for ${#PIDS[@]} parallel builds..."
    i=0
    while [ "$i" -lt "${#PIDS[@]}" ]; do
        if wait "${PIDS[$i]}"; then
            echo "  ${NAMES[$i]}: done"
        else
            echo "  ${NAMES[$i]}: FAILED"
            cat "${LOGS[$i]}" 2>/dev/null
            FAILED=1
        fi
        rm -f "${LOGS[$i]}"
        i=$((i + 1))
    done
fi
set -u

[ "$FAILED" -eq 1 ] && { echo "FATAL: One or more builds failed"; exit 1; }

echo ""
echo "All modules built. Run the simulation with:"
echo "  bash logos-delivery/simulations/mixnet/run_simulation.sh"
