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

# --- RLN module ---
if need_build "logos-rln-module/result-rln/lib/liblogos_rln_module.$EXT"; then
    echo "[1/4] Building RLN module..."
    nix build .#logos-rln-module -o logos-rln-module/result-rln
    echo "  Done: logos-rln-module/result-rln"
else
    echo "[1/4] RLN module: already built"
fi

# --- Wallet module ---
if need_build "logos-rln-module/result-wallet/lib/liblogos_execution_zone_wallet_module.$EXT"; then
    echo "[2/4] Building wallet module..."
    git submodule update --init lssa
    LSSA_PATH="$(cd lssa && pwd)"
    nix build .#wallet-module -o logos-rln-module/result-wallet \
        --override-input logos-wallet-module/logos-execution-zone "git+file://$LSSA_PATH"
    echo "  Done: logos-rln-module/result-wallet"
else
    echo "[2/4] Wallet module: already built"
fi

# --- Delivery module ---
if need_build "logos-delivery-module/result/lib/delivery_module_plugin.$EXT"; then
    echo "[3/4] Building delivery module..."
    echo "  Initializing delivery submodules (needed by nix)..."
    git submodule update --init --recursive logos-delivery logos-delivery-module
    DELIVERY_PATH="$(cd logos-delivery && pwd)"
    (cd logos-delivery-module && nix build -o result \
        --override-input logos-delivery "git+file://$DELIVERY_PATH?submodules=1")
    echo "  Done: logos-delivery-module/result"
else
    echo "[3/4] Delivery module: already built"
fi

# --- Mix simulation module ---
if need_build "mix-simulation-module/result/lib/libmix_simulation_module.$EXT"; then
    echo "[4/4] Building mix simulation module..."
    (cd mix-simulation-module && nix build -o result)
    echo "  Done: mix-simulation-module/result"
else
    echo "[4/4] Mix simulation module: already built"
fi

echo ""
echo "All modules built. Run the simulation with:"
echo "  bash logos-delivery/simulations/mixnet/run_simulation.sh"
