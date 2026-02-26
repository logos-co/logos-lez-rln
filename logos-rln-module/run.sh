#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RLN_REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Platform ---
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM="darwin-arm64"; EXT="dylib";;
  Linux-x86_64) PLATFORM="linux-x86_64"; EXT="so";;
  Linux-aarch64) PLATFORM="linux-aarch64"; EXT="so";;
  *) echo "Unsupported platform"; exit 1;;
esac

# --- Paths (all overridable via env vars) ---
LOGOSCORE="$(nix build github:logos-co/logos-liblogos --no-link --print-out-paths)/bin/logoscore"
CAPABILITY_MODULE_PATH="$(nix build github:logos-co/logos-capability-module --no-link --print-out-paths)/lib"

RLN_MODULE="$SCRIPT_DIR/result/lib/liblogos_rln_module.$EXT"
WALLET_MODULE_RESULT="${WALLET_MODULE_RESULT:-$HOME/Waku/Logos/logos-execution-zone-module/result}"
WALLET_MODULE="$WALLET_MODULE_RESULT/lib/liblogos_execution_zone_wallet_module.$EXT"

# Wallet config & storage: use NSSA_WALLET_HOME_DIR if set (same as dev/env.sh),
# otherwise fall back to repo root (where run_setup creates them).
WALLET_HOME="${NSSA_WALLET_HOME_DIR:-$RLN_REPO}"
WALLET_CONFIG="${WALLET_CONFIG:-$WALLET_HOME/wallet_config.json}"
WALLET_STORAGE="${WALLET_STORAGE:-$WALLET_HOME/storage.json}"

# --- Validate ---
fail() { echo "Error: $1"; echo "$2"; exit 1; }

[ -f "$RLN_MODULE" ] || fail "RLN module not found at $RLN_MODULE" \
  "Run: nix build --override-input logos-lez-rln path:../"
[ -f "$WALLET_MODULE" ] || fail "Wallet module not found at $WALLET_MODULE" \
  "Set WALLET_MODULE_RESULT to the wallet module result dir"
[ -f "$WALLET_CONFIG" ] || fail "Wallet config not found at $WALLET_CONFIG" \
  "Run: source dev/env.sh && cargo run --bin run_setup"
[ -f "$WALLET_STORAGE" ] || fail "Wallet storage not found at $WALLET_STORAGE" \
  "Run: source dev/env.sh && cargo run --bin run_setup"

# --- Stage modules in subdirectory layout expected by logoscore ---
MODULES_DIR=$(mktemp -d)
trap 'rm -rf "$MODULES_DIR"' EXIT

# Capability module (needed for inter-module auth tokens)
CAP_DIR="$MODULES_DIR/capability_module"
mkdir -p "$CAP_DIR"
cp -L "$CAPABILITY_MODULE_PATH/capability_module_plugin.$EXT" "$CAP_DIR/"
cat > "$CAP_DIR/manifest.json" <<EOF
{
  "name": "capability_module",
  "version": "1.0.0",
  "type": "core",
  "main": { "$PLATFORM": "capability_module_plugin.$EXT" },
  "dependencies": [],
  "capabilities": []
}
EOF

# Wallet module
WALLET_DIR="$MODULES_DIR/liblogos_execution_zone_wallet_module"
mkdir -p "$WALLET_DIR"
cp -L "$WALLET_MODULE" "$WALLET_DIR/"
[ -f "$WALLET_MODULE_RESULT/lib/libwallet_ffi.$EXT" ] && \
  cp -L "$WALLET_MODULE_RESULT/lib/libwallet_ffi.$EXT" "$WALLET_DIR/"
cat > "$WALLET_DIR/manifest.json" <<EOF
{
  "name": "liblogos_execution_zone_wallet_module",
  "version": "1.0.0",
  "type": "core",
  "main": { "$PLATFORM": "liblogos_execution_zone_wallet_module.$EXT" },
  "dependencies": [],
  "capabilities": []
}
EOF

# RLN module
RLN_DIR="$MODULES_DIR/liblogos_rln_module"
mkdir -p "$RLN_DIR"
cp -L "$RLN_MODULE" "$RLN_DIR/"
RLN_LIB_DIR="$(dirname "$RLN_MODULE")"
[ -f "$RLN_LIB_DIR/liblez_rln_ffi.$EXT" ] && \
  cp -L "$RLN_LIB_DIR/liblez_rln_ffi.$EXT" "$RLN_DIR/"
cat > "$RLN_DIR/manifest.json" <<EOF
{
  "name": "liblogos_rln_module",
  "version": "1.0.0",
  "type": "core",
  "main": { "$PLATFORM": "liblogos_rln_module.$EXT" },
  "dependencies": ["liblogos_execution_zone_wallet_module"],
  "capabilities": []
}
EOF

echo "=== Logos RLN Module ==="
echo "Wallet config:  $WALLET_CONFIG"
echo "Wallet storage: $WALLET_STORAGE"
echo ""

# --- Run ---
LOAD_FLAGS="-l capability_module,liblogos_execution_zone_wallet_module,liblogos_rln_module"
INIT_WALLET="-c liblogos_execution_zone_wallet_module.open($WALLET_CONFIG,$WALLET_STORAGE)"

if [ $# -gt 0 ]; then
  exec "$LOGOSCORE" -m "$MODULES_DIR" $LOAD_FLAGS "$INIT_WALLET" "$@"
else
  echo "Usage:"
  echo "  ./run.sh -c 'liblogos_rln_module.get_valid_roots(ACCOUNT_ID)'"
  echo ""
  exec "$LOGOSCORE" -m "$MODULES_DIR" $LOAD_FLAGS "$INIT_WALLET"
fi
