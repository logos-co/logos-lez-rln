#!/usr/bin/env bash
# Build all modules needed for the LEZ mix simulation.
# Prerequisites: nix (with flakes), Docker, cargo-risczero
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# 1. Submodules
log "Initializing submodules..."
git submodule update --init
(cd logos-delivery-module && git submodule update --init --recursive)

# 2. Guest binaries (zkVM programs)
GUEST_DIR="lez-rln/methods/guest/target/riscv32im-risc0-zkvm-elf/docker"
if [ -f "$GUEST_DIR/rln_registration.bin" ] && [ -f "$GUEST_DIR/incremental_merkle_tree.bin" ]; then
    log "Guest binaries already built, skipping. Delete $GUEST_DIR to force rebuild."
else
    log "Building guest binaries (requires Docker)..."
    (cd lez-rln && cargo risczero build --manifest-path methods/guest/Cargo.toml)
fi

# 3. RLN module (lez-rln-ffi + C++ plugin)
log "Building RLN module..."
nix build .#logos-rln-module -o logos-rln-module/result-rln

# 4. Wallet module
# --impure + RISC0_SKIP_BUILD_KERNELS: risc0-build-kernel tries to compile Metal
# GPU kernels on macOS which fails inside the nix sandbox (no Metal SDK). The
# kernels aren't needed for our simulation (CPU prover via RISC0_DEV_MODE=1).
log "Building wallet module..."
(cd logos-execution-zone-module && \
    RISC0_SKIP_BUILD_KERNELS=1 nix build --impure \
    --override-input logos-execution-zone "git+file://$(pwd)/../lssa" \
    -o ../logos-rln-module/result-wallet)

# 5. Nim binaries: liblogosdelivery, chat2mix
log "Building Nim binaries (liblogosdelivery, chat2mix)..."
(cd logos-delivery-module/vendor/logos-delivery && make -j4 liblogosdelivery chat2mix 2>&1 | tail -3)

# 6. Delivery module C++ plugin (cmake with correct SDK for LogosInstance ID)
log "Building delivery module plugin (cmake with SDK a4bd66c)..."
SDK_PATH=$(nix build github:logos-co/logos-cpp-sdk/a4bd66c --no-link --print-out-paths 2>/dev/null)
LIBLOGOS_PATH=$(nix build github:logos-co/logos-liblogos/7df6195 \
    --override-input logos-cpp-sdk github:logos-co/logos-cpp-sdk/a4bd66c \
    --no-link --print-out-paths 2>/dev/null)

# Qt paths come from the logoscore nix build (cached in store)
QT_BASE=$(find /nix/store -maxdepth 1 -name "*qtbase-6.9.2" -type d 2>/dev/null | head -1)
QT_RO=$(find /nix/store -maxdepth 1 -name "*qtremoteobjects-6.9.2" -type d 2>/dev/null | head -1)
[ -d "$QT_BASE" ] || die "Qt base 6.9.2 not in nix store — build logoscore first"
[ -d "$QT_RO" ] || die "Qt RemoteObjects 6.9.2 not in nix store — build logoscore first"

DELIVERY_MOD="$ROOT/logos-delivery-module"
cat > /tmp/_build_plugin.sh << PLUGINSCRIPT
#!/bin/bash
set -e
cd "$DELIVERY_MOD"
rm -rf build_plugin && mkdir build_plugin && cd build_plugin
mkdir -p delivery_root/bin delivery_root/liblogosdelivery
cp "$DELIVERY_MOD/vendor/logos-delivery/build/liblogosdelivery."* delivery_root/bin/ 2>/dev/null || true
cp "$DELIVERY_MOD/vendor/logos-delivery/liblogosdelivery/liblogosdelivery.h" delivery_root/liblogosdelivery/
cmake .. -GNinja \
  -DLOGOS_CPP_SDK_ROOT="$SDK_PATH" \
  -DLOGOS_LIBLOGOS_ROOT="$LIBLOGOS_PATH" \
  -DLOGOS_DELIVERY_ROOT="\$PWD/delivery_root" \
  -DLOGOS_MESSAGING_MODULE_USE_VENDOR=OFF \
  -DCMAKE_PREFIX_PATH="$QT_BASE;$QT_RO" \
  -DQT_ADDITIONAL_PACKAGES_PREFIX_PATH="$QT_RO"
ninja
PLUGINSCRIPT
chmod +x /tmp/_build_plugin.sh
nix-shell -p cmake ninja pkg-config postgresql --run "bash /tmp/_build_plugin.sh" 2>&1 | tail -5

# Verify plugin built and fix rpath on macOS
if [ "$(uname -s)" = "Darwin" ]; then
    PLUGIN="$DELIVERY_MOD/build_plugin/modules/delivery_module_plugin.dylib"
    [ -f "$PLUGIN" ] || die "cmake plugin build failed"
    ABS_PATH=$(otool -L "$PLUGIN" | grep liblogosdelivery | awk '{print $1}' | grep -v '@rpath' || true)
    [ -n "$ABS_PATH" ] && install_name_tool -change "$ABS_PATH" "@rpath/liblogosdelivery.dylib" "$PLUGIN"
else
    PLUGIN="$DELIVERY_MOD/build_plugin/modules/delivery_module_plugin.so"
    [ -f "$PLUGIN" ] || die "cmake plugin build failed"
fi
log "  Plugin built with LogosInstance ID support."

# 7. Clean stale wallet storage
[ -f "$HOME/.nssa/wallet/storage.json" ] && rm -f "$HOME/.nssa/wallet/storage.json"

log "All modules built successfully."
log ""
log "Run the simulation:"
log "  bash logos-delivery-module/simulations/mixnet-logos-core/run_simulation_lez.sh --fresh"
