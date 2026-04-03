#!/usr/bin/env bash
# Build all modules needed for the RLN relay simulation.
# Prerequisites: nix, cargo-risczero, Docker
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# 1. Submodules
log "Initializing submodules..."
git submodule update --init
(cd logos-delivery && git submodule update --init --recursive)

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

# 4. Wallet module (logos-execution-zone-module + wallet FFI from our LSSA fork)
log "Building wallet module..."
(cd logos-execution-zone-module && \
    nix build --override-input logos-execution-zone "git+file://$(pwd)/../lssa" \
    -o ../logos-rln-module/result-wallet)

# 5. Delivery module (logos-delivery-module + our delivery fork with rln_gifter)
log "Building delivery module..."
(cd logos-delivery-module && \
    nix build --override-input logos-delivery "git+file://$(pwd)/../logos-delivery?submodules=1")

# 6. Mix simulation module
log "Building mix-simulation module..."
(cd mix-simulation-module/src-local && nix build -o ../result)

# 7. Clean stale wallet storage (format may differ between LSSA versions)
if [ -f "$HOME/.nssa/wallet/storage.json" ]; then
    log "Removing stale wallet storage..."
    rm -f "$HOME/.nssa/wallet/storage.json"
fi

log "All modules built successfully."
log ""
log "Run the simulation:"
log "  bash logos-delivery/simulations/relay-rln/run_simulation.sh --fresh"
