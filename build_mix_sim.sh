#!/usr/bin/env bash
# Build the minimal modules needed for the mixnet-logos-core simulation.
#
# Builds only:
#   - chat2mix (from logos-delivery, used as sender + receiver)
#   - logos-delivery-module (the Qt plugin loaded by logoscore)
#
# Does NOT build lez-rln, RLN module, wallet module, or mix-simulation-module — none
# of them are needed for the minimal mix sim.
#
# Prerequisites: nix (with flakes), nimble/make (for chat2mix), SSH access to GitHub.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# 1. Top-level submodules. logos-delivery's vendor tree needs to be initialized for
# nim/nimble to find dependencies when building chat2mix. We init each vendor submodule
# individually so a single stale pinned subref doesn't cascade.
log "Initializing submodules..."
git submodule update --init logos-delivery logos-delivery-module
(cd logos-delivery && \
    git submodule init && \
    for mod in $(git config --file .gitmodules --get-regexp path | awk '{print $2}'); do
        git submodule update --init --recursive "$mod" 2>/dev/null || \
            echo "  warn: $mod recursive init incomplete (likely stale pinned subref)"
    done)

# 2. Build chat2mix from logos-delivery (uses make/nimble, no nix)
CHAT2MIX_BIN="logos-delivery/build/chat2mix"
if [ -x "$CHAT2MIX_BIN" ]; then
    log "chat2mix already built at $CHAT2MIX_BIN, skipping. Delete it to force rebuild."
else
    log "Building chat2mix..."
    (cd logos-delivery && make chat2mix)
fi

# 3. Build delivery_module via nix, overriding the logos-delivery flake input to point
# at our local checkout (which is on feat/logos-core-mix).
log "Building delivery_module..."
(cd logos-delivery-module && \
    nix build --override-input logos-delivery "git+file://$(pwd)/../logos-delivery?submodules=1")

log "All modules built successfully."
log ""
log "Run the simulation:"
log "  bash logos-delivery/simulations/mixnet-logos-core/run_simulation.sh --fresh"
