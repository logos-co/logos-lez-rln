#!/usr/bin/env bash
# Source this in your terminal before running RLN binaries against the local dev sequencer.
# Usage: source dev/env.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NSSA_WALLET_HOME_DIR="$SCRIPT_DIR"
