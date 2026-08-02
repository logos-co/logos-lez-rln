#!/usr/bin/env bash
#
# Refresh the two gitignored staged source copies this module builds from
# (see README "Staged sources" for why they exist):
#
#   logos-rust-sdk-src/                <- logos-co/logos-rust-sdk @ SDK_REV
#   rust-lib/lez-rln-src/rln-layouts/  <- ../lez-rln/rln-layouts/
#
# Each rsync --delete is scoped to its destination dir only; sibling files
# (e.g. the untracked rust-lib/lez-rln-src/Cargo.lock from local cargo runs)
# are never touched. --checksum keeps the itemized output honest: a leading
# ">" marks a real content change, "." is attribute-only. After syncing, a
# diff -r verification fails the script on any disagreement. This script
# never touches this repo's git state and never invokes nix.
set -euo pipefail

# The one SDK pin. MUST track the rev `nix build` actually uses — the root
# flake's logos-module-builder → logos-rust-sdk input in flake.lock
# (rust-lib/Cargo.toml, "The runtime SDK ..."). Bump deliberately, keep it
# equal to flake.lock, and re-run the sim acceptance gate afterwards.
SDK_REV=270e4cf687896d501ed73c1409ea4157cc8a5b54
SDK_REPO=https://github.com/logos-co/logos-rust-sdk
# "tests" mirrors the actual staged tree (mkLogosModule needs none of these).
SDK_EXCLUDES=(--exclude .git --exclude target --exclude doctests --exclude result --exclude tests)
LAYOUT_EXCLUDES=(--exclude target --exclude .git)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_SRC="${LOGOS_RUST_SDK_SRC:-${XDG_CACHE_HOME:-$HOME/.cache}/logos-lez-rln/logos-rust-sdk}"

if [ -n "${LOGOS_RUST_SDK_SRC:-}" ]; then
  # User-supplied checkout: used as-is (never mutated), must sit at the pin.
  sdk_head="$(git -C "$SDK_SRC" rev-parse HEAD)"
  if [ "$sdk_head" != "$SDK_REV" ]; then
    echo "stage-sources: LOGOS_RUST_SDK_SRC is at $sdk_head, expected $SDK_REV" >&2
    exit 1
  fi
else
  if [ ! -d "$SDK_SRC/.git" ]; then
    mkdir -p "$(dirname "$SDK_SRC")"
    git clone "$SDK_REPO" "$SDK_SRC"
  fi
  git -C "$SDK_SRC" rev-parse --verify --quiet "${SDK_REV}^{commit}" >/dev/null \
    || git -C "$SDK_SRC" fetch origin "$SDK_REV"
  git -C "$SDK_SRC" -c advice.detachedHead=false checkout --quiet "$SDK_REV"
fi

echo "stage-sources: syncing logos-rust-sdk-src/ (sdk @ $SDK_REV)"
rsync -ai --checksum --delete "${SDK_EXCLUDES[@]}" \
  "$SDK_SRC/" "$HERE/logos-rust-sdk-src/"

echo "stage-sources: syncing rust-lib/lez-rln-src/rln-layouts/"
rsync -ai --checksum --delete "${LAYOUT_EXCLUDES[@]}" \
  "$HERE/../lez-rln/rln-layouts/" "$HERE/rust-lib/lez-rln-src/rln-layouts/"

fail=0
diff -r "${SDK_EXCLUDES[@]}" "$SDK_SRC" "$HERE/logos-rust-sdk-src" || fail=1
diff -r "${LAYOUT_EXCLUDES[@]}" \
  "$HERE/../lez-rln/rln-layouts" "$HERE/rust-lib/lez-rln-src/rln-layouts" || fail=1
if [ "$fail" -ne 0 ]; then
  echo "stage-sources: staged copies disagree with their sources after sync" >&2
  exit 1
fi
echo "stage-sources: staged copies verified in sync"
