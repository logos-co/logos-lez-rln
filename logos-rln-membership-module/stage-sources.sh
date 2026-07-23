#!/usr/bin/env bash
#
# Refresh the gitignored staged SDK copy this module builds from (see README
# "Staged sources"):
#
#   logos-rust-sdk-src/  <- logos-co/logos-rust-sdk @ SDK_REV
#
# SDK-only variant of ../logos-rln-module/stage-sources.sh (this crate has no
# rln-layouts path-dep — all lez-rln knowledge lives behind the sibling
# module's wire). The rsync --delete is scoped to the destination dir only;
# --checksum keeps the itemized output honest: a leading ">" marks a real
# content change, "." is attribute-only. After syncing, a diff -r
# verification fails the script on any disagreement. This script never
# touches this repo's git state and never invokes nix.
set -euo pipefail

# The one SDK pin. Keep it identical to ../logos-rln-module/stage-sources.sh
# (both modules must generate + link against the same SDK rev); bump both
# deliberately and re-run each module's gates afterwards.
SDK_REV=e288fb0f8c0fd6d913e53fc19a5b574cd9628e37
SDK_REPO=https://github.com/logos-co/logos-rust-sdk
# "tests" mirrors the actual staged tree (mkLogosModule needs none of these).
SDK_EXCLUDES=(--exclude .git --exclude target --exclude doctests --exclude result --exclude tests)

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

diff -r "${SDK_EXCLUDES[@]}" "$SDK_SRC" "$HERE/logos-rust-sdk-src" || {
  echo "stage-sources: staged copy disagrees with its source after sync" >&2
  exit 1
}
echo "stage-sources: staged copy verified in sync"
