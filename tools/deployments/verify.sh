#!/usr/bin/env bash
# Verify a deployment descriptor is self-consistent and matches the guest binaries.
# FEATURE: deployment-profile tooling — the guest-drift guard.
#
#   bash verify.sh <deployment_dir>
#
# Re-derives program ids + config from the ACTUAL guest binaries (via derive_accounts,
# reusing the real PDA math — no reimplementation) and asserts they match the
# descriptor. A guest rebuilt with different code/toolchain changes program_id, so the
# same tree_id re-derives a different config -> this fails with "guest changed; re-run
# provision" instead of looking like a tree bug. Also runs stage.sh's wallet binding.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"                    # logos-lez-rln root
DEP_DIR="${1:?usage: verify.sh <deployment_dir>}"
DERIVE="${DERIVE_BIN:-$REPO/lez-rln/target/release/derive_accounts}"
export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}"

[ -x "$DERIVE" ] || { echo "verify: FAIL: derive_accounts not built at $DERIVE
  build: (cd $REPO/lez-rln && PYO3_PYTHON=\$(command -v python3) cargo build --release --bin derive_accounts)" >&2; exit 1; }

f(){ jq -re ".$1" "$DEP_DIR/deployment.json"; }
TREE=$(f tree_id); WANT_REG=$(f registration_program_id); WANT_CFG=$(f config_account)

DERIVED=$(cd "$REPO/lez-rln" && LEZ_RLN_TREE_ID_HEX="$TREE" "$DERIVE")
GOT_REG=$(echo "$DERIVED" | jq -r .registration_program_id)
GOT_CFG=$(echo "$DERIVED" | jq -r .config_account)

fail(){ echo "verify: FAIL: $1" >&2; exit 1; }
[ "$GOT_REG" = "$WANT_REG" ] || fail "registration program id drifted
  descriptor: $WANT_REG
  guest now:  $GOT_REG
  the guest binaries changed since provision — re-run provision for this deployment."
[ "$GOT_CFG" = "$WANT_CFG" ] || fail "config account mismatch (tree_id/program_id inconsistent)
  descriptor: $WANT_CFG
  re-derived: $GOT_CFG"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
bash "$HERE/stage.sh" "$DEP_DIR" "$tmp" >/dev/null

echo "verify: OK  $(f name)  program_id + config match guest binaries; wallet binding holds."
