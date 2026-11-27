#!/usr/bin/env bash
# Verify a deployment descriptor is self-consistent and matches recorded program ids.
# FEATURE: deployment-profile tooling — the descriptor consistency guard.
#
#   bash verify.sh <deployment_dir>
#
# Program ids are deployment state (the header accounts run_setup deployed), so
# they cannot be re-derived from the guest binaries. This script:
#   1. re-derives config_account from the descriptor's registration_program_id
#      and tree_id via derive_accounts (the real PDA math) and asserts it equals
#      the descriptor's cache;
#   2. when the tree's record (~/.logos-lez-rln/programs_<tree>.json) exists,
#      asserts it names the descriptor's program ids, so a descriptor and the
#      ids every tool reads back cannot silently diverge;
#   3. when the descriptor names the registry's owner and label, asserts the
#      tree id is the one the registration program makes of them;
#   4. runs stage.sh's wallet binding — unless the descriptor is a plan
#      (`"planned": true`, from plan.sh), which has no wallet yet.
# The image ids the program headers carry are checked by run_setup at deploy
# time, not here.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"                    # logos-lez-rln root
case "${1:-}" in -h|--help) echo "usage: verify.sh <deployment_dir>" >&2; exit 0;; esac
DEP_DIR="${1:?usage: verify.sh <deployment_dir>}"
DERIVE="${DERIVE_BIN:-${LEZ_RLN_BIN_DIR:-$REPO/lez-rln/target/release}/derive_accounts}"
export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}"

[ -x "$DERIVE" ] || { echo "verify: FAIL: derive_accounts not built at $DERIVE
  build: (cd $REPO/lez-rln && PYO3_PYTHON=\$(command -v python3) cargo build --release --bin derive_accounts)" >&2; exit 1; }

f(){ jq -re ".$1" "$DEP_DIR/deployment.json"; }
TREE=$(f tree_id); WANT_REG=$(f registration_program_id); WANT_MRK=$(f merkle_program_id); WANT_CFG=$(f config_account)

fail(){ echo "verify: FAIL: $1" >&2; exit 1; }

# The descriptor's ids go in through the env overrides, so derive_accounts
# reads them instead of whatever record the running HOME holds. Given the
# owner and the label beside the tree id, it refuses a tree id that is not
# theirs; a descriptor from before owned registries names neither.
OWNER=$(jq -r '.owner_account // empty' "$DEP_DIR/deployment.json")
LABEL=$(jq -r '.tree_label // empty' "$DEP_DIR/deployment.json")
unset LEZ_RLN_REGISTRY_OWNER LEZ_RLN_TREE_LABEL
if [ -n "$OWNER" ]; then
  export LEZ_RLN_REGISTRY_OWNER="$OWNER" LEZ_RLN_TREE_LABEL="$LABEL"
  OWNER_NOTE="tree id is the owner's under '$LABEL'"
else
  OWNER_NOTE="no owner recorded (tree id not cross-checked)"
fi
DERIVED=$(cd "$REPO/lez-rln" && LEZ_RLN_TREE_ID_HEX="$TREE" \
  LEZ_RLN_REGISTRATION_PROGRAM_ID="$WANT_REG" LEZ_RLN_MERKLE_PROGRAM_ID="$WANT_MRK" "$DERIVE") \
  || fail "tree id is not the one owner $OWNER holds under label '$LABEL'"
GOT_CFG=$(echo "$DERIVED" | jq -r .config_account)
[ "$GOT_CFG" = "$WANT_CFG" ] || fail "config account mismatch (tree_id/program_id inconsistent)
  descriptor: $WANT_CFG
  re-derived: $GOT_CFG"

RECORD="${HOME:-.}/.logos-lez-rln/programs_${TREE}.json"
if [ -f "$RECORD" ]; then
  REC_REG=$(jq -re .registration_program_id "$RECORD"); REC_MRK=$(jq -re .merkle_program_id "$RECORD")
  [ "$REC_REG" = "$WANT_REG" ] || fail "registration program id differs from the record $RECORD
  descriptor: $WANT_REG
  record:     $REC_REG"
  [ "$REC_MRK" = "$WANT_MRK" ] || fail "merkle program id differs from the record $RECORD
  descriptor: $WANT_MRK
  record:     $REC_MRK"
  RECORD_NOTE="program ids match $RECORD"
else
  RECORD_NOTE="no record at $RECORD (program ids not cross-checked)"
fi

if jq -e '.planned == true' "$DEP_DIR/deployment.json" >/dev/null; then
  echo "verify: OK  $(f name)  PLANNED, not deployed: config re-derives from the descriptor's ids; $OWNER_NOTE; $RECORD_NOTE."
  exit 0
fi

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
bash "$HERE/stage.sh" "$DEP_DIR" "$tmp" >/dev/null

echo "verify: OK  $(f name)  config re-derives from the descriptor's ids; $OWNER_NOTE; $RECORD_NOTE; wallet binding holds."
