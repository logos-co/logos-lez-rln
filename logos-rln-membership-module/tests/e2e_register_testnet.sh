#!/usr/bin/env bash
# End-to-end registration test IN LOGOS-CORE against the deployed testnet
# registry. Loads the real module stack into a logoscore daemon
# (logos_execution_zone -> liblogos_rln_module -> liblogos_rln_membership_module)
# and drives a PAID registration through the membership module's spec
# surface — the faucet-funded Register instruction, NOT the gifter's
# RegisterFree path:
#
#   open wallet -> sync -> derive fresh holding -> claim_tokens (faucet)
#   -> generate_identity -> unlock_keystore -> register (membership module)
#   -> poll get_membership_state to "active" -> select_membership
#   -> get_merkle_proof -> cross-check via liblogos_rln_module.get_membership
#
# Besides the registration itself this is the acceptance for two open
# architecture risks:
#   R2 — lp_* calls INTO a Rust module (membership -> rln over the raw lp
#        client). A provider_failure on every membership call while direct
#        liblogos_rln_module calls succeed means the lp transport to Rust
#        modules is broken -> fall back to the generated typed client.
#   R4 — the host stamping instance_persistence_path. unlock_keystore
#        failing with kind "internal" (no persistence path) means logoscore
#        does not provide one -> the module needs an explicit override.
#
# Cost & duration: one registration at rate_limit=100 burns
# 100 x price_per_unit (1M RLNTOK on shared-faucet) from a fresh faucet
# claim; the run takes ~3-6 min (testnet confirmation is 60-90s).
#
# Usage:  bash tests/e2e_register_testnet.sh
# Env:
#   E2E_DEPLOYMENT=shared-faucet   descriptor under <repo>/deployments/
#   WALLET_LGX / RLN_LGX / MEMBERSHIP_LGX   prebuilt bundles (else nix build)
#   LOGOSCORE=<bin>                logoscore CLI (else nix build the flake)
#   E2E_RATE_LIMIT=100             registration rate limit
#   E2E_KEEP=1                     keep daemon + state dir for debugging
#   CALL_TIMEOUT=180               per-call timeout (seconds)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPLOYMENT="${E2E_DEPLOYMENT:-shared-faucet}"
RATE_LIMIT="${E2E_RATE_LIMIT:-100}"
CALL_TIMEOUT="${CALL_TIMEOUT:-180}"

log()  { printf '%s\n' "e2e: $*"; }
DAEMON_PID=""
WORK=""
die() {
    printf '%s\n' "e2e: FAIL: $*" >&2
    if [ -n "${DAEMON_LOG:-}" ] && [ -f "$DAEMON_LOG" ]; then
        echo "---- daemon log tail ----" >&2
        tail -40 "$DAEMON_LOG" >&2 || true
    fi
    exit 1
}
cleanup() {
    if [ "${E2E_KEEP:-0}" = "1" ]; then
        log "E2E_KEEP=1: daemon pid ${DAEMON_PID:-<none>}, state in ${WORK:-<none>}"
        return
    fi
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
    [ -n "${MDIR:-}" ] && pkill -f "logoscore -m $MDIR" 2>/dev/null || true
    [ -n "$WORK" ] && rm -rf "$WORK"
}
trap cleanup EXIT

for tool in nix jq python3 tar curl openssl rsync; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  PLATFORM="darwin-arm64-dev" ;;
  Linux-x86_64)  PLATFORM="linux-x86_64-dev" ;;
  Linux-aarch64) PLATFORM="linux-aarch64-dev" ;;
  *) die "unsupported platform $(uname -s)-$(uname -m)" ;;
esac

# ---------- fixtures: stage the deployment into an isolated wallet home ----
# pwd -P: nix's path fetcher refuses symlinked ancestors (macOS /var -> /private/var).
WORK=$(mktemp -d)
WORK=$(cd "$WORK" && pwd -P)
WALLET_HOME="$WORK/wallet-home"
log "staging deployments/$DEPLOYMENT -> $WALLET_HOME"
bash "$ROOT/tools/deployments/stage.sh" "$ROOT/deployments/$DEPLOYMENT" "$WALLET_HOME" >/dev/null \
    || die "stage.sh failed for deployments/$DEPLOYMENT"
FUNDING=$(tr -d '\n\r' < "$WALLET_HOME/funding.txt")
[ "$FUNDING" = "faucet" ] || die "deployment '$DEPLOYMENT' funding=$FUNDING — this test exercises the faucet-paid path (no gifter); pick a faucet deployment"
cp "$WALLET_HOME/storage.json.seed" "$WALLET_HOME/storage.json"
CONFIG_ACCOUNT=$(tr -d '\n\r' < "$WALLET_HOME/config_account.txt")
TREE_ID_HEX=$(grep -oE 'LEZ_RLN_TREE_ID_HEX=[0-9a-f]{64}' "$WALLET_HOME/env.sh" | cut -d= -f2)
SEQUENCER=$(jq -r .sequencer_addr "$WALLET_HOME/wallet_config.json")
[ -n "$CONFIG_ACCOUNT" ] && [ -n "$TREE_ID_HEX" ] && [ -n "$SEQUENCER" ] || die "staged fixtures incomplete"

CONFIG_HEX=$(python3 - "$CONFIG_ACCOUNT" <<'EOF'
import sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = 0
for c in sys.argv[1]:
    n = n * 58 + A.index(c)
print(n.to_bytes(32, "big").hex())
EOF
)
REGISTRY_ID="logos:testnet:$CONFIG_HEX"
log "registry: $REGISTRY_ID (tree ${TREE_ID_HEX:0:8}…, sequencer $SEQUENCER)"

# ---------- binaries + bundles ---------------------------------------------
LOGOSCORE="${LOGOSCORE:-$(nix build github:logos-co/logos-logoscore-cli --no-link --print-out-paths)/bin/logoscore}"
[ -x "$LOGOSCORE" ] || die "logoscore not executable: $LOGOSCORE"

# Staged sources are gitignored; both module builds need them present, and
# the --override-input path: trees make them visible to nix.
for mod in logos-rln-module logos-rln-membership-module; do
    if [ ! -d "$ROOT/$mod/logos-rust-sdk-src" ]; then
        log "staging SDK sources for $mod"
        (cd "$ROOT/$mod" && ./stage-sources.sh >/dev/null) || die "$mod/stage-sources.sh failed"
    fi
done

lgx_of() {
    local out; out=$(find "$1/" -maxdepth 1 -name '*.lgx' | head -1)
    [ -f "$out" ] || die "no .lgx under $1"
    printf '%s' "$out"
}
# Build a module's .lgx via the root flake with the input overridden to a
# FILTERED copy of the module tree. The copy carries the working tree
# verbatim — uncommitted changes AND the gitignored staged sources the
# build needs — minus target/result/.git: a raw `path:` override copies
# rust-lib/target (~1 GB of local cargo artifacts) into /nix/store on every
# eval and fills the disk (the documented staging hazard). Nix content-
# addresses the copy, so unchanged trees rebuild for free.
module_lgx() {
    local mod="$1" attr="$2"
    local src="$WORK/src-$mod"
    log "$mod: building .#$attr from a filtered source copy" >&2
    rsync -a --exclude 'rust-lib/target' --exclude 'result*' --exclude '.git' \
        "$ROOT/$mod/" "$src/" || die "rsync $mod failed"
    local out
    out=$(cd "$ROOT" && nix build --no-link --print-out-paths ".#$attr" \
        --override-input "$mod" "path:$src") || die "nix build .#$attr failed"
    lgx_of "$out"
}
if [ -z "${WALLET_LGX:-}" ]; then
    log "building wallet-module .lgx (root flake pin)"
    _out=$(cd "$ROOT" && nix build --no-link --print-out-paths '.#wallet-module') \
        || die "nix build .#wallet-module failed"
    WALLET_LGX=$(lgx_of "$_out")
fi
[ -n "${RLN_LGX:-}" ] || RLN_LGX=$(module_lgx logos-rln-module logos-rln-module-lgx)
[ -n "${MEMBERSHIP_LGX:-}" ] || MEMBERSHIP_LGX=$(module_lgx logos-rln-membership-module logos-rln-membership-module-lgx)
log "bundles: $(basename "$WALLET_LGX"), $(basename "$RLN_LGX"), $(basename "$MEMBERSHIP_LGX")"

# ---------- install + daemon ------------------------------------------------
MDIR="$WORK/modules"
mkdir -p "$MDIR"
install_lgx() {
    local lgx="$1" name tmp
    name=$(tar xzOf "$lgx" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')
    [ -n "$name" ] || die "install_lgx: cannot read name from $lgx"
    tmp=$(mktemp -d)
    tar xzf "$lgx" -C "$tmp"
    mkdir -p "$MDIR/$name"
    cp "$tmp/manifest.json" "$MDIR/$name/"
    [ -d "$tmp/variants/$PLATFORM" ] || die "install_lgx: $lgx has no variants/$PLATFORM"
    cp -L "$tmp/variants/$PLATFORM/"* "$MDIR/$name/"
    printf '%s' "$PLATFORM" > "$MDIR/$name/variant"
    rm -rf "$tmp"
}
install_lgx "$WALLET_LGX"
install_lgx "$RLN_LGX"
install_lgx "$MEMBERSHIP_LGX"

CFG_DIR="$WORK/logoscore-cfg"
DAEMON_LOG="$WORK/daemon.log"
mkdir -p "$CFG_DIR"
log "starting logoscore daemon"
# env -i: Qt strips DYLD_* otherwise, and daemon+client must agree on the
# effective TMPDIR (QLocalSocket path) — see the sim harness for the history.
# LEZ_RLN_TREE_ID_HEX must survive into the daemon: rln_core derives PDAs
# from it.
(cd "$WORK" && env -i HOME="$HOME" PATH="$PATH" LOGOSCORE_CONFIG_DIR="$CFG_DIR" \
    RUST_BACKTRACE=full LEZ_RLN_TREE_ID_HEX="$TREE_ID_HEX" \
    "$LOGOSCORE" -m "$MDIR" -D </dev/null >>"$DAEMON_LOG" 2>&1) &
DAEMON_PID=$!
disown "$DAEMON_PID" 2>/dev/null || true

for _t in $(seq 1 60); do
    [ -f "$CFG_DIR/client/config.json" ] && break
    sleep 1
done
[ -f "$CFG_DIR/client/config.json" ] || die "daemon produced no client config"
for _t in $(seq 1 60); do
    timeout 5 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$CFG_DIR" "$LOGOSCORE" --quiet --json list-modules 2>/dev/null \
        | grep -q '"capability_module".*"loaded"' && break
    sleep 1
done
sleep 5

for mod in logos_execution_zone liblogos_rln_module liblogos_rln_membership_module; do
    log "load-module $mod"
    timeout 30 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$CFG_DIR" "$LOGOSCORE" --json load-module "$mod" \
        >>"$DAEMON_LOG" 2>&1 || die "load-module $mod failed"
done

# ---------- call plumbing ----------------------------------------------------
ARGS_DIR="$WORK/args"
mkdir -p "$ARGS_DIR"
# Digit-leading strings (base58 accounts, hex) must go via @file or the CLI
# coerces them to numbers.
argfile() { printf '%s' "$2" > "$ARGS_DIR/$1.arg"; printf '@%s' "$ARGS_DIR/$1.arg"; }
call_json() {
    local mod="$1" meth="$2"; shift 2
    timeout "$CALL_TIMEOUT" env -u TMPDIR LOGOSCORE_CONFIG_DIR="$CFG_DIR" \
        "$LOGOSCORE" --json call "$mod" "$meth" "$@" 2>/dev/null
}
jres() {
    python3 -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get("status") == "ok" and "result" in d:
        r = d["result"]
        print(r if isinstance(r, str) else json.dumps(r))
        break
'
}
jfield() { python3 -c "
import json, sys
try:
    print(json.load(sys.stdin).get('$1', ''))
except Exception:
    print('')
"; }

# ---------- wallet: open + sync ---------------------------------------------
log "opening wallet"
call_json logos_execution_zone open "$WALLET_HOME/wallet_config.json" "$WALLET_HOME/storage.json" \
    >>"$DAEMON_LOG" 2>&1 || die "wallet open failed"
CHAIN_HEAD=$(curl -sS -m 10 -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"getLastBlockId","params":[],"id":1}' \
    "$SEQUENCER" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])') \
    || die "cannot probe chain head at $SEQUENCER"
log "syncing wallet to chain head $CHAIN_HEAD"
call_json logos_execution_zone sync_to_block "$CHAIN_HEAD" >>"$DAEMON_LOG" 2>&1 || true

# ---------- faucet funding (Register-instruction path, no gifter) -----------
log "deriving a fresh holding account"
HOLDING=""
for _t in $(seq 1 30); do
    ACC=$(call_json logos_execution_zone create_account_public | jres) || ACC=""
    [ -n "$ACC" ] || { sleep 2; continue; }
    BAL_JSON=$(call_json liblogos_rln_module get_token_balance "$(argfile acc "$ACC")" | jres) || BAL_JSON=""
    case "$BAL_JSON" in
        *'"exists":false'*) HOLDING="$ACC"; break ;;
    esac
done
[ -n "$HOLDING" ] || die "no unused holding account after 30 derivations"
log "holding: $HOLDING"

# rate_limit x price_per_unit, doubled for slack — read the live price from
# the v1.1 bounds method rather than hardcoding the deployment's tariff.
BOUNDS=$(call_json liblogos_rln_module get_registry_bounds "$(argfile cfg "$CONFIG_ACCOUNT")" | jres) || BOUNDS=""
[ -n "$BOUNDS" ] || die "get_registry_bounds failed (rln module up?)"
PRICE=$(printf '%s' "$BOUNDS" | jfield price_per_unit)
[ -n "$PRICE" ] || die "no price_per_unit in bounds: $BOUNDS"
CLAIM=$(( RATE_LIMIT * PRICE * 2 ))
log "claiming $CLAIM RLNTOK from the faucet (rate $RATE_LIMIT x price $PRICE x2)"
CLAIM_RES=$(call_json liblogos_rln_module claim_tokens \
    "$(argfile cfg2 "$CONFIG_ACCOUNT")" "$(argfile hold "$HOLDING")" "$CLAIM" | jres) || CLAIM_RES=""
[ -n "$CLAIM_RES" ] || die "claim_tokens failed"
BAL=0
for _t in $(seq 1 36); do
    BAL_JSON=$(call_json liblogos_rln_module get_token_balance "$(argfile hold2 "$HOLDING")" | jres) || BAL_JSON=""
    BAL=$(printf '%s' "$BAL_JSON" | jfield balance); BAL=${BAL:-0}
    log "  credit poll $_t: balance=$BAL"
    [ "$BAL" -ge "$CLAIM" ] 2>/dev/null && break
    sleep 5
done
[ "$BAL" -ge "$CLAIM" ] 2>/dev/null || die "faucet credit never landed (balance=$BAL want $CLAIM)"

# ---------- identity (consumer-side, per spec) -------------------------------
SEED=$(openssl rand -hex 32)
ID_JSON=$(call_json liblogos_rln_module generate_identity "$(argfile seed "$SEED")" | jres) || ID_JSON=""
COMMITMENT=$(printf '%s' "$ID_JSON" | jfield id_commitment)
SECRET=$(printf '%s' "$ID_JSON" | jfield id_secret_hash)
[ -n "$COMMITMENT" ] && [ -n "$SECRET" ] || die "generate_identity failed: $ID_JSON"
log "identity commitment: ${COMMITMENT:0:16}…"

# ---------- the registration, through the membership module -----------------
UNLOCK=$(call_json liblogos_rln_membership_module unlock_keystore e2e-test-password | jres) || UNLOCK=""
case "$UNLOCK" in
    *'"unlocked":true'*) log "keystore unlocked" ;;
    *'no persistence path'*|*'not initialized'*)
        die "R4 CONFIRMED: host provides no instance_persistence_path — unlock said: $UNLOCK" ;;
    *) die "unlock_keystore failed: ${UNLOCK:-<empty>}" ;;
esac

CRED_JSON="{\"identity_commitment\":\"$COMMITMENT\",\"identity_secret_hash\":\"$SECRET\"}"
OPTIONS_JSON="{\"funding_holding_account_id\":\"$HOLDING\"}"
log "register($REGISTRY_ID, rate $RATE_LIMIT) via membership module"
REG=$(call_json liblogos_rln_membership_module register \
    "$REGISTRY_ID" "$CRED_JSON" "$RATE_LIMIT" "$OPTIONS_JSON" | jres) || REG=""
case "$REG" in
    *'"state":"pending"'*) ;;
    *'provider_failure'*)
        die "R2 CONFIRMED?: membership->rln lp transport failed. Reply: $REG — check whether direct liblogos_rln_module calls above succeeded (they did if you see this), which isolates the fault to lp calls INTO a Rust module. Fallback: generated typed client." ;;
    *) die "register failed: ${REG:-<empty>}" ;;
esac
MEMBERSHIP_HASH=$(printf '%s' "$REG" | jfield membership_hash)
log "pending membership: $MEMBERSHIP_HASH"

log "polling get_membership_state to active (testnet confirmation 60-90s)…"
STATE=""
for _t in $(seq 1 60); do
    STATE_JSON=$(call_json liblogos_rln_membership_module get_membership_state \
        "$REGISTRY_ID" "$(argfile commit "$COMMITMENT")" | jres) || STATE_JSON=""
    STATE=$(printf '%s' "$STATE_JSON" | jfield state)
    log "  state poll $_t: ${STATE:-<none>}"
    case "$STATE" in
        active|grace_period) break ;;
        failed) die "registration FAILED: $(call_json liblogos_rln_membership_module get_memberships "$REGISTRY_ID" | jres)" ;;
    esac
    sleep 10
done
[ "$STATE" = "active" ] || [ "$STATE" = "grace_period" ] \
    || die "membership never became active (last state: ${STATE:-<none>})"
LEAF=$(printf '%s' "$STATE_JSON" | jfield leaf_index)
log "ACTIVE at leaf $LEAF"

# ---------- post-registration surface ----------------------------------------
RLN_ID=$(openssl rand -hex 32)
SELECTED=$(call_json liblogos_rln_membership_module select_membership \
    "$REGISTRY_ID" "$(argfile rlnid "$RLN_ID")" "" | jres) || SELECTED=""
case "$SELECTED" in
    *"$SECRET"*) log "select_membership released the credential" ;;
    *) die "select_membership did not return the registered credential: ${SELECTED:-<empty>}" ;;
esac

PROOF=$(call_json liblogos_rln_membership_module get_merkle_proof "$REGISTRY_ID" "$LEAF" | jres) || PROOF=""
case "$PROOF" in
    *'"valid_roots"'*) log "get_merkle_proof returned a rooted proof" ;;
    *) die "get_merkle_proof failed: ${PROOF:-<empty>}" ;;
esac

CROSS=$(call_json liblogos_rln_module get_membership \
    "$(argfile cfg3 "$CONFIG_ACCOUNT")" "$(argfile commit2 "$COMMITMENT")" | jres) || CROSS=""
case "$CROSS" in
    *'"registered":true'*) log "cross-check: rln module sees the membership ($(printf '%s' "$CROSS" | jfield state))" ;;
    *) die "cross-check get_membership failed: ${CROSS:-<empty>}" ;;
esac

echo
echo "e2e: PASS — registered on $REGISTRY_ID"
echo "e2e:   membership_hash $MEMBERSHIP_HASH"
echo "e2e:   leaf_index      $LEAF"
echo "e2e:   funded by       $HOLDING (faucet claim, no gifter)"
