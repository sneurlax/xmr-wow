#!/usr/bin/env bash
# run-live-network-harness.sh: Live-network E2E harness for XMR<->WOW atomic swaps.
#
# Usage:
#   ./scripts/run-live-network-harness.sh [oob|sharechain] [--cleanup]
#
# Prerequisites:
#   - XMR stagenet daemon at http://127.0.0.1:38081
#   - WOW mainnet daemon at http://127.0.0.1:34568
#   - sharechain mode only: xmr-wow-node at http://127.0.0.1:18091
#   - Binary: cargo build --release -p xmr-wow-client
#   - Funded wallets and env vars set (see Environment variables below)
#
# Environment variables:
#   ALICE_XMR_REFUND  XMR stagenet refund address (Alice)
#   ALICE_WOW_DEST    WOW mainnet destination address (Alice)
#   BOB_WOW_REFUND    WOW mainnet refund address (Bob)
#   BOB_XMR_DEST      XMR stagenet destination address (Bob)
#   ALICE_SPEND_KEY / ALICE_VIEW_KEY  Alice's XMR keys (hex); or ALICE_MNEMONIC
#   BOB_SPEND_KEY / BOB_VIEW_KEY      Bob's WOW keys (hex); or BOB_MNEMONIC
#   AMOUNT_XMR        XMR atomic units (default: 1000000000 = 0.001 XMR)
#   AMOUNT_WOW        WOW atomic units (default: 1000000000000 = 1.0 WOW)
#   *_SCAN_FROM       Block height to start wallet scan (avoids full rescan)
#   RUN_DIR           Override run artifact directory
#
# Stdout/stderr are captured to separate files per step: tracing output on
# stderr would otherwise corrupt the xmrwow1: base64 messages on stdout.
#
# Swap DBs are NOT deleted on success; they are proof artifacts for the run.
# Pass --cleanup to remove the run directory on exit.

set -euo pipefail

TRANSPORT_ARG="${1:-oob}"
CLEANUP=false

for arg in "$@"; do
  case "$arg" in
    --cleanup) CLEANUP=true ;;
  esac
done

case "$TRANSPORT_ARG" in
  oob|out-of-band)
    TRANSPORT_MODE="out-of-band"
    ;;
  sharechain)
    TRANSPORT_MODE="sharechain"
    ;;
  --cleanup)
    TRANSPORT_MODE="out-of-band"
    ;;
  *)
    echo "Usage: $0 [oob|sharechain] [--cleanup]" >&2
    echo "  oob        Use out-of-band copy-paste transport (default)" >&2
    echo "  sharechain Use sharechain node transport (requires --node-url)" >&2
    exit 2
    ;;
esac

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BINARY="${XMR_WOW_BIN:-${ROOT_DIR}/target/release/xmr-wow}"

XMR_DAEMON_URL="${XMR_DAEMON_URL:-http://127.0.0.1:38081}"
WOW_DAEMON_URL="${WOW_DAEMON_URL:-http://127.0.0.1:34568}"
NODE_URL="${NODE_URL:-http://127.0.0.1:18091}"

# Alice locks XMR (stagenet) and receives WOW; Bob locks WOW (mainnet) and receives XMR.
ALICE_XMR_REFUND="${ALICE_XMR_REFUND:-}"
ALICE_WOW_DEST="${ALICE_WOW_DEST:-}"
BOB_WOW_REFUND="${BOB_WOW_REFUND:-}"
BOB_XMR_DEST="${BOB_XMR_DEST:-}"

ALICE_SPEND_KEY="${ALICE_SPEND_KEY:-}"
ALICE_VIEW_KEY="${ALICE_VIEW_KEY:-}"
ALICE_MNEMONIC="${ALICE_MNEMONIC:-}"            # alternative to spend/view key pair

BOB_SPEND_KEY="${BOB_SPEND_KEY:-}"
BOB_VIEW_KEY="${BOB_VIEW_KEY:-}"
BOB_MNEMONIC="${BOB_MNEMONIC:-}"                # alternative to spend/view key pair

ALICE_PW="${ALICE_PW:-alice-test-password}"
BOB_PW="${BOB_PW:-bob-test-password}"

# 0.001 XMR / 1.0 WOW in atomic units
AMOUNT_XMR="${AMOUNT_XMR:-1000000000}"
AMOUNT_WOW="${AMOUNT_WOW:-1000000000000}"

# Set to recent block heights to avoid full rescans
ALICE_XMR_SCAN_FROM="${ALICE_XMR_SCAN_FROM:-0}"
BOB_WOW_SCAN_FROM="${BOB_WOW_SCAN_FROM:-0}"
ALICE_WOW_SCAN_FROM="${ALICE_WOW_SCAN_FROM:-0}"
BOB_XMR_SCAN_FROM="${BOB_XMR_SCAN_FROM:-0}"

RUN_DIR="${RUN_DIR:-${ROOT_DIR}/scripts/live-network/runs/$(date -u +%Y%m%dT%H%M%SZ)}"

ALICE_DB="${RUN_DIR}/alice-swaps.db"
BOB_DB="${RUN_DIR}/bob-swaps.db"

if [[ "$TRANSPORT_MODE" == "out-of-band" ]]; then
  TRANSPORT_FLAGS="--transport out-of-band"
else
  TRANSPORT_FLAGS="--transport sharechain --node-url ${NODE_URL}"
fi

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
ok()  { printf '[OK] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

require_env() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "$value" ]]; then
    fail "Required env var not set: ${name}. See script header for documentation."
  fi
}

preflight() {
  log "Running preflight checks..."

  if [[ ! -x "$BINARY" ]]; then
    fail "Binary not found or not executable: ${BINARY}. Run: cargo build --release -p xmr-wow-client"
  fi
  ok "Binary: ${BINARY}"

  if ! curl -sf --max-time 5 \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' \
      -H 'Content-Type: application/json' \
      "${XMR_DAEMON_URL}/json_rpc" >/dev/null 2>&1; then
    fail "XMR daemon not responding at ${XMR_DAEMON_URL}. Start your XMR stagenet daemon."
  fi
  ok "XMR daemon: ${XMR_DAEMON_URL}"

  if ! curl -sf --max-time 5 \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' \
      -H 'Content-Type: application/json' \
      "${WOW_DAEMON_URL}/json_rpc" >/dev/null 2>&1; then
    fail "WOW daemon not responding at ${WOW_DAEMON_URL}. Start your WOW mainnet daemon."
  fi
  ok "WOW daemon: ${WOW_DAEMON_URL}"

  if [[ "$TRANSPORT_MODE" == "sharechain" ]]; then
    if ! curl -sf --max-time 5 "${NODE_URL}/" >/dev/null 2>&1; then
      fail "Sharechain node not responding at ${NODE_URL}. Start xmr-wow-node."
    fi
    ok "Sharechain node: ${NODE_URL}"
  fi

  require_env ALICE_XMR_REFUND
  require_env ALICE_WOW_DEST
  require_env BOB_WOW_REFUND
  require_env BOB_XMR_DEST

  if [[ -z "$ALICE_MNEMONIC" ]]; then
    require_env ALICE_SPEND_KEY
    require_env ALICE_VIEW_KEY
  fi

  if [[ -z "$BOB_MNEMONIC" ]]; then
    require_env BOB_SPEND_KEY
    require_env BOB_VIEW_KEY
  fi

  log "All preflight checks passed."
}

step_init_alice() {
  log "Step 1: init-alice"

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$ALICE_PW" --db "$ALICE_DB" \
    init-alice \
    --amount-xmr "$AMOUNT_XMR" \
    --amount-wow "$AMOUNT_WOW" \
    --xmr-daemon "$XMR_DAEMON_URL" \
    --wow-daemon "$WOW_DAEMON_URL" \
    --alice-refund-address "$ALICE_XMR_REFUND" \
    > "${RUN_DIR}/init-alice.stdout" \
    2> "${RUN_DIR}/init-alice.stderr"

  # grep stdout only: stderr carries tracing logs that would corrupt the match
  ALICE_INIT_MSG="$(grep '^xmrwow1:' "${RUN_DIR}/init-alice.stdout" | head -1)"
  if [[ -z "$ALICE_INIT_MSG" ]]; then
    cat "${RUN_DIR}/init-alice.stderr" >&2
    fail "No xmrwow1: message in init-alice output"
  fi

  TEMP_SWAP_ID="$(awk '/Temp swap ID:/ {print $NF}' "${RUN_DIR}/init-alice.stdout")"
  if [[ -z "$TEMP_SWAP_ID" ]]; then
    fail "Could not parse Temp swap ID from init-alice output"
  fi

  ok "Step 1: init-alice completed (temp swap ID: ${TEMP_SWAP_ID})"
}

step_init_bob() {
  log "Step 2: init-bob"

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$BOB_PW" --db "$BOB_DB" \
    init-bob \
    --message "$ALICE_INIT_MSG" \
    --bob-refund-address "$BOB_WOW_REFUND" \
    > "${RUN_DIR}/init-bob.stdout" \
    2> "${RUN_DIR}/init-bob.stderr"

  BOB_RESPONSE_MSG="$(grep '^xmrwow1:' "${RUN_DIR}/init-bob.stdout" | head -1)"
  if [[ -z "$BOB_RESPONSE_MSG" ]]; then
    cat "${RUN_DIR}/init-bob.stderr" >&2
    fail "No xmrwow1: message in init-bob output"
  fi

  BOB_SWAP_ID="$(awk '/^Swap ID:/ {print $NF}' "${RUN_DIR}/init-bob.stdout")"
  if [[ -z "$BOB_SWAP_ID" ]]; then
    fail "Could not parse Bob swap ID from init-bob output"
  fi

  ok "Step 2: init-bob completed (Bob swap ID: ${BOB_SWAP_ID})"
}

step_import() {
  log "Step 3: import (Alice imports Bob's response)"

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$ALICE_PW" --db "$ALICE_DB" \
    import \
    --swap-id "$TEMP_SWAP_ID" \
    --message "$BOB_RESPONSE_MSG" \
    > "${RUN_DIR}/import.stdout" \
    2> "${RUN_DIR}/import.stderr"

  ALICE_SWAP_ID="$(awk '/^Swap ID:/ {print $NF}' "${RUN_DIR}/import.stdout")"
  if [[ -z "$ALICE_SWAP_ID" ]]; then
    # fallback pattern for alternate output format
    ALICE_SWAP_ID="$(awk '/swap.id/ {print $NF}' "${RUN_DIR}/import.stdout" | head -1)"
  fi
  if [[ -z "$ALICE_SWAP_ID" ]]; then
    fail "Could not parse Alice swap ID from import output"
  fi

  ok "Step 3: import completed (Alice swap ID: ${ALICE_SWAP_ID})"
}

step_lock_wow() {
  log "Step 4: lock-wow (Bob locks WOW first: lock-order safety)"

  local bob_wallet_args=()
  if [[ -n "$BOB_MNEMONIC" ]]; then
    bob_wallet_args=(--mnemonic "$BOB_MNEMONIC")
  else
    bob_wallet_args=(--spend-key "$BOB_SPEND_KEY" --view-key "$BOB_VIEW_KEY")
  fi

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$BOB_PW" --db "$BOB_DB" \
    lock-wow \
    --swap-id "$BOB_SWAP_ID" \
    --wow-daemon "$WOW_DAEMON_URL" \
    --scan-from "$BOB_WOW_SCAN_FROM" \
    "${bob_wallet_args[@]}" \
    > "${RUN_DIR}/lock-wow.stdout" \
    2> "${RUN_DIR}/lock-wow.stderr"

  ok "Step 4: lock-wow completed"
}

step_lock_xmr() {
  log "Step 5: lock-xmr (Alice locks XMR after verifying Bob's WOW lock)"

  local alice_wallet_args=()
  if [[ -n "$ALICE_MNEMONIC" ]]; then
    alice_wallet_args=(--mnemonic "$ALICE_MNEMONIC")
  else
    alice_wallet_args=(--spend-key "$ALICE_SPEND_KEY" --view-key "$ALICE_VIEW_KEY")
  fi

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$ALICE_PW" --db "$ALICE_DB" \
    lock-xmr \
    --swap-id "$ALICE_SWAP_ID" \
    --xmr-daemon "$XMR_DAEMON_URL" \
    --wow-daemon "$WOW_DAEMON_URL" \
    --scan-from "$ALICE_XMR_SCAN_FROM" \
    "${alice_wallet_args[@]}" \
    > "${RUN_DIR}/lock-xmr.stdout" \
    2> "${RUN_DIR}/lock-xmr.stderr"

  ok "Step 5: lock-xmr completed"
}

step_exchange_pre_sig() {
  log "Step 6a: exchange-pre-sig (Alice sends pre-sig to Bob)"

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$ALICE_PW" --db "$ALICE_DB" \
    exchange-pre-sig \
    --swap-id "$ALICE_SWAP_ID" \
    --message "" \
    > "${RUN_DIR}/exchange-pre-sig-alice.stdout" \
    2> "${RUN_DIR}/exchange-pre-sig-alice.stderr" || true

  ALICE_PRESIG_MSG="$(grep '^xmrwow1:' "${RUN_DIR}/exchange-pre-sig-alice.stdout" | head -1)"

  log "Step 6b: exchange-pre-sig (Bob receives Alice's pre-sig, sends his)"

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$BOB_PW" --db "$BOB_DB" \
    exchange-pre-sig \
    --swap-id "$BOB_SWAP_ID" \
    --message "${ALICE_PRESIG_MSG:-}" \
    > "${RUN_DIR}/exchange-pre-sig-bob.stdout" \
    2> "${RUN_DIR}/exchange-pre-sig-bob.stderr"

  BOB_PRESIG_MSG="$(grep '^xmrwow1:' "${RUN_DIR}/exchange-pre-sig-bob.stdout" | head -1)"
  if [[ -z "$BOB_PRESIG_MSG" ]]; then
    cat "${RUN_DIR}/exchange-pre-sig-bob.stderr" >&2
    fail "No xmrwow1: message from Bob exchange-pre-sig"
  fi

  ok "Step 6: exchange-pre-sig completed"
}

step_claim_wow() {
  log "Step 7: claim-wow (Alice claims WOW using Bob's completed adaptor sig)"

  "$BINARY" $TRANSPORT_FLAGS \
    --password "$ALICE_PW" --db "$ALICE_DB" \
    claim-wow \
    --swap-id "$ALICE_SWAP_ID" \
    --wow-daemon "$WOW_DAEMON_URL" \
    --message "$BOB_PRESIG_MSG" \
    --destination "$ALICE_WOW_DEST" \
    --scan-from "$ALICE_WOW_SCAN_FROM" \
    > "${RUN_DIR}/claim-wow.stdout" \
    2> "${RUN_DIR}/claim-wow.stderr"

  # Alice's WOW claim reveals her spend key contribution on-chain; capture proof msg
  ALICE_CLAIM_PROOF_MSG="$(grep '^xmrwow1:' "${RUN_DIR}/claim-wow.stdout" | head -1)"

  ok "Step 7: claim-wow completed"
}

step_claim_xmr() {
  log "Step 8: claim-xmr (Bob claims XMR using Alice's claim proof)"

  # claim-xmr derives the full adaptor sig from the on-chain WOW transaction;
  # falls back to Alice's pre-sig if no explicit claim proof was captured.
  "$BINARY" $TRANSPORT_FLAGS \
    --password "$BOB_PW" --db "$BOB_DB" \
    claim-xmr \
    --swap-id "$BOB_SWAP_ID" \
    --xmr-daemon "$XMR_DAEMON_URL" \
    --message "${ALICE_CLAIM_PROOF_MSG:-$ALICE_PRESIG_MSG}" \
    --destination "$BOB_XMR_DEST" \
    --scan-from "$BOB_XMR_SCAN_FROM" \
    > "${RUN_DIR}/claim-xmr.stdout" \
    2> "${RUN_DIR}/claim-xmr.stderr"

  ok "Step 8: claim-xmr completed"
}

cleanup_on_exit() {
  if [[ "$CLEANUP" == "true" ]]; then
    log "Cleaning up run directory: ${RUN_DIR}"
    rm -rf "$RUN_DIR"
  fi
}
trap cleanup_on_exit EXIT

echo "=== XMR-WOW E2E Live Network Harness ==="
echo "Transport: ${TRANSPORT_MODE}"
echo "XMR daemon: ${XMR_DAEMON_URL}"
echo "WOW daemon: ${WOW_DAEMON_URL}"
if [[ "$TRANSPORT_MODE" == "sharechain" ]]; then
  echo "Sharechain node: ${NODE_URL}"
fi

preflight

mkdir -p "$RUN_DIR"
echo "Run dir: ${RUN_DIR}"
echo ""

ALICE_INIT_MSG=""
BOB_RESPONSE_MSG=""
TEMP_SWAP_ID=""
BOB_SWAP_ID=""
ALICE_SWAP_ID=""
ALICE_PRESIG_MSG=""
BOB_PRESIG_MSG=""
ALICE_CLAIM_PROOF_MSG=""

# Bob locks WOW first, Alice locks XMR second (lock-order safety invariant)
step_init_alice
step_init_bob
step_import

echo ""
echo "=== Swap IDs ==="
echo "Alice swap ID: ${ALICE_SWAP_ID}"
echo "Bob swap ID:   ${BOB_SWAP_ID}"
echo ""
echo "NOTE: lock-wow, lock-xmr, exchange-pre-sig, and claim steps require"
echo "funded wallets and live daemon interaction. They may fail if wallets"
echo "are not funded or daemons are not synced."
echo ""

step_lock_wow
step_lock_xmr
step_exchange_pre_sig
step_claim_wow
step_claim_xmr

echo ""
echo "=== ALL STEPS COMPLETED ==="
echo "Artifacts in: ${RUN_DIR}"
echo ""
echo "Per-step artifacts:"
ls -lh "${RUN_DIR}/" 2>/dev/null || true
echo ""
echo "Swap DBs (proof artifacts):"
echo "  Alice: ${ALICE_DB}"
echo "  Bob:   ${BOB_DB}"
echo ""
echo "To inspect swap state:"
echo "  ${BINARY} --password \"\$ALICE_PW\" --db \"${ALICE_DB}\" list"
echo "  ${BINARY} --password \"\$BOB_PW\" --db \"${BOB_DB}\" list"
