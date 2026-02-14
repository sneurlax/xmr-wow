#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN=false
RUN_DIR=""

usage() {
  cat <<'USAGE'
Usage: scripts/run-live-network-harness.sh [--dry-run] [--run-dir <path>]

Automated single-machine harness for the live-network flow:
  publish-offer -> accept-offer -> init-alice -> init-bob -> import -> lock-wow -> lock-xmr ->
  exchange-pre-sig -> (bob claim-xmr publishes claim proof) -> alice claim-wow -> bob claim-xmr completes

Safety:
  - Reads all secrets from environment variables (never hardcoded).
  - Requires XMR_WOW_LIVE_CONFIRM=1 to run live mode.
  - Runs daemon + sharechain preflight BEFORE creating swap DB files.

See docs/DEPLOYMENT.md for daemon setup prerequisites.

Options:
  --dry-run           Print required env vars and exit 0 (no network calls).
  --run-dir <path>    Directory for logs + swap DBs (default: .planning/reports/live-harness-<ts>).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --run-dir) RUN_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

XMR_WOW_BIN="${XMR_WOW_BIN:-$ROOT_DIR/target/release/xmr-wow}"

XMR_DAEMON_URL="${XMR_DAEMON_URL:-http://127.0.0.1:38081}"
WOW_DAEMON_URL="${WOW_DAEMON_URL:-http://127.0.0.1:34568}"
SHARECHAIN_NODE_URL="${SHARECHAIN_NODE_URL:-http://127.0.0.1:18091}"

ALICE_LABEL="${ALICE_LABEL:-alice}"
BOB_LABEL="${BOB_LABEL:-bob}"

AMOUNT_XMR="${AMOUNT_XMR:-1000000000}"
AMOUNT_WOW="${AMOUNT_WOW:-100000000000}"
XMR_LOCK_BLOCKS="${XMR_LOCK_BLOCKS:-50}"
WOW_LOCK_BLOCKS="${WOW_LOCK_BLOCKS:-200}"

ALICE_PASSWORD="${ALICE_PASSWORD:-}"
BOB_PASSWORD="${BOB_PASSWORD:-}"

ALICE_XMR_REFUND_ADDRESS="${ALICE_XMR_REFUND_ADDRESS:-}"
BOB_WOW_REFUND_ADDRESS="${BOB_WOW_REFUND_ADDRESS:-}"
ALICE_WOW_DESTINATION_ADDRESS="${ALICE_WOW_DESTINATION_ADDRESS:-}"
BOB_XMR_DESTINATION_ADDRESS="${BOB_XMR_DESTINATION_ADDRESS:-}"

ALICE_XMR_MNEMONIC="${ALICE_XMR_MNEMONIC:-}"
ALICE_XMR_SPEND_KEY="${ALICE_XMR_SPEND_KEY:-}"
ALICE_XMR_VIEW_KEY="${ALICE_XMR_VIEW_KEY:-}"

BOB_WOW_MNEMONIC="${BOB_WOW_MNEMONIC:-}"
BOB_WOW_SPEND_KEY="${BOB_WOW_SPEND_KEY:-}"
BOB_WOW_VIEW_KEY="${BOB_WOW_VIEW_KEY:-}"

ALICE_XMR_SCAN_FROM="${ALICE_XMR_SCAN_FROM:-0}"
ALICE_WOW_SCAN_FROM="${ALICE_WOW_SCAN_FROM:-0}"
BOB_WOW_SCAN_FROM="${BOB_WOW_SCAN_FROM:-0}"
BOB_XMR_SCAN_FROM="${BOB_XMR_SCAN_FROM:-0}"

require() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "$value" ]]; then
    echo "ERROR: missing required env var: ${name}" >&2
    exit 1
  fi
}

announce() { printf '%s\n' "$1"; }

preflight() {
  XMR_DAEMON_URL="$XMR_DAEMON_URL" \
  WOW_DAEMON_URL="$WOW_DAEMON_URL" \
  SHARECHAIN_NODE_URL="$SHARECHAIN_NODE_URL" \
    ./scripts/live-network/preflight.sh
}

announce "XMR-WOW live-network harness"
announce "Reference: docs/DEPLOYMENT.md"

if [[ "$DRY_RUN" == "true" ]]; then
  announce ""
  announce "Dry run enabled (no network calls)."
  announce ""
  announce "Required env vars:"
  announce "- XMR_WOW_LIVE_CONFIRM=1 (for live execution)"
  announce "- ALICE_PASSWORD, BOB_PASSWORD"
  announce "- ALICE_XMR_REFUND_ADDRESS, BOB_WOW_REFUND_ADDRESS"
  announce "- ALICE_WOW_DESTINATION_ADDRESS, BOB_XMR_DESTINATION_ADDRESS"
  announce "- Either ALICE_XMR_MNEMONIC OR (ALICE_XMR_SPEND_KEY + ALICE_XMR_VIEW_KEY)"
  announce "- Either BOB_WOW_MNEMONIC OR (BOB_WOW_SPEND_KEY + BOB_WOW_VIEW_KEY)"
  announce ""
  announce "Optional:"
  announce "- XMR_WOW_BIN (default: ./target/release/xmr-wow)"
  announce "- XMR_DAEMON_URL (default: http://127.0.0.1:38081)"
  announce "- WOW_DAEMON_URL (default: http://127.0.0.1:34568)"
  announce "- SHARECHAIN_NODE_URL (default: http://127.0.0.1:18091)"
  announce "- AMOUNT_XMR, AMOUNT_WOW, XMR_LOCK_BLOCKS, WOW_LOCK_BLOCKS"
  announce "- *_SCAN_FROM overrides"
  exit 0
fi

if [[ "${XMR_WOW_LIVE_CONFIRM:-0}" != "1" ]]; then
  echo "ERROR: live execution is gated. Set XMR_WOW_LIVE_CONFIRM=1 to proceed." >&2
  exit 1
fi

if [[ ! -x "$XMR_WOW_BIN" ]]; then
  echo "ERROR: xmr-wow binary not found/executable at ${XMR_WOW_BIN}" >&2
  echo "Hint: run: cargo build --release -p xmr-wow-client" >&2
  exit 1
fi

require ALICE_PASSWORD
require BOB_PASSWORD
require ALICE_XMR_REFUND_ADDRESS
require BOB_WOW_REFUND_ADDRESS
require ALICE_WOW_DESTINATION_ADDRESS
require BOB_XMR_DESTINATION_ADDRESS

if [[ -z "$ALICE_XMR_MNEMONIC" ]]; then
  require ALICE_XMR_SPEND_KEY
  require ALICE_XMR_VIEW_KEY
fi
if [[ -z "$BOB_WOW_MNEMONIC" ]]; then
  require BOB_WOW_SPEND_KEY
  require BOB_WOW_VIEW_KEY
fi

# Preflight must run before creating swap DB files.
preflight

ts="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="${ROOT_DIR}/.planning/reports/live-harness-${ts}"
fi
mkdir -p "$RUN_DIR"

ALICE_DB="${RUN_DIR}/alice-swaps.db"
BOB_DB="${RUN_DIR}/bob-swaps.db"

announce ""
announce "Run dir: ${RUN_DIR}"

announce ""
announce "== Offer publish/accept =="
offer_out="$("$XMR_WOW_BIN" publish-offer \
  --node "$SHARECHAIN_NODE_URL" \
  --maker "$ALICE_LABEL" \
  --amount-xmr "$AMOUNT_XMR" \
  --amount-wow "$AMOUNT_WOW")"
echo "$offer_out" | tee "${RUN_DIR}/publish-offer.log"
OFFER_ID="$(echo "$offer_out" | awk '/^Offer ID:/ {print $3}')"
if [[ -z "$OFFER_ID" ]]; then
  echo "ERROR: failed to parse Offer ID from publish-offer output" >&2
  exit 1
fi

accept_out="$("$XMR_WOW_BIN" accept-offer \
  --node "$SHARECHAIN_NODE_URL" \
  --offer-id "$OFFER_ID" \
  --taker "$BOB_LABEL")"
echo "$accept_out" | tee "${RUN_DIR}/accept-offer.log"
BILATERAL_TOPIC="$(echo "$accept_out" | awk '/^Bilateral Topic:/ {print $3}')"
if [[ -z "$BILATERAL_TOPIC" ]]; then
  echo "ERROR: failed to parse Bilateral Topic from accept-offer output" >&2
  exit 1
fi

announce ""
announce "Bilateral topic: ${BILATERAL_TOPIC}"

announce ""
announce "== Init Alice/Bob + import =="
init_alice_out="$("$XMR_WOW_BIN" --password "$ALICE_PASSWORD" --db "$ALICE_DB" init-alice \
  --amount-xmr "$AMOUNT_XMR" \
  --amount-wow "$AMOUNT_WOW" \
  --xmr-daemon "$XMR_DAEMON_URL" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --xmr-lock-blocks "$XMR_LOCK_BLOCKS" \
  --wow-lock-blocks "$WOW_LOCK_BLOCKS" \
  --alice-refund-address "$ALICE_XMR_REFUND_ADDRESS" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$ALICE_LABEL" \
  --coord-counterparty "$BOB_LABEL")"
echo "$init_alice_out" | tee "${RUN_DIR}/init-alice.log"
TEMP_SWAP_ID="$(echo "$init_alice_out" | awk '/^Temp swap ID:/ {print $4}')"
if [[ -z "$TEMP_SWAP_ID" ]]; then
  echo "ERROR: failed to parse Temp swap ID from init-alice output" >&2
  exit 1
fi

init_bob_out="$("$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" init-bob \
  --bob-refund-address "$BOB_WOW_REFUND_ADDRESS" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$BOB_LABEL" \
  --coord-counterparty "$ALICE_LABEL")"
echo "$init_bob_out" | tee "${RUN_DIR}/init-bob.log"
BOB_SWAP_ID="$(echo "$init_bob_out" | awk '/^Swap ID:/ {print $3}')"
if [[ -z "$BOB_SWAP_ID" ]]; then
  echo "ERROR: failed to parse Bob swap ID from init-bob output" >&2
  exit 1
fi

import_out="$("$XMR_WOW_BIN" --password "$ALICE_PASSWORD" --db "$ALICE_DB" import \
  --swap-id "$TEMP_SWAP_ID" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$ALICE_LABEL" \
  --coord-counterparty "$BOB_LABEL")"
echo "$import_out" | tee "${RUN_DIR}/import.log"
ALICE_SWAP_ID="$(echo "$import_out" | awk '/^Swap ID:/ {print $3}')"
if [[ -z "$ALICE_SWAP_ID" ]]; then
  echo "ERROR: failed to parse Alice swap ID from import output" >&2
  exit 1
fi

announce ""
announce "Swap IDs: alice=${ALICE_SWAP_ID} bob=${BOB_SWAP_ID}"

announce ""
announce "== Locks =="

bob_lock_args=()
if [[ -n "$BOB_WOW_MNEMONIC" ]]; then
  bob_lock_args+=(--mnemonic "$BOB_WOW_MNEMONIC")
else
  bob_lock_args+=(--spend-key "$BOB_WOW_SPEND_KEY" --view-key "$BOB_WOW_VIEW_KEY")
fi

"$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" lock-wow \
  --swap-id "$BOB_SWAP_ID" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --scan-from "$BOB_WOW_SCAN_FROM" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$BOB_LABEL" \
  --coord-counterparty "$ALICE_LABEL" \
  "${bob_lock_args[@]}" | tee "${RUN_DIR}/lock-wow.log"

alice_lock_args=()
if [[ -n "$ALICE_XMR_MNEMONIC" ]]; then
  alice_lock_args+=(--mnemonic "$ALICE_XMR_MNEMONIC")
else
  alice_lock_args+=(--spend-key "$ALICE_XMR_SPEND_KEY" --view-key "$ALICE_XMR_VIEW_KEY")
fi

"$XMR_WOW_BIN" --password "$ALICE_PASSWORD" --db "$ALICE_DB" lock-xmr \
  --swap-id "$ALICE_SWAP_ID" \
  --xmr-daemon "$XMR_DAEMON_URL" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --scan-from "$ALICE_XMR_SCAN_FROM" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$ALICE_LABEL" \
  --coord-counterparty "$BOB_LABEL" \
  "${alice_lock_args[@]}" | tee "${RUN_DIR}/lock-xmr.log"

announce ""
announce "== Exchange adaptor pre-sigs =="
"$XMR_WOW_BIN" --password "$ALICE_PASSWORD" --db "$ALICE_DB" exchange-pre-sig \
  --swap-id "$ALICE_SWAP_ID" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$ALICE_LABEL" \
  --coord-counterparty "$BOB_LABEL" | tee "${RUN_DIR}/exchange-pre-sig-alice.log"

"$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" exchange-pre-sig \
  --swap-id "$BOB_SWAP_ID" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$BOB_LABEL" \
  --coord-counterparty "$ALICE_LABEL" | tee "${RUN_DIR}/exchange-pre-sig-bob.log"

announce ""
announce "== Claims =="
announce "Starting Bob claim-xmr in background (it will publish Bob's claim proof, then wait for Alice)."

BOB_CLAIM_LOG="${RUN_DIR}/claim-xmr.log"
(
  "$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" claim-xmr \
    --swap-id "$BOB_SWAP_ID" \
    --xmr-daemon "$XMR_DAEMON_URL" \
    --destination "$BOB_XMR_DESTINATION_ADDRESS" \
    --scan-from "$BOB_XMR_SCAN_FROM" \
    --coord-node "$SHARECHAIN_NODE_URL" \
    --coord-topic "$BILATERAL_TOPIC" \
    --coord-self "$BOB_LABEL" \
    --coord-counterparty "$ALICE_LABEL"
) 2>&1 | tee "$BOB_CLAIM_LOG" &
BOB_CLAIM_PID=$!

# Wait for Bob to publish claim proof before Alice tries to claim WOW.
for _ in $(seq 1 60); do
  if rg -q "Your claim proof" "$BOB_CLAIM_LOG" 2>/dev/null || rg -q "Published Bob's claim proof" "$BOB_CLAIM_LOG" 2>/dev/null; then
    break
  fi
  sleep 1
done

announce "Running Alice claim-wow (will fetch Bob claim proof from sharechain)."
"$XMR_WOW_BIN" --password "$ALICE_PASSWORD" --db "$ALICE_DB" claim-wow \
  --swap-id "$ALICE_SWAP_ID" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --destination "$ALICE_WOW_DESTINATION_ADDRESS" \
  --scan-from "$ALICE_WOW_SCAN_FROM" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$ALICE_LABEL" \
  --coord-counterparty "$BOB_LABEL" | tee "${RUN_DIR}/claim-wow.log"

announce "Waiting for Bob claim-xmr to complete..."
wait "$BOB_CLAIM_PID"

announce ""
announce "Live harness complete"
announce "Logs + DBs: ${RUN_DIR}"
