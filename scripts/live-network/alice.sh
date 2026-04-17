#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN=false
TRANSPORT_MODE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --transport-mode) TRANSPORT_MODE="$2"; shift 2 ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/live-network/alice.sh [--transport-mode sharechain|out-of-band] [--dry-run]

Alice side of the live-network flow (Alice locks XMR, claims WOW).

Options:
  --transport-mode sharechain    Use sharechain node for coordination (requires xmr-wow-node)
  --transport-mode out-of-band   Use manual message exchange (default)
  --dry-run                      Print required env vars and exit without running

This script is intentionally verbose and explanation-heavy. For prerequisites, see:
  docs/DEPLOYMENT.md or scripts/live-network/RUNBOOK.md

Secrets are read from environment variables (never hardcoded).

Sharechain mode env:
  SHARECHAIN_NODE_URL  URL of the xmr-wow-node RPC (default: http://127.0.0.1:18091)

Out-of-band mode: init-alice prints an xmrwow1: message that must be passed manually
to Bob's init-bob --message flag. Each subsequent step may also produce/consume messages.
USAGE
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

TRANSPORT_MODE="${TRANSPORT_MODE:-out-of-band}"

XMR_WOW_BIN="${XMR_WOW_BIN:-$ROOT_DIR/target/release/xmr-wow}"

XMR_DAEMON_URL="${XMR_DAEMON_URL:-http://127.0.0.1:38081}"
WOW_DAEMON_URL="${WOW_DAEMON_URL:-http://127.0.0.1:34568}"
SHARECHAIN_NODE_URL="${SHARECHAIN_NODE_URL:-http://127.0.0.1:18091}"

AMOUNT_XMR="${AMOUNT_XMR:-1000000000}"
AMOUNT_WOW="${AMOUNT_WOW:-100000000000}"
XMR_LOCK_BLOCKS="${XMR_LOCK_BLOCKS:-50}"
WOW_LOCK_BLOCKS="${WOW_LOCK_BLOCKS:-200}"

ALICE_PASSWORD="${ALICE_PASSWORD:-}"
ALICE_DB="${ALICE_DB:-}"

ALICE_XMR_REFUND_ADDRESS="${ALICE_XMR_REFUND_ADDRESS:-}"
ALICE_WOW_DESTINATION_ADDRESS="${ALICE_WOW_DESTINATION_ADDRESS:-}"

ALICE_XMR_MNEMONIC="${ALICE_XMR_MNEMONIC:-}"
ALICE_XMR_SPEND_KEY="${ALICE_XMR_SPEND_KEY:-}"
ALICE_XMR_VIEW_KEY="${ALICE_XMR_VIEW_KEY:-}"
ALICE_XMR_SCAN_FROM="${ALICE_XMR_SCAN_FROM:-0}"
ALICE_WOW_SCAN_FROM="${ALICE_WOW_SCAN_FROM:-0}"

OFFER_ID="${OFFER_ID:-}"
TEMP_SWAP_ID="${TEMP_SWAP_ID:-}"
ALICE_SWAP_ID="${ALICE_SWAP_ID:-}"

if [[ "$TRANSPORT_MODE" == "sharechain" ]]; then
  TRANSPORT_FLAGS="--transport sharechain --node-url ${SHARECHAIN_NODE_URL}"
else
  TRANSPORT_FLAGS="--transport out-of-band"
fi

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
  if [[ "$DRY_RUN" == "true" ]]; then
    ./scripts/live-network/preflight.sh --dry-run
  else
    ./scripts/live-network/preflight.sh
  fi
}

announce "XMR-WOW live-network script (Alice)"
announce "Transport mode: ${TRANSPORT_MODE}"
announce "Why: run the Alice side of the flow (--transport ${TRANSPORT_MODE}), without hardcoding secrets."
announce "Reference: scripts/live-network/RUNBOOK.md"

preflight

if [[ "$DRY_RUN" == "true" ]]; then
  announce ""
  announce "Dry run: required env vars for live execution:"
  announce "- ALICE_PASSWORD, ALICE_XMR_REFUND_ADDRESS, ALICE_WOW_DESTINATION_ADDRESS"
  announce "- Either ALICE_XMR_MNEMONIC OR (ALICE_XMR_SPEND_KEY + ALICE_XMR_VIEW_KEY)"
  announce ""
  announce "Transport mode (--transport-mode flag, default: out-of-band):"
  announce "- out-of-band: init-alice prints an xmrwow1: string; pass it manually to Bob"
  announce "- sharechain:  requires SHARECHAIN_NODE_URL and a running xmr-wow-node"
  announce "               BILATERAL_TOPIC is not needed for sharechain mode"
  announce ""
  announce "Optional:"
  announce "- OFFER_ID (if you want this script to publish the offer)"
  announce "- ALICE_DB (defaults to a timestamped run directory)"
  announce "- AMOUNT_XMR, AMOUNT_WOW, XMR_LOCK_BLOCKS, WOW_LOCK_BLOCKS"
  announce "- ALICE_XMR_SCAN_FROM, ALICE_WOW_SCAN_FROM"
  exit 0
fi

if [[ ! -x "$XMR_WOW_BIN" ]]; then
  echo "ERROR: xmr-wow binary not found/executable at ${XMR_WOW_BIN}" >&2
  echo "Hint: run: cargo build --release -p xmr-wow-client" >&2
  exit 1
fi

if [[ "${XMR_WOW_LIVE_CONFIRM:-0}" != "1" ]]; then
  echo "ERROR: live execution is gated. Set XMR_WOW_LIVE_CONFIRM=1 to proceed." >&2
  exit 1
fi

require ALICE_PASSWORD
require ALICE_XMR_REFUND_ADDRESS
require ALICE_WOW_DESTINATION_ADDRESS

if [[ -z "$ALICE_DB" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  run_dir="${ROOT_DIR}/runs/live-network-${ts}"
  mkdir -p "$run_dir"
  ALICE_DB="${run_dir}/alice-swaps.db"
fi

announce ""
announce "== Step A1: Publish offer (optional) =="
announce "What: advertise swap terms on the sharechain so Bob can accept without manual coordination."
announce "Why: lets accept-offer compute a bilateral topic for message exchange."
if [[ -z "$OFFER_ID" ]]; then
  offer_out="$("$XMR_WOW_BIN" $TRANSPORT_FLAGS publish-offer \
    --amount-xmr "$AMOUNT_XMR" \
    --amount-wow "$AMOUNT_WOW")"
  echo "$offer_out"
  OFFER_ID="$(echo "$offer_out" | awk '/^Offer ID:/ {print $3}')"
  if [[ -z "$OFFER_ID" ]]; then
    echo "ERROR: failed to parse Offer ID from publish-offer output" >&2
    exit 1
  fi
fi

announce ""
announce "== Step A2: init-alice (publishes Init on the transport channel) =="
announce "What: create the initial swap transcript and store the encrypted secret locally."
announce "Why: this produces the Init message Bob needs to respond."
init_out="$("$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$ALICE_PASSWORD" --db "$ALICE_DB" init-alice \
  --amount-xmr "$AMOUNT_XMR" \
  --amount-wow "$AMOUNT_WOW" \
  --xmr-daemon "$XMR_DAEMON_URL" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --xmr-lock-blocks "$XMR_LOCK_BLOCKS" \
  --wow-lock-blocks "$WOW_LOCK_BLOCKS" \
  --alice-refund-address "$ALICE_XMR_REFUND_ADDRESS")"
echo "$init_out"
TEMP_SWAP_ID="$(echo "$init_out" | awk '/^Temp swap ID:/ {print $4}')"
if [[ -z "$TEMP_SWAP_ID" ]]; then
  echo "ERROR: failed to parse Temp swap ID from init-alice output" >&2
  exit 1
fi

announce ""
announce "== Step A3: import (waits for Bob Response on the transport channel) =="
announce "What: import Bob's response to derive the real swap ID and joint addresses."
announce "Why: the real swap ID is needed for lock and claim steps."
import_out="$("$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$ALICE_PASSWORD" --db "$ALICE_DB" import \
  --swap-id "$TEMP_SWAP_ID")"
echo "$import_out"
ALICE_SWAP_ID="$(echo "$import_out" | awk '/^Swap ID:/ {print $3}')"
if [[ -z "$ALICE_SWAP_ID" ]]; then
  echo "ERROR: failed to parse Swap ID from import output" >&2
  exit 1
fi

announce ""
announce "== Step A4: lock-xmr (Alice locks second) =="
announce "What: verify Bob's WOW lock and lock XMR to the joint address."
announce "Why: WOW-first lock order is the safety contract for this swap."
lock_args=()
if [[ -n "$ALICE_XMR_MNEMONIC" ]]; then
  lock_args+=(--mnemonic "$ALICE_XMR_MNEMONIC")
else
  require ALICE_XMR_SPEND_KEY
  require ALICE_XMR_VIEW_KEY
  lock_args+=(--spend-key "$ALICE_XMR_SPEND_KEY" --view-key "$ALICE_XMR_VIEW_KEY")
fi

"$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$ALICE_PASSWORD" --db "$ALICE_DB" lock-xmr \
  --swap-id "$ALICE_SWAP_ID" \
  --xmr-daemon "$XMR_DAEMON_URL" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --scan-from "$ALICE_XMR_SCAN_FROM" \
  "${lock_args[@]}"

announce ""
announce "== Step A5: exchange-pre-sig =="
announce "What: record Bob's adaptor pre-signature and make sure both sides have both pre-sigs."
"$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$ALICE_PASSWORD" --db "$ALICE_DB" exchange-pre-sig \
  --swap-id "$ALICE_SWAP_ID"

announce ""
announce "== Step A6: claim-wow (waits for Bob claim proof) =="
announce "What: claim WOW after Bob publishes his claim proof; then publish your claim proof for Bob."
announce "Why: Bob needs your claim proof to claim XMR."
"$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$ALICE_PASSWORD" --db "$ALICE_DB" claim-wow \
  --swap-id "$ALICE_SWAP_ID" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --destination "$ALICE_WOW_DESTINATION_ADDRESS" \
  --scan-from "$ALICE_WOW_SCAN_FROM"

announce ""
announce "Alice flow complete."
announce "Note: Bob still needs to complete claim-xmr (he will read your claim proof from the transport channel)."
