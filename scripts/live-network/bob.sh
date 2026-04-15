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
Usage: scripts/live-network/bob.sh [--transport-mode sharechain|out-of-band] [--dry-run]

Bob side of the live-network flow (Bob locks WOW first, claims XMR).

Options:
  --transport-mode sharechain    Use sharechain node for coordination (requires xmr-wow-node)
  --transport-mode out-of-band   Use manual message exchange (default)
  --dry-run                      Print required env vars and exit without running

Prerequisites and the manual flow:
  scripts/live-network/RUNBOOK.md

Sharechain mode: no manual xmrwow1 copy/paste required when a sharechain node is available.
Out-of-band mode: each step prints/consumes xmrwow1: messages that must be passed manually.
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

BOB_PASSWORD="${BOB_PASSWORD:-}"
BOB_DB="${BOB_DB:-}"

BOB_WOW_REFUND_ADDRESS="${BOB_WOW_REFUND_ADDRESS:-}"
BOB_XMR_DESTINATION_ADDRESS="${BOB_XMR_DESTINATION_ADDRESS:-}"

BOB_WOW_MNEMONIC="${BOB_WOW_MNEMONIC:-}"
BOB_WOW_SPEND_KEY="${BOB_WOW_SPEND_KEY:-}"
BOB_WOW_VIEW_KEY="${BOB_WOW_VIEW_KEY:-}"
BOB_WOW_SCAN_FROM="${BOB_WOW_SCAN_FROM:-0}"
BOB_XMR_SCAN_FROM="${BOB_XMR_SCAN_FROM:-0}"

OFFER_ID="${OFFER_ID:-}"
BOB_SWAP_ID="${BOB_SWAP_ID:-}"

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

announce "XMR-WOW live-network script (Bob)"
announce "Transport mode: ${TRANSPORT_MODE}"
announce "Why: run the Bob side of the flow (--transport ${TRANSPORT_MODE}), without hardcoding secrets."
announce "Reference: scripts/live-network/RUNBOOK.md"

preflight

if [[ "$DRY_RUN" == "true" ]]; then
  announce ""
  announce "Dry run: required env vars for live execution:"
  announce "- BOB_PASSWORD, BOB_WOW_REFUND_ADDRESS, BOB_XMR_DESTINATION_ADDRESS"
  announce "- Either BOB_WOW_MNEMONIC OR (BOB_WOW_SPEND_KEY + BOB_WOW_VIEW_KEY)"
  announce "- OFFER_ID (from Alice's publish-offer output, or discoverable via list-offers)"
  announce ""
  announce "Transport mode (--transport-mode flag, default: out-of-band):"
  announce "- out-of-band: each step prints/consumes xmrwow1: messages for manual handoff"
  announce "- sharechain:  requires SHARECHAIN_NODE_URL and a running xmr-wow-node"
  announce ""
  announce "Outputs:"
  announce "- BOB_SWAP_ID"
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

require BOB_PASSWORD
require BOB_WOW_REFUND_ADDRESS
require BOB_XMR_DESTINATION_ADDRESS
require OFFER_ID

if [[ -z "$BOB_DB" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  run_dir="${ROOT_DIR}/runs/live-network-${ts}"
  mkdir -p "$run_dir"
  BOB_DB="${run_dir}/bob-swaps.db"
fi

announce ""
announce "== Step B1: accept-offer =="
announce "What: accept Alice's public offer and establish the swap linkage."
accept_out="$("$XMR_WOW_BIN" $TRANSPORT_FLAGS accept-offer \
  --offer-id "$OFFER_ID")"
echo "$accept_out"
# In sharechain mode the bilateral topic is handled internally; we only need the swap context.
# In OOB mode accept-offer may print a xmrwow1: message for manual handoff.
announce "Captured accept-offer output above."

announce ""
announce "== Step B2: init-bob (reads Init from the transport channel) =="
announce "What: respond to Alice and commit your WOW refund destination."
announce "Why: this derives the real swap ID and joint addresses."
init_out="$("$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$BOB_PASSWORD" --db "$BOB_DB" init-bob \
  --bob-refund-address "$BOB_WOW_REFUND_ADDRESS")"
echo "$init_out"
BOB_SWAP_ID="$(echo "$init_out" | awk '/^Swap ID:/ {print $3}')"
if [[ -z "$BOB_SWAP_ID" ]]; then
  echo "ERROR: failed to parse Swap ID from init-bob output" >&2
  exit 1
fi

announce ""
announce "== Step B3: lock-wow (Bob locks first) =="
announce "What: lock WOW to the joint address and publish adaptor pre-sig to the transport channel."
lock_args=()
if [[ -n "$BOB_WOW_MNEMONIC" ]]; then
  lock_args+=(--mnemonic "$BOB_WOW_MNEMONIC")
else
  require BOB_WOW_SPEND_KEY
  require BOB_WOW_VIEW_KEY
  lock_args+=(--spend-key "$BOB_WOW_SPEND_KEY" --view-key "$BOB_WOW_VIEW_KEY")
fi

"$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$BOB_PASSWORD" --db "$BOB_DB" lock-wow \
  --swap-id "$BOB_SWAP_ID" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --scan-from "$BOB_WOW_SCAN_FROM" \
  "${lock_args[@]}"

announce ""
announce "== Step B4: exchange-pre-sig =="
announce "What: record Alice's adaptor pre-signature (published when she locks XMR)."
"$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$BOB_PASSWORD" --db "$BOB_DB" exchange-pre-sig \
  --swap-id "$BOB_SWAP_ID"

announce ""
announce "== Step B5: claim-xmr =="
announce "What: publish Bob's claim proof first (so Alice can claim WOW), then wait for Alice's claim proof and sweep XMR."
announce "Note: this command will block until Alice completes claim-wow and publishes her claim proof."
"$XMR_WOW_BIN" $TRANSPORT_FLAGS --password "$BOB_PASSWORD" --db "$BOB_DB" claim-xmr \
  --swap-id "$BOB_SWAP_ID" \
  --xmr-daemon "$XMR_DAEMON_URL" \
  --destination "$BOB_XMR_DESTINATION_ADDRESS" \
  --scan-from "$BOB_XMR_SCAN_FROM"

announce ""
announce "Bob flow complete."
