#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/live-network/bob.sh [--dry-run]

Bob side of the live-network flow (Bob locks WOW first, claims XMR).

Prerequisites and the manual 9-step procedure:
  docs/DEPLOYMENT.md

This script uses sharechain coordination flags so no manual xmrwow1 copy/paste
is required when a sharechain node is available.
USAGE
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

XMR_WOW_BIN="${XMR_WOW_BIN:-$ROOT_DIR/target/release/xmr-wow}"

XMR_DAEMON_URL="${XMR_DAEMON_URL:-http://127.0.0.1:38081}"
WOW_DAEMON_URL="${WOW_DAEMON_URL:-http://127.0.0.1:34568}"
SHARECHAIN_NODE_URL="${SHARECHAIN_NODE_URL:-http://127.0.0.1:18091}"

ALICE_LABEL="${ALICE_LABEL:-alice}"
BOB_LABEL="${BOB_LABEL:-bob}"

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
BILATERAL_TOPIC="${BILATERAL_TOPIC:-}"
BOB_SWAP_ID="${BOB_SWAP_ID:-}"

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
announce "Why: run the Bob side of the flow with sharechain coordination, without hardcoding secrets."
announce "Reference: docs/DEPLOYMENT.md (manual flow and daemon prerequisites)."

preflight

if [[ "$DRY_RUN" == "true" ]]; then
  announce ""
  announce "Dry run: required env vars for live execution:"
  announce "- BOB_PASSWORD, BOB_WOW_REFUND_ADDRESS, BOB_XMR_DESTINATION_ADDRESS"
  announce "- Either BOB_WOW_MNEMONIC OR (BOB_WOW_SPEND_KEY + BOB_WOW_VIEW_KEY)"
  announce "- OFFER_ID (from Alice's publish-offer output, or discoverable via list-offers)"
  announce ""
  announce "Outputs:"
  announce "- BILATERAL_TOPIC (used by Alice + Bob for coordination)"
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
  run_dir="${ROOT_DIR}/.planning/reports/live-network-${ts}"
  mkdir -p "$run_dir"
  BOB_DB="${run_dir}/bob-swaps.db"
fi

announce ""
announce "== Step B1: accept-offer =="
announce "What: accept Alice's public offer and establish the bilateral coordination topic."
accept_out="$("$XMR_WOW_BIN" accept-offer \
  --node "$SHARECHAIN_NODE_URL" \
  --offer-id "$OFFER_ID" \
  --taker "$BOB_LABEL")"
echo "$accept_out"
BILATERAL_TOPIC="$(echo "$accept_out" | awk '/^Bilateral Topic:/ {print $3}')"
if [[ -z "$BILATERAL_TOPIC" ]]; then
  echo "ERROR: failed to parse Bilateral Topic from accept-offer output" >&2
  exit 1
fi
announce "Captured BILATERAL_TOPIC=${BILATERAL_TOPIC}"

announce ""
announce "== Step B2: init-bob (reads Init from the sharechain) =="
announce "What: respond to Alice and commit your WOW refund destination."
announce "Why: this derives the real swap ID and joint addresses."
init_out="$("$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" init-bob \
  --bob-refund-address "$BOB_WOW_REFUND_ADDRESS" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$BOB_LABEL" \
  --coord-counterparty "$ALICE_LABEL")"
echo "$init_out"
BOB_SWAP_ID="$(echo "$init_out" | awk '/^Swap ID:/ {print $3}')"
if [[ -z "$BOB_SWAP_ID" ]]; then
  echo "ERROR: failed to parse Swap ID from init-bob output" >&2
  exit 1
fi

announce ""
announce "== Step B3: lock-wow (Bob locks first) =="
announce "What: lock WOW to the joint address and publish adaptor pre-sig to the sharechain."
lock_args=()
if [[ -n "$BOB_WOW_MNEMONIC" ]]; then
  lock_args+=(--mnemonic "$BOB_WOW_MNEMONIC")
else
  require BOB_WOW_SPEND_KEY
  require BOB_WOW_VIEW_KEY
  lock_args+=(--spend-key "$BOB_WOW_SPEND_KEY" --view-key "$BOB_WOW_VIEW_KEY")
fi

"$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" lock-wow \
  --swap-id "$BOB_SWAP_ID" \
  --wow-daemon "$WOW_DAEMON_URL" \
  --scan-from "$BOB_WOW_SCAN_FROM" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$BOB_LABEL" \
  --coord-counterparty "$ALICE_LABEL" \
  "${lock_args[@]}"

announce ""
announce "== Step B4: exchange-pre-sig =="
announce "What: record Alice's adaptor pre-signature (published when she locks XMR)."
"$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" exchange-pre-sig \
  --swap-id "$BOB_SWAP_ID" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$BOB_LABEL" \
  --coord-counterparty "$ALICE_LABEL"

announce ""
announce "== Step B5: claim-xmr =="
announce "What: publish Bob's claim proof first (so Alice can claim WOW), then wait for Alice's claim proof and sweep XMR."
announce "Note: this command will block until Alice completes claim-wow and publishes her claim proof."
"$XMR_WOW_BIN" --password "$BOB_PASSWORD" --db "$BOB_DB" claim-xmr \
  --swap-id "$BOB_SWAP_ID" \
  --xmr-daemon "$XMR_DAEMON_URL" \
  --destination "$BOB_XMR_DESTINATION_ADDRESS" \
  --scan-from "$BOB_XMR_SCAN_FROM" \
  --coord-node "$SHARECHAIN_NODE_URL" \
  --coord-topic "$BILATERAL_TOPIC" \
  --coord-self "$BOB_LABEL" \
  --coord-counterparty "$ALICE_LABEL"

announce ""
announce "Bob flow complete"
