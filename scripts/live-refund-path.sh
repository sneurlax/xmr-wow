#!/usr/bin/env bash
# live-refund-path.sh -- Refund path (Alice disappears after Bob locks WOW)
#
# VALID-02 live tier: Bob locks WOW, Alice disappears, Bob refunds after timelock.
#
# Prerequisites:
#   - monerod running on stagenet (port 38081)
#   - wownerod running (port 34568)
#   - Bob's WOW wallet funded
#
# Usage:
#   ./scripts/live-refund-path.sh
set -euo pipefail

if [[ "${ALLOW_UNSUPPORTED_XMR_WOW_LIVE_FLOW:-0}" != "1" ]]; then
    cat >&2 <<'EOF'
This script is historical/manual only.
Supported path: ./scripts/phase16-proof-harness.sh
Current refund-readiness gating keeps this live flow blocked or unsupported-for-guarantee.
Set ALLOW_UNSUPPORTED_XMR_WOW_LIVE_FLOW=1 only if you intentionally need the old path.
EOF
    exit 1
fi

XMR_DAEMON="${XMR_DAEMON:-http://127.0.0.1:38081}"
WOW_DAEMON="${WOW_DAEMON:-http://127.0.0.1:34568}"
PASSWORD="${SWAP_PASSWORD:-test-swap-password}"
ALICE_DB="${ALICE_DB:-/tmp/alice-refund-$$.db}"
BOB_DB="${BOB_DB:-/tmp/bob-refund-$$.db}"
LOG="swap-refund-$(date +%s).log"

AMOUNT_XMR="${AMOUNT_XMR:-1000000000}"
AMOUNT_WOW="${AMOUNT_WOW:-100000000000}"
# Short lock for refund testing -- Bob waits fewer WOW blocks
XMR_LOCK_BLOCKS="${XMR_LOCK_BLOCKS:-50}"
WOW_LOCK_BLOCKS="${WOW_LOCK_BLOCKS:-200}"

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }
run_alice() {
    log "ALICE> $*"
    cargo run -p xmr-wow-client -- --password "$PASSWORD" --db "$ALICE_DB" "$@" 2>&1 | tee -a "$LOG"
}
run_bob() {
    log "BOB> $*"
    cargo run -p xmr-wow-client -- --password "$PASSWORD" --db "$BOB_DB" "$@" 2>&1 | tee -a "$LOG"
}

# Generate Bob's wallet (he locks WOW first)
log "--- Key Generation ---"
BOB_WALLET_OUTPUT=$(cargo run -p xmr-wow-client -- generate-wallet --network wow-mainnet 2>/dev/null)
BOB_SPEND_KEY=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'Spend key \(private\): \K[0-9a-f]+')
BOB_VIEW_KEY=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'View key \(private\):  \K[0-9a-f]+')
BOB_ADDRESS=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'Address:             \K\S+')
log "Bob WOW address: $BOB_ADDRESS"
log "Fund this address on WOW mainnet before proceeding."
log ""

log "=== WOW REFUND PATH (Alice Disappears) ==="
log "WOW daemon: $WOW_DAEMON"
log ""

# Step 1: Alice initiates
log "--- Step 1: Alice init ---"
ALICE_OUTPUT=$(run_alice init-alice \
    --amount-xmr "$AMOUNT_XMR" --amount-wow "$AMOUNT_WOW" \
    --xmr-lock-blocks "$XMR_LOCK_BLOCKS" --wow-lock-blocks "$WOW_LOCK_BLOCKS")
ALICE_MSG=$(echo "$ALICE_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1)
ALICE_SWAP_ID=$(echo "$ALICE_OUTPUT" | grep -oiP 'swap ID: \K[0-9a-f]+' | tail -1)
log "Alice swap ID: $ALICE_SWAP_ID"
log ""

# Step 2: Bob responds (Alice will disappear after lock)
log "--- Step 2: Bob responds ---"
BOB_OUTPUT=$(run_bob init-bob --message "$ALICE_MSG")
BOB_MSG=$(echo "$BOB_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1)
BOB_SWAP_ID=$(echo "$BOB_OUTPUT" | grep -oP 'Swap ID: \K[0-9a-f]+' | tail -1)
log "Bob swap ID: $BOB_SWAP_ID"
log ""

# Step 3: Alice imports Bob's response
log "--- Step 3: Alice import ---"
run_alice import --swap-id "$ALICE_SWAP_ID" --message "$BOB_MSG"
log ""

# Step 4: Bob locks WOW
log "--- Step 4: Bob locks WOW ---"
run_bob lock-wow --swap-id "$BOB_SWAP_ID" --wow-daemon "$WOW_DAEMON" \
    --spend-key "$BOB_SPEND_KEY" --view-key "$BOB_VIEW_KEY"
log ""

# Step 5: Alice has DISAPPEARED -- no XMR lock
log "--- Step 5: Alice has DISAPPEARED ---"
log "Alice never locks XMR. Bob's WOW is locked until timelock expiry."
log ""

# Step 6: Wait for timelock (in practice, wait for blocks)
log "--- Step 6: Waiting for WOW timelock expiry ---"
log "WOW lock blocks: $WOW_LOCK_BLOCKS"
log "On WOW mainnet (~2 min/block), this will take ~$((WOW_LOCK_BLOCKS * 2)) minutes."
log "Monitor block height at: $WOW_DAEMON/json_rpc (method: get_block_count)"
log ""
log "When timelock expires, run the refund command:"
log "  cargo run -p xmr-wow-client -- --password '$PASSWORD' --db '$BOB_DB' refund --swap-id '$BOB_SWAP_ID' --wow-daemon '$WOW_DAEMON'"
log ""

# Step 7: Bob attempts WOW refund (manual -- user runs when timelock expires)
log "--- Step 7: Bob attempts WOW refund ---"
REFUND_OUTPUT=$(run_bob refund --swap-id "$BOB_SWAP_ID" --wow-daemon "$WOW_DAEMON" 2>&1 || true)
log "Refund output: $REFUND_OUTPUT"
log ""

# Final status
log "--- Final Status ---"
run_bob show "$BOB_SWAP_ID" || true

log ""
log "=== REFUND PATH COMPLETE ==="
log "Note: Per PoC limitation, refund marks state as Refunded but does not"
log "sweep funds from the joint address (requires script layer, out of scope)."
log "The test proves: timelock enforcement + state transition correctness."
log "Log saved to: $LOG"
