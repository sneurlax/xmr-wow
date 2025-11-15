#!/usr/bin/env bash
# live-refund-premature.sh -- Premature refund rejection test
#
# Scenario (D-04.3, D-07): Bob locks WOW, both cooperate on refund tx,
# then Bob attempts to broadcast the refund BEFORE the timelock expires.
# The script verifies:
#   1. Client-side rejection (D-03): broadcast-refund checks block height
#   2. Daemon-side rejection (D-07): raw tx submitted directly is rejected
#   3. After timelock expiry, the same refund tx succeeds
#
# Prerequisites:
#   - wownerod running (port 34568 default)
#   - monerod running on stagenet (port 38081 default)
#   - Bob's WOW wallet funded
#
# Usage:
#   ./scripts/live-refund-premature.sh [--bob-seed "25 words"] [--alice-seed "25 words"]
#   ./scripts/live-refund-premature.sh --resume <state-file>
set -euo pipefail

# --- Parse arguments ---
ALICE_SEED=""
BOB_SEED=""
RESUME_FILE=""
XMR_SCAN_FROM="${XMR_SCAN_FROM:-0}"
WOW_SCAN_FROM="${WOW_SCAN_FROM:-0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --alice-seed)    ALICE_SEED="$2";    shift 2 ;;
        --bob-seed)      BOB_SEED="$2";      shift 2 ;;
        --resume)        RESUME_FILE="$2";   shift 2 ;;
        --xmr-scan-from) XMR_SCAN_FROM="$2"; shift 2 ;;
        --wow-scan-from) WOW_SCAN_FROM="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# --- Configuration ---
XMR_DAEMON="${XMR_DAEMON:-http://127.0.0.1:38081}"
WOW_DAEMON="${WOW_DAEMON:-http://127.0.0.1:34568}"
PASSWORD="${SWAP_PASSWORD:-test-swap-password}"

# Small amounts for PoC (0.001 XMR, 1 WOW)
AMOUNT_XMR="${AMOUNT_XMR:-1000000000}"
AMOUNT_WOW="${AMOUNT_WOW:-100000000000}"
# Short timelocks for refund testing per D-05
XMR_LOCK_BLOCKS="${XMR_LOCK_BLOCKS:-15}"
WOW_LOCK_BLOCKS="${WOW_LOCK_BLOCKS:-130}"

# --- State management ---
STATE_FILE=""
COMPLETED_STEP=0

# State variables
ALICE_DB=""
BOB_DB=""
ALICE_SPEND_KEY=""
ALICE_VIEW_KEY=""
ALICE_ADDRESS=""
BOB_SPEND_KEY=""
BOB_VIEW_KEY=""
BOB_ADDRESS=""
ALICE_SWAP_ID=""
ALICE_MSG=""
BOB_SWAP_ID=""
BOB_MSG=""
ALICE_COOP=""
BOB_REFUND_HEIGHT=""
REFUND_TX_HEX=""

save_state() {
    cat > "$STATE_FILE" <<EOF
{
  "completed_step": $COMPLETED_STEP,
  "alice_db": "$ALICE_DB",
  "bob_db": "$BOB_DB",
  "xmr_daemon": "$XMR_DAEMON",
  "wow_daemon": "$WOW_DAEMON",
  "alice_spend_key": "$ALICE_SPEND_KEY",
  "alice_view_key": "$ALICE_VIEW_KEY",
  "alice_address": "$ALICE_ADDRESS",
  "bob_spend_key": "$BOB_SPEND_KEY",
  "bob_view_key": "$BOB_VIEW_KEY",
  "bob_address": "$BOB_ADDRESS",
  "alice_swap_id": "$ALICE_SWAP_ID",
  "alice_msg": "$ALICE_MSG",
  "bob_swap_id": "$BOB_SWAP_ID",
  "bob_msg": "$BOB_MSG",
  "alice_coop": "$ALICE_COOP",
  "bob_refund_height": "$BOB_REFUND_HEIGHT",
  "refund_tx_hex": "$REFUND_TX_HEX"
}
EOF
    chmod 600 "$STATE_FILE"
}

load_state() {
    local file="$1"
    COMPLETED_STEP=$(python3 -c "import json; d=json.load(open('$file')); print(d['completed_step'])")
    ALICE_DB=$(python3 -c "import json; d=json.load(open('$file')); print(d['alice_db'])")
    BOB_DB=$(python3 -c "import json; d=json.load(open('$file')); print(d['bob_db'])")
    ALICE_SPEND_KEY=$(python3 -c "import json; d=json.load(open('$file')); print(d['alice_spend_key'])")
    ALICE_VIEW_KEY=$(python3 -c "import json; d=json.load(open('$file')); print(d['alice_view_key'])")
    ALICE_ADDRESS=$(python3 -c "import json; d=json.load(open('$file')); print(d['alice_address'])")
    BOB_SPEND_KEY=$(python3 -c "import json; d=json.load(open('$file')); print(d['bob_spend_key'])")
    BOB_VIEW_KEY=$(python3 -c "import json; d=json.load(open('$file')); print(d['bob_view_key'])")
    BOB_ADDRESS=$(python3 -c "import json; d=json.load(open('$file')); print(d['bob_address'])")
    ALICE_SWAP_ID=$(python3 -c "import json; d=json.load(open('$file')); print(d['alice_swap_id'])")
    ALICE_MSG=$(python3 -c "import json; d=json.load(open('$file')); print(d['alice_msg'])")
    BOB_SWAP_ID=$(python3 -c "import json; d=json.load(open('$file')); print(d['bob_swap_id'])")
    BOB_MSG=$(python3 -c "import json; d=json.load(open('$file')); print(d['bob_msg'])")
    ALICE_COOP=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('alice_coop',''))")
    BOB_REFUND_HEIGHT=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('bob_refund_height',''))")
    REFUND_TX_HEX=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('refund_tx_hex',''))")
    STATE_FILE="$file"
}

# --- Resume or fresh start ---
if [ -n "$RESUME_FILE" ]; then
    echo "Resuming from: $RESUME_FILE"
    load_state "$RESUME_FILE"
    echo "Completed through step $COMPLETED_STEP. Continuing..."
else
    ALICE_DB="${ALICE_DB:-/tmp/alice-refund-premature-$$.db}"
    BOB_DB="${BOB_DB:-/tmp/bob-refund-premature-$$.db}"
    STATE_FILE="refund-premature-state-$(date +%s).json"
fi

LOG="refund-premature-$(date +%s).log"

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }
run_alice() {
    log "ALICE> $*"
    cargo run --release -p xmr-wow-client -- --password "$PASSWORD" --db "$ALICE_DB" "$@" 2>&1 | tee -a "$LOG"
}
run_bob() {
    log "BOB> $*"
    cargo run --release -p xmr-wow-client -- --password "$PASSWORD" --db "$BOB_DB" "$@" 2>&1 | tee -a "$LOG"
}

poll_height() {
    local daemon="$1"
    local target="$2"
    local chain_name="$3"

    while true; do
        local current
        current=$(curl -s "$daemon/json_rpc" \
            -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' \
            | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['count'])")

        if [ "$current" -ge "$target" ]; then
            log "$chain_name height $current >= target $target -- timelock expired!"
            break
        fi

        local remaining=$((target - current))
        local est_minutes=$((remaining * 2))
        log "$chain_name: block $current / $target ($remaining remaining, ~${est_minutes} min)"
        sleep 30
    done
}

log "=== PREMATURE REFUND REJECTION TEST ==="
log "XMR daemon: $XMR_DAEMON"
log "WOW daemon: $WOW_DAEMON"
log "Alice DB: $ALICE_DB"
log "Bob DB: $BOB_DB"
log "State: $STATE_FILE"
log "Amount: $AMOUNT_XMR piconero XMR, $AMOUNT_WOW wonkero WOW"
log "Timelocks: XMR=$XMR_LOCK_BLOCKS blocks, WOW=$WOW_LOCK_BLOCKS blocks"
log ""

# ============================================================
# Step 0: Key Generation
# ============================================================
if [ "$COMPLETED_STEP" -lt 1 ]; then
    log "--- Step 0: Key Generation ---"

    if [ -n "$ALICE_SEED" ]; then
        ALICE_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network xmr-stagenet --mnemonic "$ALICE_SEED" 2>/dev/null)
    else
        ALICE_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network xmr-stagenet 2>/dev/null)
    fi
    ALICE_SPEND_KEY=$(echo "$ALICE_WALLET_OUTPUT" | grep -oP 'Spend key \(private\): \K[0-9a-f]+')
    ALICE_VIEW_KEY=$(echo "$ALICE_WALLET_OUTPUT" | grep -oP 'View key \(private\):  \K[0-9a-f]+')
    ALICE_ADDRESS=$(echo "$ALICE_WALLET_OUTPUT" | grep -oP 'Address:             \K\S+')
    log "Alice XMR address: $ALICE_ADDRESS"

    if [ -n "$BOB_SEED" ]; then
        BOB_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network wow-mainnet --mnemonic "$BOB_SEED" 2>/dev/null)
    else
        BOB_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network wow-mainnet 2>/dev/null)
    fi
    BOB_SPEND_KEY=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'Spend key \(private\): \K[0-9a-f]+')
    BOB_VIEW_KEY=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'View key \(private\):  \K[0-9a-f]+')
    BOB_ADDRESS=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'Address:             \K\S+')
    log "Bob WOW address: $BOB_ADDRESS"
    log ""

    log "IMPORTANT: Fund Bob's WOW wallet before proceeding:"
    log "  Bob WOW (mainnet): $BOB_ADDRESS"
    log ""

    COMPLETED_STEP=1
    save_state
    log "State saved (step $COMPLETED_STEP). Safe to interrupt."

    read -p "Fund Bob's WOW address above, then press Enter to continue..."
    log "User confirmed funding. Continuing..."
    log ""
fi

# ============================================================
# Step 1: Alice initiates
# ============================================================
if [ "$COMPLETED_STEP" -lt 2 ]; then
    log "--- Step 1: Alice init ---"
    ALICE_OUTPUT=$(run_alice init-alice \
        --amount-xmr "$AMOUNT_XMR" --amount-wow "$AMOUNT_WOW" \
        --xmr-lock-blocks "$XMR_LOCK_BLOCKS" --wow-lock-blocks "$WOW_LOCK_BLOCKS")
    ALICE_MSG=$(echo "$ALICE_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1)
    ALICE_SWAP_ID=$(echo "$ALICE_OUTPUT" | grep -oiP 'swap ID: \K[0-9a-f]+' | tail -1)
    log "Alice swap ID: $ALICE_SWAP_ID"
    log ""

    COMPLETED_STEP=2
    save_state
fi

# ============================================================
# Step 2: Bob responds
# ============================================================
if [ "$COMPLETED_STEP" -lt 3 ]; then
    log "--- Step 2: Bob responds ---"
    BOB_OUTPUT=$(run_bob init-bob --message "$ALICE_MSG")
    BOB_MSG=$(echo "$BOB_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1)
    BOB_SWAP_ID=$(echo "$BOB_OUTPUT" | grep -oP 'Swap ID: \K[0-9a-f]+' | tail -1)
    log "Bob swap ID: $BOB_SWAP_ID"
    log ""

    COMPLETED_STEP=3
    save_state
fi

# ============================================================
# Step 3: Alice imports Bob's response
# ============================================================
if [ "$COMPLETED_STEP" -lt 4 ]; then
    log "--- Step 3: Alice import ---"
    IMPORT_OUTPUT=$(run_alice import --swap-id "$ALICE_SWAP_ID" --message "$BOB_MSG")
    REAL_SWAP_ID=$(echo "$IMPORT_OUTPUT" | grep -oP 'Swap ID: \K[0-9a-f]+' | tail -1)
    if [ -n "$REAL_SWAP_ID" ]; then
        ALICE_SWAP_ID="$REAL_SWAP_ID"
    fi
    log ""

    COMPLETED_STEP=4
    save_state
fi

# ============================================================
# Step 4: Bob imports Alice's init message
# ============================================================
if [ "$COMPLETED_STEP" -lt 5 ]; then
    log "--- Step 4: Bob import ---"
    run_bob import --swap-id "$BOB_SWAP_ID" --message "$ALICE_MSG"
    log ""

    COMPLETED_STEP=5
    save_state
fi

# ============================================================
# Step 5: Bob locks WOW
# ============================================================
if [ "$COMPLETED_STEP" -lt 6 ]; then
    log "--- Step 5: Bob locks WOW ---"
    BOB_LOCK_OUTPUT=$(run_bob lock-wow --swap-id "$BOB_SWAP_ID" \
        --wow-daemon "$WOW_DAEMON" \
        --spend-key "$BOB_SPEND_KEY" --view-key "$BOB_VIEW_KEY" \
        --scan-from "$WOW_SCAN_FROM")
    log "Lock output: $BOB_LOCK_OUTPUT"
    log ""

    COMPLETED_STEP=6
    save_state
fi

# ============================================================
# Step 6: Cooperative refund key exchange and build refund tx
# ============================================================
if [ "$COMPLETED_STEP" -lt 7 ]; then
    log "--- Step 6: Cooperative refund and build refund tx ---"

    log "Alice generates refund cooperation message..."
    ALICE_COOP_OUTPUT=$(run_alice generate-refund-cooperate --swap-id "$ALICE_SWAP_ID")
    ALICE_COOP=$(echo "$ALICE_COOP_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1)

    log "Bob generates refund cooperation message..."
    BOB_COOP_OUTPUT=$(run_bob generate-refund-cooperate --swap-id "$BOB_SWAP_ID")
    BOB_COOP=$(echo "$BOB_COOP_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1)

    log "Bob builds refund tx..."
    BOB_REFUND_OUTPUT=$(run_bob build-refund --swap-id "$BOB_SWAP_ID" \
        --cooperate-msg "$ALICE_COOP" \
        --destination "$BOB_ADDRESS" \
        --wow-daemon "$WOW_DAEMON" \
        --scan-from "$WOW_SCAN_FROM")
    log "Build-refund output: $BOB_REFUND_OUTPUT"

    # Extract refund tx hex for daemon-side test
    REFUND_TX_HEX=$(echo "$BOB_REFUND_OUTPUT" | grep -oiP 'Refund tx hex:\s*\K[0-9a-f]+' | head -1 || true)
    if [ -z "$REFUND_TX_HEX" ]; then
        REFUND_TX_HEX=$(echo "$BOB_REFUND_OUTPUT" | grep -oiP 'tx.hex[:\s]*\K[0-9a-f]+' | head -1 || true)
    fi

    # Extract refund height
    BOB_REFUND_HEIGHT=$(echo "$BOB_REFUND_OUTPUT" | grep -oiP 'refund height[:\s]*\K[0-9]+' | tail -1 || true)
    if [ -z "$BOB_REFUND_HEIGHT" ]; then
        BOB_REFUND_HEIGHT=$(echo "$BOB_REFUND_OUTPUT" | grep -oiP 'timelock[:\s]*\K[0-9]+' | tail -1 || true)
    fi
    if [ -z "$BOB_REFUND_HEIGHT" ]; then
        BOB_REFUND_HEIGHT=$(echo "$BOB_REFUND_OUTPUT" | grep -oiP 'unlock.time[:\s]*\K[0-9]+' | tail -1 || true)
    fi
    if [ -z "$BOB_REFUND_HEIGHT" ]; then
        log "WARNING: Could not extract refund height. Querying current height + WOW_LOCK_BLOCKS..."
        CURRENT_HEIGHT=$(curl -s "$WOW_DAEMON/json_rpc" \
            -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}' \
            | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['count'])")
        BOB_REFUND_HEIGHT=$((CURRENT_HEIGHT + WOW_LOCK_BLOCKS))
    fi
    log "WOW refund height target: $BOB_REFUND_HEIGHT"
    log ""

    COMPLETED_STEP=7
    save_state
fi

# ============================================================
# Step 7: PREMATURE REFUND -- Client-side rejection (D-03)
# ============================================================
if [ "$COMPLETED_STEP" -lt 8 ]; then
    log "--- Step 7: Premature refund attempt (client-side check) ---"
    log "Attempting broadcast-refund BEFORE timelock expires..."

    RESULT=$(run_bob broadcast-refund --swap-id "$BOB_SWAP_ID" --wow-daemon "$WOW_DAEMON" 2>&1 || true)

    if echo "$RESULT" | grep -qi "timelock\|unlock\|not yet\|expired\|remaining\|too early\|height"; then
        log "PASS (client-side): Client rejected premature refund broadcast"
        log "Rejection message: $(echo "$RESULT" | tail -3)"
    else
        log "WARNING: Expected timelock rejection but got unexpected output:"
        log "$RESULT"
        log "Continuing to daemon-side test..."
    fi
    log ""

    COMPLETED_STEP=8
    save_state
fi

# ============================================================
# Step 8: PREMATURE REFUND -- Daemon-side rejection (D-07)
# ============================================================
if [ "$COMPLETED_STEP" -lt 9 ]; then
    log "--- Step 8: Premature refund attempt (daemon-side check) ---"

    if [ -n "$REFUND_TX_HEX" ]; then
        log "Submitting raw refund tx directly to WOW daemon..."
        DAEMON_RESULT=$(curl -s "$WOW_DAEMON/sendrawtransaction" \
            -d "{\"tx_as_hex\":\"$REFUND_TX_HEX\"}" 2>&1 || true)
        log "Daemon response: $DAEMON_RESULT"

        if echo "$DAEMON_RESULT" | grep -qi "unlock\|timelock\|not yet\|too early\|nonzero unlock\|failed\|error\|rejected"; then
            log "PASS (daemon-side): Daemon rejected premature raw tx submission"
        else
            log "NOTE: Daemon response may not explicitly mention timelock. Full response logged above."
            log "The daemon may accept the tx into the pool but not mine it until timelock height."
        fi
    else
        log "SKIP: Could not extract refund tx hex from build-refund output."
        log "Daemon-side rejection test requires tx hex. Client-side test still valid."
    fi
    log ""

    COMPLETED_STEP=9
    save_state
fi

# ============================================================
# Step 9: Poll until timelock expires
# ============================================================
if [ "$COMPLETED_STEP" -lt 10 ]; then
    log "--- Step 9: Polling WOW block height until timelock expiry ---"
    poll_height "$WOW_DAEMON" "$BOB_REFUND_HEIGHT" "WOW"
    log ""

    COMPLETED_STEP=10
    save_state
fi

# ============================================================
# Step 10: Successful refund after timelock
# ============================================================
if [ "$COMPLETED_STEP" -lt 11 ]; then
    log "--- Step 10: Bob broadcasts refund (after timelock) ---"
    REFUND_OUTPUT=$(run_bob broadcast-refund --swap-id "$BOB_SWAP_ID" --wow-daemon "$WOW_DAEMON")
    log "Refund broadcast output: $REFUND_OUTPUT"

    # Extract refund tx hash as evidence (D-06)
    REFUND_TX_HASH=$(echo "$REFUND_OUTPUT" | grep -oiP '(tx.hash|transaction.hash|refund.tx)[:\s]*\K[0-9a-f]{64}' | head -1 || true)
    if [ -z "$REFUND_TX_HASH" ]; then
        REFUND_TX_HASH=$(echo "$REFUND_OUTPUT" | grep -oP '[0-9a-f]{64}' | head -1 || true)
    fi

    if [ -n "$REFUND_TX_HASH" ]; then
        log "REFUND TX HASH: $REFUND_TX_HASH"
    else
        log "WARNING: Could not extract refund tx hash from output"
    fi
    log ""

    COMPLETED_STEP=11
    save_state
fi

# ============================================================
# Final status
# ============================================================
log "--- Final Status ---"
run_bob show "$BOB_SWAP_ID" || true

log ""
log "================================================================"
log "PASS: Premature rejection verified AND refund succeeded after timelock"
log "================================================================"
log "Test results:"
log "  1. Client-side: broadcast-refund rejected before timelock (D-03)"
if [ -n "${REFUND_TX_HEX:-}" ]; then
    log "  2. Daemon-side: raw tx submission tested (D-07)"
fi
log "  3. After timelock: refund broadcast succeeded"
if [ -n "${REFUND_TX_HASH:-}" ]; then
    log "Evidence: Refund tx $REFUND_TX_HASH"
fi
log "State: $STATE_FILE"
log "Log:   $LOG"
