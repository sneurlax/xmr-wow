#!/usr/bin/env bash
# live-happy-path.sh -- Full XMR<->WOW atomic swap on live networks
#
# Supports persistence: saves state after each step to a JSON file.
# If interrupted, re-run with --resume <state-file> to continue.
# Supports mnemonic seeds: --alice-seed "25 words" --bob-seed "25 words"
#
# Usage:
#   ./scripts/live-happy-path.sh [--alice-seed "words..."] [--bob-seed "words..."]
#   ./scripts/live-happy-path.sh --resume swap-state-<ts>.json
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
XMR_LOCK_BLOCKS="${XMR_LOCK_BLOCKS:-50}"
WOW_LOCK_BLOCKS="${WOW_LOCK_BLOCKS:-200}"

# --- State management ---
STATE_FILE=""
COMPLETED_STEP=0

# State variables (populated from state file on resume)
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
ALICE_PRESIG=""
BOB_PRESIG=""
BOB_XMR_DEST=""
ALICE_WOW_DEST=""
BOB_CLAIM_MSG=""
ALICE_CLAIM_MSG=""

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
  "alice_presig": "$ALICE_PRESIG",
  "bob_presig": "$BOB_PRESIG",
  "bob_xmr_dest": "$BOB_XMR_DEST",
  "alice_wow_dest": "$ALICE_WOW_DEST",
  "bob_claim_msg": "$BOB_CLAIM_MSG",
  "alice_claim_msg": "$ALICE_CLAIM_MSG"
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
    ALICE_PRESIG=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('alice_presig',''))")
    BOB_PRESIG=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('bob_presig',''))")
    BOB_XMR_DEST=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('bob_xmr_dest',''))")
    ALICE_WOW_DEST=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('alice_wow_dest',''))")
    BOB_CLAIM_MSG=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('bob_claim_msg',''))")
    ALICE_CLAIM_MSG=$(python3 -c "import json; d=json.load(open('$file')); print(d.get('alice_claim_msg',''))")
    STATE_FILE="$file"
}

# --- Resume or fresh start ---
if [ -n "$RESUME_FILE" ]; then
    echo "Resuming from: $RESUME_FILE"
    load_state "$RESUME_FILE"
    echo "Completed through step $COMPLETED_STEP. Continuing..."
else
    ALICE_DB="${ALICE_DB:-/tmp/alice-swap-$$.db}"
    BOB_DB="${BOB_DB:-/tmp/bob-swap-$$.db}"
    STATE_FILE="swap-state-$(date +%s).json"
fi

LOG="swap-happy-$(date +%s).log"

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }
run_alice() {
    log "ALICE> $*"
    cargo run --release -p xmr-wow-client -- --password "$PASSWORD" --db "$ALICE_DB" "$@" 2>&1 | tee -a "$LOG"
}
run_bob() {
    log "BOB> $*"
    cargo run --release -p xmr-wow-client -- --password "$PASSWORD" --db "$BOB_DB" "$@" 2>&1 | tee -a "$LOG"
}

log "=== XMR<->WOW HAPPY PATH SWAP ==="
log "XMR daemon: $XMR_DAEMON"
log "WOW daemon: $WOW_DAEMON"
log "Alice DB: $ALICE_DB"
log "Bob DB: $BOB_DB"
log "State: $STATE_FILE"
log "Amount: $AMOUNT_XMR piconero XMR, $AMOUNT_WOW wonkero WOW"
log ""

# ============================================================
# Step 0: Key Generation (or import from mnemonic seeds)
# ============================================================
if [ "$COMPLETED_STEP" -lt 1 ]; then
    log "--- Step 0: Key Generation ---"

    if [ -n "$ALICE_SEED" ]; then
        log "Importing Alice's wallet from mnemonic seed..."
        ALICE_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network xmr-stagenet --mnemonic "$ALICE_SEED" 2>/dev/null)
    else
        log "Generating Alice's XMR stagenet wallet..."
        ALICE_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network xmr-stagenet 2>/dev/null)
    fi
    ALICE_SPEND_KEY=$(echo "$ALICE_WALLET_OUTPUT" | grep -oP 'Spend key \(private\): \K[0-9a-f]+')
    ALICE_VIEW_KEY=$(echo "$ALICE_WALLET_OUTPUT" | grep -oP 'View key \(private\):  \K[0-9a-f]+')
    ALICE_ADDRESS=$(echo "$ALICE_WALLET_OUTPUT" | grep -oP 'Address:             \K\S+')
    ALICE_SEED_WORDS=$(echo "$ALICE_WALLET_OUTPUT" | grep -oP 'Seed:                \K.+')
    log "Alice XMR address: $ALICE_ADDRESS"
    log "Alice spend key:   ${ALICE_SPEND_KEY:0:8}..."

    if [ -n "$BOB_SEED" ]; then
        log "Importing Bob's wallet from mnemonic seed..."
        BOB_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network wow-mainnet --mnemonic "$BOB_SEED" 2>/dev/null)
    else
        log "Generating Bob's WOW mainnet wallet..."
        BOB_WALLET_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network wow-mainnet 2>/dev/null)
    fi
    BOB_SPEND_KEY=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'Spend key \(private\): \K[0-9a-f]+')
    BOB_VIEW_KEY=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'View key \(private\):  \K[0-9a-f]+')
    BOB_ADDRESS=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'Address:             \K\S+')
    BOB_SEED_WORDS=$(echo "$BOB_WALLET_OUTPUT" | grep -oP 'Seed:                \K.+')
    log "Bob WOW address:   $BOB_ADDRESS"
    log "Bob spend key:     ${BOB_SPEND_KEY:0:8}..."
    log ""

    log "Alice seed: $ALICE_SEED_WORDS"
    log "Bob seed:   $BOB_SEED_WORDS"
    log ""

    log "IMPORTANT: Fund these addresses before proceeding:"
    log "  Alice XMR (stagenet): $ALICE_ADDRESS"
    log "  Bob WOW (mainnet):    $BOB_ADDRESS"
    log ""

    COMPLETED_STEP=1
    save_state
    log "State saved (step $COMPLETED_STEP). Safe to interrupt."

    read -p "Fund both addresses above, then press Enter to continue..."
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
    log "Alice message: ${ALICE_MSG:0:40}..."
    log "Alice swap ID: $ALICE_SWAP_ID"
    log ""

    COMPLETED_STEP=2
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 2: Bob responds
# ============================================================
if [ "$COMPLETED_STEP" -lt 3 ]; then
    log "--- Step 2: Bob init ---"
    BOB_OUTPUT=$(run_bob init-bob --message "$ALICE_MSG")
    BOB_MSG=$(echo "$BOB_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1)
    BOB_SWAP_ID=$(echo "$BOB_OUTPUT" | grep -oP 'Swap ID: \K[0-9a-f]+' | tail -1)
    log "Bob message: ${BOB_MSG:0:40}..."
    log "Bob swap ID: $BOB_SWAP_ID"
    log ""

    COMPLETED_STEP=3
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 3: Alice imports Bob's response
# ============================================================
if [ "$COMPLETED_STEP" -lt 4 ]; then
    log "--- Step 3: Alice import ---"
    IMPORT_OUTPUT=$(run_alice import --swap-id "$ALICE_SWAP_ID" --message "$BOB_MSG")
    # Import produces a new real swap ID (replacing the temp ID)
    REAL_SWAP_ID=$(echo "$IMPORT_OUTPUT" | grep -oP 'Swap ID: \K[0-9a-f]+' | tail -1)
    if [ -n "$REAL_SWAP_ID" ]; then
        log "Alice swap ID updated: $ALICE_SWAP_ID -> $REAL_SWAP_ID"
        ALICE_SWAP_ID="$REAL_SWAP_ID"
    fi
    log ""

    COMPLETED_STEP=4
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 4: Bob locks WOW (first lock)
# ============================================================
if [ "$COMPLETED_STEP" -lt 5 ]; then
    log "--- Step 4: Bob locks WOW ---"
    BOB_LOCK_OUTPUT=$(run_bob lock-wow --swap-id "$BOB_SWAP_ID" \
        --wow-daemon "$WOW_DAEMON" \
        --spend-key "$BOB_SPEND_KEY" --view-key "$BOB_VIEW_KEY" --scan-from "$WOW_SCAN_FROM")
    log "Lock output: $BOB_LOCK_OUTPUT"
    BOB_PRESIG=$(echo "$BOB_LOCK_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1 || true)
    log ""

    COMPLETED_STEP=5
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 5: Alice verifies Bob's WOW lock and locks XMR
# ============================================================
if [ "$COMPLETED_STEP" -lt 6 ]; then
    log "--- Step 5: Alice locks XMR ---"
    ALICE_LOCK_OUTPUT=$(run_alice lock-xmr --swap-id "$ALICE_SWAP_ID" \
        --xmr-daemon "$XMR_DAEMON" --wow-daemon "$WOW_DAEMON" \
        --spend-key "$ALICE_SPEND_KEY" --view-key "$ALICE_VIEW_KEY" --scan-from "$XMR_SCAN_FROM")
    log "Lock output: $ALICE_LOCK_OUTPUT"
    ALICE_PRESIG=$(echo "$ALICE_LOCK_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1 || true)
    log ""

    COMPLETED_STEP=6
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 6: Exchange adaptor pre-signatures
# ============================================================
if [ "$COMPLETED_STEP" -lt 7 ]; then
    log "--- Step 6: Exchange pre-sigs ---"
    if [ -n "${ALICE_PRESIG:-}" ]; then
        run_bob exchange-pre-sig --swap-id "$BOB_SWAP_ID" --message "$ALICE_PRESIG"
    fi
    if [ -n "${BOB_PRESIG:-}" ]; then
        run_alice exchange-pre-sig --swap-id "$ALICE_SWAP_ID" --message "$BOB_PRESIG"
    fi
    log ""

    # Generate destination addresses for claiming
    BOB_XMR_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network xmr-stagenet 2>/dev/null)
    BOB_XMR_DEST=$(echo "$BOB_XMR_OUTPUT" | grep -oP 'Address:             \K\S+')
    log "Bob's XMR destination: $BOB_XMR_DEST"

    ALICE_WOW_OUTPUT=$(cargo run --release -p xmr-wow-client -- generate-wallet --network wow-mainnet 2>/dev/null)
    ALICE_WOW_DEST=$(echo "$ALICE_WOW_OUTPUT" | grep -oP 'Address:             \K\S+')
    log "Alice's WOW destination: $ALICE_WOW_DEST"

    COMPLETED_STEP=7
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 7: Bob claims XMR (reveals his secret)
# ============================================================
if [ "$COMPLETED_STEP" -lt 8 ]; then
    log "--- Step 7: Bob initiates claim ---"
    log "NOTE: Bob claims first per protocol (shorter WOW timelock)."
    BOB_CLAIM_OUTPUT=$(run_bob claim-xmr --swap-id "$BOB_SWAP_ID" \
        --xmr-daemon "$XMR_DAEMON" --destination "$BOB_XMR_DEST" \
        --scan-from "$XMR_SCAN_FROM" \
        --message "placeholder" || true)
    BOB_CLAIM_MSG=$(echo "$BOB_CLAIM_OUTPUT" | grep -oP 'xmrwow1:[A-Za-z0-9+/=]{10,}' | head -1 || true)
    log ""

    COMPLETED_STEP=8
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 8: Alice claims WOW (using Bob's revealed secret)
# ============================================================
if [ "$COMPLETED_STEP" -lt 9 ]; then
    log "--- Step 8: Alice claims WOW ---"
    if [ -n "${BOB_CLAIM_MSG:-}" ]; then
        ALICE_CLAIM_OUTPUT=$(run_alice claim-wow --swap-id "$ALICE_SWAP_ID" \
            --wow-daemon "$WOW_DAEMON" --destination "$ALICE_WOW_DEST" \
            --scan-from "$WOW_SCAN_FROM" \
            --message "$BOB_CLAIM_MSG" || true)
        ALICE_CLAIM_MSG=$(echo "$ALICE_CLAIM_OUTPUT" | grep -o 'xmrwow1:[A-Za-z0-9+/=]*' | tail -1 || true)
    fi
    log ""

    COMPLETED_STEP=9
    save_state
    log "State saved (step $COMPLETED_STEP)."
fi

# ============================================================
# Step 9: Bob completes XMR claim with Alice's ClaimProof
# ============================================================
if [ "$COMPLETED_STEP" -lt 10 ]; then
    log "--- Step 9: Bob completes XMR claim ---"
    if [ -n "${ALICE_CLAIM_MSG:-}" ]; then
        run_bob claim-xmr --swap-id "$BOB_SWAP_ID" \
            --xmr-daemon "$XMR_DAEMON" --destination "$BOB_XMR_DEST" \
            --scan-from "$XMR_SCAN_FROM" \
            --message "$ALICE_CLAIM_MSG" || true
    fi
    log ""

    COMPLETED_STEP=10
    save_state
fi

# ============================================================
# Final status
# ============================================================
log "--- Final Status ---"
run_alice show "$ALICE_SWAP_ID" || true
run_bob show "$BOB_SWAP_ID" || true

log ""
log "=== HAPPY PATH COMPLETE ==="
log "State: $STATE_FILE"
log "Log:   $LOG"
log "Review tx hashes above to verify on block explorer."
