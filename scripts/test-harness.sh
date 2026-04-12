#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/runs/test-harness}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/proof-harness-${timestamp}.log}"
mkdir -p "$LOG_DIR"

announce() {
    printf '%s\n' "$1" | tee -a "$LOG_FILE"
}

run() {
    announce ""
    announce ">>> $*"
    "$@" 2>&1 | tee -a "$LOG_FILE"
}

: > "$LOG_FILE"
announce "XMR-WOW supported v1.2 proof harness"
announce "Log: $LOG_FILE"

run cargo test -p xmr-wow-wallet xmr_wallet_refund_artifact_round_trip_on_simnet wow_wallet_refund_artifact_round_trip_on_simnet -- --nocapture
run cargo test -p xmr-wow-integration happy_path_uses_real_wallets_and_swap_state_on_simnet refund_artifact_survives_restart_and_solves_to_real_sweep -- --nocapture
run cargo test --manifest-path deps/wownero-simnet/Cargo.toml --features spend-tests alice_sends_to_bob_and_bob_finds_output -- --nocapture

announce ""
announce "Proof harness complete"
announce "Log: $LOG_FILE"
