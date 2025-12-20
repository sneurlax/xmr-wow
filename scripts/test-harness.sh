#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/.planning/reports}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/phase16-proof-harness-${timestamp}.log}"
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

run cargo test -p xmr-wow-wallet phase16_ -- --nocapture
run cargo test -p xmr-wow-integration phase16_ -- --nocapture
run cargo test --manifest-path deps/wownero-simnet/Cargo.toml --features spend-tests alice_sends_to_bob_and_bob_finds_output -- --nocapture

announce ""
announce "Phase 16 proof harness complete"
announce "Log: $LOG_FILE"
