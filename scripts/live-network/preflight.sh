#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN=false

usage() {
  cat <<'USAGE'
Usage: scripts/live-network/preflight.sh [--dry-run]

Validates that required daemons are reachable and on the expected networks
before you run any commands that write swap state.

Environment variables:
  XMR_DAEMON_URL        (default: http://127.0.0.1:38081)  # XMR stagenet
  WOW_DAEMON_URL        (default: http://127.0.0.1:34568)  # WOW mainnet
  SHARECHAIN_NODE_URL   (default: http://127.0.0.1:18091)  # xmr-wow-node JSON-RPC base URL

Options:
  --dry-run             Print what would be checked and exit 0.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

XMR_DAEMON_URL="${XMR_DAEMON_URL:-http://127.0.0.1:38081}"
WOW_DAEMON_URL="${WOW_DAEMON_URL:-http://127.0.0.1:34568}"
SHARECHAIN_NODE_URL="${SHARECHAIN_NODE_URL:-http://127.0.0.1:18091}"

announce() {
  printf '%s\n' "$1"
}

json_rpc() {
  local url="$1"
  local method="$2"
  curl -fsS --max-time 8 \
    "${url%/}/json_rpc" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"${method}\"}"
}

infer_nettype() {
  local json="$1"

  local nettype
  nettype="$(echo "$json" | jq -r '.result.nettype // empty')"
  if [[ -n "$nettype" && "$nettype" != "null" ]]; then
    case "$nettype" in
      mainnet|testnet|stagenet) echo "$nettype"; return 0 ;;
      0) echo "mainnet"; return 0 ;;
      1) echo "testnet"; return 0 ;;
      2) echo "stagenet"; return 0 ;;
      *) echo "$nettype"; return 0 ;;
    esac
  fi

  local is_stagenet is_testnet
  is_stagenet="$(echo "$json" | jq -r '.result.stagenet // false')"
  is_testnet="$(echo "$json" | jq -r '.result.testnet // false')"

  if [[ "$is_stagenet" == "true" ]]; then echo "stagenet"; return 0; fi
  if [[ "$is_testnet" == "true" ]]; then echo "testnet"; return 0; fi
  echo "mainnet"
}

check_daemon() {
  local label="$1"
  local url="$2"
  local expected_net="$3"

  announce ""
  announce "== ${label} preflight =="
  announce "URL: ${url}"
  announce "Expected nettype: ${expected_net}"

  local info_json
  if ! info_json="$(json_rpc "$url" get_info 2>/dev/null)"; then
    echo "ERROR: ${label} daemon is unreachable at ${url} (get_info failed)." >&2
    echo "Hint: verify the daemon is running and the RPC port is correct." >&2
    return 1
  fi

  local synchronized nettype height target_height
  synchronized="$(echo "$info_json" | jq -r '.result.synchronized // false')"
  nettype="$(infer_nettype "$info_json")"
  height="$(echo "$info_json" | jq -r '.result.height // empty')"
  target_height="$(echo "$info_json" | jq -r '.result.target_height // empty')"

  if [[ "$synchronized" != "true" ]]; then
    echo "ERROR: ${label} daemon reports synchronized=false." >&2
    echo "Hint: wait for sync to complete, then re-run preflight." >&2
    echo "Observed: height=${height:-?} target_height=${target_height:-?} nettype=${nettype:-?}" >&2
    return 1
  fi

  if [[ "$nettype" != "$expected_net" ]]; then
    echo "ERROR: ${label} daemon nettype mismatch. Expected ${expected_net}, got ${nettype}." >&2
    echo "Hint: restart the daemon with the correct network flags." >&2
    return 1
  fi

  announce "OK: synchronized=true nettype=${nettype} height=${height:-?}"
}

check_sharechain_node() {
  local url="$1"
  announce ""
  announce "== Sharechain node preflight =="
  announce "URL: ${url}"

  if ! curl -fsS --max-time 6 "${url%/}/health" >/dev/null 2>&1; then
    echo "ERROR: sharechain node healthcheck failed at ${url}/health" >&2
    echo "Hint: start xmr-wow-node (and confirm its --rpc-port) before running the live harness." >&2
    return 1
  fi

  announce "OK: /health returned HTTP 200"
}

announce "XMR-WOW live-network preflight"
announce "References: docs/DEPLOYMENT.md (daemon prerequisites and manual flow)"

if [[ "$DRY_RUN" == "true" ]]; then
  announce ""
  announce "Dry run enabled; would check:"
  announce "- XMR daemon: ${XMR_DAEMON_URL} (stagenet, synchronized)"
  announce "- WOW daemon: ${WOW_DAEMON_URL} (mainnet, synchronized)"
  announce "- Sharechain node: ${SHARECHAIN_NODE_URL}/health"
  exit 0
fi

check_daemon "XMR" "$XMR_DAEMON_URL" "stagenet"
check_daemon "WOW" "$WOW_DAEMON_URL" "mainnet"
check_sharechain_node "$SHARECHAIN_NODE_URL"

announce ""
announce "Preflight OK"
