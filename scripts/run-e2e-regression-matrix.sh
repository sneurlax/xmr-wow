#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [--artifact-root DIR] [--run-id ID] [--work-root DIR] [--dry-run]

Run the local E2E regression matrix:
  - Shadow OOB via simulations/shadow-swap.yaml
  - Shadow sharechain via simulations/shadow-sharechain-swap.yaml
  - Live harness dry-run via scripts/run-live-network-harness.sh --dry-run

Artifacts:
  Timestamped: <artifact-root>/runs/<run-id>/
  Stable copy: <artifact-root>/latest/

This proves local regression coverage only. It does not replace live-network
operator validation with real funded secrets.
EOF
}

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"
}

fail() {
  printf '[FAIL] %s\n' "$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -e "$path" ]] || fail "Missing required file: $path"
}

json_get() {
  local path="$1"
  local key="$2"
  python3 - "$path" "$key" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    value = json.load(fh)

for part in sys.argv[2].split("."):
    value = value[part]

print(value)
PY
}

find_host_log() {
  local host_dir="$1"
  local marker="$2"
  local match
  match="$(grep -R -l -F --include='bash.*.stdout' -- "$marker" "$host_dir" | sort | tail -1 || true)"
  [[ -n "$match" ]] || fail "Could not find host log marker '$marker' under $host_dir"
  printf '%s\n' "$match"
}

maybe_find_host_log() {
  local host_dir="$1"
  local marker="$2"
  grep -R -l -F --include='bash.*.stdout' -- "$marker" "$host_dir" 2>/dev/null | sort | tail -1 || true
}

capture_markers() {
  local log_path="$1"
  local output_path="$2"
  shift 2

  : > "$output_path"
  local marker
  for marker in "$@"; do
    if ! grep -n -F -- "$marker" "$log_path" >> "$output_path"; then
      fail "Expected marker '$marker' missing in $log_path"
    fi
  done
}

reset_cli_shared_state() {
  mkdir -p "$SHARED_DIR"
  rm -f \
    "$SHARED_DIR"/xmr_wow_cli_msg_*.json \
    "$SHARED_DIR"/xmr_wow_cli_msg_*.lock \
    "$SHARED_DIR"/xmr_wow_cli_result_*.json \
    "$SHARED_DIR"/xmr_wow_cli_result_*.lock
}

reset_sharechain_shared_state() {
  mkdir -p "$SHARED_DIR"
  rm -f \
    "$SHARED_DIR"/xmr_wow_sharechain_result_*.json \
    "$SHARED_DIR"/xmr_wow_sharechain_result_*.lock \
    "$SHARED_DIR"/xmr_wow_sharechain_coord.json \
    "$SHARED_DIR"/xmr_wow_sharechain_coord.json.lock
}

write_lane_summary() {
  local lane_dir="$1"
  local lane_label="$2"
  local scenario="$3"
  local swap_id="$4"
  local alice_status="$5"
  local bob_status="$6"
  local alice_log_src="$7"
  local bob_log_src="$8"
  local shadow_output="$9"

  cat > "$lane_dir/SUMMARY.md" <<EOF
# ${lane_label}

- Scenario: \`${scenario}\`
- Swap ID: \`${swap_id}\`
- Alice terminal status: \`${alice_status}\`
- Bob terminal status: \`${bob_status}\`
- Shadow output: \`${shadow_output}\`
- Alice log source: \`${alice_log_src}\`
- Bob log source: \`${bob_log_src}\`
EOF
}

compact_command_stdout() {
  local src="$1"
  local dest="$2"
  local byte_count
  local line_count

  if [[ ! -s "$src" ]]; then
    : > "$dest"
    return 0
  fi

  byte_count="$(wc -c < "$src" | tr -d ' ')"
  line_count="$(wc -l < "$src" | tr -d ' ')"

  {
    printf '# Trimmed command stdout\n'
    printf '# Original size: %s bytes across %s lines\n' "$byte_count" "$line_count"
    printf '# Kept sections: first 40 lines and last 200 lines\n\n'
    printf '## First 40 lines\n'
    sed -n '1,40p' "$src"
    printf '\n## Last 200 lines\n'
    tail -n 200 "$src"
  } > "$dest"
}

shadow_lane_ready() {
  local shadow_output="$1"
  local alice_result_src="$2"
  local bob_result_src="$3"
  local alice_marker_primary="$4"
  local bob_marker_primary="$5"
  local alice_marker_secondary="${6:-}"

  [[ -f "$alice_result_src" && -f "$bob_result_src" ]] || return 1

  local alice_status
  local bob_status
  local alice_swap_id
  local bob_swap_id
  alice_status="$(json_get "$alice_result_src" status 2>/dev/null || true)"
  bob_status="$(json_get "$bob_result_src" status 2>/dev/null || true)"
  alice_swap_id="$(json_get "$alice_result_src" swap_id 2>/dev/null || true)"
  bob_swap_id="$(json_get "$bob_result_src" swap_id 2>/dev/null || true)"

  case "$alice_status" in
    claimed|complete) ;;
    *) return 1 ;;
  esac

  case "$bob_status" in
    claimed|complete) ;;
    *) return 1 ;;
  esac

  [[ -n "$alice_swap_id" && "$alice_swap_id" == "$bob_swap_id" ]] || return 1

  local alice_log_src
  local bob_log_src
  alice_log_src="$(maybe_find_host_log "$shadow_output/shadow.data/hosts/alice" "$alice_marker_primary")"
  bob_log_src="$(maybe_find_host_log "$shadow_output/shadow.data/hosts/bob" "$bob_marker_primary")"
  [[ -n "$alice_log_src" && -n "$bob_log_src" ]] || return 1

  if [[ -n "$alice_marker_secondary" ]]; then
    grep -Fq -- "$alice_marker_secondary" "$alice_log_src" || return 1
  fi

  return 0
}

stop_lane_process() {
  local lane_pid="$1"
  pkill -TERM -P "$lane_pid" 2>/dev/null || true
  kill -TERM "$lane_pid" 2>/dev/null || true
  sleep 1
  pkill -KILL -P "$lane_pid" 2>/dev/null || true
  kill -KILL "$lane_pid" 2>/dev/null || true
  wait "$lane_pid" 2>/dev/null || true
}

run_shadow_lane() {
  local lane_name="$1"
  local lane_label="$2"
  local scenario_rel="$3"
  local result_prefix="$4"
  local alice_marker_primary="$5"
  local bob_marker_primary="$6"
  local alice_marker_secondary="${7:-}"

  local lane_dir="$RUN_DIR/$lane_name"
  local shadow_output="$WORK_ROOT/$lane_name"
  local command_stdout="$lane_dir/command.stdout"
  local command_stdout_full="$WORK_ROOT/${lane_name}.command.stdout.full"
  local command_stderr="$lane_dir/command.stderr"
  local scenario_abs="$ROOT_DIR/$scenario_rel"
  local alice_result_src="$SHARED_DIR/${result_prefix}_alice.json"
  local bob_result_src="$SHARED_DIR/${result_prefix}_bob.json"
  local lane_pid=""
  local lane_completed_via_monitor=false

  mkdir -p "$lane_dir"
  printf 'bash scripts/run-shadow-cli-scenario.sh --output %s %s\n' \
    "$shadow_output" "$scenario_rel" > "$lane_dir/command.txt"

  case "$result_prefix" in
    xmr_wow_cli_result)
      reset_cli_shared_state
      ;;
    xmr_wow_sharechain_result)
      reset_sharechain_shared_state
      ;;
    *)
      fail "Unknown result prefix: $result_prefix"
      ;;
  esac

  log "Running ${lane_label}"
  bash "$ROOT_DIR/scripts/run-shadow-cli-scenario.sh" \
    --output "$shadow_output" \
    "$scenario_abs" \
    >"$command_stdout_full" \
    2>"$command_stderr" &
  lane_pid="$!"

  while kill -0 "$lane_pid" 2>/dev/null; do
    if shadow_lane_ready \
        "$shadow_output" \
        "$alice_result_src" \
        "$bob_result_src" \
        "$alice_marker_primary" \
        "$bob_marker_primary" \
        "$alice_marker_secondary"; then
      log "${lane_label} reached terminal success markers; stopping Shadow early"
      stop_lane_process "$lane_pid"
      lane_completed_via_monitor=true
      break
    fi
    sleep 5
  done

  if [[ "$lane_completed_via_monitor" == "false" ]]; then
    if ! wait "$lane_pid"; then
      mv "$command_stdout_full" "$command_stdout"
      fail "${lane_label} failed. See ${command_stdout} and ${command_stderr}"
    fi
  fi

  compact_command_stdout "$command_stdout_full" "$command_stdout"
  rm -f "$command_stdout_full"

  [[ -f "$alice_result_src" ]] || fail "${lane_label} missing result file: $alice_result_src"
  [[ -f "$bob_result_src" ]] || fail "${lane_label} missing result file: $bob_result_src"

  cp "$alice_result_src" "$lane_dir/alice-result.json"
  cp "$bob_result_src" "$lane_dir/bob-result.json"

  local alice_status
  local bob_status
  local alice_swap_id
  local bob_swap_id
  alice_status="$(json_get "$alice_result_src" status)"
  bob_status="$(json_get "$bob_result_src" status)"
  alice_swap_id="$(json_get "$alice_result_src" swap_id)"
  bob_swap_id="$(json_get "$bob_result_src" swap_id)"

  case "$alice_status" in
    claimed|complete) ;;
    *) fail "${lane_label} Alice status was '${alice_status}', expected claimed or complete" ;;
  esac

  case "$bob_status" in
    claimed|complete) ;;
    *) fail "${lane_label} Bob status was '${bob_status}', expected claimed or complete" ;;
  esac

  [[ -n "$alice_swap_id" ]] || fail "${lane_label} Alice result missing swap_id"
  [[ "$alice_swap_id" == "$bob_swap_id" ]] || fail "${lane_label} swap_id mismatch (${alice_swap_id} != ${bob_swap_id})"

  local alice_log_src
  local bob_log_src
  alice_log_src="$(find_host_log "$shadow_output/shadow.data/hosts/alice" "$alice_marker_primary")"
  bob_log_src="$(find_host_log "$shadow_output/shadow.data/hosts/bob" "$bob_marker_primary")"

  cp "$alice_log_src" "$lane_dir/alice-host.log"
  cp "$bob_log_src" "$lane_dir/bob-host.log"

  if [[ -n "$alice_marker_secondary" ]]; then
    capture_markers "$lane_dir/alice-host.log" "$lane_dir/alice-markers.txt" \
      "$alice_marker_primary" "$alice_marker_secondary"
  else
    capture_markers "$lane_dir/alice-host.log" "$lane_dir/alice-markers.txt" \
      "$alice_marker_primary"
  fi
  capture_markers "$lane_dir/bob-host.log" "$lane_dir/bob-markers.txt" \
    "$bob_marker_primary"

  printf '%s\n' "$shadow_output" > "$lane_dir/shadow-output-path.txt"
  write_lane_summary \
    "$lane_dir" \
    "$lane_label" \
    "$scenario_rel" \
    "$alice_swap_id" \
    "$alice_status" \
    "$bob_status" \
    "$alice_log_src" \
    "$bob_log_src" \
    "$shadow_output"

  case "$lane_name" in
    shadow-oob)
      OOB_SWAP_ID="$alice_swap_id"
      OOB_ALICE_STATUS="$alice_status"
      OOB_BOB_STATUS="$bob_status"
      ;;
    shadow-sharechain)
      SHARECHAIN_SWAP_ID="$alice_swap_id"
      SHARECHAIN_ALICE_STATUS="$alice_status"
      SHARECHAIN_BOB_STATUS="$bob_status"
      ;;
  esac

  log "${lane_label} passed (swap_id=${alice_swap_id})"
}

run_live_dry_run() {
  local lane_dir="$RUN_DIR/live-dry-run"
  local stdout_path="$lane_dir/stdout.log"
  local stderr_path="$lane_dir/stderr.log"

  mkdir -p "$lane_dir"
  printf 'bash scripts/run-live-network-harness.sh --dry-run\n' > "$lane_dir/command.txt"

  log "Running live harness dry-run"
  if ! bash "$ROOT_DIR/scripts/run-live-network-harness.sh" --dry-run \
      >"$stdout_path" \
      2>"$stderr_path"; then
    fail "Live harness dry-run failed. See ${stdout_path} and ${stderr_path}"
  fi

  grep -Fq "Dry run: would run preflight" "$stdout_path" || \
    fail "Live harness dry-run output did not contain the expected dry-run marker"

  cat > "$lane_dir/SUMMARY.md" <<EOF
# Live Harness Dry Run

- Command: \`bash scripts/run-live-network-harness.sh --dry-run\`
- Result: passed
- Scope: validates the repo-local live harness entrypoint shape only
EOF

  LIVE_DRY_RUN_STATUS="passed"
  log "Live harness dry-run passed"
}

write_run_report() {
  cat > "$RUN_DIR/RUN-REPORT.md" <<EOF
# E2E Regression Matrix Run

- Run ID: \`${RUN_ID}\`
- Generated: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`
- Artifact root: \`${ARTIFACT_ROOT}\`
- Work root: \`${WORK_ROOT}\`

## Lanes

| Lane | Result | Swap ID |
|------|--------|---------|
| Shadow OOB | passed (${OOB_ALICE_STATUS}/${OOB_BOB_STATUS}) | \`${OOB_SWAP_ID}\` |
| Shadow sharechain | passed (${SHARECHAIN_ALICE_STATUS}/${SHARECHAIN_BOB_STATUS}) | \`${SHARECHAIN_SWAP_ID}\` |
| Live dry-run | ${LIVE_DRY_RUN_STATUS} | n/a |

## Scope

This matrix proves the local production-path regression lanes are still healthy:

- Shadow OOB reaches terminal success
- Shadow sharechain reaches terminal success
- the live harness dry-run command still executes cleanly

This does not replace live-network operator validation with real funded secrets
and actual live harness execution with sanitized artifacts.
EOF
}

refresh_latest() {
  rm -rf "$LATEST_DIR"
  mkdir -p "$LATEST_DIR"
  cp -a "$RUN_DIR/." "$LATEST_DIR/"
}

DRY_RUN=false
ARTIFACT_ROOT=""
RUN_ID=""
WORK_ROOT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      ARTIFACT_ROOT="${2:-}"
      shift 2
      ;;
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --work-root)
      WORK_ROOT="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "Unknown option: $1"
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-$ROOT_DIR/artifacts/e2e-regression-matrix}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_ROOT="${WORK_ROOT:-/tmp/xmr-wow-e2e-regression-${RUN_ID}}"
RUN_DIR="$ARTIFACT_ROOT/runs/$RUN_ID"
LATEST_DIR="$ARTIFACT_ROOT/latest"
SHARED_DIR="${MONEROSIM_SHARED_DIR:-/tmp/monerosim_shared}"

if [[ "$DRY_RUN" == "true" ]]; then
  cat <<EOF
E2E regression matrix dry run
Artifact root: ${ARTIFACT_ROOT}
Run ID: ${RUN_ID}
Work root: ${WORK_ROOT}

Planned lanes:
  - shadow-oob: bash scripts/run-shadow-cli-scenario.sh --output ${WORK_ROOT}/shadow-oob simulations/shadow-swap.yaml
  - shadow-sharechain: bash scripts/run-shadow-cli-scenario.sh --output ${WORK_ROOT}/shadow-sharechain simulations/shadow-sharechain-swap.yaml
  - live-dry-run: bash scripts/run-live-network-harness.sh --dry-run
EOF
  exit 0
fi

require_file "$ROOT_DIR/scripts/run-shadow-cli-scenario.sh"
require_file "$ROOT_DIR/scripts/run-live-network-harness.sh"
require_file "$ROOT_DIR/simulations/shadow-swap.yaml"
require_file "$ROOT_DIR/simulations/shadow-sharechain-swap.yaml"
require_file "$ROOT_DIR/target/release/xmr-wow"
require_file "$ROOT_DIR/target/release/xmr-wow-node"

mkdir -p "$RUN_DIR" "$WORK_ROOT"

OOB_SWAP_ID=""
OOB_ALICE_STATUS=""
OOB_BOB_STATUS=""
SHARECHAIN_SWAP_ID=""
SHARECHAIN_ALICE_STATUS=""
SHARECHAIN_BOB_STATUS=""
LIVE_DRY_RUN_STATUS=""

log "Writing timestamped artifacts to ${RUN_DIR}"
log "Using work root ${WORK_ROOT}"

run_shadow_lane \
  "shadow-oob" \
  "Shadow OOB" \
  "simulations/shadow-swap.yaml" \
  "xmr_wow_cli_result" \
  "WOW claimed successfully." \
  "XMR claimed. Swap complete."

run_shadow_lane \
  "shadow-sharechain" \
  "Shadow sharechain" \
  "simulations/shadow-sharechain-swap.yaml" \
  "xmr_wow_sharechain_result" \
  "WOW claimed successfully." \
  "XMR claimed. Swap complete." \
  "alice observed Bob result file"

run_live_dry_run
write_run_report
refresh_latest

log "E2E regression matrix passed"
printf 'Artifacts: %s\n' "$RUN_DIR"
printf 'Latest: %s\n' "$LATEST_DIR"
