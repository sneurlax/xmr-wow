#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_MONEROSIM_DIR="$(cd "${REPO_ROOT}/../../monerosim" && pwd)"
MONEROSIM_DIR="${MONEROSIM_DIR:-${DEFAULT_MONEROSIM_DIR}}"
DEFAULT_SHADOW_BIN="${HOME}/.monerosim/bin/shadow"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--generate-only] [--output DIR] <scenario.yaml>

Generate a monerosim Shadow config for an XMR-WOW CLI-driven scenario, rewrite
the generated wrappers so they execute the repo-local agent files, and
optionally launch Shadow using the monerosim-managed binary.

Options:
  --generate-only   Generate and patch wrappers, but do not launch Shadow
  --output DIR      Output directory for generated Shadow config
  -h, --help        Show this help

Environment:
  MONEROSIM_DIR     Monerosim checkout path (default: ${DEFAULT_MONEROSIM_DIR})
  SHADOW_BIN        Shadow binary path (default: ${DEFAULT_SHADOW_BIN} if present,
                    otherwise first 'shadow' on PATH)
EOF
}

GENERATE_ONLY=0
OUT_DIR=""
SCENARIO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --generate-only)
      GENERATE_ONLY=1
      shift
      ;;
    --output)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "${SCENARIO}" ]]; then
        echo "Only one scenario path may be provided" >&2
        usage >&2
        exit 1
      fi
      SCENARIO="$1"
      shift
      ;;
  esac
done

if [[ -z "${SCENARIO}" ]]; then
  usage >&2
  exit 1
fi

if [[ ! -f "${SCENARIO}" ]]; then
  echo "Scenario not found: ${SCENARIO}" >&2
  exit 1
fi

if [[ ! -d "${MONEROSIM_DIR}" ]]; then
  echo "Monerosim checkout not found: ${MONEROSIM_DIR}" >&2
  exit 1
fi

if [[ -z "${OUT_DIR}" ]]; then
  SCENARIO_BASENAME="$(basename "${SCENARIO}" .yaml)"
  OUT_DIR="/tmp/${SCENARIO_BASENAME}-shadow"
fi

if [[ -n "${SHADOW_BIN:-}" ]]; then
  :
elif [[ -x "${DEFAULT_SHADOW_BIN}" ]]; then
  SHADOW_BIN="${DEFAULT_SHADOW_BIN}"
else
  SHADOW_BIN="$(command -v shadow)"
fi

if [[ ! -x "${SHADOW_BIN}" ]]; then
  echo "Shadow binary is not executable: ${SHADOW_BIN}" >&2
  exit 1
fi

SCENARIO_ABS="$(cd "$(dirname "${SCENARIO}")" && pwd)/$(basename "${SCENARIO}")"

echo "Generating Shadow config:"
echo "  scenario: ${SCENARIO_ABS}"
echo "  output:   ${OUT_DIR}"
echo "  monerosim:${MONEROSIM_DIR}"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

(
  cd "${MONEROSIM_DIR}"
  cargo run --bin monerosim -- --config "${SCENARIO_ABS}" --output "${OUT_DIR}"
)

patch_wrapper() {
  local wrapper="$1"
  local from="$2"
  local to="$3"
  if [[ -f "${wrapper}" ]] && grep -q -- "${from}" "${wrapper}"; then
    python3 - "${wrapper}" "${from}" "${to}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
PY
    echo "patched wrapper: ${wrapper##*/}"
  fi
}

patch_wow_wallet_args() {
  local target="$1"
  if [[ -f "${target}" ]] && grep -q -- "wownero-wallet-rpc" "${target}"; then
    python3 - "${target}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
rewritten = []
for line in lines:
    if "wownero-wallet-rpc" in line:
        line = line.replace("--shared-ringdb-dir=", "--wow-shared-ringdb-dir=")
        if "--testnet" not in line:
            line = line.replace("wownero-wallet-rpc ", "wownero-wallet-rpc --testnet ", 1)
    rewritten.append(line)
path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
PY
    echo "patched WOW wallet args: ${target##*/}"
  fi
}

patch_wow_daemon_args() {
  local target="$1"
  if [[ -f "${target}" ]] && grep -q -- "wownerod" "${target}" && grep -q -- "--regtest" "${target}"; then
    python3 - "${target}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
rewritten = []
for line in lines:
    if "wownerod" in line:
        line = line.replace(" --regtest ", " --testnet ", 1)
    rewritten.append(line)
path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
PY
    echo "patched WOW daemon args: ${target##*/}"
  fi
}

patch_agent_expected_final_state() {
  local target="$1"
  if [[ -f "${target}" ]] && grep -q -- "agent_.*_wrapper.sh" "${target}"; then
    python3 - "${target}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
rewritten = []
agent_wrapper_process = False

for line in lines:
    stripped = line.strip()
    if stripped.startswith("- path: "):
        agent_wrapper_process = False
    elif stripped.startswith("args: ") and "agent_" in stripped and "_wrapper.sh" in stripped:
        agent_wrapper_process = True

    if agent_wrapper_process and stripped == "expected_final_state: running":
        indent = line[: len(line) - len(line.lstrip())]
        rewritten.append(f"{indent}expected_final_state:")
        rewritten.append(f"{indent}  exited: 0")
        agent_wrapper_process = False
        continue

    rewritten.append(line)

path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
PY
    echo "patched agent final state: ${target##*/}"
  fi
}

SCRIPTS_DIR="${OUT_DIR}/scripts"
CLI_AGENT="${REPO_ROOT}/simulations/agents/xmr_wow_cli_agent.py"
SHARECHAIN_AGENT="${REPO_ROOT}/simulations/agents/xmr_wow_sharechain_agent.py"

if [[ -d "${SCRIPTS_DIR}" ]]; then
  while IFS= read -r -d '' wrapper; do
    patch_wrapper "${wrapper}" "python3 -m agents.xmr_wow_cli_agent" "python3 ${CLI_AGENT}"
    patch_wrapper "${wrapper}" "python3 -m agents.xmr_wow_sharechain_agent" "python3 ${SHARECHAIN_AGENT}"
    patch_wow_daemon_args "${wrapper}"
    patch_wow_wallet_args "${wrapper}"
  done < <(find "${SCRIPTS_DIR}" -maxdepth 1 -type f -name '*wrapper.sh' -print0)
fi

patch_wow_daemon_args "${OUT_DIR}/shadow_agents.yaml"
patch_wow_wallet_args "${OUT_DIR}/shadow_agents.yaml"
patch_agent_expected_final_state "${OUT_DIR}/shadow_agents.yaml"

echo "Using Shadow binary: ${SHADOW_BIN}"
echo "Generated config: ${OUT_DIR}/shadow_agents.yaml"

if [[ "${GENERATE_ONLY}" -eq 1 ]]; then
  exit 0
fi

(
  cd "${OUT_DIR}"
  exec "${SHADOW_BIN}" "${OUT_DIR}/shadow_agents.yaml"
)
