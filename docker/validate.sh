#!/usr/bin/env bash
# Static validation for xmr-wow Docker Compose infrastructure.
# Does NOT require a running Docker daemon or container build.
# Exits 0 on full pass, non-zero on any failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

PASS=0
FAIL=0

check() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: ${label}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${label}"
        FAIL=$((FAIL + 1))
    fi
}

check_grep() {
    local label="$1"
    local file="$2"
    local pattern="$3"
    if grep -qE "${pattern}" "${file}" 2>/dev/null; then
        echo "  PASS: ${label}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${label} (pattern '${pattern}' not found in ${file})"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== XMR-WOW Docker Infrastructure Validation ==="
echo ""

# --- 1. File existence ---
echo "-- File existence --"
for f in Dockerfile.xmr-wow docker-compose.yaml \
          sharechain-node-entrypoint.sh alice-entrypoint.sh bob-entrypoint.sh \
          README.md; do
    check "exists: ${f}" test -f "${f}"
done
echo ""

# --- 2. Shell syntax ---
echo "-- Shell syntax (bash -n) --"
for sh in sharechain-node-entrypoint.sh alice-entrypoint.sh bob-entrypoint.sh validate.sh; do
    check "bash -n ${sh}" bash -n "${sh}"
done
echo ""

# --- 3. Dockerfile structural checks ---
echo "-- Dockerfile structure --"
check_grep "multi-stage: builder stage"  Dockerfile.xmr-wow "FROM rust.*AS builder"
check_grep "multi-stage: runtime stage" Dockerfile.xmr-wow "FROM debian.*AS runtime"
check_grep "binary: xmr-wow-node copied" Dockerfile.xmr-wow "xmr-wow-node"
check_grep "binary: xmr-wow copied"     Dockerfile.xmr-wow "COPY.*xmr-wow[^-]"
check_grep "non-root user"              Dockerfile.xmr-wow "USER xmrwow"
check_grep "entrypoint scripts copied"  Dockerfile.xmr-wow "alice-entrypoint"
echo ""

# --- 4. docker-compose.yaml: YAML parse ---
echo "-- docker-compose.yaml YAML parse --"
if command -v docker >/dev/null 2>&1; then
    check "docker compose config (full parse)" \
        docker compose -f docker-compose.yaml config
else
    check "python3 yaml.safe_load parse" \
        python3 -c "import yaml,sys; yaml.safe_load(open('docker-compose.yaml'))"
fi
echo ""

# --- 5. docker-compose.yaml structural checks ---
echo "-- docker-compose.yaml structure --"
check_grep "service: sharechain-node"      docker-compose.yaml "sharechain-node:"
check_grep "service: alice"               docker-compose.yaml "alice:"
check_grep "service: bob"                 docker-compose.yaml "bob:"
check_grep "healthcheck on node"          docker-compose.yaml "healthcheck:"
check_grep "alice depends_on node"        docker-compose.yaml "service_healthy"
check_grep "NODE_URL env in alice"        docker-compose.yaml "NODE_URL"
check_grep "SWAP_PASSWORD env in compose" docker-compose.yaml "SWAP_PASSWORD"
check_grep "volumes section"              docker-compose.yaml "^volumes:"
check_grep "alice-data volume"            docker-compose.yaml "alice-data"
check_grep "bob-data volume"              docker-compose.yaml "bob-data"
echo ""

# --- 6. Entrypoint content checks ---
echo "-- Entrypoint content --"
check_grep "node uses --rpc-only"         sharechain-node-entrypoint.sh "rpc-only"
check_grep "alice uses --transport sharechain" alice-entrypoint.sh "transport sharechain"
check_grep "bob uses --transport sharechain"   bob-entrypoint.sh   "transport sharechain"
check_grep "alice uses NODE_URL"          alice-entrypoint.sh "NODE_URL"
check_grep "bob uses NODE_URL"            bob-entrypoint.sh   "NODE_URL"
check_grep "alice STUB label"             alice-entrypoint.sh "STUB"
check_grep "bob STUB label"               bob-entrypoint.sh   "STUB"
echo ""

# --- 7. README checks ---
echo "-- README.md content --"
check_grep "docker compose up in README"     README.md "docker compose.*up"
check_grep "docker compose down -v in README" README.md "docker compose.*down"
check_grep "WOW port 34568 in README"        README.md "34568"
check_grep "scope limitation documented"     README.md "[Ss]cope"
check_grep "scope limitation documented"     README.md "[Ss]cope"
echo ""

# --- 8. Optional: hadolint (Dockerfile linter) ---
echo "-- Dockerfile lint (hadolint, optional) --"
if command -v hadolint >/dev/null 2>&1; then
    check "hadolint Dockerfile.xmr-wow" hadolint Dockerfile.xmr-wow
    echo "  (hadolint available: full lint run)"
else
    echo "  SKIP: hadolint not installed (install from https://github.com/hadolint/hadolint)"
fi
echo ""

# --- Summary ---
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
