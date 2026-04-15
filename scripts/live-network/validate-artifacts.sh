#!/usr/bin/env bash
# validate-artifacts.sh: Validate committed live-run artifact files.
#
# Usage: bash scripts/live-network/validate-artifacts.sh
#
# Exits 0 if all filled artifacts pass checks, or if all files are still unfilled templates.
# Exits 1 if any check fails on a filled artifact.
#
# Checks performed:
#   1. File existence (all four artifact files present and non-empty)
#   2. Terminal state markers (terminal_state is not PLACEHOLDER; value is claimed|refunded|aborted)
#   3. swap_id matching between Alice and Bob files for each transport mode
#   4. No private key material (spend_key/view_key 64-char hex lines)

set -euo pipefail

ARTIFACTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/artifacts/live-network"

SC_ALICE="${ARTIFACTS_DIR}/sharechain-run-alice.md"
SC_BOB="${ARTIFACTS_DIR}/sharechain-run-bob.md"
OOB_ALICE="${ARTIFACTS_DIR}/oob-run-alice.md"
OOB_BOB="${ARTIFACTS_DIR}/oob-run-bob.md"

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "[SKIP] $1"; }

# ---------------------------------------------------------------------------
# Category 1: File existence
# ---------------------------------------------------------------------------
echo "=== Category 1: File existence ==="

all_exist=true
for f in "$SC_ALICE" "$SC_BOB" "$OOB_ALICE" "$OOB_BOB"; do
  if [[ -f "$f" && -s "$f" ]]; then
    pass "exists and non-empty: $(basename "$f")"
  else
    fail "missing or empty: $(basename "$f")"
    all_exist=false
  fi
done

if [[ "$all_exist" == "false" ]]; then
  echo "=== Validation complete: ${PASS} passed, ${FAIL} failed ==="
  exit 1
fi

# ---------------------------------------------------------------------------
# Early exit: all four files are unfilled templates
# ---------------------------------------------------------------------------
sc_alice_unfilled=false
sc_bob_unfilled=false
oob_alice_unfilled=false
oob_bob_unfilled=false

grep -q "^swap_id: PLACEHOLDER" "$SC_ALICE"   && sc_alice_unfilled=true   || true
grep -q "^swap_id: PLACEHOLDER" "$SC_BOB"     && sc_bob_unfilled=true     || true
grep -q "^swap_id: PLACEHOLDER" "$OOB_ALICE"  && oob_alice_unfilled=true  || true
grep -q "^swap_id: PLACEHOLDER" "$OOB_BOB"    && oob_bob_unfilled=true    || true

if [[ "$sc_alice_unfilled" == "true" && "$sc_bob_unfilled" == "true" && \
      "$oob_alice_unfilled" == "true" && "$oob_bob_unfilled" == "true" ]]; then
  echo ""
  echo "Templates not yet filled: run live swap first."
  echo "(All four artifact files still contain PLACEHOLDER swap_ids: this is the expected pre-run state.)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Category 2: Terminal state markers
# ---------------------------------------------------------------------------
echo ""
echo "=== Category 2: Terminal state markers ==="

for f in "$SC_ALICE" "$SC_BOB" "$OOB_ALICE" "$OOB_BOB"; do
  name="$(basename "$f")"

  if grep -q "^terminal_state: PLACEHOLDER" "$f"; then
    fail "terminal_state not filled in ${name}"
  elif grep -qE "^terminal_state: (claimed|refunded|aborted)" "$f"; then
    pass "terminal_state valid in ${name}"
  else
    fail "terminal_state has unexpected value in ${name} (expected: claimed | refunded | aborted)"
  fi
done

# ---------------------------------------------------------------------------
# Category 3: swap_id matching between Alice and Bob
# ---------------------------------------------------------------------------
echo ""
echo "=== Category 3: swap_id matching ==="

check_swap_id_pair() {
  local label="$1"
  local alice_file="$2"
  local bob_file="$3"
  local alice_id bob_id

  alice_id=$(grep "^swap_id:" "$alice_file" | awk '{print $2}')
  bob_id=$(grep "^swap_id:" "$bob_file" | awk '{print $2}')

  if [[ "$alice_id" == "PLACEHOLDER" || "$bob_id" == "PLACEHOLDER" || -z "$alice_id" || -z "$bob_id" ]]; then
    skip "${label}: swap_ids not yet filled (PLACEHOLDER still present)"
    return
  fi

  if [[ "$alice_id" == "$bob_id" ]]; then
    pass "${label}: Alice swap_id matches Bob swap_id (${alice_id})"
  else
    fail "${label}: Alice swap_id does not match Bob swap_id (alice=${alice_id} bob=${bob_id})"
  fi
}

check_swap_id_pair "sharechain run" "$SC_ALICE" "$SC_BOB"
check_swap_id_pair "oob run"        "$OOB_ALICE" "$OOB_BOB"

# ---------------------------------------------------------------------------
# Category 4: No private key material
# ---------------------------------------------------------------------------
echo ""
echo "=== Category 4: Private key material scan ==="

for f in "$SC_ALICE" "$SC_BOB" "$OOB_ALICE" "$OOB_BOB"; do
  name="$(basename "$f")"

  # Hard fail: explicit spend_key line with 64-char hex
  if grep -qE "^spend_key: [0-9a-f]{64}$" "$f"; then
    fail "private spend_key found in ${name}: remove before committing"
  else
    pass "no spend_key leak in ${name}"
  fi

  # Hard fail: explicit view_key line with 64-char hex
  if grep -qE "^view_key: [0-9a-f]{64}$" "$f"; then
    fail "private view_key found in ${name}: remove before committing"
  else
    pass "no view_key leak in ${name}"
  fi

  # Warn (non-failing): bare 64-char hex line anywhere in file (heuristic)
  bare_count=$(grep -cE "^[0-9a-f]{64}$" "$f" || true)
  if [[ "$bare_count" -gt 0 ]]; then
    echo "[WARN] bare 64-char hex found in ${name} (${bare_count} line(s)): verify not key material"
  fi
done

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Validation complete: ${PASS} passed, ${FAIL} failed ==="
if [[ $FAIL -gt 0 ]]; then exit 1; fi
exit 0
