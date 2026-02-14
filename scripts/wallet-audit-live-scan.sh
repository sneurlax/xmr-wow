#!/usr/bin/env bash
set -euo pipefail

# Wallet audit: scan-test against live daemons, assert no key leaks in output.
# Test wallets only: do not use for real funds.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="$PROJECT_ROOT/audit-artifacts"
BINARY="$PROJECT_ROOT/target/release/xmr-wow"
DATE=$(date +%Y-%m-%d)

# XMR stagenet test wallet
XMR_SPEND_KEY="094f70b39403c8ced4db1d93f8b7b9931d84e4e8466afd762943e9c5158c8800"
XMR_VIEW_KEY="eeb4f237134b899a1681dd7aa80efa7a0dc90068fc0289d0cb60d470976a6f0d"
XMR_FROM_HEIGHT=2085100

# WOW mainnet test wallet
WOW_SPEND_KEY="22ad0595698de12062869ba59bb0c96a083e5ce768b1d845b100004701d8110c"
WOW_VIEW_KEY="642aac8295eb60f215ccadfe4f0d8e8f1fd2c7f5aa38d8d911991604f920f30d"
WOW_FROM_HEIGHT=825200

WOW_DAEMON="http://127.0.0.1:34568"
XMR_DAEMON="http://127.0.0.1:38081"

echo "=== Wallet Audit Live-Scan ($DATE) ==="
echo "Script: WALLET-03 evidence collection"
echo "Artifact dir: $ARTIFACT_DIR"
echo ""

# Verify binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    echo "Run: cargo build -p xmr-wow-client --release"
    exit 1
fi

LEAK_FOUND=0
WOW_SUCCESS=0
XMR_SUCCESS=0

# --- WOW mainnet scan ---
echo "=== WOW mainnet scan-test ==="
echo "Daemon: $WOW_DAEMON"
echo "Scan from height: $WOW_FROM_HEIGHT"
echo ""

# Check daemon reachability
if curl -s --max-time 5 "$WOW_DAEMON/json_rpc" \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' \
    -H 'Content-Type: application/json' > /dev/null 2>&1; then
    echo "WOW daemon: REACHABLE"
    if "$BINARY" scan-test \
        --network wow-mainnet \
        --daemon "$WOW_DAEMON" \
        --spend-key "$WOW_SPEND_KEY" \
        --view-key "$WOW_VIEW_KEY" \
        --scan-from "$WOW_FROM_HEIGHT" \
        2>&1 | tee "$ARTIFACT_DIR/live-scan-wow.log"; then
        echo ""
        echo "WOW scan: COMPLETE"
        WOW_SUCCESS=1
    else
        echo ""
        echo "WOW scan: FAILED (exit code $?)"
        echo "WOW scan-test failed" >> "$ARTIFACT_DIR/live-scan-wow.log"
    fi
else
    echo "WOW daemon: UNREACHABLE ($WOW_DAEMON)"
    echo "WOW daemon unreachable at $WOW_DAEMON: WALLET-03 deferred (daemon unavailable)" > "$ARTIFACT_DIR/live-scan-wow.log"
fi

echo ""

# --- XMR stagenet scan ---
echo "=== XMR stagenet scan-test ==="
echo "Daemon: $XMR_DAEMON"
echo "Scan from height: $XMR_FROM_HEIGHT"
echo ""

# Check daemon reachability
if curl -s --max-time 5 "$XMR_DAEMON/json_rpc" \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' \
    -H 'Content-Type: application/json' > /dev/null 2>&1; then
    echo "XMR daemon: REACHABLE"
    if "$BINARY" scan-test \
        --network xmr-stagenet \
        --daemon "$XMR_DAEMON" \
        --spend-key "$XMR_SPEND_KEY" \
        --view-key "$XMR_VIEW_KEY" \
        --scan-from "$XMR_FROM_HEIGHT" \
        2>&1 | tee "$ARTIFACT_DIR/live-scan-xmr.log"; then
        echo ""
        echo "XMR scan: COMPLETE"
        XMR_SUCCESS=1
    else
        echo ""
        echo "XMR scan: FAILED (exit code $?)"
        echo "XMR scan-test failed" >> "$ARTIFACT_DIR/live-scan-xmr.log"
    fi
else
    echo "XMR daemon: UNREACHABLE ($XMR_DAEMON)"
    echo "XMR daemon unreachable at $XMR_DAEMON: WALLET-03 deferred (daemon unavailable)" > "$ARTIFACT_DIR/live-scan-xmr.log"
fi

echo ""

# --- Secret leak check ---
echo "=== Secret leak check ==="

for logfile in "$ARTIFACT_DIR/live-scan-wow.log" "$ARTIFACT_DIR/live-scan-xmr.log"; do
    if [ ! -f "$logfile" ]; then
        echo "WARN: Log file not found: $logfile"
        continue
    fi

    logname=$(basename "$logfile")

    # Check for literal "View privkey:" string (should be gated behind --verbose)
    if grep -q "View privkey: [0-9a-f]" "$logfile" 2>/dev/null; then
        echo "FAIL: Found raw view private key value in $logname"
        LEAK_FOUND=1
    else
        echo "PASS: No raw view private key value in $logname"
    fi

    # Check for known WOW view key hex
    if grep -q "$WOW_VIEW_KEY" "$logfile" 2>/dev/null; then
        echo "FAIL: Found WOW view key hex in $logname"
        LEAK_FOUND=1
    else
        echo "PASS: WOW view key hex not in $logname"
    fi

    # Check for known XMR view key hex
    if grep -q "$XMR_VIEW_KEY" "$logfile" 2>/dev/null; then
        echo "FAIL: Found XMR view key hex in $logname"
        LEAK_FOUND=1
    else
        echo "PASS: XMR view key hex not in $logname"
    fi

    # Check for known WOW spend key hex
    if grep -q "$WOW_SPEND_KEY" "$logfile" 2>/dev/null; then
        echo "FAIL: Found WOW spend key hex in $logname"
        LEAK_FOUND=1
    else
        echo "PASS: WOW spend key hex not in $logname"
    fi

    # Check for known XMR spend key hex
    if grep -q "$XMR_SPEND_KEY" "$logfile" 2>/dev/null; then
        echo "FAIL: Found XMR spend key hex in $logname"
        LEAK_FOUND=1
    else
        echo "PASS: XMR spend key hex not in $logname"
    fi

    echo ""
done

# --- Summary ---
echo "=== Summary ==="
echo "WOW scan: $([ $WOW_SUCCESS -eq 1 ] && echo 'SUCCESS' || echo 'DEFERRED/FAILED')"
echo "XMR scan: $([ $XMR_SUCCESS -eq 1 ] && echo 'SUCCESS' || echo 'DEFERRED/FAILED')"

if [ $LEAK_FOUND -eq 0 ]; then
    echo "Secret leak check: PASS: no private key material found in live scan logs"
    echo ""
    echo "WALLET-03: EVIDENCE COLLECTED: logs committed to $ARTIFACT_DIR"
else
    echo "Secret leak check: FAIL: private key material detected in live scan logs"
    exit 1
fi

# Require at least one successful daemon scan
if [ $WOW_SUCCESS -eq 0 ] && [ $XMR_SUCCESS -eq 0 ]; then
    echo "WARN: Neither daemon produced a successful scan. Check daemon status."
    echo "WALLET-03: DEFERRED: both daemons unreachable or scan failed"
    exit 2
fi
