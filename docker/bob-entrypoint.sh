#!/usr/bin/env bash
# Entrypoint for the Bob swap client container.
#
# SCOPE NOTE: Full swap execution (init-bob through claim-wow) is not yet
# implemented here. This script demonstrates the correct CLI invocation pattern
# with --transport sharechain.
#
# Required env vars:
#   NODE_URL         : URL of the sharechain-node service (e.g. http://sharechain-node:18091)
#   BOB_XMR_ADDRESS  : Bob's Monero stagenet address
#   BOB_WOW_ADDRESS  : Bob's Wownero mainnet address
#   XMR_DAEMON_URL   : Monero stagenet daemon RPC URL
#   WOW_DAEMON_URL   : Wownero mainnet daemon RPC URL
#   SWAP_PASSWORD    : Key encryption password
set -euo pipefail

NODE_URL="${NODE_URL:?NODE_URL env var required}"
SWAP_PASSWORD="${SWAP_PASSWORD:?SWAP_PASSWORD env var required}"

COMMON_FLAGS="--transport sharechain --node-url ${NODE_URL} --password ${SWAP_PASSWORD}"

echo "[bob] sharechain node: ${NODE_URL}"
echo "[bob] STUB: swap orchestration not yet implemented in this entrypoint"
echo "[bob] When ready, invoke:"
echo "  xmr-wow ${COMMON_FLAGS} init-bob \\"
echo "      --xmr-address \${BOB_XMR_ADDRESS} \\"
echo "      --wow-address \${BOB_WOW_ADDRESS} \\"
echo "      --xmr-daemon-url \${XMR_DAEMON_URL} \\"
echo "      --wow-daemon-url \${WOW_DAEMON_URL}"
echo "[bob] exiting (stub)"
