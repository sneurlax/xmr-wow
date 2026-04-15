#!/usr/bin/env bash
# Entrypoint for the Alice swap client container.
#
# SCOPE NOTE: Full swap execution (init-alice through claim-xmr) is not yet
# implemented here. This script demonstrates the correct CLI invocation pattern
# with --transport sharechain.
#
# Required env vars:
#   NODE_URL          : URL of the sharechain-node service (e.g. http://sharechain-node:18091)
#   ALICE_XMR_ADDRESS : Alice's Monero stagenet address
#   ALICE_WOW_ADDRESS : Alice's Wownero mainnet address
#   XMR_DAEMON_URL    : Monero stagenet daemon RPC URL
#   WOW_DAEMON_URL    : Wownero mainnet daemon RPC URL
#   SWAP_PASSWORD     : Key encryption password
set -euo pipefail

NODE_URL="${NODE_URL:?NODE_URL env var required}"
SWAP_PASSWORD="${SWAP_PASSWORD:?SWAP_PASSWORD env var required}"

COMMON_FLAGS="--transport sharechain --node-url ${NODE_URL} --password ${SWAP_PASSWORD}"

echo "[alice] sharechain node: ${NODE_URL}"
echo "[alice] STUB: swap orchestration not yet implemented in this entrypoint"
echo "[alice] When ready, invoke:"
echo "  xmr-wow ${COMMON_FLAGS} init-alice \\"
echo "      --xmr-address \${ALICE_XMR_ADDRESS} \\"
echo "      --wow-address \${ALICE_WOW_ADDRESS} \\"
echo "      --xmr-daemon-url \${XMR_DAEMON_URL} \\"
echo "      --wow-daemon-url \${WOW_DAEMON_URL}"
echo "[alice] exiting (stub)"
