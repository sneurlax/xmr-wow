#!/usr/bin/env bash
# Entrypoint for the sharechain-node service.
# Runs xmr-wow-node in RPC-only mode so Alice and Bob can coordinate via HTTP.
set -euo pipefail

RPC_PORT="${RPC_PORT:-18091}"

echo "[sharechain-node] starting xmr-wow-node --rpc-only --rpc-port ${RPC_PORT}"
exec xmr-wow-node \
    --rpc-port "${RPC_PORT}" \
    --rpc-only
