# XMR-WOW Docker Compose

Reproducible multi-container environment for an XMR-WOW atomic swap: a shared
sharechain node plus isolated Alice and Bob swap clients.

## Services

| Service | Image | Role |
|---------|-------|------|
| `sharechain-node` | `xmr-wow:latest` | WOW sharechain RPC node (`xmr-wow-node --rpc-only`) |
| `alice` | `xmr-wow:latest` | Alice swap client (`xmr-wow --transport sharechain`) |
| `bob` | `xmr-wow:latest` | Bob swap client (`xmr-wow --transport sharechain`) |

Alice and Bob wait for the sharechain-node health check to pass before starting.

## Prerequisites

- Docker 24+ with Compose plugin (`docker compose version`)
- Running Monero stagenet daemon accessible from containers
- Running Wownero mainnet daemon accessible from containers

## Quick Start

```
# 1. Build the image (from repository root)
docker compose -f docker/docker-compose.yaml build

# 2. Set required env vars (copy and fill in real values)
export ALICE_XMR_ADDRESS=<alice stagenet address>
export ALICE_WOW_ADDRESS=<alice wownero address>
export BOB_XMR_ADDRESS=<bob stagenet address>
export BOB_WOW_ADDRESS=<bob wownero address>
export XMR_DAEMON_URL=http://<host>:38081
export WOW_DAEMON_URL=http://<host>:34568
export SWAP_PASSWORD=changeme

# 3. Start services
docker compose -f docker/docker-compose.yaml up

# 4. Observe logs
docker compose -f docker/docker-compose.yaml logs -f

# 5. Clean up (removes containers and named volumes for a fresh run)
docker compose -f docker/docker-compose.yaml down -v
```

A second run after `docker compose down -v` starts from clean state; no leftover swap databases or coord files.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ALICE_XMR_ADDRESS` | yes | Alice's Monero stagenet address |
| `ALICE_WOW_ADDRESS` | yes | Alice's Wownero mainnet address |
| `BOB_XMR_ADDRESS` | yes | Bob's Monero stagenet address |
| `BOB_WOW_ADDRESS` | yes | Bob's Wownero mainnet address |
| `XMR_DAEMON_URL` | yes | Monero stagenet daemon RPC URL (e.g. `http://host:38081`) |
| `WOW_DAEMON_URL` | yes | Wownero mainnet daemon RPC URL (e.g. `http://host:34568`) |
| `SWAP_PASSWORD` | yes | Password for swap key encryption |
| `RPC_PORT` | no | sharechain-node RPC port (default: 18091) |

Note: WOW mainnet daemon default port is 34568 (not 34567).

## Volumes

| Volume | Mount | Purpose |
|--------|-------|---------|
| `alice-data` | `/home/xmrwow` (alice) | Alice's swap database |
| `bob-data` | `/home/xmrwow` (bob) | Bob's swap database |
| `coord-data` | `/coord` (bob) | Coord handoff scratch space |

## Known Scope Limitation

<!-- scope: structural proof only; full e2e deferred -->

**End-to-end swap execution is not yet implemented in the entrypoint scripts.**

This Docker Compose infrastructure is a structural deliverable. The actual
multi-container end-to-end swap run requires working production-mode swap
orchestration between two clients with real daemons (daemon-polling
orchestration via the sharechain transport dispatch).

The entrypoint scripts (`alice-entrypoint.sh`, `bob-entrypoint.sh`) print the
correct CLI invocation pattern and exit. Replace the stub bodies with real
swap-driving loops modeled on
`simulations/agents/xmr_wow_sharechain_agent.py`.

