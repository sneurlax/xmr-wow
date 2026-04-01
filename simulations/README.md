# Shadow Network Simulation for XMR-WOW Atomic Swap

## Overview

This directory contains [Shadow](https://shadow.github.io/) network simulation
configs for testing the XMR-WOW atomic swap protocol under realistic network
conditions.

**Shadow** is a discrete-event network simulator that runs real application
binaries (like `monerod`) in a simulated network environment. It provides
deterministic, reproducible experiments with configurable latency, bandwidth,
and network partitions.

**monerosim** is a Rust configuration generator that takes a YAML scenario
description and produces Shadow-compatible configs plus Python agent scripts.
It handles IP allocation, topology setup, daemon/wallet process management,
and agent lifecycle.

**Why this matters for XMR-WOW:** While the in-process simnet tests prove swap
correctness with instant blocks and no network overhead, Shadow simulations
validate that the 9-step operator flow and its refund-safety assumptions survive
realistic networking: latency, message reordering, restarts, and partitions.
Shadow runs real daemon binaries with real consensus rules.

These simulations are validation artifacts. They are not operator-facing live
walkthroughs and they do not replace the refund-readiness checks documented in
`docs/DEPLOYMENT.md`.

## Prerequisites

- **Shadow** -- Install from [shadow.github.io](https://shadow.github.io/docs/guide/install_dependencies.html)
- **monerod compiled for Shadow** -- From `shadowformonero` at `/home/user/src/monero/shadowformonero/`
  (Shadow requires binaries compiled with its interposition library)
- **monerosim** -- Configuration generator at `/home/user/src/monero/monerosim/`
- **Python 3.x** with `requests` library (for agent scripts)
- **monero-wallet-rpc** -- Wallet RPC binary (from same Shadow-compatible build)

## Scenarios

### `shadow-swap.yaml` -- CLI-Driven 9-Step Flow

Runs the real `xmr-wow` binary as a subprocess inside Shadow through
`agents/xmr_wow_cli_agent.py`. This is the highest-level simulation artifact in
the repo: message exchange happens through shared files, but lock, claim,
resume, and refund-gating behavior are exercised through the real CLI.

### `swap-scenario.yaml` -- 9-Step Atomic Swap

Models the supported swap ordering between Alice (XMR) and Bob (WOW):

1. Two chains mine maturity blocks (76 blocks each)
2. Alice and Bob exchange Ed25519 key contributions
3. Alice locks XMR to the joint address
4. Bob verifies Alice's lock, then locks WOW
5. Alice claims WOW (revealing the adaptor signature secret)
6. Bob uses the revealed secret to claim XMR

Agents: 2 miners (one per chain), Alice, Bob, miner-distributor, monitor.
Duration: 4 hours simulated time.

### `shadow-network-partition.yaml` -- CLI-Driven Refund Safety

Uses the same CLI-driving agent, but puts both parties in `refund_test` mode so
the simulation focuses on checkpoint persistence, `resume`, and refund safety
once the counterparty stops advancing the swap.

### `network-partition.yaml` -- Refund Safety Under Network Partition

Tests the safety properties when a counterparty goes offline:

1. Alice and Bob exchange keys
2. Alice locks XMR
3. Bob goes offline (simulated by stopping Bob's processes)
4. Alice waits for the refund timelock height
5. Alice reclaims her locked XMR

Validates safety requirements SAFE-01 through SAFE-04: no funds are lost even
when the counterparty disappears.

Duration: 6 hours simulated time.

## Running a Simulation

```bash
# 1. Generate Shadow config from monerosim YAML
cd /home/user/src/monero/monerosim
cargo run -- generate ../swap/xmr-wow/simulations/swap-scenario.yaml -o /tmp/swap-sim

# 2. Run Shadow simulation
shadow /tmp/swap-sim/shadow.yaml

# 3. Analyze results
# Shadow outputs are in /tmp/swap-sim/shadow.data/
# Agent logs are in each host's stdout/stderr files
# Swap results are in /tmp/monerosim_shared/swap_state_*_result.json
```

For the refund scenario:

```bash
cd /home/user/src/monero/monerosim
cargo run -- generate ../swap/xmr-wow/simulations/network-partition.yaml -o /tmp/refund-sim
shadow /tmp/refund-sim/shadow.yaml
```

For the CLI-driven scenarios:

```bash
cd /home/user/src/monero/monerosim
cargo run -- generate ../swap/xmr-wow/simulations/shadow-swap.yaml -o /tmp/shadow-cli-swap
shadow /tmp/shadow-cli-swap/shadow.yaml

cargo run -- generate ../swap/xmr-wow/simulations/shadow-network-partition.yaml -o /tmp/shadow-cli-refund
shadow /tmp/shadow-cli-refund/shadow.yaml
```

## Integration with XMR-WOW

These Shadow simulations complement the in-process simnet tests:

| Aspect           | Simnet (cuprate-simnet)       | Shadow (monerosim)              |
|------------------|-------------------------------|---------------------------------|
| Block production | Instant, in-process           | Real monerod, 120s target       |
| Network          | Direct function calls         | Simulated TCP with latency      |
| Consensus        | Real validation rules         | Full monerod consensus          |
| Determinism      | Fully deterministic           | Deterministic (single-threaded) |
| Speed            | Seconds                       | Minutes to hours                |
| Use case         | Functional correctness        | Network resilience              |

**Shadow is NOT required for development.** The simnet tests cover functional
correctness of the swap protocol. Shadow tests are for validating behavior under
network conditions that the simnet cannot model (latency, partitions, reorgs).

## Agent Details

### `swap_agent.py`

The `SwapAgent` class extends monerosim's `BaseAgent` and implements the swap
protocol as a state machine:

| State                | Description                                    |
|----------------------|------------------------------------------------|
| `init`               | Agent started, waiting for activity start time |
| `keys_generated`     | Ed25519 key pair generated                     |
| `keys_exchanged`     | Counterparty key received, joint address derived |
| `locked`             | Funds transferred to joint address             |
| `counterparty_locked`| Counterparty's lock verified                   |
| `claimed`            | Funds claimed using revealed secret            |
| `refunded`           | Funds reclaimed after timelock (failure path)  |

The agent communicates with its counterparty via JSON files in monerosim's
shared state directory (`/tmp/monerosim_shared/`). In production, the XMR-WOW
swap uses manual exchange of protocol messages, but only within the supported
9-step flow and only when refund checkpoints are ready.

Each method maps to a protocol phase:
- `generate_keys()` -- Phase 1: create Ed25519 key contribution
- `send_init_message()` / `receive_init_message()` -- Phase 2-3: key exchange
- `lock_funds()` -- Phase 4-5: lock funds to joint address via wallet RPC
- `verify_lock()` -- Phase 5: confirm counterparty lock via daemon RPC
- `claim_funds()` -- Phase 6-7: sweep using adaptor signature secret
- `wait_for_refund()` -- Failure path: wait for timelock, then reclaim

### `xmr_wow_cli_agent.py`

`XmrWowCliAgent` shells out to `target/release/xmr-wow` with explicit
`--password` and `--db` arguments, parses `Swap ID:` and `xmrwow1:` outputs,
and writes shared JSON files so Alice and Bob can exchange the same messages a
human operator would copy/paste manually.

This agent is intentionally geared toward Shadow validation, not normal local
development. It assumes the simulation environment has already built the
`xmr-wow` binary and exposed reachable daemon RPC endpoints.

### Configuration

Swap agents are configured via monerosim YAML attributes:

```yaml
alice:
  daemon: monerod
  wallet: 'monero-wallet-rpc'
  script: agents.swap_agent
  attributes:
    role: alice
    swap_amount: '1.0'
    counterparty: bob
    chain: xmr
    lock_confirmations: '10'
    refund_timeout_blocks: '76'
```

## Future Work

- Multi-node reorg scenarios (test swap safety under chain reorganization)
- Variable latency stress testing (high-latency links between parties)
- Automated CI integration when Shadow is available on build infrastructure
- Two-chain Shadow simulation with separate monerod and wownero-daemon binaries
  (currently both chains use monerod since Shadow runs real Monero binaries)
- Transaction fee estimation under different network load conditions
