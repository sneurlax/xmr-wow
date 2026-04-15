# XMR-WOW Live-Network Swap Runbook

## Overview

This runbook covers performing a full XMR<->WOW atomic swap against real network daemons using
either **sharechain** or **out-of-band** transport. Alice locks XMR (stagenet) and receives WOW
(mainnet). Bob locks WOW (mainnet) first and receives XMR (stagenet) second.

Both transport modes use the same 8-step swap sequence:
`init-alice -> init-bob -> import -> lock-wow -> lock-xmr -> exchange-pre-sig -> claim-wow -> claim-xmr`

The difference is coordination: sharechain automatically relays messages between Alice and Bob;
out-of-band requires the operator to copy/paste `xmrwow1:` messages between terminals.

---

## Prerequisites

- **Binary built:** `cargo build --release -p xmr-wow-client`
- **XMR stagenet daemon** running and synced to at least block **2085170**, reachable at
  `XMR_DAEMON_URL` (default `http://127.0.0.1:38081`)
- **WOW mainnet daemon** running and synced to at least block **825252**, reachable at
  `WOW_DAEMON_URL` (default `http://127.0.0.1:34568`; note: port is **34568**, NOT 34567)
- **Sharechain mode only:** `xmr-wow-node` running and reachable at `SHARECHAIN_NODE_URL`
  (default `http://127.0.0.1:18091`)
- **Funded wallets:** Alice needs XMR stagenet funds; Bob needs WOW mainnet funds
- **Live gate:** `export XMR_WOW_LIVE_CONFIRM=1` to unlock live execution

---

## Environment Variables

| Variable | Required for | Description | Example |
|---|---|---|---|
| `XMR_WOW_BIN` | both | Path to xmr-wow binary | `./target/release/xmr-wow` |
| `XMR_DAEMON_URL` | both | XMR stagenet daemon URL | `http://127.0.0.1:38081` |
| `WOW_DAEMON_URL` | both | WOW mainnet daemon URL | `http://127.0.0.1:34568` |
| `SHARECHAIN_NODE_URL` | sharechain mode | xmr-wow-node RPC URL | `http://127.0.0.1:18091` |
| `XMR_WOW_LIVE_CONFIRM` | both | Set to `1` to unlock live run | `1` |
| `ALICE_PASSWORD` | alice | Wallet DB password | (secret) |
| `ALICE_XMR_REFUND_ADDRESS` | alice | XMR stagenet refund address | (stagenet addr) |
| `ALICE_WOW_DESTINATION_ADDRESS` | alice | WOW mainnet destination address | (mainnet addr) |
| `ALICE_XMR_MNEMONIC` | alice | XMR wallet mnemonic (or use spend/view key pair) | (secret) |
| `ALICE_XMR_SPEND_KEY` | alice | XMR spend key (alternative to mnemonic) | (64-char hex) |
| `ALICE_XMR_VIEW_KEY` | alice | XMR view key (alternative to mnemonic) | (64-char hex) |
| `ALICE_XMR_SCAN_FROM` | alice | XMR block height to scan from | `2085170` |
| `ALICE_WOW_SCAN_FROM` | alice | WOW block height to scan from | `825252` |
| `BOB_PASSWORD` | bob | Wallet DB password | (secret) |
| `BOB_WOW_REFUND_ADDRESS` | bob | WOW mainnet refund address | (mainnet addr) |
| `BOB_XMR_DESTINATION_ADDRESS` | bob | XMR stagenet destination address | (stagenet addr) |
| `BOB_WOW_MNEMONIC` | bob | WOW wallet mnemonic (or use spend/view key pair) | (secret) |
| `BOB_WOW_SPEND_KEY` | bob | WOW spend key (alternative to mnemonic) | (64-char hex) |
| `BOB_WOW_VIEW_KEY` | bob | WOW view key (alternative to mnemonic) | (64-char hex) |
| `BOB_WOW_SCAN_FROM` | bob | WOW block height to scan from | `825252` |
| `BOB_XMR_SCAN_FROM` | bob | XMR block height to scan from | `2085170` |
| `OFFER_ID` | bob | Alice's offer ID (from publish-offer output) | (UUID/hash) |

---

## Run A: Sharechain Transport

Sharechain transport automatically relays all protocol messages between Alice and Bob via the
`xmr-wow-node` RPC. No manual copy/paste of `xmrwow1:` strings is needed.

### A0: Start sharechain node (terminal 0)

```bash
xmr-wow-node --rpc-bind-port 18091
```

Wait until it responds:
```bash
curl http://127.0.0.1:18091/
```

### A1-A6: Alice steps (terminal 1)

```bash
export XMR_WOW_LIVE_CONFIRM=1
export ALICE_PASSWORD=...
export ALICE_XMR_REFUND_ADDRESS=...
export ALICE_WOW_DESTINATION_ADDRESS=...
export ALICE_XMR_MNEMONIC=...   # or ALICE_XMR_SPEND_KEY + ALICE_XMR_VIEW_KEY
export ALICE_XMR_SCAN_FROM=2085170
export ALICE_WOW_SCAN_FROM=825252

scripts/live-network/alice.sh --transport-mode sharechain
```

What each step does:

| Step | Command | What happens |
|---|---|---|
| A1 | `publish-offer` | Alice advertises swap terms on the sharechain so Bob can accept |
| A2 | `init-alice` | Creates initial swap transcript; Init message published to sharechain |
| A3 | `import` | Waits for Bob's response on sharechain; derives real swap ID |
| A4 | `lock-xmr` | After verifying Bob's WOW lock, locks XMR to joint address |
| A5 | `exchange-pre-sig` | Exchanges adaptor pre-signatures via sharechain |
| A6 | `claim-wow` | Claims WOW after Bob's claim proof; publishes Alice's proof for Bob |

### B1-B5: Bob steps (terminal 2, concurrent with Alice)

```bash
export XMR_WOW_LIVE_CONFIRM=1
export BOB_PASSWORD=...
export BOB_WOW_REFUND_ADDRESS=...
export BOB_XMR_DESTINATION_ADDRESS=...
export BOB_WOW_MNEMONIC=...     # or BOB_WOW_SPEND_KEY + BOB_WOW_VIEW_KEY
export BOB_WOW_SCAN_FROM=825252
export BOB_XMR_SCAN_FROM=2085170
export OFFER_ID=...              # from Alice's publish-offer output (step A1)

scripts/live-network/bob.sh --transport-mode sharechain
```

What each step does:

| Step | Command | What happens |
|---|---|---|
| B1 | `accept-offer` | Bob accepts Alice's offer; establishes swap linkage |
| B2 | `init-bob` | Reads Alice's Init from sharechain; derives swap ID and joint addresses |
| B3 | `lock-wow` | Locks WOW to joint address (WOW-first lock-order safety invariant) |
| B4 | `exchange-pre-sig` | Exchanges adaptor pre-signatures via sharechain |
| B5 | `claim-xmr` | Publishes Bob's claim proof; waits for Alice's proof; sweeps XMR |

### Sequencing note

Alice and Bob run their scripts in **parallel in separate terminals**. The sharechain coordinates
the handoff automatically: no manual copy/paste is needed. The sequence of protocol-level
dependencies is:

```
Alice: publish-offer
Bob:  accept-offer -> init-bob
Alice:               (waits for Bob's init via sharechain) -> import -> lock-xmr -> exchange-pre-sig -> claim-wow
Bob:                                                          lock-wow -> exchange-pre-sig -> claim-xmr
```

### Capturing artifacts (sharechain)

After completion, fill in the artifact templates:

Fill in the artifact templates under `artifacts/live-network/`.

---

## Run B: Out-of-Band Transport

Out-of-band transport requires the operator to manually copy `xmrwow1:` base64 messages between
terminals. Each step either produces a message (on stdout) or consumes one (via `--message`).

### B0: No sharechain node needed

Out-of-band mode uses stdin/stdout pass-through only. No `xmr-wow-node` is required.

### Manual handoff flow

The OOB message handoff follows this sequence:

```
1. Alice: init-alice         -> prints xmrwow1:<init-msg>
2. Bob:   init-bob --message <xmrwow1:init-msg>   -> prints xmrwow1:<bob-response>
3. Alice: import --message <xmrwow1:bob-response> -> prints real swap IDs
4. Bob:   lock-wow           -> no message to pass (WOW tx is on-chain)
5. Alice: lock-xmr           -> no message to pass (XMR tx is on-chain)
6. Alice: exchange-pre-sig   -> prints xmrwow1:<alice-presig>
7. Bob:   exchange-pre-sig --message <xmrwow1:alice-presig> -> prints xmrwow1:<bob-presig>
8. Alice: claim-wow --message <xmrwow1:bob-presig> -> prints xmrwow1:<claim-proof>
9. Bob:   claim-xmr --message <xmrwow1:claim-proof>
```

### Running OOB with the scripts

```bash
# Terminal 1: Alice
scripts/live-network/alice.sh --transport-mode out-of-band
```

```bash
# Terminal 2: Bob
scripts/live-network/bob.sh --transport-mode out-of-band
```

Note: for OOB mode, the scripts wrap the underlying commands and print the `xmrwow1:` messages
at each step. The operator must copy each message from one terminal and pass it to the next
command as `--message <xmrwow1:...>`.

For a fully automated OOB run (no copy/paste), use the automated harness instead:
```bash
./scripts/run-live-network-harness.sh oob
```

### Alice OOB steps detail (terminal 1)

```bash
export XMR_WOW_LIVE_CONFIRM=1
export ALICE_PASSWORD=...
export ALICE_XMR_REFUND_ADDRESS=...
export ALICE_WOW_DESTINATION_ADDRESS=...
export ALICE_XMR_MNEMONIC=...
export ALICE_XMR_SCAN_FROM=2085170
export ALICE_WOW_SCAN_FROM=825252

scripts/live-network/alice.sh --transport-mode out-of-band
```

After `init-alice`, Alice's stdout will contain an `xmrwow1:` string. Copy it and provide it to
Bob's `init-bob` step.

### Bob OOB steps detail (terminal 2)

```bash
export XMR_WOW_LIVE_CONFIRM=1
export BOB_PASSWORD=...
export BOB_WOW_REFUND_ADDRESS=...
export BOB_XMR_DESTINATION_ADDRESS=...
export BOB_WOW_MNEMONIC=...
export BOB_WOW_SCAN_FROM=825252
export BOB_XMR_SCAN_FROM=2085170
export OFFER_ID=...

scripts/live-network/bob.sh --transport-mode out-of-band
```

### Capturing artifacts (OOB)

After completion:
Fill in the artifact templates under `artifacts/live-network/`.

---

## Sanitizing Artifacts Before Commit

Before committing artifact files, verify no private key material appears:

```bash
scripts/live-network/validate-artifacts.sh
```

The script will flag any long hex strings that appear in `spend_key` or `view_key` fields.
**Do not commit artifacts that fail validation.**

---

## Troubleshooting

| Symptom | Resolution |
|---|---|
| "daemon not responding" | Ensure XMR stagenet and WOW mainnet daemons are running and synced |
| "wallet not funded" | Check stagenet/mainnet block explorers; wait for daemon sync |
| `XMR_WOW_LIVE_CONFIRM not set` | `export XMR_WOW_LIVE_CONFIRM=1` |
| WOW daemon connection refused | WOW daemon port is **34568** (not 34567): check `WOW_DAEMON_URL` |
| Sharechain node not responding | Start `xmr-wow-node --rpc-bind-port 18091` (terminal 0) |
| `init-bob` fails in sharechain mode | Ensure Alice's `init-alice` has run first so the Init message exists on the sharechain |
| Long `lock-wow` or `lock-xmr` wait | Daemons need to be synced and wallets funded; check block height vs scan-from |
| `claim-xmr` blocks indefinitely | Alice must complete `claim-wow` first to publish her claim proof |
