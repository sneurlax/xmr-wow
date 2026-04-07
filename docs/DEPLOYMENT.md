# XMR-WOW Deployment Guide

## 1. Overview

The swap flow is:

1. Alice initializes the swap.
2. Bob responds.
3. Alice imports Bob's response.
4. Bob locks WOW first.
5. Alice locks XMR second.
6. Both sides exchange adaptor pre-signatures.
7. Bob sends the first claim proof.
8. Alice claims WOW and returns her claim proof.
9. Bob claims XMR.

The repo only documents and supports that sequence when both refund checkpoints below are validated:

- `before_wow_lock`: must be `ready` before Bob runs `lock-wow`
- `before_xmr_lock`: must be `ready` before Alice runs `lock-xmr`

`ready` means the refund artifact is present, validated, and tied to a refund address and refund height. Any `blocked` or `unsupported-for-guarantee` result is a stop condition.

## 2. Prerequisites

### Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustc --version
```

### XMR stagenet daemon

```bash
monerod --stagenet --rpc-bind-port 38081
```

### WOW mainnet daemon

```bash
wownerod --rpc-bind-port 34568
```

Both daemons must be fully synced before you start. Check:

```bash
curl -s http://localhost:38081/json_rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_info","id":"0"}' | jq '.result.synchronized'

curl -s http://localhost:34568/json_rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_info","id":"0"}' | jq '.result.synchronized'
```

## 3. Build

```bash
cargo build --release -p xmr-wow-client
./target/release/xmr-wow --help
```

Useful global flags:

- `--password`: password used to encrypt swap secrets
- `--db`: SQLite path for swap state

## 4. Wallet Setup

Generate or import wallets with:

```bash
./target/release/xmr-wow generate-wallet --network xmr-stagenet
./target/release/xmr-wow generate-wallet --network wow-mainnet
./target/release/xmr-wow generate-wallet --network xmr-stagenet --mnemonic "word1 ... word25"
```

For the 9-step flow you need:

- Alice: funded XMR wallet, WOW destination address, XMR refund address
- Bob: funded WOW wallet, XMR destination address, WOW refund address

Record the mnemonic, spend key, view key, and address for each funded wallet.

## 5. Refund Gating

Refund readiness is part of the protocol, not an optional recovery path.

After `init-bob` and after Alice imports Bob's response, inspect the swap:

```bash
./target/release/xmr-wow --password "alice-secret-pw" --db alice-swaps.db show <alice-swap-id>
./target/release/xmr-wow --password "bob-secret-pw" --db bob-swaps.db show <bob-swap-id>
```

The output includes:

- `Checkpoint before_wow_lock`
- `Checkpoint before_xmr_lock`
- `Status`
- `Artifact present`
- `Artifact validated`
- `Refund address`
- `Refund height`

Do not continue unless the checkpoint needed for the next lock step is `ready` and `Artifact validated: true`.

The legacy refund commands remain fail-closed in the CLI and are no longer supported:

- `generate-refund-cooperate`
- `build-refund`
- `broadcast-refund`
- `refund`

## 6. Supported 9-Step Procedure

All commands below assume you are using the release binary:

```bash
BIN=./target/release/xmr-wow
```

Example values:

- `1000000000` = `0.001 XMR`
- `100000000000` = `1 WOW`
- XMR refund heights should leave Alice enough time after WOW claim
- WOW refund heights should exceed the XMR side

### Step 1: Alice starts the swap

Alice records refund timing against both daemons and supplies her XMR refund destination up front:

```bash
$BIN --password "alice-secret-pw" --db alice-swaps.db init-alice \
  --amount-xmr 1000000000 \
  --amount-wow 100000000000 \
  --xmr-daemon http://127.0.0.1:38081 \
  --wow-daemon http://127.0.0.1:34568 \
  --xmr-lock-blocks 50 \
  --wow-lock-blocks 200 \
  --alice-refund-address <alice-xmr-refund-address>
```

Alice sends the emitted `xmrwow1:...` message to Bob.

### Step 2: Bob responds

Bob imports Alice's message and commits his WOW refund destination:

```bash
$BIN --password "bob-secret-pw" --db bob-swaps.db init-bob \
  --message "xmrwow1:<alice-init-message>" \
  --bob-refund-address <bob-wow-refund-address>
```

Bob sends the emitted `xmrwow1:...` message back to Alice.

### Step 3: Alice imports Bob's response

```bash
$BIN --password "alice-secret-pw" --db alice-swaps.db import \
  --swap-id <alice-swap-id> \
  --message "xmrwow1:<bob-response>"
```

Both parties should run `show` now. Bob must not proceed to Step 4 unless `before_wow_lock` is `ready`.

### Step 4: Bob locks WOW

> **Note:** The current keysplit wallet flow has no proven pre-lock refund artifact.
> The `before_wow_lock` checkpoint will report `unsupported-for-guarantee`.
> Pass `--accept-risk` to proceed (funds may not be recoverable if the swap fails).

```bash
$BIN --password "bob-secret-pw" --db bob-swaps.db lock-wow \
  --swap-id <bob-swap-id> \
  --wow-daemon http://127.0.0.1:34568 \
  --spend-key <bob-wow-spend-key> \
  --view-key <bob-wow-view-key> \
  --scan-from <recent-wow-height> \
  --accept-risk
```

Or:

```bash
$BIN --password "bob-secret-pw" --db bob-swaps.db lock-wow \
  --swap-id <bob-swap-id> \
  --wow-daemon http://127.0.0.1:34568 \
  --mnemonic "word1 ... word25" \
  --scan-from <recent-wow-height> \
  --accept-risk
```

Bob sends the emitted adaptor pre-signature message to Alice.

### Step 5: Alice locks XMR

> **Note:** The `before_xmr_lock` checkpoint will report `blocked` because Monero relay
> policy rejects nonzero `unlock_time` for non-coinbase transactions.
> Pass `--accept-risk` to proceed (funds may not be recoverable if the swap fails).

```bash
$BIN --password "alice-secret-pw" --db alice-swaps.db lock-xmr \
  --swap-id <alice-swap-id> \
  --xmr-daemon http://127.0.0.1:38081 \
  --wow-daemon http://127.0.0.1:34568 \
  --spend-key <alice-xmr-spend-key> \
  --view-key <alice-xmr-view-key> \
  --scan-from <recent-xmr-height> \
  --accept-risk
```

Or:

```bash
$BIN --password "alice-secret-pw" --db alice-swaps.db lock-xmr \
  --swap-id <alice-swap-id> \
  --xmr-daemon http://127.0.0.1:38081 \
  --wow-daemon http://127.0.0.1:34568 \
  --mnemonic "word1 ... word25" \
  --scan-from <recent-xmr-height> \
  --accept-risk
```

Alice sends the emitted adaptor pre-signature message to Bob.

### Step 6: Exchange adaptor pre-signatures

```bash
$BIN --password "alice-secret-pw" --db alice-swaps.db exchange-pre-sig \
  --swap-id <alice-swap-id> \
  --message "xmrwow1:<bob-presig>"

$BIN --password "bob-secret-pw" --db bob-swaps.db exchange-pre-sig \
  --swap-id <bob-swap-id> \
  --message "xmrwow1:<alice-presig>"
```

### Step 7: Bob sends the first claim proof

```bash
$BIN --password "bob-secret-pw" --db bob-swaps.db generate-claim-proof \
  --presig "xmrwow1:<alice-presig>" \
  --swap-id <bob-swap-id>
```

Bob sends the emitted `xmrwow1:...` claim proof to Alice.

### Step 8: Alice claims WOW

```bash
$BIN --password "alice-secret-pw" --db alice-swaps.db claim-wow \
  --swap-id <alice-swap-id> \
  --wow-daemon http://127.0.0.1:34568 \
  --message "xmrwow1:<bob-claim-proof>" \
  --destination <alice-wow-destination-address> \
  --scan-from <recent-wow-height>
```

Alice sends the emitted `xmrwow1:...` claim proof to Bob.

### Step 9: Bob claims XMR

```bash
$BIN --password "bob-secret-pw" --db bob-swaps.db claim-xmr \
  --swap-id <bob-swap-id> \
  --xmr-daemon http://127.0.0.1:38081 \
  --message "xmrwow1:<alice-claim-proof>" \
  --destination <bob-xmr-destination-address> \
  --scan-from <recent-xmr-height>
```

## 7. Validation Harness

For proof coverage, use:

```bash
./scripts/test-harness.sh
```

## 8. Troubleshooting

### Checkpoint says `blocked` or `unsupported-for-guarantee`

Stop. Do not run the next lock command. The swap is outside the supported refund-required contract.

### Daemon unreachable

- Verify `monerod` or `wownerod` is running
- Verify ports `38081` and `34568`
- Test RPC connectivity with `curl`

### No outputs found

- Confirm the wallet is funded
- Confirm the daemon is synced
- Use a `--scan-from` height before the funding transaction

### Invalid mnemonic or scalar errors

- Re-check the 25-word seed or 64-hex private key input
- Regenerate the wallet if needed

### Torsion point or signature verification failures

Stop the swap immediately. Do not lock or claim funds after a cryptographic validation error.

## 9. Security Notes

- Never share mnemonic seeds or wallet private keys with a counterparty
- Back up the swap database between steps
- Use authenticated messaging when exchanging `xmrwow1:...` payloads
- Keep WOW refund time longer than XMR refund time
- Treat refund-readiness checks as mandatory protocol validation, not operator guidance
