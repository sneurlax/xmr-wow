# XMR-WOW Atomic Swap Deployment Guide

Step-by-step guide for setting up and running XMR-WOW atomic swaps on
XMR stagenet and WOW mainnet.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Building](#3-building)
4. [Wallet Setup](#4-wallet-setup)
5. [Running a Swap (Manual CLI)](#5-running-a-swap-manual-cli)
6. [Running a Swap (Scripted)](#6-running-a-swap-scripted)
7. [Refund Procedures](#7-refund-procedures)
8. [Troubleshooting](#8-troubleshooting)
9. [Security Considerations](#9-security-considerations)

---

## 1. Overview

XMR-WOW is a proof-of-concept atomic swap between Monero (XMR) and Wownero
(WOW). Two users run CLI tools, manually exchange protocol messages via
copy-paste (or any messaging channel), and trustlessly swap coins using DLEQ
proofs and adaptor signatures.

**What it does:**
- Bob locks WOW first (first lock)
- Alice verifies Bob's WOW lock, then locks XMR (second lock)
- Alice claims WOW, revealing her secret via an adaptor signature
- Bob uses the revealed secret to claim XMR
- Both parties end up with the other's coins

**Trust model:** Adaptor signatures provide cryptographic atomicity. Claiming
on one chain mathematically reveals the secret needed to claim on the other.
No trusted third party, no consensus layer, no networking infrastructure.

**Current limitations:**
- XMR stagenet + WOW mainnet only (no mainnet XMR)
- Manual message exchange (copy-paste `xmrwow1:` strings between parties)
- No automated peer discovery or order matching
- Refunds are cooperative today; unilateral refunds are not guaranteed if the counterparty disappears

---

## 2. Prerequisites

### Rust Toolchain

Install Rust stable (1.70+, tested on 1.89.0):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustc --version  # Should print 1.70.0 or later
```

No system libraries required (SQLite is bundled via `rusqlite/bundled`).

### XMR Stagenet Daemon

Download from [getmonero.org](https://www.getmonero.org/downloads/) and run:

```bash
monerod --stagenet --rpc-bind-port 38081
```

Wait for full sync. Check sync status:

```bash
curl -s http://localhost:38081/json_rpc \
  -d '{"jsonrpc":"2.0","method":"get_info","id":"0"}' \
  -H 'Content-Type: application/json' \
  | jq '.result.synchronized'
```

Should return `true` when fully synced.

Check current block height:

```bash
curl -s http://localhost:38081/json_rpc \
  -d '{"jsonrpc":"2.0","method":"get_block_count","id":"0"}' \
  -H 'Content-Type: application/json' \
  | jq '.result.count'
```

### WOW Mainnet Daemon

Download from [wownero.org](https://git.wownero.com/wownero/wownero/releases)
and run:

```bash
wownerod --rpc-bind-port 34568
```

> **Note:** WOW stagenet and testnet are non-functional. All WOW operations
> use mainnet. WOW has minimal monetary value, making mainnet suitable for
> testing.

Check sync status:

```bash
curl -s http://localhost:34568/json_rpc \
  -d '{"jsonrpc":"2.0","method":"get_info","id":"0"}' \
  -H 'Content-Type: application/json' \
  | jq '.result.synchronized'
```

### Both Daemons Must Be Fully Synced

Do not proceed until both daemons report `synchronized: true`. Attempting
wallet operations against an unsynced daemon will produce incorrect balances
or missing outputs.

---

## 3. Building

Clone the repository and build the client binary:

```bash
git clone <repo-url> xmr-wow
cd xmr-wow
cargo build --release -p xmr-wow-client
```

The binary is at `target/release/xmr-wow`. Verify it works:

```bash
./target/release/xmr-wow --help
```

Expected output includes subcommands: `init-alice`, `init-bob`, `import`,
`lock-wow`, `lock-xmr`, `exchange-pre-sig`, `claim-wow`, `claim-xmr`,
`generate-wallet`, `generate-refund-cooperate`, `build-refund`,
`broadcast-refund`, `show`, `list`, `resume`.

### Global Flags

| Flag         | Default              | Description                        |
|--------------|----------------------|------------------------------------|
| `--password` | (prompted if absent) | Password for encrypting secret keys |
| `--db`       | `xmr-wow-swaps.db`  | Path to the SQLite swap database   |

---

## 4. Wallet Setup

### Generate Wallets

Each party needs wallets on both networks. Generate them with the CLI:

**Alice (locks XMR, receives WOW):**

```bash
# XMR stagenet wallet
./target/release/xmr-wow generate-wallet --network xmr-stagenet

# WOW mainnet wallet (destination for received WOW)
./target/release/xmr-wow generate-wallet --network wow-mainnet
```

**Bob (locks WOW, receives XMR):**

```bash
# WOW mainnet wallet
./target/release/xmr-wow generate-wallet --network wow-mainnet

# XMR stagenet wallet (destination for received XMR)
./target/release/xmr-wow generate-wallet --network xmr-stagenet
```

Each command prints:
- **Mnemonic seed** (25 words) -- back this up securely
- **Private spend key** (64 hex characters)
- **Private view key** (64 hex characters)
- **Public address** (starts with `5` for XMR stagenet, `Wo` for WOW mainnet)

Record all four values. You will need the spend key and view key for lock and
claim operations.

### Import from Existing Seed

If you already have a wallet, import it:

```bash
./target/release/xmr-wow generate-wallet \
  --network xmr-stagenet \
  --mnemonic "word1 word2 word3 ... word25"
```

### Fund Wallets

**XMR stagenet:** Use a stagenet faucet or mine blocks to your wallet address.
You need at least 0.001 XMR (1000000000 atomic units) plus fees.

**WOW mainnet:** Send at least 1 WOW (100000000000 wonkero atomic units) to
your wallet address. WOW can be obtained from the Wownero community.

### Verify Funding

There is no built-in balance check. Verify by checking the daemon for
transactions to your address, or use `monero-wallet-cli` / `wownero-wallet-cli`
to confirm the balance.

---

## 5. Running a Swap (Manual CLI)

This section walks through the complete 9-step swap protocol. Alice and Bob
exchange `xmrwow1:<base64>` messages at each step -- via DM, email, or any
channel.

### Step 1: Alice Initiates the Swap

Alice creates the swap with her desired amounts and timelocks:

```bash
./target/release/xmr-wow init-alice \
  --amount-xmr 1000000000 \
  --amount-wow 100000000000 \
  --xmr-lock-blocks 50 \
  --wow-lock-blocks 200 \
  --password "alice-secret-pw" \
  --db alice-swaps.db
```

**Output:** An `xmrwow1:...` Init message and a swap ID.

**Action:** Alice sends the `xmrwow1:...` message to Bob.

> **Amounts:** `1000000000` = 0.001 XMR (piconero), `100000000000` = 1 WOW (wonkero).
>
> **Timelocks:** `--xmr-lock-blocks 50` means Alice's XMR is locked for 50 blocks
> (~100 minutes on stagenet). `--wow-lock-blocks 200` means Bob's WOW is locked
> for 200 blocks (~400 minutes). WOW timelock should be longer than XMR to give
> Alice time to claim first.

### Step 2: Bob Responds

Bob imports Alice's message and generates his response:

```bash
./target/release/xmr-wow init-bob \
  --message "xmrwow1:<alice-init-message>" \
  --password "bob-secret-pw" \
  --db bob-swaps.db
```

**Output:** A swap ID and an `xmrwow1:...` Response message.

**Action:** Bob sends the `xmrwow1:...` message back to Alice.

### Step 3: Alice Imports Bob's Response

Alice imports Bob's response to derive joint addresses:

```bash
./target/release/xmr-wow import \
  --swap-id <alice-swap-id> \
  --message "xmrwow1:<bob-response>" \
  --password "alice-secret-pw" \
  --db alice-swaps.db
```

**What happens:** Both parties now have the same joint addresses on both chains
(derived from combined key contributions). The state advances to `JointAddress`.

### Step 4: Bob Locks WOW (First Lock)

Bob locks his WOW to the joint WOW address:

```bash
./target/release/xmr-wow lock-wow \
  --swap-id <bob-swap-id> \
  --wow-daemon http://localhost:34568 \
  --spend-key <bob-wow-spend-key> \
  --view-key <bob-wow-view-key> \
  --scan-from <recent-block-height> \
  --password "bob-secret-pw" \
  --db bob-swaps.db
```

Alternatively, use a mnemonic seed:

```bash
./target/release/xmr-wow lock-wow \
  --swap-id <bob-swap-id> \
  --wow-daemon http://localhost:34568 \
  --mnemonic "word1 word2 ... word25" \
  --scan-from <recent-block-height> \
  --password "bob-secret-pw" \
  --db bob-swaps.db
```

**Output:** A WOW lock transaction hash and an `xmrwow1:...` AdaptorPreSig
message.

**Action:** Bob sends the `xmrwow1:...` pre-sig message to Alice.

> **`--scan-from`:** Set this to a block height slightly before your funding
> transaction to avoid scanning the entire blockchain. Use `0` if unsure (slow
> but safe).

### Step 5: Alice Locks XMR (Second Lock)

Alice verifies Bob's WOW lock on-chain and locks her XMR:

```bash
./target/release/xmr-wow lock-xmr \
  --swap-id <alice-swap-id> \
  --xmr-daemon http://localhost:38081 \
  --wow-daemon http://localhost:34568 \
  --spend-key <alice-xmr-spend-key> \
  --view-key <alice-xmr-view-key> \
  --scan-from <recent-block-height> \
  --password "alice-secret-pw" \
  --db alice-swaps.db
```

Or with mnemonic:

```bash
./target/release/xmr-wow lock-xmr \
  --swap-id <alice-swap-id> \
  --xmr-daemon http://localhost:38081 \
  --wow-daemon http://localhost:34568 \
  --mnemonic "word1 word2 ... word25" \
  --scan-from <recent-block-height> \
  --password "alice-secret-pw" \
  --db alice-swaps.db
```

**What happens:**
1. Alice's client checks Bob's WOW lock on the WOW daemon (verifies amount
   at the joint address using the view key)
2. If verified, Alice locks her XMR to the joint XMR address
3. Generates an AdaptorPreSig message

**Output:** An XMR lock transaction hash and an `xmrwow1:...` AdaptorPreSig message.

**Action:** Alice sends the `xmrwow1:...` pre-sig message to Bob.

### Step 6: Exchange Pre-Signatures

Both parties import each other's adaptor pre-signatures:

**Alice imports Bob's pre-sig:**

```bash
./target/release/xmr-wow exchange-pre-sig \
  --swap-id <alice-swap-id> \
  --message "xmrwow1:<bob-presig>" \
  --password "alice-secret-pw" \
  --db alice-swaps.db
```

**Bob imports Alice's pre-sig:**

```bash
./target/release/xmr-wow exchange-pre-sig \
  --swap-id <bob-swap-id> \
  --message "xmrwow1:<alice-presig>" \
  --password "bob-secret-pw" \
  --db bob-swaps.db
```

**What happens:** Both sides now hold the adaptor pre-signature from the other
party. This is the critical step that enables atomic claiming.

### Step 7: Bob Claims XMR (Sends ClaimProof)

Bob generates a ClaimProof by completing the adaptor signature with his
private spend key:

```bash
./target/release/xmr-wow generate-claim-proof \
  --presig "xmrwow1:<alice-presig>" \
  --spend-key <bob-private-spend-key>
```

**Output:** An `xmrwow1:...` ClaimProof message.

**Action:** Bob sends the ClaimProof to Alice.

> **Why Bob goes first:** Bob has the shorter WOW timelock. By revealing his
> ClaimProof first, he gives Alice time to extract his secret and claim WOW
> before the WOW timelock expires.

### Step 8: Alice Claims WOW

Alice imports Bob's ClaimProof, extracts Bob's secret scalar `b`, and sweeps
WOW from the joint address to her destination:

```bash
./target/release/xmr-wow claim-wow \
  --swap-id <alice-swap-id> \
  --wow-daemon http://localhost:34568 \
  --message "xmrwow1:<bob-claim-proof>" \
  --destination <alice-wow-destination-address> \
  --scan-from <recent-block-height> \
  --password "alice-secret-pw" \
  --db alice-swaps.db
```

**What happens:**
1. Alice extracts Bob's secret `b` from the completed adaptor signature
2. Constructs the combined spend key (`a + b`) for the joint WOW address
3. Sweeps all WOW from the joint address to her destination
4. Generates her own ClaimProof in the output

**Output:** A WOW sweep transaction hash and an `xmrwow1:...` ClaimProof message.

**Action:** Alice sends her ClaimProof to Bob.

### Step 9: Bob Claims XMR

Bob imports Alice's ClaimProof, extracts Alice's secret scalar `a`, and sweeps
XMR from the joint address to his destination:

```bash
./target/release/xmr-wow claim-xmr \
  --swap-id <bob-swap-id> \
  --xmr-daemon http://localhost:38081 \
  --message "xmrwow1:<alice-claim-proof>" \
  --destination <bob-xmr-destination-address> \
  --scan-from <recent-block-height> \
  --password "bob-secret-pw" \
  --db bob-swaps.db
```

**What happens:**
1. Bob extracts Alice's secret `a` from the completed adaptor signature
2. Constructs the combined spend key (`a + b`) for the joint XMR address
3. Sweeps all XMR from the joint address to his destination

**Output:** An XMR sweep transaction hash. The swap is complete.

### Checking Swap Status

At any point, view a swap's current state:

```bash
./target/release/xmr-wow show <swap-id> --db alice-swaps.db
```

List all tracked swaps:

```bash
./target/release/xmr-wow list --db alice-swaps.db
# Include orphaned temp-ID entries:
./target/release/xmr-wow list --all --db alice-swaps.db
```

---

## 6. Running a Swap (Scripted)

For automated testing, use `scripts/live-happy-path-v2.sh` which runs all
9 steps in a single terminal.

### Environment Variables

| Variable         | Default                      | Description                       |
|------------------|------------------------------|-----------------------------------|
| `XMR_DAEMON`     | `http://127.0.0.1:38081`    | XMR stagenet daemon RPC URL       |
| `WOW_DAEMON`     | `http://127.0.0.1:34568`    | WOW mainnet daemon RPC URL        |
| `SWAP_PASSWORD`  | `test-swap-password`         | Encryption password for secrets   |
| `AMOUNT_XMR`     | `1000000000` (0.001 XMR)    | XMR amount in piconero            |
| `AMOUNT_WOW`     | `100000000000` (1 WOW)      | WOW amount in wonkero             |
| `XMR_LOCK_BLOCKS`| `50`                         | XMR timelock in blocks            |
| `WOW_LOCK_BLOCKS`| `200`                        | WOW timelock in blocks            |
| `XMR_SCAN_FROM`  | `0`                          | Block height to start XMR scan    |
| `WOW_SCAN_FROM`  | `0`                          | Block height to start WOW scan    |

### Basic Usage

```bash
# With defaults (localhost daemons, auto-generated wallets)
./scripts/live-happy-path-v2.sh

# With existing wallet seeds
./scripts/live-happy-path-v2.sh \
  --alice-seed "word1 word2 ... word25" \
  --bob-seed "word1 word2 ... word25"

# With custom daemon URLs and scan heights
XMR_DAEMON=http://remote:38081 \
WOW_DAEMON=http://remote:34568 \
XMR_SCAN_FROM=2085000 \
WOW_SCAN_FROM=825000 \
./scripts/live-happy-path-v2.sh
```

### Resume After Interruption

The script saves state after each step. If interrupted, resume:

```bash
./scripts/live-happy-path-v2.sh --resume swap-state-<timestamp>.json
```

### What the Script Does

1. Pre-builds the `xmr-wow` binary (no per-step compilation noise)
2. Generates wallets for Alice and Bob (or uses provided seeds)
3. Runs all 9 protocol steps sequentially in one terminal
4. Captures lock and sweep transaction hashes
5. Prints a transaction summary on exit (success or failure)

---

## 7. Refund Procedures

Refunds are cooperative in the current implementation. They are not
pre-signed before locking. Instead, the refunding party needs a later
`RefundCooperate` message from the counterparty to reconstruct the combined
key and build a timelocked refund transaction. If the counterparty disappears
before sending that message, unilateral refund is not guaranteed.

### When to Use Refunds

- **Bob's WOW refund:** Alice disappears after Bob locks WOW but before she
  locks XMR (or before claiming).
- **Alice's XMR refund:** Bob disappears after both parties lock but before
  he sends his ClaimProof.

### Three-Step Cooperative Refund

**Step 1: Generate RefundCooperate message**

The party who wants to help the other refund shares their secret:

```bash
./target/release/xmr-wow generate-refund-cooperate \
  --swap-id <swap-id> \
  --password "my-password" \
  --db my-swaps.db
```

**Output:** An `xmrwow1:...` RefundCooperate message. Send to your
counterparty.

> **Important:** Only share this after your lock transaction is confirmed
> and verified by the counterparty. The RefundCooperate message contains
> your secret scalar.

**Step 2: Build the refund transaction**

The party who needs the refund constructs the timelocked transaction:

```bash
# Bob refunding WOW:
./target/release/xmr-wow build-refund \
  --swap-id <swap-id> \
  --cooperate-msg "xmrwow1:<counterparty-refund-msg>" \
  --destination <your-wow-address> \
  --wow-daemon http://localhost:34568 \
  --scan-from <recent-block-height> \
  --password "my-password" \
  --db my-swaps.db

# Alice refunding XMR:
./target/release/xmr-wow build-refund \
  --swap-id <swap-id> \
  --cooperate-msg "xmrwow1:<counterparty-refund-msg>" \
  --destination <your-xmr-address> \
  --xmr-daemon http://localhost:38081 \
  --scan-from <recent-block-height> \
  --password "my-password" \
  --db my-swaps.db
```

**What happens:** The combined spend key is reconstructed from both secrets,
the joint address is scanned for outputs, and a timelocked transaction is
built and stored in the swap database.

**Step 3: Broadcast after timelock expires**

Wait for the timelock to pass, then broadcast:

```bash
# Bob broadcasting WOW refund:
./target/release/xmr-wow broadcast-refund \
  --swap-id <swap-id> \
  --wow-daemon http://localhost:34568 \
  --password "my-password" \
  --db my-swaps.db

# Alice broadcasting XMR refund:
./target/release/xmr-wow broadcast-refund \
  --swap-id <swap-id> \
  --xmr-daemon http://localhost:38081 \
  --password "my-password" \
  --db my-swaps.db
```

The client performs a timelock check before broadcasting. If the current
block height has not reached the timelock height, the broadcast is rejected
with an error message showing how many blocks remain.

### Timelock Constraints

- WOW timelock is shorter (Bob locks first, refunds first if needed)
- XMR timelock is longer (Alice locks second, needs more time)
- Default test values: XMR 15 blocks, WOW 130 blocks (for refund testing)
- Production-like values: XMR 50 blocks (~100 min), WOW 200 blocks (~400 min)
- Maximum sanity cap: 10000 blocks

### Refund Scripts

Automated refund testing scripts:

```bash
# Bob refunds WOW (Alice disappears after Bob locks)
./scripts/live-refund-bob-wow.sh [--bob-seed "25 words"] [--alice-seed "25 words"]

# Alice refunds XMR (Bob disappears after both lock)
./scripts/live-refund-alice-xmr.sh [--alice-seed "25 words"] [--bob-seed "25 words"]

# Test premature broadcast rejection
./scripts/live-refund-premature.sh
```

---

## 8. Troubleshooting

### "daemon unreachable" / Connection Refused

**Cause:** The daemon is not running or is listening on a different port.

**Fix:**
- Verify the daemon process is running: `ps aux | grep monerod` or `ps aux | grep wownerod`
- Check the port: XMR stagenet default is `38081`, WOW mainnet is `34568`
- Test connectivity: `curl -s http://localhost:38081/json_rpc -d '{"method":"get_info"}'`
- If using a remote daemon, ensure firewall allows the connection

### "insufficient funds" / No Outputs Found

**Cause:** The wallet has no spendable outputs, or the daemon is not synced.

**Fix:**
- Confirm daemon is fully synced (see [Prerequisites](#2-prerequisites))
- Verify your address received funds using a block explorer or wallet CLI
- Use `--scan-from` with a block height before your funding transaction
- Ensure enough time has passed for outputs to be spendable (10 confirmations
  for XMR, 4 for WOW)

### "timelock not expired" / Premature Broadcast

**Cause:** Attempting to broadcast a refund before the timelock block height.

**Fix:**
- The error message shows the required block height and current height
- Wait for the chain to advance past the timelock height
- Check current height: `curl -s http://localhost:38081/json_rpc -d '{"method":"get_block_count"}' | jq .result.count`
- Stagenet block time is approximately 2 minutes per block

### "invalid mnemonic" / Mnemonic Parsing Error

**Cause:** The mnemonic seed is malformed.

**Fix:**
- Ensure the seed is exactly 25 words
- Words must be from the standard Monero/Wownero word list
- No extra spaces or punctuation
- Use `generate-wallet` to create a fresh valid seed

### "non-canonical scalar"

**Cause:** A private key value is outside the valid Ed25519 scalar range.

**Fix:**
- The key material may be corrupted or from an incompatible source
- Regenerate the wallet with `generate-wallet`
- If importing, verify the hex string is exactly 64 characters

### "torsion point" / Invalid Counterparty Key

**Cause:** The counterparty sent a public key with a small-order (torsion)
component, which could enable fund theft.

**Fix:**
- **Do not proceed with this swap.** A torsion point indicates either a bug
  in the counterparty's software or a deliberate attack.
- Abort and start a new swap with a trusted counterparty.

### "sweep failed" / Transaction Construction Error

**Cause:** The sweep transaction could not be constructed, possibly due to
ring member selection issues or daemon version mismatch.

**Fix:**
- Ensure the daemon version supports the current network consensus rules
- WOW requires ring size 22 (enforced since v20 hard fork)
- XMR stagenet should use a recent monerod release
- Check that the daemon is fully synced and not pruned

### HTTP Timeout / Retry Exhaustion

**Cause:** The daemon did not respond within the timeout period, or all
retries were exhausted during confirmation polling.

**Fix:**
- HTTP timeout is 30 seconds per request
- Confirmation polling uses up to 30 retries with exponential backoff
  (10 seconds initial, capped at 120 seconds)
- Check daemon logs for errors or high load
- Ensure the network connection to the daemon is stable
- Restart the daemon if it becomes unresponsive

### Database Errors

**Cause:** Corruption or concurrent access to the SQLite database.

**Fix:**
- Do not run multiple swap commands against the same database simultaneously
- Back up the database file before critical operations
- If corrupted, restore from backup or start fresh with a new `--db` path

---

## 9. Security Considerations

### Key Management

- **Never share mnemonic seeds or private spend keys** except via the
  explicit `generate-refund-cooperate` command (which shares only the swap
  key contribution, not your wallet key).
- **Use a strong password** for the `--password` flag. Secrets are encrypted
  at rest using Argon2 key derivation and AES-GCM encryption.
- Keep secret keys offline when not actively running swap commands.
- Consider using separate wallets with small balances for swap testing.

### Network Verification

- **Verify your daemon is on the correct network.** A stagenet daemon
  connecting to mainnet peers (or vice versa) can cause fund loss.
- XMR stagenet addresses start with `5`.
- WOW mainnet addresses start with `Wo`.
- Check `get_info` output for the network type before proceeding.

### Database Backups

- The swap database (`xmr-wow-swaps.db` by default) contains your swap state.
- **Back up the database between protocol steps**, especially before and
  after lock operations.
- Secret scalars are NOT stored in the database (`#[serde(skip)]`); they
  exist only in encrypted form via the password-derived key.
- Losing the database means losing the ability to resume an in-progress swap.

### Protocol Messages

- Protocol messages (`xmrwow1:...` strings) contain public keys and
  signatures. They are safe to transmit over unencrypted channels.
- However, an attacker who can modify messages in transit could disrupt the
  protocol. Use an authenticated channel when possible.

### Timelock Safety

- Set timelocks conservatively. If the counterparty claims just before the
  timelock expires, you need enough blocks to extract the secret and claim
  on the other chain.
- The WOW timelock should be significantly longer than the XMR timelock to
  give Alice (the second locker) adequate time to claim first.
- Maximum timelock sanity cap is 10000 blocks.

### Adaptor Signature Atomicity

- The security of the swap relies on adaptor signatures. Claiming WOW
  mathematically reveals Alice's secret `a`, enabling Bob to claim XMR.
- If you see warnings about signature verification failures, **stop the swap
  immediately** and do not lock funds.
- Never bypass DLEQ proof verification or adaptor signature checks.
