# Live Network Validation Scripts

Shell scripts for validating the XMR<->WOW atomic swap on live networks.
These scripts are the "live tier" of Phase 4 validation (per D-01/D-08).

## Prerequisites

### XMR Stagenet
- Running `monerod --stagenet` on port 38081 (default)
- A funded stagenet wallet (mine or use a faucet)
- At least 0.001 XMR in the wallet

### WOW Mainnet (per D-03)
- Running `wownerod` on port 34568 (mainnet default)
- WOW mainnet is used because WOW stagenet/testnet are non-functional
- At least 1 WOW in the wallet (WOW has minimal monetary value)

## Scripts

### Happy Path (`live-happy-path.sh`)
Full swap round-trip: Alice locks XMR, Bob locks WOW, both claim.

```bash
# With defaults (localhost daemons)
./scripts/live-happy-path.sh

# With custom daemon URLs
XMR_DAEMON=http://remote:38081 WOW_DAEMON=http://remote:34568 ./scripts/live-happy-path.sh

# With custom amounts
AMOUNT_XMR=500000000 AMOUNT_WOW=50000000000 ./scripts/live-happy-path.sh
```

**Note:** The happy path script requires TWO terminals (one for Alice, one for Bob)
and manual copy-paste of `xmrwow1:` messages between them. The script logs commands
but some steps need the output from the previous step.

### Refund Path (`live-refund-path.sh`)
Alice locks XMR, Bob disappears, Alice refunds after timelock.

```bash
./scripts/live-refund-path.sh
```

**Note:** The refund requires waiting for the timelock to expire (XMR_LOCK_BLOCKS blocks
at ~2 minutes each on stagenet). The script will print the manual refund command.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `XMR_DAEMON` | `http://127.0.0.1:38081` | XMR stagenet RPC |
| `WOW_DAEMON` | `http://127.0.0.1:34568` | WOW mainnet RPC |
| `SWAP_PASSWORD` | `test-swap-password` | Encryption password |
| `AMOUNT_XMR` | `1000000000` | XMR amount (piconero) |
| `AMOUNT_WOW` | `100000000000` | WOW amount (wonkero) |
| `XMR_LOCK_BLOCKS` | `200` | XMR timelock blocks |
| `WOW_LOCK_BLOCKS` | `50` | WOW timelock blocks |

## Known Limitations

- **Refund does not sweep funds**: Per PoC design, refund marks state as Refunded
  but cannot sweep from the joint address (requires combined key or script layer).
- **Block times**: Stagenet ~2 min/block, mainnet ~2 min/block. Be patient.
- **Destination addresses**: Replace `ENTER_*_DESTINATION` placeholders with actual addresses.
- **Single terminal**: Scripts run both Alice and Bob in the same terminal for
  convenience, but a real swap would use two separate machines.
