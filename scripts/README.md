# Operator Scripts

The supported operator path is the local test harness.
Historical live walkthroughs remain here for reference, but they are not the
refund-safe flow and now exit by default.

## Supported

### `test-harness.sh`

Runs the supported proof set and writes a timestamped log:

```bash
./scripts/test-harness.sh
```

Coverage:

- direct XMR refund-artifact proof coverage on simnet
- direct WOW refund-artifact proof coverage on simnet
- main-workspace happy-path and refund-path `SwapState + CryptoNoteWallet` coverage on simnet
- restart-safe refund persistence and premature-refund rejection

Optional overrides:

```bash
LOG_FILE=/tmp/xmr-wow-test-harness.log ./scripts/test-harness.sh
LOG_DIR=/tmp ./scripts/test-harness.sh
```

## Historical / Manual Only

These scripts are kept for prior evidence and manual use:

- `live-happy-path.sh`
- `live-happy-path-v2.sh`
- `live-refund-path.sh`
- `live-refund-bob-wow.sh`
- `live-refund-alice-xmr.sh`
- `live-refund-premature.sh`

They are not the supported refund-safe flow because the current readiness model
keeps the risky live lock and cooperative refund paths blocked or
`unsupported-for-guarantee`.

To run one deliberately anyway:

```bash
ALLOW_UNSUPPORTED_XMR_WOW_LIVE_FLOW=1 ./scripts/live-happy-path-v2.sh
```

Use that override only when you intentionally need the old manual path.
