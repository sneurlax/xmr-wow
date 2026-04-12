#!/usr/bin/env python3
"""
Shadow/monerosim agent driving the xmr-wow CLI with --transport sharechain.

Proves that a sharechain-mediated atomic swap completes without any manual
protocol-message string exchange. All protocol messages (Init, Response,
AdaptorPreSig, ClaimProof) route through the xmr-wow-node sharechain host.
The only shared-state file between agents is the coord_id handoff so Bob
can run init-bob.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from .base_agent import BaseAgent
except ImportError:
    class BaseAgent:  # type: ignore[no-redef]
        """Minimal stub for syntax validation outside monerosim."""

        def __init__(self, agent_id: str, **kwargs: Any) -> None:
            self.agent_id = agent_id
            self.running = True
            self.logger = logging.getLogger(agent_id)
            self.attributes: Dict[str, Any] = {}
            self._shared_dir = Path("/tmp/monerosim_shared")

        @property
        def shared_dir(self) -> Path:
            return self._shared_dir

        def write_shared_state(self, filename: str, data: Dict[str, Any],
                               use_lock: bool = True) -> None:
            path = self.shared_dir / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)

        def read_shared_state(self, filename: str,
                              use_lock: bool = False) -> Optional[Dict[str, Any]]:
            path = self.shared_dir / filename
            if not path.exists():
                return None
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)

        def interruptible_sleep(self, duration: float) -> None:
            time.sleep(min(duration, 1.0))


class XmrWowSharechainAgent(BaseAgent):
    """
    Drives the xmr-wow CLI binary with --transport sharechain.

    Every CLI invocation includes --transport sharechain --node-url <url>.
    No protocol message strings are ever extracted or passed as --message arguments.
    Protocol message routing is entirely handled by the xmr-wow-node process.
    """

    # State machine constants
    STATE_WAIT_COORD_ID = "wait_coord_id"   # Bob only: poll for Alice's coord_id
    STATE_BOOTSTRAP = "bootstrap"            # Alice: init-alice; Bob: init-bob
    STATE_WAIT_IMPORT = "wait_import"        # Alice only: wait for Bob's swap_id, then import
    STATE_EXCHANGE_PRESIG = "exchange_presig"  # Alice only: exchange-pre-sig (auto-polls node)
    STATE_LOCK = "lock"                      # Alice: lock-xmr; Bob: lock-wow
    STATE_CLAIM = "claim"                    # Alice: claim-wow; Bob: claim-xmr
    STATE_DONE = "done"

    # Shared state file names
    COORD_FILE = "xmr_wow_sharechain_coord.json"

    # Result file prefix; matches artifact file names.
    RESULT_FILE_PREFIX = "xmr_wow_sharechain_result"

    def __init__(self, agent_id: str, **kwargs: Any) -> None:
        super().__init__(agent_id=agent_id, **kwargs)
        self.role = "alice"
        self.binary = "target/release/xmr-wow"
        self.password = "shadow-test"
        self.db = ""
        self.node_url = "http://sharechain-node:18091"
        self.xmr_daemon = "http://127.0.0.1:38081"
        self.wow_daemon = "http://127.0.0.1:34568"
        self.destination = ""
        self.scan_from = "0"
        self.alice_refund_address = ""
        self.bob_refund_address = ""
        self.coord_id: Optional[str] = None
        self.swap_id: Optional[str] = None

        # Bob starts in wait_coord_id; Alice starts in bootstrap
        self.state = self.STATE_BOOTSTRAP

    def _setup_agent(self) -> None:
        self.role = str(self.attributes.get("role", "alice"))
        self.binary = str(self.attributes.get("binary", "target/release/xmr-wow"))
        self.password = str(self.attributes.get("password", "shadow-test"))
        default_db = f"/tmp/{self.agent_id}-sharechain.db"
        self.db = str(self.attributes.get("db", default_db))
        self.node_url = str(self.attributes.get("node_url", "http://sharechain-node:18091"))
        self.xmr_daemon = str(self.attributes.get("xmr_daemon", self.xmr_daemon))
        self.wow_daemon = str(self.attributes.get("wow_daemon", self.wow_daemon))
        self.destination = str(self.attributes.get("destination", ""))
        self.scan_from = str(self.attributes.get("scan_from", "0"))
        self.alice_refund_address = str(self.attributes.get("alice_refund_address", ""))
        self.bob_refund_address = str(self.attributes.get("bob_refund_address", ""))

        # Bob waits for Alice's coord_id before bootstrapping
        if self.role == "bob":
            self.state = self.STATE_WAIT_COORD_ID

    def run_iteration(self) -> float:
        try:
            if self.state == self.STATE_WAIT_COORD_ID:
                return self._handle_wait_coord_id()

            if self.state == self.STATE_BOOTSTRAP:
                return self._handle_bootstrap()

            if self.state == self.STATE_WAIT_IMPORT:
                return self._handle_wait_import()

            if self.state == self.STATE_EXCHANGE_PRESIG:
                return self._handle_exchange_presig()

            if self.state == self.STATE_LOCK:
                return self._handle_lock()

            if self.state == self.STATE_CLAIM:
                return self._handle_claim()

            return 60.0

        except Exception as exc:  # pragma: no cover - exercised only in Shadow
            self.logger.exception("sharechain agent failed: %s", exc)
            self._record_result({"status": "failed", "error": str(exc)})
            self.state = self.STATE_DONE
            self.running = False
            return 60.0

    # -------------------------------------------------------------------------
    # State handlers
    # -------------------------------------------------------------------------

    def _handle_wait_coord_id(self) -> float:
        """Bob polls shared state for Alice's coord_id."""
        data = self.read_shared_state(self.COORD_FILE)
        if data is None or data.get("sender") != "alice" or not data.get("coord_id"):
            self.logger.debug("waiting for Alice coord_id...")
            return 10.0
        self.coord_id = str(data["coord_id"])
        self.logger.info("received Alice coord_id: %s", self.coord_id)
        self.state = self.STATE_BOOTSTRAP
        return 1.0

    def _handle_bootstrap(self) -> float:
        """Alice runs init-alice; Bob runs init-bob."""
        if self.role == "alice":
            output = self._run_cli([
                "init-alice",
                "--amount-xmr", str(self.attributes.get("amount_xmr", "1000000000000")),
                "--amount-wow", str(self.attributes.get("amount_wow", "500000000000")),
                "--xmr-lock-blocks", str(self.attributes.get("xmr_lock_blocks", "120")),
                "--wow-lock-blocks", str(self.attributes.get("wow_lock_blocks", "260")),
                "--xmr-daemon", self.xmr_daemon,
                "--wow-daemon", self.wow_daemon,
                "--alice-refund-address", self.alice_refund_address,
            ])
            self.coord_id = self._extract_required(
                r"Swap coord ID:\s*([0-9a-fA-F]{64})", output
            )
            self.logger.info("Alice init-alice complete, coord_id=%s", self.coord_id)
            # Write coord_id to shared state for Bob
            self.write_shared_state(
                self.COORD_FILE,
                {"coord_id": self.coord_id, "sender": "alice"},
            )
            self.state = self.STATE_WAIT_IMPORT
            return 5.0

        else:  # Bob
            if self.coord_id is None:
                raise RuntimeError("Bob bootstrap requires coord_id from Alice")
            output = self._run_cli([
                "init-bob",
                "--swap-id", self.coord_id,
                "--bob-refund-address", self.bob_refund_address,
            ])
            self.swap_id = self._extract_required(
                r"Swap ID:\s*([0-9a-fA-F]{64})", output
            )
            self.logger.info("Bob init-bob complete, swap_id=%s", self.swap_id)
            # Overwrite coord file so Alice can read Bob's swap_id
            self.write_shared_state(
                self.COORD_FILE,
                {"coord_id": self.coord_id, "swap_id": self.swap_id, "sender": "bob"},
            )
            self.state = self.STATE_LOCK
            return 5.0

    def _handle_wait_import(self) -> float:
        """Alice waits for Bob's swap_id in shared state, then runs import."""
        data = self.read_shared_state(self.COORD_FILE)
        if data is None or data.get("sender") != "bob" or not data.get("swap_id"):
            self.logger.debug("Alice waiting for Bob swap_id...")
            return 10.0
        # Alice imports by coord_id; the CLI migrates the DB key.
        output = self._run_cli([
            "import",
            "--swap-id", self.coord_id,  # type: ignore[arg-type]
        ])
        self.swap_id = self._extract_required(
            r"Swap ID:\s*([0-9a-fA-F]{64})", output
        )
        self.logger.info("Alice import complete, real swap_id=%s", self.swap_id)
        self.state = self.STATE_EXCHANGE_PRESIG
        return 1.0

    def _handle_exchange_presig(self) -> float:
        """Alice runs exchange-pre-sig (auto-polls node; retries if no presig yet)."""
        self._run_cli(["exchange-pre-sig", "--swap-id", self.swap_id], retries=30)  # type: ignore[arg-type]
        self.logger.info("Alice exchange-pre-sig complete")
        self.state = self.STATE_LOCK
        return 1.0

    def _handle_lock(self) -> float:
        """Bob locks WOW; Alice locks XMR."""
        if self.role == "bob":
            self._run_cli([
                "lock-wow",
                "--swap-id", self.swap_id,  # type: ignore[arg-type]
                "--wow-daemon", self.wow_daemon,
                "--mnemonic", str(self.attributes.get("mnemonic", "")),
                "--scan-from", self.scan_from,
            ])
            self.logger.info("Bob lock-wow complete")
        else:
            self._run_cli([
                "lock-xmr",
                "--swap-id", self.swap_id,  # type: ignore[arg-type]
                "--xmr-daemon", self.xmr_daemon,
                "--wow-daemon", self.wow_daemon,
                "--mnemonic", str(self.attributes.get("mnemonic", "")),
                "--scan-from", self.scan_from,
            ])
            self.logger.info("Alice lock-xmr complete")
        self.state = self.STATE_CLAIM
        return 10.0

    def _handle_claim(self) -> float:
        """Alice claims WOW; Bob claims XMR. Both auto-poll sharechain node."""
        if self.role == "alice":
            self._run_cli([
                "claim-wow",
                "--swap-id", self.swap_id,  # type: ignore[arg-type]
                "--wow-daemon", self.wow_daemon,
                "--destination", self.destination,
                "--scan-from", self.scan_from,
            ], retries=30)
            self.logger.info("Alice claim-wow complete")
        else:
            self._run_cli([
                "claim-xmr",
                "--swap-id", self.swap_id,  # type: ignore[arg-type]
                "--xmr-daemon", self.xmr_daemon,
                "--destination", self.destination,
                "--scan-from", self.scan_from,
            ], retries=30)
            self.logger.info("Bob claim-xmr complete")
        self._record_result({"status": "claimed", "swap_id": self.swap_id})
        self.state = self.STATE_DONE
        return 60.0

    # -------------------------------------------------------------------------
    # CLI runner. Always includes --transport sharechain --node-url.
    # NEVER includes --message
    # -------------------------------------------------------------------------

    def _run_cli(self, args: list[str], retries: int = 0) -> str:
        cmd = [
            self.binary,
            "--transport", "sharechain",
            "--node-url", self.node_url,
            "--password", self.password,
            "--db", self.db,
            *[arg for arg in args if arg],
        ]
        self.logger.info("running xmr-wow command: %s", " ".join(cmd))
        for attempt in range(retries + 1):
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if proc.returncode == 0:
                if proc.stderr:
                    self.logger.debug("xmr-wow stderr: %s", proc.stderr.strip())
                return proc.stdout
            if attempt < retries:
                self.logger.info(
                    "retry %d/%d (rc=%d): %s",
                    attempt + 1, retries,
                    proc.returncode,
                    proc.stderr.strip()[:200],
                )
                time.sleep(10)
        proc.check_returncode()  # raises CalledProcessError
        return ""  # unreachable

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _extract_required(self, pattern: str, output: str) -> str:
        match = re.search(pattern, output)
        if match is None:
            raise RuntimeError(f"pattern not found in xmr-wow output: {pattern}")
        return match.group(1)

    def _record_result(self, payload: Dict[str, Any]) -> None:
        filename = f"{self.RESULT_FILE_PREFIX}_{self.agent_id}.json"
        self.write_shared_state(filename, payload)
