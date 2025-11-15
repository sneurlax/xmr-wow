#!/usr/bin/env python3
"""
Shadow/monerosim agent which drives the real `xmr-wow` CLI binary as a subprocess.

This complements `swap_agent.py`, which talks to daemon and wallet RPC directly.
`XmrWowCliAgent` is intended for higher-level simulations where the XMR-WOW client
binary itself is the system under test.
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


class XmrWowCliAgent(BaseAgent):
    """Runs the `xmr-wow` CLI and exchanges protocol messages through shared state."""

    STATE_BOOTSTRAP = "bootstrap"
    STATE_WAIT_IMPORT = "wait_import"
    STATE_LOCK = "lock"
    STATE_WAIT_CLAIM = "wait_claim"
    STATE_WAIT_REFUND = "wait_refund"
    STATE_DONE = "done"

    MESSAGE_FILE_PREFIX = "xmr_wow_cli_msg"
    RESULT_FILE_PREFIX = "xmr_wow_cli_result"

    def __init__(self, agent_id: str, **kwargs: Any) -> None:
        super().__init__(agent_id=agent_id, **kwargs)
        self.state = self.STATE_BOOTSTRAP
        self.role = "alice"
        self.counterparty = ""
        self.binary = "target/release/xmr-wow"
        self.password = "shadow-test"
        self.db = ""
        self.swap_id: Optional[str] = None
        self.xmr_daemon = "http://127.0.0.1:38081"
        self.wow_daemon = "http://127.0.0.1:34568"
        self.destination = ""
        self.scan_from = "0"
        self.refund_mode = False
        self.claim_message: Optional[str] = None

    def _setup_agent(self) -> None:
        self.role = str(self.attributes.get("role", "alice"))
        self.counterparty = str(self.attributes.get("counterparty", ""))
        self.binary = str(self.attributes.get("binary", "target/release/xmr-wow"))
        self.password = str(self.attributes.get("password", "shadow-test"))
        default_db = f"/tmp/{self.agent_id}-xmr-wow.db"
        self.db = str(self.attributes.get("db", default_db))
        self.xmr_daemon = str(self.attributes.get("xmr_daemon", self.xmr_daemon))
        self.wow_daemon = str(self.attributes.get("wow_daemon", self.wow_daemon))
        self.destination = str(self.attributes.get("destination", ""))
        self.scan_from = str(self.attributes.get("scan_from", "0"))
        self.refund_mode = str(self.attributes.get("mode", "")) == "refund_test"

    def run_iteration(self) -> float:
        try:
            if self.state == self.STATE_BOOTSTRAP:
                self._bootstrap_swap()
                self.state = self.STATE_WAIT_IMPORT
                return 5.0

            if self.state == self.STATE_WAIT_IMPORT:
                if self._import_counterparty_message():
                    self.state = self.STATE_LOCK
                    return 1.0
                return 10.0

            if self.state == self.STATE_LOCK:
                self._perform_lock_step()
                self.state = self.STATE_WAIT_REFUND if self.refund_mode else self.STATE_WAIT_CLAIM
                return 10.0

            if self.state == self.STATE_WAIT_CLAIM:
                if self._claim_if_ready():
                    self.state = self.STATE_DONE
                    self._record_result({"status": "claimed", "swap_id": self.swap_id})
                return 15.0

            if self.state == self.STATE_WAIT_REFUND:
                if self._refund_if_ready():
                    self.state = self.STATE_DONE
                    self._record_result({"status": "refunded", "swap_id": self.swap_id})
                return 30.0

            return 60.0
        except Exception as exc:  # pragma: no cover - exercised only in Shadow
            self.logger.exception("xmr-wow CLI agent failed: %s", exc)
            self._record_result({"status": "failed", "error": str(exc)})
            self.state = self.STATE_DONE
            self.running = False
            return 60.0

    def _bootstrap_swap(self) -> None:
        if self.role == "alice":
            output = self._run_cli([
                "init-alice",
                "--amount-xmr", str(self.attributes.get("amount_xmr", "1000000000000")),
                "--amount-wow", str(self.attributes.get("amount_wow", "500000000000")),
                "--xmr-lock-blocks", str(self.attributes.get("xmr_lock_blocks", "120")),
                "--wow-lock-blocks", str(self.attributes.get("wow_lock_blocks", "260")),
            ])
            self.swap_id = self._extract_required(r"Swap ID:\s*([0-9a-fA-F]{64})", output)
            message = self._extract_message(output)
            self._write_message("bootstrap", {"swap_id": self.swap_id, "message": message})
            return

        inbound = self._read_message("bootstrap")
        if inbound is None:
            raise RuntimeError("Bob bootstrap requires Alice init message")
        output = self._run_cli([
            "init-bob",
            "--message", str(inbound["message"]),
        ])
        self.swap_id = self._extract_required(r"Swap ID:\s*([0-9a-fA-F]{64})", output)
        message = self._extract_message(output)
        self._write_message("bootstrap", {"swap_id": self.swap_id, "message": message})

    def _import_counterparty_message(self) -> bool:
        inbound = self._read_message("bootstrap")
        if inbound is None or inbound.get("swap_id") == self.swap_id:
            return False
        if self.swap_id is None:
            return False
        self._run_cli([
            "import",
            "--swap-id", self.swap_id,
            "--message", str(inbound["message"]),
        ])
        return True

    def _perform_lock_step(self) -> None:
        if self.swap_id is None:
            raise RuntimeError("lock step requires swap_id")

        if self.role == "bob":
            output = self._run_cli([
                "lock-wow",
                "--swap-id", self.swap_id,
                "--wow-daemon", self.wow_daemon,
                "--mnemonic", str(self.attributes.get("mnemonic", "")),
                "--scan-from", self.scan_from,
            ])
            self._write_message("presig", {"swap_id": self.swap_id, "message": self._extract_message(output)})
            return

        presig = self._wait_for_message("presig")
        if presig is None:
            raise RuntimeError("Alice timed out waiting for Bob presig message")
        self._run_cli([
            "exchange-pre-sig",
            "--swap-id", self.swap_id,
            "--message", str(presig["message"]),
        ])
        output = self._run_cli([
            "lock-xmr",
            "--swap-id", self.swap_id,
            "--xmr-daemon", self.xmr_daemon,
            "--wow-daemon", self.wow_daemon,
            "--mnemonic", str(self.attributes.get("mnemonic", "")),
            "--scan-from", self.scan_from,
        ])
        self._write_message("presig", {"swap_id": self.swap_id, "message": self._extract_message(output)})

    def _claim_if_ready(self) -> bool:
        if self.swap_id is None:
            return False

        if self.role == "bob":
            presig = self._read_message("presig")
            if presig is None or presig.get("swap_id") != self.swap_id:
                return False
            self._run_cli([
                "exchange-pre-sig",
                "--swap-id", self.swap_id,
                "--message", str(presig["message"]),
            ])
            if self.claim_message is None:
                return False
            self._run_cli([
                "claim-xmr",
                "--swap-id", self.swap_id,
                "--xmr-daemon", self.xmr_daemon,
                "--message", self.claim_message,
                "--destination", self.destination,
                "--scan-from", self.scan_from,
            ])
            return True

        output = self._run_cli([
            "claim-wow",
            "--swap-id", self.swap_id,
            "--wow-daemon", self.wow_daemon,
            "--message", str(self._read_message("presig")["message"]),
            "--destination", self.destination,
            "--scan-from", self.scan_from,
        ])
        self.claim_message = self._extract_message(output)
        self._write_message("claim", {"swap_id": self.swap_id, "message": self.claim_message})
        return True

    def _refund_if_ready(self) -> bool:
        if self.swap_id is None:
            return False
        output = self._run_cli(["resume", "--swap-id", self.swap_id])
        if "refund" not in output.lower():
            return False
        self._run_cli([
            "refund",
            "--swap-id", self.swap_id,
            "--xmr-daemon", self.xmr_daemon,
            "--wow-daemon", self.wow_daemon,
        ])
        return True

    def _run_cli(self, args: list[str]) -> str:
        cmd = [
            self.binary,
            "--password", self.password,
            "--db", self.db,
            *[arg for arg in args if arg],
        ]
        self.logger.info("running xmr-wow command: %s", " ".join(cmd))
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
        )
        if proc.stderr:
            self.logger.debug("xmr-wow stderr: %s", proc.stderr.strip())
        return proc.stdout

    def _extract_message(self, output: str) -> str:
        for line in output.splitlines():
            if line.startswith("xmrwow1:"):
                return line.strip()
        raise RuntimeError("xmr-wow output did not include a protocol message")

    def _extract_required(self, pattern: str, output: str) -> str:
        match = re.search(pattern, output)
        if match is None:
            raise RuntimeError(f"pattern not found in xmr-wow output: {pattern}")
        return match.group(1)

    def _message_path(self, stage: str) -> str:
        return f"{self.MESSAGE_FILE_PREFIX}_{stage}.json"

    def _result_path(self) -> str:
        return f"{self.RESULT_FILE_PREFIX}_{self.agent_id}.json"

    def _write_message(self, stage: str, payload: Dict[str, Any]) -> None:
        data = {"sender": self.agent_id, **payload}
        self.write_shared_state(self._message_path(stage), data)

    def _read_message(self, stage: str) -> Optional[Dict[str, Any]]:
        data = self.read_shared_state(self._message_path(stage))
        if data is None:
            return None
        if data.get("sender") == self.agent_id:
            return None
        return data

    def _wait_for_message(self, stage: str, timeout_s: int = 600) -> Optional[Dict[str, Any]]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            data = self._read_message(stage)
            if data is not None:
                return data
            self.interruptible_sleep(2.0)
        return None

    def _record_result(self, payload: Dict[str, Any]) -> None:
        self.write_shared_state(self._result_path(), payload)
