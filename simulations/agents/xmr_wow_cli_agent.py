#!/usr/bin/env python3
"""
Shadow/monerosim agent which drives the real `xmr-wow` CLI binary as a subprocess.

This complements `swap_agent.py`, which talks to daemon and wallet RPC directly.
`XmrWowCliAgent` is intended for higher-level simulations where the XMR-WOW client
binary itself is the system under test.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.request as urlrequest
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from .base_agent import BaseAgent
except ImportError:
    class BaseAgent:  # type: ignore[no-redef]
        """Standalone-compatible fallback when monerosim isn't importable."""

        def __init__(self, agent_id: str, **kwargs: Any) -> None:
            self.agent_id = agent_id
            self.running = True
            self.rpc_host = str(kwargs.get("rpc_host", "127.0.0.1"))
            self.daemon_rpc_port = kwargs.get("daemon_rpc_port")
            self.wallet_rpc_port = kwargs.get("wallet_rpc_port")
            self.p2p_port = kwargs.get("p2p_port")
            self.log_level = str(kwargs.get("log_level", "INFO"))
            self.logger = logging.getLogger(agent_id)
            self.logger.setLevel(getattr(logging, self.log_level.upper(), logging.INFO))
            self.attributes = self._coerce_attributes(kwargs.get("attributes", {}))
            self._shared_dir = Path(str(kwargs.get("shared_dir", "/tmp/monerosim_shared")))

        @staticmethod
        def create_argument_parser(description: str) -> argparse.ArgumentParser:
            parser = argparse.ArgumentParser(description=description)
            parser.add_argument("--id", required=True)
            parser.add_argument("--shared-dir", default="/tmp/monerosim_shared")
            parser.add_argument("--rpc-host", default="127.0.0.1")
            parser.add_argument("--daemon-rpc-port", type=int)
            parser.add_argument("--wallet-rpc-port", type=int)
            parser.add_argument("--p2p-port", type=int)
            parser.add_argument("--log-level", default="INFO")
            parser.add_argument("--attributes", nargs=2, action="append", default=[])
            return parser

        @staticmethod
        def _coerce_attributes(raw: Any) -> Dict[str, Any]:
            if isinstance(raw, dict):
                return raw
            if isinstance(raw, list):
                return {str(key): value for key, value in raw}
            return {}

        @property
        def shared_dir(self) -> Path:
            return self._shared_dir

        def setup(self) -> None:
            self.shared_dir.mkdir(parents=True, exist_ok=True)
            self._setup_agent()

        def run(self) -> None:
            self.setup()
            while self.running:
                sleep_duration = self.run_iteration() or 1.0
                self.interruptible_sleep(sleep_duration)
            self._cleanup_agent()

        def _cleanup_agent(self) -> None:
            return None

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

    STATE_PREPARE_FUNDS = "prepare_funds"
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
        self.state = self.STATE_PREPARE_FUNDS
        self.role = "alice"
        self.counterparty = ""
        self.binary = "target/release/xmr-wow"
        self.password = "shadow-test"
        self.db = ""
        self.swap_id: Optional[str] = None
        self.wallet_name = f"{agent_id}_wallet"
        self.wallet_address: Optional[str] = None
        self.wallet_address_cache: Optional[str] = None
        self.xmr_daemon = "http://127.0.0.1:38081"
        self.wow_daemon = "http://127.0.0.1:38081"
        self.destination = ""
        self.scan_from = "0"
        self.mnemonic = ""
        self.wallet_mnemonic_cache: Optional[str] = None
        self.bootstrap_xmr_blocks = 0
        self.bootstrap_wow_blocks = 0
        self.pending_xmr_blocks = 0
        self.pending_wow_blocks = 0
        self.bootstrap_announced: set[str] = set()
        self.bootstrap_last_busy_log: Dict[str, float] = {}
        self.vts_squarings_per_second = ""
        self.vts_modulus_bits = ""
        self.refund_mode = False
        self.claim_message: Optional[str] = None
        self.alice_has_bob_presig = False
        self.bob_has_alice_presig = False
        self.wow_confirmation_scan_buffer = 32
        self.wow_bounded_mining_poll_interval_secs = 0.005

    def _setup_agent(self) -> None:
        self.role = str(self.attributes.get("role", "alice"))
        self.counterparty = str(self.attributes.get("counterparty", ""))
        self.binary = self._resolve_repo_path(
            str(self.attributes.get("binary", "target/release/xmr-wow"))
        )
        self.password = str(self.attributes.get("password", "shadow-test"))
        default_db = f"/tmp/{self.agent_id}-xmr-wow.db"
        self.db = str(self.attributes.get("db", default_db))
        self.wallet_name = str(self.attributes.get("wallet_name", self.wallet_name))
        self.xmr_daemon = str(self.attributes.get("xmr_daemon", self._default_daemon_url()))
        self.wow_daemon = str(self.attributes.get("wow_daemon", self._default_daemon_url()))
        self.destination = str(self.attributes.get("destination", ""))
        self.scan_from = str(self.attributes.get("scan_from", "0"))
        self.mnemonic = (
            str(self.attributes.get("mnemonic", ""))
            .strip()
            .replace("|", " ")
            .replace(",", " ")
        )
        self.bootstrap_xmr_blocks = int(
            self.attributes.get("bootstrap_xmr_blocks", self.bootstrap_xmr_blocks)
        )
        self.bootstrap_wow_blocks = int(
            self.attributes.get("bootstrap_wow_blocks", self.bootstrap_wow_blocks)
        )
        self.pending_xmr_blocks = self.bootstrap_xmr_blocks
        self.pending_wow_blocks = self.bootstrap_wow_blocks
        self.vts_squarings_per_second = str(
            self.attributes.get("vts_squarings_per_second", "")
        ).strip()
        self.vts_modulus_bits = str(self.attributes.get("vts_modulus_bits", "")).strip()
        self.refund_mode = str(self.attributes.get("mode", "")) == "refund_test"
        self._ensure_wallet_ready()
        self._publish_wallet_identity()

    def run_iteration(self) -> float:
        try:
            if self.state == self.STATE_PREPARE_FUNDS:
                next_state, delay = self._prepare_funds_step()
                self.state = next_state
                return delay

            if self.state == self.STATE_BOOTSTRAP:
                next_state = self._bootstrap_swap()
                if next_state is not None:
                    self.state = next_state
                    return 5.0
                return 5.0

            if self.state == self.STATE_WAIT_IMPORT:
                if self._import_counterparty_message():
                    self.state = self.STATE_LOCK
                    return 1.0
                return 10.0

            if self.state == self.STATE_LOCK:
                if self._perform_lock_step():
                    self.state = (
                        self.STATE_WAIT_REFUND if self.refund_mode else self.STATE_WAIT_CLAIM
                    )
                    return 10.0
                return 5.0

            if self.state == self.STATE_WAIT_CLAIM:
                if self._claim_if_ready():
                    self.state = self.STATE_DONE
                    self._record_result({"status": "claimed", "swap_id": self.swap_id})
                    self.running = False
                    return 0.0
                return 15.0

            if self.state == self.STATE_WAIT_REFUND:
                if self._refund_if_ready():
                    self.state = self.STATE_DONE
                    self._record_result({"status": "refunded", "swap_id": self.swap_id})
                    self.running = False
                    return 0.0
                return 30.0

            if self.state == self.STATE_DONE:
                self.running = False
                return 0.0

            return 60.0
        except Exception as exc:  # pragma: no cover - exercised only in Shadow
            self.logger.exception("xmr-wow CLI agent failed: %s", exc)
            self._record_result({"status": "failed", "error": str(exc)})
            self.state = self.STATE_DONE
            self.running = False
            return 60.0

    def _prepare_funds_step(self) -> tuple[str, float]:
        wallet_address = self._wallet_address_value()

        if self.pending_xmr_blocks > 0:
            mined = self._bootstrap_mine_block(
                self.xmr_daemon,
                wallet_address,
                label="XMR",
                pending_attr="pending_xmr_blocks",
                total_blocks=self.bootstrap_xmr_blocks,
            )
            return self.STATE_PREPARE_FUNDS, 1.0 if mined else 10.0

        if self.pending_wow_blocks > 0:
            mined = self._bootstrap_mine_block(
                self.wow_daemon,
                wallet_address,
                label="WOW",
                pending_attr="pending_wow_blocks",
                total_blocks=self.bootstrap_wow_blocks,
            )
            return self.STATE_PREPARE_FUNDS, 1.0 if mined else 10.0

        return self.STATE_BOOTSTRAP, 1.0

    def _bootstrap_swap(self) -> Optional[str]:
        if self.role == "alice":
            output = self._run_cli([
                "init-alice",
                "--amount-xmr", str(self.attributes.get("amount_xmr", "1000000000000")),
                "--amount-wow", str(self.attributes.get("amount_wow", "500000000000")),
                "--xmr-daemon", self.xmr_daemon,
                "--wow-daemon", self.wow_daemon,
                "--xmr-refund-delay", str(self.attributes.get("xmr_refund_delay", "120")),
                "--wow-refund-delay", str(self.attributes.get("wow_refund_delay", "260")),
                "--alice-refund-address", self._resolved_refund_address("alice_refund_address"),
            ])
            self.swap_id = self._extract_swap_id(output)
            message = self._extract_message(output)
            self._write_message("bootstrap", {"swap_id": self.swap_id, "message": message})
            return self.STATE_WAIT_IMPORT

        inbound = self._read_message("bootstrap")
        if inbound is None:
            self.logger.info("bob waiting for Alice init message")
            return None
        output = self._run_cli([
            "init-bob",
            "--message", str(inbound["message"]),
            "--bob-refund-address", self._resolved_refund_address("bob_refund_address"),
        ])
        self.swap_id = self._extract_swap_id(output)
        message = self._extract_message(output)
        self._write_message("bootstrap", {"swap_id": self.swap_id, "message": message})
        return self.STATE_LOCK

    def _import_counterparty_message(self) -> bool:
        inbound = self._read_message("bootstrap")
        if inbound is None or inbound.get("swap_id") == self.swap_id:
            return False
        if self.swap_id is None:
            return False
        output = self._run_cli([
            "import",
            "--swap-id", self.swap_id,
            "--message", str(inbound["message"]),
        ])
        self.swap_id = self._extract_swap_id(output)
        if self.role == "alice":
            self._write_message(
                "refund_artifact",
                {"swap_id": self.swap_id, "message": self._extract_message(output)},
            )
        return True

    def _perform_lock_step(self) -> bool:
        if self.swap_id is None:
            raise RuntimeError("lock step requires swap_id")

        if self.role == "bob":
            refund_artifact = self._wait_for_message("refund_artifact")
            if refund_artifact is None:
                raise RuntimeError("Bob timed out waiting for Alice refund artifact message")
            mnemonic = self._wallet_mnemonic()
            output = self._run_cli([
                "lock-wow",
                "--swap-id", self.swap_id,
                "--wow-daemon", self.wow_daemon,
                "--message", str(refund_artifact["message"]),
                "--mnemonic", mnemonic,
                "--scan-from", self.scan_from,
            ])
            confirmed_height = self._extract_confirmation_height(output)
            self._write_message(
                "presig_bob",
                {
                    "swap_id": self.swap_id,
                    "message": self._extract_message(output),
                    "scan_from": self._scan_from_for_confirmed_height(confirmed_height),
                },
            )
            return True

        presig = self._wait_for_message("presig_bob")
        if presig is None:
            raise RuntimeError("Alice timed out waiting for Bob presig message")

        required_amount = int(self.attributes.get("amount_xmr", "1000000000000"))
        xmr_balance, xmr_unlocked = self._wallet_balances()
        if xmr_unlocked < required_amount:
            if xmr_balance >= required_amount:
                self.logger.info(
                    "alice funding is present but still locked; mining bounded XMR bursts to mature outputs"
                )
                bursts = 0
                burst_cap = 4
                while xmr_unlocked < required_amount and bursts < burst_cap:
                    if not self._mine_confirmation_block(
                        "XMR",
                        self.xmr_daemon,
                        self._confirmation_wallet_address("XMR"),
                    ):
                        break
                    bursts += 1
                    xmr_balance, xmr_unlocked = self._wallet_balances()
                if xmr_unlocked >= required_amount:
                    self.logger.info(
                        "alice XMR funding matured after %d bounded burst(s) unlocked=%s total=%s",
                        bursts,
                        xmr_unlocked,
                        xmr_balance,
                    )
            self.logger.info(
                "alice waiting for XMR spendable balance unlocked=%s total=%s required=%s",
                xmr_unlocked,
                xmr_balance,
                required_amount,
            )
            return False

        mnemonic = self._wallet_mnemonic()
        scan_from = self._message_scan_from(presig)
        try:
            output = self._run_cli([
                "lock-xmr",
                "--swap-id", self.swap_id,
                "--xmr-daemon", self.xmr_daemon,
                "--wow-daemon", self.wow_daemon,
                "--mnemonic", mnemonic,
                "--scan-from", scan_from,
            ])
        except RuntimeError as exc:
            if self._is_retryable_error(
                exc,
                "no outputs found at joint address",
                "insufficient funds",
                "RPC connection failed",
                "wallet RPC",
            ):
                self.logger.info(
                    "alice waiting for spendable XMR inputs or daemon/wallet readiness before lock-xmr"
                )
                self._mine_confirmation_block(
                    "XMR",
                    self.xmr_daemon,
                    self._confirmation_wallet_address("XMR"),
                )
                return False
            raise
        confirmed_height = self._extract_confirmation_height(output)
        self._run_cli([
            "exchange-pre-sig",
            "--swap-id", self.swap_id,
            "--message", str(presig["message"]),
        ])
        self.alice_has_bob_presig = True
        self._write_message(
            "presig_alice",
            {
                "swap_id": self.swap_id,
                "message": self._extract_message(output),
                "scan_from": self._scan_from_for_confirmed_height(confirmed_height),
            },
        )
        return True

    def _claim_if_ready(self) -> bool:
        if self.swap_id is None:
            return False

        if self.role == "bob":
            presig = self._read_message("presig_alice")
            if presig is None or presig.get("swap_id") != self.swap_id:
                return False
            xmr_scan_from = self._message_scan_from(presig)

            if not self.bob_has_alice_presig:
                self._run_cli([
                    "exchange-pre-sig",
                    "--swap-id", self.swap_id,
                    "--message", str(presig["message"]),
                ])
                self.bob_has_alice_presig = True

            if self.claim_message is None:
                output = self._run_cli([
                    "claim-xmr",
                    "--swap-id", self.swap_id,
                    "--xmr-daemon", self.xmr_daemon,
                    *self._optional_arg("--destination", self._resolved_destination()),
                    "--scan-from", xmr_scan_from,
                ])
                self.claim_message = self._extract_message(output)
                self._write_message(
                    "claim_bob",
                    {"swap_id": self.swap_id, "message": self.claim_message},
                )
                return False

            self._mine_confirmation_block(
                "WOW",
                self.wow_daemon,
                self._confirmation_wallet_address("WOW"),
            )
            self._mine_confirmation_block(
                "XMR",
                self.xmr_daemon,
                self._confirmation_wallet_address("XMR"),
            )
            claim = self._read_message("claim_alice")
            if claim is None or claim.get("swap_id") != self.swap_id:
                return False
            try:
                self._run_cli([
                    "claim-xmr",
                    "--swap-id", self.swap_id,
                    "--xmr-daemon", self.xmr_daemon,
                    "--message", str(claim["message"]),
                    *self._optional_arg("--destination", self._resolved_destination()),
                    "--scan-from", xmr_scan_from,
                ])
            except RuntimeError as exc:
                if "no spendable outputs at joint address yet" in str(exc):
                    self.logger.info("bob waiting for XMR lock output maturity before claim-xmr")
                    return False
                raise
            return True

        claim = self._read_message("claim_bob")
        if claim is None or claim.get("swap_id") != self.swap_id:
            return False

        wow_scan_from = self.scan_from
        presig = self._read_message("presig_bob")
        if presig is not None and presig.get("swap_id") == self.swap_id:
            wow_scan_from = self._message_scan_from(presig)

        try:
            output = self._run_cli([
                "claim-wow",
                "--swap-id", self.swap_id,
                "--wow-daemon", self.wow_daemon,
                "--message", str(claim["message"]),
                *self._optional_arg("--destination", self._resolved_destination()),
                "--scan-from", wow_scan_from,
            ])
        except RuntimeError as exc:
            if "no spendable outputs at joint address yet" in str(exc):
                self.logger.info("alice waiting for WOW lock output maturity before claim-wow")
                return False
            raise

        self.claim_message = self._extract_message(output)
        self._write_message(
            "claim_alice",
            {"swap_id": self.swap_id, "message": self.claim_message},
        )
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
        env = os.environ.copy()
        if self.vts_squarings_per_second:
            env["XMR_WOW_VTS_SQUARINGS_PER_SECOND"] = self.vts_squarings_per_second
        if self.vts_modulus_bits:
            env["XMR_WOW_VTS_MODULUS_BITS"] = self.vts_modulus_bits
        command_name = args[0] if args else ""
        timeout = 240 if command_name in {"lock-wow", "lock-xmr", "claim-wow", "claim-xmr"} else 180
        stop_event = threading.Event()
        miner_thread: Optional[threading.Thread] = None
        miner_plan = self._confirmation_mining_plan(command_name)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            if miner_plan is not None:
                miner_thread = threading.Thread(
                    target=self._run_confirmation_miner,
                    args=(stop_event, command_name, miner_plan["label"], miner_plan["daemon_url"], miner_plan["wallet_address"]),
                    daemon=True,
                )
                miner_thread.start()
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise RuntimeError(
                f"xmr-wow timed out after {timeout}s: "
                f"stdout={stdout.strip()!r} stderr={stderr.strip()!r}"
            ) from exc
        finally:
            stop_event.set()
            if miner_thread is not None:
                miner_thread.join(timeout=5.0)

        if stdout:
            self.logger.debug("xmr-wow stdout: %s", stdout.strip())
        if stderr:
            self.logger.debug("xmr-wow stderr: %s", stderr.strip())
        if proc.returncode != 0:
            raise RuntimeError(
                f"xmr-wow exited with {proc.returncode}: "
                f"stdout={stdout.strip()!r} stderr={stderr.strip()!r}"
            )
        return stdout

    def _confirmation_mining_plan(self, command_name: str) -> Optional[Dict[str, str]]:
        if command_name in {"lock-xmr", "claim-xmr"}:
            return {
                "label": "XMR",
                "daemon_url": self.xmr_daemon,
                "wallet_address": self._confirmation_wallet_address("XMR"),
            }
        if command_name == "lock-wow":
            return {
                "label": "WOW",
                "daemon_url": self.wow_daemon,
                "wallet_address": self._confirmation_wallet_address("WOW"),
            }
        return None

    def _confirmation_wallet_address(self, label: str) -> str:
        if (label == "WOW" and self.role != "bob") or (
            label == "XMR" and self.role == "bob"
        ):
            counterparty_info = self.read_shared_state(
                f"{self.counterparty}_user_info.json"
            )
            if isinstance(counterparty_info, dict):
                counterparty_address = str(
                    counterparty_info.get("wallet_address", "")
                ).strip()
                if counterparty_address:
                    return counterparty_address
        return self._wallet_address_value()

    def _run_confirmation_miner(
        self,
        stop_event: threading.Event,
        command_name: str,
        label: str,
        daemon_url: str,
        wallet_address: str,
    ) -> None:
        if stop_event.wait(1.0):
            return

        # XMR lock/claim commands can spend several seconds scanning the sender
        # wallet or waiting for joint outputs before the transaction is actually
        # broadcast. Keep the exact-block XMR confirmation miner alive much
        # longer so the first post-broadcast block is still produced by the
        # helper thread. WOW stays on the shorter budget because its bounded
        # fallback mining path can overshoot heavily under Shadow.
        max_attempts = 60 if label == "XMR" else 6

        for attempt in range(max_attempts):
            if stop_event.is_set():
                return
            mined = self._mine_confirmation_block(label, daemon_url, wallet_address)
            if mined:
                self.logger.info(
                    "%s confirmation miner produced block %s on %s daemon %s",
                    command_name,
                    attempt + 1,
                    label,
                    daemon_url,
                )
            if stop_event.wait(1.0):
                return

    def _mine_confirmation_block(
        self,
        label: str,
        daemon_url: str,
        wallet_address: str,
    ) -> bool:
        try:
            if label == "XMR":
                self._daemon_json_rpc(
                    daemon_url,
                    "generateblocks",
                    {
                        "amount_of_blocks": 1,
                        "wallet_address": wallet_address,
                        "pre_pow_blob": "sim",
                    },
                )
                return True

            initial_height = self._current_chain_height(daemon_url)
            final_height = self._mine_wow_blocks_bounded(
                daemon_url,
                wallet_address,
                count=1,
            )
            if final_height is None:
                return False
            return final_height > initial_height
        except RuntimeError as exc:
            message = str(exc)
            if "status BUSY" not in message:
                self.logger.debug(
                    "%s confirmation miner on %s did not complete cleanly: %s",
                    label,
                    daemon_url,
                    exc,
                )
            return False

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

    def _extract_swap_id(self, output: str) -> str:
        match = re.search(r"(?:Temp )?[Ss]wap ID:\s*([0-9a-fA-F]{64})", output)
        if match is None:
            raise RuntimeError("swap id not present in xmr-wow output")
        return match.group(1)

    def _extract_confirmation_height(self, output: str) -> Optional[int]:
        match = re.search(r"Confirmed at height (\d+)", output)
        if match is None:
            return None
        return int(match.group(1))

    def _scan_from_for_confirmed_height(self, confirmed_height: Optional[int]) -> str:
        if confirmed_height is None:
            return self.scan_from
        return str(max(confirmed_height - self.wow_confirmation_scan_buffer, 0))

    def _message_scan_from(self, message: Dict[str, Any]) -> str:
        shared_scan_from = message.get("scan_from")
        if isinstance(shared_scan_from, int):
            return str(max(shared_scan_from, 0))
        if isinstance(shared_scan_from, str) and shared_scan_from.strip().isdigit():
            return str(max(int(shared_scan_from.strip()), 0))
        return self.scan_from

    def _resolve_repo_path(self, path: str) -> str:
        candidate = Path(path)
        if candidate.is_absolute():
            return str(candidate)

        repo_root = Path(__file__).resolve().parents[2]
        repo_candidate = repo_root / candidate
        if repo_candidate.exists():
            return str(repo_candidate)
        return path

    def _default_daemon_url(self) -> str:
        if self.daemon_rpc_port is None:
            return self.xmr_daemon
        return f"http://{self.rpc_host}:{self.daemon_rpc_port}"

    def _current_chain_height(self, daemon_url: str) -> int:
        return int(self._daemon_json_rpc(daemon_url, "get_block_count").get("count", 0))

    def _wallet_rpc_url(self) -> str:
        if self.wallet_rpc_port is None:
            raise RuntimeError("wallet RPC port missing from agent context")
        return f"http://{self.rpc_host}:{self.wallet_rpc_port}/json_rpc"

    def _wallet_rpc_call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params or {},
        }).encode("utf-8")
        request = urlrequest.Request(
            self._wallet_rpc_url(),
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlrequest.urlopen(request, timeout=20) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"wallet RPC call {method} failed: {exc}") from exc

        error = decoded.get("error")
        if error:
            raise RuntimeError(f"wallet RPC {method} error: {error}")

        result = decoded.get("result")
        if not isinstance(result, dict):
            raise RuntimeError(f"wallet RPC {method} returned no result payload")
        return result

    def _wallet_balances(self) -> tuple[int, int]:
        self._wallet_rpc_call("refresh")
        result = self._wallet_rpc_call("get_balance", {"account_index": 0})
        balance = int(result.get("balance", 0))
        unlocked = int(result.get("unlocked_balance", 0))
        return balance, unlocked

    def _daemon_json_rpc(
        self,
        daemon_url: str,
        method: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params or {},
        }).encode("utf-8")
        request = urlrequest.Request(
            f"{daemon_url}/json_rpc",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlrequest.urlopen(request, timeout=20) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"daemon RPC call {method} failed: {exc}") from exc

        error = decoded.get("error")
        if error:
            raise RuntimeError(f"daemon RPC {method} error: {error}")

        result = decoded.get("result")
        if not isinstance(result, dict):
            raise RuntimeError(f"daemon RPC {method} returned no result payload")
        status = result.get("status")
        if isinstance(status, str) and status != "OK":
            raise RuntimeError(f"daemon RPC {method} returned status {status}")
        return result

    def _daemon_rpc_call(
        self,
        daemon_url: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        timeout_s: float = 20.0,
        ok_statuses: Optional[set[str]] = None,
    ) -> Dict[str, Any]:
        request = urlrequest.Request(
            f"{daemon_url}/{path}",
            data=json.dumps(payload or {}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlrequest.urlopen(request, timeout=timeout_s) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"daemon RPC call {path} failed: {exc}") from exc

        if not isinstance(decoded, dict):
            raise RuntimeError(f"daemon RPC {path} returned no result payload")

        allowed_statuses = ok_statuses or {"OK"}
        status = decoded.get("status")
        if isinstance(status, str) and status not in allowed_statuses:
            raise RuntimeError(f"daemon RPC {path} returned status {status}")
        return decoded

    def _mine_wow_block_with_start_stop(
        self,
        daemon_url: str,
        wallet_address: str,
    ) -> Optional[tuple[int, int]]:
        try:
            initial_height = int(
                self._daemon_json_rpc(daemon_url, "get_block_count").get("count", 0)
            )
        except Exception as exc:
            self.logger.warning(
                "WOW bootstrap fallback could not read initial height from %s: %s",
                daemon_url,
                exc,
            )
            return None

        payload = {
            "miner_address": wallet_address,
            "threads_count": 1,
            "do_background_mining": False,
            "ignore_battery": True,
        }
        try:
            self._daemon_rpc_call(
                daemon_url,
                "start_mining",
                payload,
                timeout_s=2.0,
            )
        except RuntimeError as exc:
            message = str(exc).lower()
            if "timed out" not in message:
                self.logger.info(
                    "WOW bootstrap start_mining did not return cleanly on %s: %s",
                    daemon_url,
                    exc,
                )

        current_height = initial_height
        for _ in range(200):
            time.sleep(0.05)
            try:
                current_height = int(
                    self._daemon_json_rpc(daemon_url, "get_block_count").get("count", 0)
                )
            except RuntimeError:
                continue
            if current_height > initial_height:
                break

        try:
            self._daemon_rpc_call(
                daemon_url,
                "stop_mining",
                {},
                timeout_s=5.0,
                ok_statuses={"OK", "Mining never started"},
            )
        except RuntimeError as exc:
            self.logger.warning(
                "WOW bootstrap stop_mining did not return cleanly on %s: %s",
                daemon_url,
                exc,
            )

        stable_height = current_height
        stable_polls = 0
        for _ in range(100):
            time.sleep(0.05)
            try:
                observed_height = int(
                    self._daemon_json_rpc(daemon_url, "get_block_count").get("count", 0)
                )
            except RuntimeError:
                break
            if observed_height == stable_height:
                stable_polls += 1
                if stable_polls >= 3:
                    break
            else:
                stable_height = observed_height
                stable_polls = 0

        if stable_height <= initial_height:
            return None
        return initial_height, stable_height

    def _wait_for_wow_height_to_stabilize(
        self,
        daemon_url: str,
        observed_height: int,
        *,
        stable_polls_required: int = 3,
        max_polls: int = 100,
    ) -> int:
        last_height = observed_height
        stable_polls = 0
        for _ in range(max_polls):
            time.sleep(0.05)
            try:
                current_height = self._current_chain_height(daemon_url)
            except RuntimeError:
                continue
            if current_height == last_height:
                stable_polls += 1
                if stable_polls >= stable_polls_required:
                    return current_height
                continue
            last_height = current_height
            stable_polls = 0
        return last_height

    def _mine_wow_blocks_bounded(
        self,
        daemon_url: str,
        wallet_address: str,
        *,
        count: int,
    ) -> Optional[int]:
        initial_height = self._current_chain_height(daemon_url)
        try:
            result = self._daemon_json_rpc(
                daemon_url,
                "generateblocks",
                {
                    "amount_of_blocks": int(count),
                    "wallet_address": wallet_address,
                    "pre_pow_blob": "sim",
                },
            )
        except RuntimeError as exc:
            self.logger.debug(
                "WOW generateblocks rejected for %s block(s) on %s: %s",
                count,
                daemon_url,
                exc,
            )
        else:
            final_height = result.get("height", initial_height)
            try:
                return int(final_height)
            except (TypeError, ValueError):
                return initial_height

        payload = {
            "miner_address": wallet_address,
            "threads_count": 1,
            "do_background_mining": False,
            "ignore_battery": True,
        }
        try:
            self._daemon_rpc_call(
                daemon_url,
                "start_mining",
                payload,
                timeout_s=2.0,
            )
        except RuntimeError as exc:
            message = str(exc).lower()
            if "timed out" not in message:
                self.logger.info(
                    "WOW bounded confirmation start_mining did not return cleanly on %s: %s",
                    daemon_url,
                    exc,
                )

        target_height = initial_height + int(count)
        current_height = initial_height
        bounded_poll_interval = max(
            min(self.wow_bounded_mining_poll_interval_secs, 0.05),
            0.001,
        )
        max_polls = max(200, int(10 / bounded_poll_interval))
        for _ in range(max_polls):
            time.sleep(bounded_poll_interval)
            try:
                current_height = self._current_chain_height(daemon_url)
            except RuntimeError:
                continue
            if current_height >= target_height:
                break

        try:
            self._daemon_rpc_call(
                daemon_url,
                "stop_mining",
                {},
                timeout_s=2.0,
                ok_statuses={"OK", "Mining never started"},
            )
        except RuntimeError as exc:
            self.logger.debug(
                "WOW bounded confirmation stop_mining did not return cleanly on %s: %s",
                daemon_url,
                exc,
            )

        final_height = self._wait_for_wow_height_to_stabilize(daemon_url, current_height)
        produced = max(final_height - initial_height, 0)
        if produced > count + 8:
            self.logger.warning(
                "WOW bounded confirmation mining overshot: requested=%s produced=%s initial=%s final=%s",
                count,
                produced,
                initial_height,
                final_height,
            )
        return final_height

    def _ensure_wallet_ready(self) -> str:
        if self.wallet_address is not None:
            return self.wallet_address

        open_params = {"filename": self.wallet_name, "password": ""}
        create_params = {**open_params, "language": "English"}
        configured_mnemonic = self.mnemonic.strip()
        restore_params = {
            **open_params,
            "language": "English",
            "seed": configured_mnemonic,
            "restore_height": 0,
        }

        try:
            self._wallet_rpc_call("open_wallet", open_params)
        except RuntimeError as exc:
            message = str(exc).lower()
            if (
                "wallet not found" not in message
                and "wallet file not found" not in message
                and "file not found" not in message
                and "no such file or directory" not in message
                and "no wallet file" not in message
            ):
                raise
            if configured_mnemonic and not configured_mnemonic.startswith("SHADOW_"):
                self._wallet_rpc_call("restore_deterministic_wallet", restore_params)
            else:
                self._wallet_rpc_call("create_wallet", create_params)

        result = self._wallet_rpc_call(
            "get_address",
            {"account_index": 0, "address_index": [0]},
        )
        addresses = result.get("addresses")
        if not isinstance(addresses, list) or not addresses:
            raise RuntimeError("wallet RPC get_address returned no addresses")
        address = str(addresses[0].get("address", "")).strip()
        if not address:
            raise RuntimeError("wallet RPC get_address returned an empty address")
        self.wallet_address = address
        self.wallet_address_cache = address
        return address

    def _wallet_mnemonic(self) -> str:
        mnemonic = self.wallet_mnemonic_cache
        if mnemonic:
            return mnemonic

        configured = self.mnemonic.strip()
        if configured and not configured.startswith("SHADOW_"):
            self.wallet_mnemonic_cache = configured
            return configured

        self._ensure_wallet_ready()
        result = self._wallet_rpc_call("query_key", {"key_type": "mnemonic"})
        mnemonic = str(result.get("key", "")).strip()
        if not mnemonic:
            raise RuntimeError("wallet RPC query_key did not return a mnemonic")
        self.wallet_mnemonic_cache = mnemonic
        return mnemonic

    def _wallet_address_value(self) -> str:
        address = self.wallet_address_cache
        if address:
            return address
        return self._ensure_wallet_ready()

    def _bootstrap_mine_block(
        self,
        daemon_url: str,
        wallet_address: str,
        *,
        label: str,
        pending_attr: str,
        total_blocks: int,
    ) -> bool:
        pending_blocks = int(getattr(self, pending_attr, 0))
        if pending_blocks <= 0:
            return True

        if label not in self.bootstrap_announced:
            self.logger.info(
                "bootstrap-mining %s block(s) on %s daemon %s to %s",
                total_blocks,
                label,
                daemon_url,
                wallet_address,
            )
            self.bootstrap_announced.add(label)

        completed_blocks = total_blocks - pending_blocks
        next_block = completed_blocks + 1
        blocks_requested = min(pending_blocks, 200) if label == "XMR" else 1
        produced_blocks = blocks_requested
        try:
            result = self._daemon_json_rpc(
                daemon_url,
                "generateblocks",
                {
                    "amount_of_blocks": blocks_requested,
                    "wallet_address": wallet_address,
                    "pre_pow_blob": "sim",
                },
            )
        except RuntimeError as exc:
            message = str(exc)
            if "status BUSY" in message:
                now = time.monotonic()
                last_log = self.bootstrap_last_busy_log.get(label, 0.0)
                if now - last_log >= 5.0:
                    self.logger.info(
                        "%s daemon %s is busy before bootstrap block %s/%s; waiting",
                        label,
                        daemon_url,
                        next_block,
                        total_blocks,
                    )
                    self.bootstrap_last_busy_log[label] = now
                return False

            if label == "WOW":
                fallback_result = self._mine_wow_block_with_start_stop(
                    daemon_url,
                    wallet_address,
                )
                if fallback_result is None:
                    raise
                initial_height, fallback_height = fallback_result
                produced_blocks = max(fallback_height - initial_height, 1)
                result = {"height": fallback_height}
            else:
                raise

        pending_blocks = max(pending_blocks - produced_blocks, 0)
        setattr(self, pending_attr, pending_blocks)
        completed_blocks = total_blocks - pending_blocks
        current_height = result.get("height", "unknown")
        if completed_blocks == total_blocks or completed_blocks % 10 == 0:
            self.logger.info(
                "%s bootstrap mined %s/%s block(s); current height %s",
                label,
                completed_blocks,
                total_blocks,
                current_height,
            )
        if completed_blocks == total_blocks:
            self.logger.info(
                "%s bootstrap mining complete at height %s",
                label,
                current_height,
            )
        return True

    def _publish_wallet_identity(self) -> None:
        if self.wallet_address is None:
            return
        self.write_shared_state(
            f"{self.agent_id}_user_info.json",
            {
                "agent_id": self.agent_id,
                "wallet_address": self.wallet_address,
                "timestamp": time.time(),
                "agent_type": "regular_user",
            },
        )

    def _resolved_destination(self) -> str:
        configured = self.destination.strip()
        if configured and not configured.startswith("SHADOW_"):
            return configured
        return self._wallet_address_value()

    def _resolved_refund_address(self, attr_name: str) -> str:
        configured = str(self.attributes.get(attr_name, self.destination)).strip()
        if configured and not configured.startswith("SHADOW_"):
            return configured
        return self._wallet_address_value()

    @staticmethod
    def _optional_arg(flag: str, value: Any) -> list[str]:
        text = str(value).strip()
        if not text:
            return []
        return [flag, text]

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

    @staticmethod
    def _is_retryable_error(exc: Exception, *markers: str) -> bool:
        message = str(exc)
        return any(marker in message for marker in markers)


def main() -> None:
    parser = XmrWowCliAgent.create_argument_parser(
        "XMR/WOW CLI-driven agent for Monerosim"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    agent = XmrWowCliAgent(
        agent_id=args.id,
        shared_dir=args.shared_dir,
        daemon_rpc_port=args.daemon_rpc_port,
        wallet_rpc_port=args.wallet_rpc_port,
        p2p_port=args.p2p_port,
        rpc_host=args.rpc_host,
        log_level=args.log_level,
        attributes=args.attributes,
    )
    agent.run()


if __name__ == "__main__":
    main()
