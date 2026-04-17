#!/usr/bin/env python3
"""
Shadow/monerosim agent driving the real xmr-wow CLI with sharechain
transport dispatch (--transport sharechain --node-url <url>) and the
--proof-harness test mode.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib import request as urlrequest

# Retry-classifier marker for the CLI's "wait for counterparty to publish" error.
# Source of truth: crates/xmr-wow-client/src/main.rs:666-670 and :877-881, both
# formatted as:
#     "No message from counterparty yet under coord ID {hex}. Re-run when counterparty has published."
# This single substring covers all coordination wait states (Init, Response,
# AdaptorPreSig, ClaimProof) because the CLI uses the same error text for every
# state: the state name lives only in the CoordMessage payload, not in the
# human-readable error. Collapsed here to prevent future drift.
COORD_WAIT_RETRY_PATTERN = "No message from counterparty yet under coord ID"

try:
    from .base_agent import BaseAgent
except ImportError:
    import argparse

    class BaseAgent:  # type: ignore[no-redef]
        def __init__(self, agent_id: str, **kwargs: Any) -> None:
            self.agent_id = agent_id
            self.running = True
            self.rpc_host = str(kwargs.get("rpc_host", "127.0.0.1"))
            self.daemon_rpc_port = kwargs.get("daemon_rpc_port")
            self.wallet_rpc_port = kwargs.get("wallet_rpc_port")
            self.p2p_port = kwargs.get("p2p_port")
            self.log_level = str(kwargs.get("log_level", "INFO"))
            self.logger = logging.getLogger(f"{self.__class__.__name__}[{agent_id}]")
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
            # Shadow wrappers may pass through network selectors for the local
            # WOW toolchain; the agent derives network mode from attributes.
            parser.add_argument("--mainnet", action="store_true")
            parser.add_argument("--testnet", action="store_true")
            parser.add_argument("--stagenet", action="store_true")
            parser.add_argument("--regtest", action="store_true")
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
            time.sleep(max(duration, 0.0))


class XmrWowSharechainAgent(BaseAgent):
    STATE_WAIT_COORD_ID = "wait_coord_id"   # Bob only: poll for Alice's swap_id in COORD_FILE
    STATE_BOOTSTRAP = "bootstrap"
    STATE_WAIT_ACCEPT = "wait_accept"
    STATE_WAIT_IMPORT = "wait_import"
    STATE_LOCK = "lock"
    STATE_WAIT_CLAIM = "wait_claim"
    STATE_DONE = "done"

    # Shared coord-file name for Alice->Bob swap_id handoff (init-bob --swap-id)
    COORD_FILE = "xmr_wow_sharechain_coord.json"

    RESULT_FILE_PREFIX = "xmr_wow_sharechain_result"

    def __init__(self, agent_id: str, **kwargs: Any) -> None:
        super().__init__(agent_id=agent_id, **kwargs)
        self.state = self.STATE_BOOTSTRAP
        self.role = "alice"
        self.counterparty = ""
        self.binary = "target/release/xmr-wow"
        self.node_binary = "target/release/xmr-wow-node"
        self.password = "shadow-test"
        self.db = ""
        self.swap_id: Optional[str] = None
        self.offer_id: Optional[str] = None
        self.bilateral_topic: Optional[str] = None
        self.node_rpc_port = 18091
        self.node_p2p_port = 37891
        self.node_peers: List[str] = []
        self.node_process: Optional[subprocess.Popen[str]] = None
        self.node_stdout_handle: Optional[Any] = None
        self.node_stderr_handle: Optional[Any] = None
        self.xmr_daemon = "http://127.0.0.1:38081"
        self.wow_daemon = "http://127.0.0.1:34568"
        self.wallet_name = f"{agent_id}_wallet"
        self.wallet_address: Optional[str] = None
        self.wallet_mnemonic_cache: Optional[str] = None
        self.wallet_address_cache: Optional[str] = None
        self.generated_wow_destination: Optional[str] = None
        self.wow_local_daemon = False
        self.wow_daemon_binary = "wownerod"
        self.wow_wallet_binary = "wownero-wallet-rpc"
        self.wow_network = "testnet"
        self.wow_keep_fakechain = True
        self.wow_offline = True
        self.wow_fixed_difficulty = 1
        self.wow_bootstrap_fixed_difficulty = 1
        self.wow_daemon_host = "127.0.0.1"
        self.wow_daemon_port = 34568
        self.wow_p2p_port = 34567
        self.wow_wallet_rpc_port = 34569
        self.wow_wallet_name = f"{agent_id}_wow_wallet"
        self.wow_wallet_address: Optional[str] = None
        self.wow_wallet_mnemonic_cache: Optional[str] = None
        self.wow_wallet_address_cache: Optional[str] = None
        self.wow_retry_mining_wallet_name = f"{agent_id}_wow_retry_miner"
        self.wow_retry_mining_address: Optional[str] = None
        self.wow_retry_mining_spend_key_hex: str = ""
        self.wow_generate_blocks = 0
        self.wow_spend_key_hex: str = ""
        self.wow_background_mining = False
        self.wow_mining_burst_seconds = 0.5
        self.wow_confirmation_mining_interval_secs = 2.0
        self.wow_bootstrap_poll_interval_secs = 0.1
        self.wow_bounded_mining_poll_interval_secs = 0.005
        self.wow_retry_block_burst = 1
        # Convert oversized one-block bursts into only a few skipped retries,
        # not a one-for-one block credit that can starve height advancement.
        self.wow_retry_credit_cap = 4
        self.xmr_retry_block_burst = 3
        self.wow_credit_deferral_sleep_secs = 1.0
        self.wow_mining_timer: Optional[threading.Timer] = None
        self.cli_timeout = 1800
        self.vts_squarings_per_second = ""
        self.vts_modulus_bits = ""
        self.wow_daemon_process: Optional[subprocess.Popen[str]] = None
        self.wow_daemon_stdout_handle: Optional[Any] = None
        self.wow_daemon_stderr_handle: Optional[Any] = None
        self.wow_wallet_process: Optional[subprocess.Popen[str]] = None
        self.wow_wallet_stdout_handle: Optional[Any] = None
        self.wow_wallet_stderr_handle: Optional[Any] = None
        self.destination = ""
        self.alice_xmr_locked = False
        # Bob-side flag: set once Bob's exchange-pre-sig has successfully
        # received Alice's AdaptorPreSig from the sharechain. Before this
        # flag is set, Bob's claim retry loop does NOT mine WOW blocks
        # (there is nothing in the WOW mempool that needs confirming and
        # the burst-mining cost would just flood the log). After the flag
        # is set, Bob knows Alice is about to publish her claim-wow sweep
        # tx and must mine to advance the WOW chain so that tx confirms.
        self.bob_has_alice_presig = False
        self.pending_wow_lock_tx_hash: Optional[str] = None
        self.wow_retry_block_credit = 0
        self.last_wow_lock_attempt_height: Optional[int] = None
        self.lock_step_retry_delay_secs: Optional[float] = None
        self.done_result_recorded = False
        self.post_completion_grace_deadline: Optional[float] = None
        self.post_completion_grace_period_secs = 600.0

    def _shared_wallet_dir(self, wallet_name: str) -> Path:
        return self.shared_dir / wallet_name

    def _clear_directory_contents(self, path: Path, label: str) -> None:
        path.mkdir(parents=True, exist_ok=True)
        removed_any = False
        for child in path.iterdir():
            removed_any = True
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                try:
                    child.unlink()
                except FileNotFoundError:
                    pass
        if removed_any:
            self.logger.info("cleared stale %s contents: %s", label, path)

    def _remove_stale_path(self, path: Path, label: str) -> None:
        if path.is_dir():
            self.logger.info("removing stale %s: %s", label, path)
            shutil.rmtree(path, ignore_errors=True)
            return
        if path.exists():
            self.logger.info("removing stale %s: %s", label, path)
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _clear_sharechain_run_artifacts(self) -> None:
        result_path = self.shared_dir / f"{self.RESULT_FILE_PREFIX}_{self.agent_id}.json"
        result_lock_path = self.shared_dir / f"{self.RESULT_FILE_PREFIX}_{self.agent_id}.lock"
        self._remove_stale_path(result_path, "sharechain result file")
        self._remove_stale_path(result_lock_path, "sharechain result lock")

        if self.role == "alice":
            coord_path = self.shared_dir / self.COORD_FILE
            coord_lock_path = self.shared_dir / f"{self.COORD_FILE}.lock"
            self._remove_stale_path(coord_path, "sharechain coord file")
            self._remove_stale_path(coord_lock_path, "sharechain coord lock")

    def _counterparty_result_path(self) -> Path:
        return self.shared_dir / f"{self.RESULT_FILE_PREFIX}_{self.counterparty}.json"

    def _hold_sharechain_until_counterparty_result(self) -> bool:
        if self.role != "alice" or not self.counterparty:
            return False

        result_path = self._counterparty_result_path()
        if result_path.exists():
            self.logger.info(
                "alice observed Bob result file at %s; stopping local sharechain node",
                result_path,
            )
            return False

        if self.post_completion_grace_deadline is None:
            self.post_completion_grace_deadline = (
                time.monotonic() + self.post_completion_grace_period_secs
            )
            self.logger.info(
                "alice keeping sharechain node alive for up to %.0fs while waiting for Bob result file %s",
                self.post_completion_grace_period_secs,
                result_path,
            )
            return True

        if time.monotonic() < self.post_completion_grace_deadline:
            return True

        self.logger.warning(
            "alice post-claim grace period expired without Bob result file %s; stopping local sharechain node",
            result_path,
        )
        return False

    def _setup_agent(self) -> None:
        self.role = str(self.attributes.get("role", "alice"))
        self.counterparty = str(self.attributes.get("counterparty", ""))
        self.binary = self._resolve_repo_path(str(self.attributes.get("binary", self.binary)))
        self.node_binary = self._resolve_repo_path(str(self.attributes.get("node_binary", self.node_binary)))
        self.password = str(self.attributes.get("password", self.password))
        self.db = str(self.attributes.get("db", f"/tmp/{self.agent_id}-sharechain.db"))
        if os.path.exists(self.db):
            self.logger.info("removing stale swap db: %s", self.db)
            os.remove(self.db)
        self.node_rpc_port = int(self.attributes.get("node_rpc_port", "18091"))
        self.node_p2p_port = int(self.attributes.get("node_p2p_port", "37891"))
        # Optional override to point this agent's CLI at a DIFFERENT xmr-wow-node
        # (not its locally-spawned one). xmr-wow-node has no P2P gossip, so all
        # agents must share a single node. Empty/unset means "use local".
        self.node_url_override = str(
            self.attributes.get("node_url_override", "")
        ).strip() or None
        parsed_node_peers = self._parse_node_peers(self.attributes.get("node_peers", []))
        self.node_peers = [str(peer) for peer in parsed_node_peers]
        self.node_peers = [self._resolve_peer_address(peer) for peer in self.node_peers]
        default_daemon = self._default_daemon_url()
        self.xmr_daemon = str(self.attributes.get("xmr_daemon", default_daemon))
        self.wallet_name = str(self.attributes.get("wallet_name", self.wallet_name))
        self.wow_local_daemon = self._coerce_bool(
            self.attributes.get("wow_local_daemon", self.role == "bob")
        )
        self.wow_daemon_binary = self._resolve_repo_path(
            str(self.attributes.get("wow_daemon_binary", self.wow_daemon_binary))
        )
        self.wow_wallet_binary = self._resolve_repo_path(
            str(self.attributes.get("wow_wallet_binary", self.wow_wallet_binary))
        )
        self.wow_network = str(self.attributes.get("wow_network", self.wow_network)).strip().lower()
        self.wow_keep_fakechain = self._coerce_bool(
            self.attributes.get("wow_keep_fakechain", self.wow_keep_fakechain)
        )
        self.wow_offline = self._coerce_bool(
            self.attributes.get("wow_offline", self.wow_offline)
        )
        self.wow_fixed_difficulty = int(
            self.attributes.get("wow_fixed_difficulty", self.wow_fixed_difficulty)
        )
        self.wow_bootstrap_fixed_difficulty = int(
            self.attributes.get(
                "wow_bootstrap_fixed_difficulty",
                self.wow_fixed_difficulty,
            )
        )
        self.wow_daemon_port = int(self.attributes.get("wow_daemon_port", self.wow_daemon_port))
        self.wow_p2p_port = int(self.attributes.get("wow_p2p_port", self.wow_p2p_port))
        self.wow_wallet_rpc_port = int(
            self.attributes.get("wow_wallet_rpc_port", self.wow_wallet_rpc_port)
        )
        self.wow_wallet_name = str(
            self.attributes.get("wow_wallet_name", self.wow_wallet_name)
        )
        self.wow_generate_blocks = int(
            self.attributes.get("wow_generate_blocks", self.wow_generate_blocks)
        )
        self.wow_mining_burst_seconds = float(
            self.attributes.get(
                "wow_mining_burst_seconds",
                self.wow_mining_burst_seconds,
            )
        )
        self.wow_confirmation_mining_interval_secs = float(
            self.attributes.get(
                "wow_confirmation_mining_interval_secs",
                self.wow_confirmation_mining_interval_secs,
            )
        )
        self.wow_bounded_mining_poll_interval_secs = float(
            self.attributes.get(
                "wow_bounded_mining_poll_interval_secs",
                self.wow_bounded_mining_poll_interval_secs,
            )
        )
        self.wow_retry_block_burst = int(
            self.attributes.get("wow_retry_block_burst", self.wow_retry_block_burst)
        )
        self.wow_retry_credit_cap = int(
            self.attributes.get("wow_retry_credit_cap", self.wow_retry_credit_cap)
        )
        self.xmr_retry_block_burst = int(
            self.attributes.get("xmr_retry_block_burst", self.xmr_retry_block_burst)
        )
        self.wow_credit_deferral_sleep_secs = float(
            self.attributes.get(
                "wow_credit_deferral_sleep_secs",
                self.wow_credit_deferral_sleep_secs,
            )
        )
        self.cli_timeout = int(
            self.attributes.get("cli_timeout", self.cli_timeout)
        )
        self.vts_squarings_per_second = str(
            self.attributes.get("vts_squarings_per_second", "")
        ).strip()
        self.vts_modulus_bits = str(
            self.attributes.get("vts_modulus_bits", "")
        ).strip()
        raw_wow_host = str(
            self.attributes.get(
                "wow_daemon_host",
                self.agent_id if self.wow_local_daemon else self.counterparty or self.rpc_host,
            )
        ).strip()
        self.wow_daemon_host = self._resolve_host(raw_wow_host) if raw_wow_host else self.rpc_host
        self.wow_daemon = str(
            self.attributes.get(
                "wow_daemon",
                f"http://{self.wow_daemon_host}:{self.wow_daemon_port}",
            )
        )
        self.destination = str(self.attributes.get("destination", ""))
        # Monerosim resets daemon data between reruns but leaves
        # /tmp/monerosim_shared intact. Clean simulation-local wallet and
        # handoff artifacts here so interrupted runs cannot poison retries.
        self._clear_sharechain_run_artifacts()
        wallet_dir = self._shared_wallet_dir(self.wallet_name)
        self._clear_directory_contents(wallet_dir, "XMR wallet dir")
        self._ensure_wallet_ready()
        self._publish_wallet_identity()
        self.logger.info(
            "sharechain node config rpc=%s p2p=%s peers=%s wallet=%s address=%s",
            self.node_rpc_port,
            self.node_p2p_port,
            self.node_peers,
            self.wallet_name,
            self.wallet_address,
        )
        self._start_sharechain_node()
        if self.wow_local_daemon:
            self._start_wow_runtime()
        # Bob starts by polling COORD_FILE for Alice's swap_id before init-bob
        if self.role == "bob":
            self.state = self.STATE_WAIT_COORD_ID

    def run_iteration(self) -> float:
        try:
            # Bob waits for Alice's swap_id written to COORD_FILE after init-alice
            if self.state == self.STATE_WAIT_COORD_ID:
                if not self._wait_for_coord_id():
                    return 10.0
                self.state = self.STATE_BOOTSTRAP
                return 1.0

            if self.state == self.STATE_BOOTSTRAP:
                if self.role == "alice":
                    if not self._run_init_alice():
                        return 5.0
                    # Alice writes swap_id to COORD_FILE for Bob (done inside _run_init_alice)
                    self.state = self.STATE_WAIT_IMPORT
                else:
                    if not self._run_init_bob():
                        return 5.0
                    self.state = self.STATE_WAIT_IMPORT
                return 5.0

            if self.state == self.STATE_WAIT_IMPORT:
                if self._import_or_init_bob():
                    self.state = self.STATE_LOCK
                    return 5.0
                return 10.0

            if self.state == self.STATE_LOCK:
                if self._perform_lock_step():
                    self.lock_step_retry_delay_secs = None
                    self.state = self.STATE_WAIT_CLAIM
                    return 10.0
                retry_delay = self.lock_step_retry_delay_secs
                self.lock_step_retry_delay_secs = None
                if retry_delay is not None:
                    return max(retry_delay, 0.0)
                return 10.0

            if self.state == self.STATE_WAIT_CLAIM:
                if self._claim_if_ready():
                    self.state = self.STATE_DONE
                    if not self.done_result_recorded:
                        self._record_result({
                            "status": "claimed",
                            "swap_id": self.swap_id,
                            "role": self.role,
                            "transport": "sharechain",
                            "note": "Shadow/monerosim run",
                        })
                        self.done_result_recorded = True
                    if self._hold_sharechain_until_counterparty_result():
                        return 15.0
                    self.running = False
                    return 0.0
                return 15.0

            if self.state == self.STATE_DONE:
                if (
                    self.done_result_recorded
                    and self._hold_sharechain_until_counterparty_result()
                ):
                    return 15.0
                self.running = False
                return 0.0

            return 60.0
        except Exception as exc:  # pragma: no cover - Shadow-only path
            self.logger.exception("sharechain agent failed: %s", exc)
            self._record_result({"status": "failed", "error": str(exc)})
            self.running = False
            self.state = self.STATE_DONE
            return 60.0

    def _start_sharechain_node(self) -> None:
        cmd = [
            self.node_binary,
            "--rpc-port", str(self.node_rpc_port),
            "--p2p-port", str(self.node_p2p_port),
            "--min-difficulty", "1",
        ]
        for peer in self.node_peers:
            cmd.extend(["--peer", peer])
        self.logger.info("starting sharechain node: %s", " ".join(cmd))
        # Write xmr-wow-node logs to per-host /tmp (preserved in Shadow archive).
        node_stdout_path = f"/tmp/{self.agent_id}-xmr-wow-node.stdout.log"
        node_stderr_path = f"/tmp/{self.agent_id}-xmr-wow-node.stderr.log"
        self.node_stdout_handle = open(node_stdout_path, "a", encoding="utf-8")
        self.node_stderr_handle = open(node_stderr_path, "a", encoding="utf-8")
        self.logger.info(
            "sharechain node stdout=%s stderr=%s",
            node_stdout_path,
            node_stderr_path,
        )
        # Enable verbose tracing so node startup and port binding are visible.
        node_env = {
            **os.environ,
            "RUST_LOG": "info,xmr_wow_node=trace,xmr_wow_sharechain=trace",
            "RUST_BACKTRACE": "full",
        }
        self.node_process = subprocess.Popen(
            cmd,
            stdout=self.node_stdout_handle,
            stderr=self.node_stderr_handle,
            env=node_env,
        )

        # Poll the node's RPC TCP listener until it accepts connections, with
        # a 30-second budget, to confirm axum::serve() bound successfully.
        import socket as _socket  # local import to avoid polluting module namespace
        ready_deadline = time.monotonic() + 30.0
        ready_attempts = 0
        last_err: Optional[Exception] = None
        while time.monotonic() < ready_deadline:
            ready_attempts += 1
            # Check if the child process is still alive: a dead process will
            # never become ready, so fail fast.
            if self.node_process.poll() is not None:
                raise RuntimeError(
                    f"xmr-wow-node exited before becoming ready (exit code "
                    f"{self.node_process.returncode}); stderr path: "
                    f"{node_stderr_path}"
                )
            try:
                with _socket.create_connection(
                    ("127.0.0.1", self.node_rpc_port),
                    timeout=1.0,
                ):
                    self.logger.info(
                        "sharechain node ready after %d attempts (rpc_port=%d)",
                        ready_attempts,
                        self.node_rpc_port,
                    )
                    break
            except (ConnectionRefusedError, OSError) as exc:
                last_err = exc
                time.sleep(0.5)
        else:
            raise RuntimeError(
                f"xmr-wow-node RPC not ready on 127.0.0.1:{self.node_rpc_port} "
                f"after 30s ({ready_attempts} attempts, last err: {last_err}); "
                f"stderr path: {node_stderr_path}"
            )

    def _cleanup_agent(self) -> None:
        self._stop_wow_background_mining()
        self._stop_process(
            self.node_process,
            self.node_stdout_handle,
            self.node_stderr_handle,
        )
        self._stop_process(
            self.wow_wallet_process,
            self.wow_wallet_stdout_handle,
            self.wow_wallet_stderr_handle,
        )
        self._stop_process(
            self.wow_daemon_process,
            self.wow_daemon_stdout_handle,
            self.wow_daemon_stderr_handle,
        )

    def _bootstrap(self) -> bool:
        if self.role == "alice":
            output = self._run_cli([
                "publish-offer",
                "--node", self._node_url(),
                "--maker", self.agent_id,
                "--amount-xmr", str(self.attributes.get("amount_xmr", "1000000000000")),
                "--amount-wow", str(self.attributes.get("amount_wow", "500000000000")),
                "--expires-in-secs", str(self.attributes.get("offer_ttl_secs", "900")),
                "--note", "shadow-sharechain",
            ])
            self.offer_id = self._extract_required(r"Offer ID:\s*([0-9a-fA-F]{64})", output)
            return True

        output = self._run_cli([
            "list-offers",
            "--node", self._node_url(),
        ])
        match = re.search(r"Offer ID:\s*([0-9a-fA-F]{64})", output)
        if match is None:
            self.logger.info("no sharechain offers visible yet; retrying bootstrap")
            return False
        self.offer_id = match.group(1)
        accept_output = self._run_cli([
            "accept-offer",
            "--node", self._node_url(),
            "--offer-id", self.offer_id,
            "--taker", self.agent_id,
        ])
        self.bilateral_topic = self._extract_required(
            r"Bilateral Topic:\s*(\S+)",
            accept_output,
        )
        return True

    def _discover_acceptance(self) -> bool:
        if self.offer_id is None:
            return False
        output = self._run_cli([
            "show-offer",
            "--node", self._node_url(),
            "--offer-id", self.offer_id,
        ])
        if "Status:        Accepted" not in output:
            return False
        self.bilateral_topic = self._extract_required(r"Bilateral Topic:\s*(\S+)", output)
        return True

    def _wait_for_coord_id(self) -> bool:
        """Bob polls COORD_FILE for Alice's swap_id written after init-alice."""
        data = self.read_shared_state(self.COORD_FILE)
        if data is None or "swap_id" not in data:
            self.logger.debug("bob waiting for Alice COORD_FILE with swap_id...")
            return False
        self.swap_id = str(data["swap_id"])
        self.logger.info("bob received Alice swap_id from COORD_FILE: %s", self.swap_id)
        return True

    def _run_init_alice(self) -> bool:
        try:
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
        except RuntimeError as exc:
            if self._is_retryable_error(exc, "RPC connection failed", "wallet RPC"):
                self.logger.info("alice init waiting for daemon or wallet RPC availability")
                return False
            raise
        self.swap_id = self._extract_swap_id(output)
        # Write swap_id to COORD_FILE so Bob can read it for --swap-id in init-bob
        self.write_shared_state(
            self.COORD_FILE,
            {
                "swap_id": self.swap_id,
                "sender": "alice",
                "created_at": time.time(),
            },
        )
        self.logger.info("alice wrote swap_id to COORD_FILE: %s", self.swap_id)
        return True

    def _run_init_bob(self) -> bool:
        # Read COORD_FILE to get Alice's swap_id for init-bob --swap-id
        coord_payload = self.read_shared_state(self.COORD_FILE)
        if coord_payload is None or "swap_id" not in coord_payload:
            self.logger.info("bob waiting for alice COORD_FILE with swap_id")
            return False
        alice_swap_id = coord_payload["swap_id"]
        try:
            output = self._run_cli([
                "init-bob",
                "--bob-refund-address", self._resolved_refund_address("bob_refund_address"),
                "--swap-id", alice_swap_id,
            ])
        except RuntimeError as exc:
            if self._is_retryable_error(exc, COORD_WAIT_RETRY_PATTERN):
                self.logger.info("bob waiting for sharechain Init message")
                return False
            if self._is_retryable_error(exc, "wallet RPC"):
                self.logger.info("bob init waiting for wallet RPC availability")
                return False
            raise
        self.swap_id = self._extract_swap_id(output)
        self.logger.info("bob swap_id after init-bob: %s", self.swap_id)
        return True

    def _import_or_init_bob(self) -> bool:
        if self.role == "bob":
            if self.swap_id is not None:
                return True
            return self._run_init_bob()

        if self.swap_id is None:
            return False
        try:
            output = self._run_cli([
                "import",
                "--swap-id", self.swap_id,
            ])
            self.swap_id = self._extract_swap_id(output)
            self.logger.info("alice swap_id after import: %s", self.swap_id)
        except RuntimeError as exc:
            if self._is_retryable_error(exc, COORD_WAIT_RETRY_PATTERN):
                self.logger.info("alice waiting for sharechain Response message")
                return False
            latest = self._latest_swap_record_from_db()
            if self._is_retryable_error(exc, "invalid state transition") and latest is not None:
                latest_swap_id, latest_phase = latest
                if latest_phase in {
                    "joint_address",
                    "wow_locked",
                    "xmr_locked",
                    "complete",
                    "refunded",
                }:
                    self.swap_id = latest_swap_id
                    self.logger.info(
                        "alice import already materialized in db as phase=%s swap_id=%s; continuing",
                        latest_phase,
                        latest_swap_id,
                    )
                    return True
            raise
        return True

    def _lock_wow_with_retry(self) -> bool:
        """Bounded retry loop around Bob's lock-wow step.

        Delegates to the Bob branch of _perform_lock_step, which already
        encodes the WOW balance wait, discrete block burst, and retry logic
        Named explicitly so the orchestration
        helper survives tool-level existence checks.
        """
        if self.role != "bob":
            return False
        return self._perform_lock_step()

    def _perform_lock_step(self) -> bool:
        if self.swap_id is None:
            raise RuntimeError("lock step requires swap_id")
        self.lock_step_retry_delay_secs = None
        self.logger.info("%s entering lock step with swap_id=%s", self.role, self.swap_id)

        if self.role == "bob":
            required_amount = int(self.attributes.get("amount_wow", "500000000000"))
            wow_balance, wow_unlocked = self._wow_wallet_balances()
            if wow_unlocked < required_amount:
                self.logger.info(
                    "bob waiting for WOW spendable balance unlocked=%s total=%s required=%s",
                    wow_unlocked,
                    wow_balance,
                    required_amount,
                )
                return False

            # Ensure the WOW chain has enough mature RCT outputs for
            # ring-signature decoy selection before invoking lock-wow. The coinbase
            # outputs mined during the bootstrap need CRYPTONOTE_MINED_MONEY_
            # UNLOCK_WINDOW (60 blocks in Wownero, per deps/wownero-simnet/)
            # to become spendable AND contribute to the decoy pool. At
            # bootstrap height 1000, we want tip height >= 1000 + 60 = 1060
            # before lock-wow. Additionally, Wownero's ringsize is 22 (vs
            # Monero's 16), so the decoy pool needs more distinct RCT outputs
            # than a raw unlock-window count might suggest. Target a safety
            # margin: tip height >= wow_generate_blocks + 128 (double the
            # unlock window plus a ring-size buffer).
            if self.wow_generate_blocks > 0:
                try:
                    height_resp = self._daemon_json_rpc(
                        self.wow_daemon, "get_block_count"
                    )
                    current_height = int(height_resp.get("count", 0))
                except Exception as exc:
                    self.logger.info(
                        "bob could not fetch WOW height (%s); retrying", exc
                    )
                    return False
                maturity_target = self.wow_generate_blocks + 128
                if current_height < maturity_target:
                    missing_blocks = maturity_target - current_height
                    self.logger.info(
                        "bob mining %d more WOW blocks for decoy-selection maturity (current=%d target=%d)",
                        missing_blocks,
                        current_height,
                        maturity_target,
                    )
                    # Bounded burst: mine in groups of wow_retry_block_burst
                    # until we reach target or hit a hard cap of 16 bursts per
                    # retry iteration (to protect Shadow's sim ratio). The
                    # outer retry loop will re-enter on the next tick.
                    burst_cap = 16
                    bursts = 0
                    while current_height < maturity_target and bursts < burst_cap:
                        self._generate_wow_blocks(
                            max(self.wow_retry_block_burst, 1)
                        )
                        bursts += 1
                        try:
                            height_resp = self._daemon_json_rpc(
                                self.wow_daemon, "get_block_count"
                            )
                            current_height = int(height_resp.get("count", 0))
                        except Exception as exc:
                            self.logger.info(
                                "bob WOW height fetch failed mid-burst (%s); yielding",
                                exc,
                            )
                            return False
                    if current_height < maturity_target:
                        self.logger.info(
                            "bob still waiting for WOW maturity (current=%d target=%d after %d bursts)",
                            current_height,
                            maturity_target,
                            bursts,
                        )
                        return False

            lock_wow_args = [
                "lock-wow",
                "--swap-id", self.swap_id,
                "--wow-daemon", self.wow_daemon,
                "--mnemonic", self._wow_wallet_mnemonic(),
            ]
            pending_lock_tx_hash = self.pending_wow_lock_tx_hash
            if pending_lock_tx_hash:
                if self._wow_tx_confirmed(pending_lock_tx_hash):
                    self.logger.info(
                        "bob pending WOW lock tx %s is already confirmed; clearing confirmation resume hint",
                        pending_lock_tx_hash,
                    )
                    self.pending_wow_lock_tx_hash = None
                    pending_lock_tx_hash = None
                else:
                    self.logger.info(
                        "bob mining WOW until pending lock tx %s confirms before re-entering lock-wow",
                        pending_lock_tx_hash,
                    )
                    mined_height = self._generate_wow_blocks(
                        max(self.wow_retry_block_burst, 1)
                    )
                    if mined_height < 0:
                        self.logger.info(
                            "bob waiting for WOW bounded mining burst while pending lock tx %s remains unconfirmed",
                            pending_lock_tx_hash,
                        )
                        return False
                    if self._wow_tx_confirmed(pending_lock_tx_hash):
                        self.logger.info(
                            "bob pending WOW lock tx %s confirmed after bounded retry mining",
                            pending_lock_tx_hash,
                        )
                        self.pending_wow_lock_tx_hash = None
                        pending_lock_tx_hash = None
                    else:
                        self.logger.info(
                            "bob waiting for pending WOW lock tx %s to confirm",
                            pending_lock_tx_hash,
                        )
                        return False
            try:
                # Keep the wallet-settle preflight, but use the simpler
                # subprocess path for fresh pre-broadcast lock-wow attempts.
                # Pending lock txs are mined to confirmation out-of-process
                # above so retries do
                # not consume the already-read refund artifact or attempt a
                # second lock while the first tx is still in flight.
                preflight_height = self._current_wow_height()
                requested_burst = max(self.wow_retry_block_burst, 0)
                if requested_burst > 0:
                    credit_used = min(self.wow_retry_block_credit, requested_burst)
                    if credit_used > 0:
                        self.wow_retry_block_credit -= credit_used
                        self.logger.info(
                            "bob consuming %s retry slot(s) of prior WOW overshoot throttle; remaining retry credit=%s",
                            credit_used,
                            self.wow_retry_block_credit,
                        )
                    burst_to_mine = requested_burst - credit_used
                    if burst_to_mine > 0:
                        preflight_start_height = preflight_height
                        preflight_height = self._generate_wow_blocks(burst_to_mine)
                        if preflight_height < 0:
                            self.logger.info(
                                "bob waiting for WOW bounded mining burst to complete cleanly before lock-wow"
                            )
                            return False
                        actual_advanced = max(
                            preflight_height - preflight_start_height,
                            0,
                        )
                        extra_credit = max(actual_advanced - burst_to_mine, 0)
                        if extra_credit > 0:
                            uncapped_credit = self.wow_retry_block_credit + extra_credit
                            retry_credit_cap = max(self.wow_retry_credit_cap, 0)
                            self.wow_retry_block_credit = min(
                                uncapped_credit,
                                retry_credit_cap,
                            )
                            if self.wow_retry_block_credit < uncapped_credit:
                                self.logger.info(
                                    "bob WOW retry burst overshot requested %s block(s) by %s "
                                    "(start=%s final=%s); capping retry credit to %s (uncapped=%s)",
                                    burst_to_mine,
                                    extra_credit,
                                    preflight_start_height,
                                    preflight_height,
                                    self.wow_retry_block_credit,
                                    uncapped_credit,
                                )
                            else:
                                self.logger.info(
                                    "bob WOW retry burst overshot requested %s block(s) by %s "
                                    "(start=%s final=%s); carrying retry credit=%s",
                                    burst_to_mine,
                                    extra_credit,
                                    preflight_start_height,
                                    preflight_height,
                                    self.wow_retry_block_credit,
                                )
                    else:
                        self.logger.info(
                            "bob skipping WOW retry burst at daemon height %s because retained overshoot throttle already covers this retry",
                            preflight_height,
                        )
                        if (
                            credit_used > 0
                            and self.last_wow_lock_attempt_height == preflight_height
                        ):
                            if self.wow_retry_block_credit > 0:
                                self.logger.info(
                                    "bob collapsing remaining retained WOW retry credit from %s to 0 at daemon height %s so the next retry returns to a fresh-height attempt",
                                    self.wow_retry_block_credit,
                                    preflight_height,
                                )
                                self.wow_retry_block_credit = 0
                            self.lock_step_retry_delay_secs = max(
                                self.wow_credit_deferral_sleep_secs,
                                0.0,
                            )
                            self.logger.info(
                                "bob deferring same-height lock-wow retry at daemon height %s while spending retained overshoot throttle; remaining retry credit=%s next_retry_in=%ss",
                                preflight_height,
                                self.wow_retry_block_credit,
                                self.lock_step_retry_delay_secs,
                            )
                            return False
                if not self._wait_for_wow_wallet_refresh_to_settle(
                    label=f"bob lock-wow preflight at daemon height {preflight_height}",
                    target_height=preflight_height,
                ):
                    self.logger.info(
                        "bob waiting for WOW wallet refresh to settle before lock-wow"
                    )
                    return False
                self.last_wow_lock_attempt_height = preflight_height
                self._run_cli(lock_wow_args, timeout=self.cli_timeout)
            except RuntimeError as exc:
                pending_tx_from_error = self._remember_pending_wow_lock_tx(str(exc))
                if self._is_retryable_error(
                    exc,
                    COORD_WAIT_RETRY_PATTERN,
                    "RPC connection failed",
                    "wallet RPC",
                    "no outputs found at joint address",
                    "insufficient funds",
                    "confirmation timeout",
                    # "decoy selection round limit" is recoverable by mining
                    # more blocks so additional mature coinbase RCT outputs
                    # become available. The retry loop's _generate_wow_blocks
                    # burst + maturity-wait gate advances the chain each cycle.
                    "decoy selection",
                    "hit decoy selection round limit",
                    "transaction building failed",
                ):
                    if pending_tx_from_error:
                        self.logger.info(
                            "bob waiting for pending WOW lock tx %s to confirm",
                            pending_tx_from_error,
                        )
                    else:
                        self.logger.info(
                            "bob waiting for daemon, wallet RPC, spendable WOW outputs, decoy pool depth, or lock-wow confirmation"
                        )
                    return False
                raise
            self.pending_wow_lock_tx_hash = None
            self.wow_retry_block_credit = 0
            self.last_wow_lock_attempt_height = None
            return True

        # Alice must lock-xmr BEFORE exchange-pre-sig.  lock-xmr transitions
        # the swap state from JointAddress -> XmrLocked (and publishes Alice's
        # own AdaptorPreSig).  exchange-pre-sig requires XmrLocked to receive
        # Bob's AdaptorPreSig.
        if not self.alice_xmr_locked:
            required_amount = int(self.attributes.get("amount_xmr", "1000000000000"))
            xmr_balance, xmr_unlocked = self._wallet_balances()
            if xmr_unlocked < required_amount:
                # Continuous XMR funding can arrive faster than the Poisson
                # miner advances the chain, leaving Alice funded but locked.
                # Mine a few bounded bursts so the oldest incoming transfer
                # can age past Monero's spendable-height gate.
                if xmr_balance >= required_amount:
                    self.logger.info(
                        "alice funding is present but still locked; mining bounded XMR bursts to mature outputs"
                    )
                    burst_cap = 4
                    bursts = 0
                    while xmr_unlocked < required_amount and bursts < burst_cap:
                        mined_height = self._generate_xmr_blocks(
                            self.xmr_retry_block_burst
                        )
                        bursts += 1
                        if mined_height < 0:
                            break
                        xmr_balance, xmr_unlocked = self._wallet_balances()
                    if xmr_unlocked >= required_amount:
                        self.logger.info(
                            "alice XMR funding matured after %d bounded burst(s) unlocked=%s total=%s",
                            bursts,
                            xmr_unlocked,
                            xmr_balance,
                        )
                    else:
                        self.logger.info(
                            "alice XMR funding still locked after %d bounded burst(s) unlocked=%s total=%s required=%s",
                            bursts,
                            xmr_unlocked,
                            xmr_balance,
                            required_amount,
                        )
                self.logger.info(
                    "alice waiting for XMR spendable balance unlocked=%s total=%s required=%s",
                    xmr_unlocked,
                    xmr_balance,
                    required_amount,
                )
                return False
            try:
                self._run_cli([
                    "lock-xmr",
                    "--swap-id", self.swap_id,
                    "--xmr-daemon", self.xmr_daemon,
                    "--wow-daemon", self.wow_daemon,
                    "--mnemonic", self._wallet_mnemonic(),
                    ], timeout=self.cli_timeout)
                self.alice_xmr_locked = True
                self.logger.info("alice lock-xmr succeeded, state -> XmrLocked")
            except RuntimeError as exc:
                if self._is_retryable_error(
                    exc,
                    "WOW verification window is empty",
                    "no outputs found at joint address",
                    "insufficient funds",
                    "RPC connection failed",
                    "wallet RPC",
                    "Connection refused",
                ):
                    self.logger.info(
                        "alice waiting for Bob WOW lock confirmation or daemon/wallet RPC availability before lock-xmr"
                    )
                    return False
                raise

        try:
            self._run_cli([
                "exchange-pre-sig",
                "--swap-id", self.swap_id,
            ], timeout=self.cli_timeout)
        except RuntimeError as exc:
            if self._is_retryable_error(
                exc,
                COORD_WAIT_RETRY_PATTERN,
                "RPC connection failed",
            ):
                self.logger.info(
                    "alice waiting for Bob adaptor pre-signature on sharechain"
                )
                return False
            raise
        return True

    def _claim_if_ready(self) -> bool:
        if self.swap_id is None:
            return False

        if self.role == "bob":
            # Only mine WOW blocks AFTER Bob has received Alice's AdaptorPreSig.
            # Before that point there is nothing in the WOW mempool that
            # needs confirming (Bob's own lock-wow is already confirmed),
            # and mining every retry iteration would just flood the log.
            # Once Bob has Alice's pre-sig, Alice is about to broadcast her
            # claim-wow sweep tx; Bob's WOW daemon is the only node that
            # can mine, so Bob's retry loop becomes the confirmation-
            # advancement loop for Alice's in-flight sweep. Bob's claim-xmr
            # path also depends on Alice's XMR lock output aging past
            # Monero's 10-block spend lock, so once claim retries begin we
            # need bounded bursts on BOTH chains. Each retry iteration then
            # produces bounded WOW + XMR advancement and stops, giving
            # deterministic progress without the old unbounded start_mining
            # pattern.
            if self.bob_has_alice_presig:
                self._generate_wow_blocks(self.wow_retry_block_burst)
                self._generate_xmr_blocks(self.xmr_retry_block_burst)
            try:
                if not self.bob_has_alice_presig:
                    exchange_stdout = self._run_cli([
                        "exchange-pre-sig",
                        "--swap-id", self.swap_id,
                        ], timeout=self.cli_timeout)
                    if "Counterparty pre-signature verified" in exchange_stdout:
                        self.logger.info(
                            "bob received Alice's AdaptorPreSig; enabling WOW "
                            "confirmation mining for the claim phase"
                        )
                        self.bob_has_alice_presig = True
                else:
                    # Bob already stored Alice's AdaptorPreSig in an earlier
                    # claim iteration. Re-running exchange-pre-sig after Alice
                    # has moved on to publishing ClaimProof will read the wrong
                    # message type and fail, so retry claim-xmr directly.
                    self.logger.debug(
                        "bob already has Alice's AdaptorPreSig; skipping "
                        "exchange-pre-sig before claim-xmr retry"
                    )
                # Final Bob-side claim can block waiting for the XMR sweep
                # confirmation after Alice has already published ClaimProof.
                # Keep exact-block XMR mining running in the background so
                # the CLI sees its own confirmation instead of timing out
                # under Shadow's slow wall-clock pacing.
                self._run_cli_with_xmr_confirmation_mining([
                    "claim-xmr",
                    "--swap-id", self.swap_id,
                    "--xmr-daemon", self.xmr_daemon,
                    "--destination", self._resolved_destination(),
                    ], timeout=self.cli_timeout)
            except RuntimeError as exc:
                if self._is_retryable_error(
                    exc,
                    COORD_WAIT_RETRY_PATTERN,
                    "no spendable outputs at joint address yet",
                    "confirmation timeout",
                    "RPC connection failed",
                    "wallet RPC",
                ):
                    self.logger.info(
                        "bob waiting for claim prerequisites on the sharechain"
                    )
                    return False
                raise
            return True

        # Alice claim-wow retry path. Same throttle pattern as Bob: a discrete
        # burst per iteration instead of unbounded start_mining. Alice's
        # claim-wow needs the joint WOW output to mature, which is purely a
        # height-advancement requirement, so each retry advances the chain by
        # ``wow_retry_block_burst`` blocks and the polling loop sleep absorbs
        # the rest.
        self._generate_wow_blocks(self.wow_retry_block_burst)
        try:
            _, wow_base = self._latest_base_heights_from_db()
            self._run_cli([
                "claim-wow",
                "--swap-id", self.swap_id,
                "--wow-daemon", self.wow_daemon,
                "--destination", self._resolved_destination(),
                "--scan-from", str(wow_base) if wow_base is not None else "0",
            ], timeout=self.cli_timeout)
        except RuntimeError as exc:
            if self._is_retryable_error(
                exc,
                "no spendable outputs at joint address yet",
            ):
                self.logger.info(
                    "alice waiting for WOW joint output maturity before claim-wow"
                )
                return False
            if self._is_retryable_error(
                exc,
                COORD_WAIT_RETRY_PATTERN,
                "confirmation timeout",
                "RPC connection failed",
                "wallet RPC",
                ):
                self.logger.info("alice waiting for claim prerequisites or wallet RPC on the sharechain")
                return False
            raise
        return True

    def _node_url(self) -> str:
        # Honor node_url_override to let one agent point its CLI at another
        # agent's xmr-wow-node, so both agents share the same in-memory
        # coord_store. Empty/unset -> local loopback.
        if self.node_url_override:
            return self.node_url_override
        return f"http://127.0.0.1:{self.node_rpc_port}"

    def _start_wow_runtime(self) -> None:
        # Clean previous fakechain data so mining targets the current wallet's address.
        self._remove_stale_path(
            Path(f"/tmp/wownero-{self.agent_id}"),
            "WOW fakechain data dir",
        )
        wow_wallet_dir = self._shared_wallet_dir(self.wow_wallet_name)
        self._clear_directory_contents(wow_wallet_dir, "WOW wallet dir")
        bootstrap_difficulty = (
            self.wow_bootstrap_fixed_difficulty
            if self.wow_generate_blocks > 0
            else self.wow_fixed_difficulty
        )
        # Boot without spendkey first just to pull the wallet's spend key from RPC;
        # hardfork-18 mining requires the daemon to know it up front.
        self.logger.info("starting WOW daemon (no spendkey) to bootstrap wallet")
        self._start_wow_daemon(fixed_difficulty=bootstrap_difficulty)
        self._wait_for_daemon_rpc(self.wow_daemon, "WOW daemon")
        self._start_wow_wallet_rpc()
        self._wait_for_wallet_rpc(self._wow_wallet_rpc_url(), "WOW wallet RPC")
        self._ensure_wow_wallet_ready()
        spend_key_hex = self._query_wow_spend_key_hex()
        self.wow_spend_key_hex = spend_key_hex
        self.logger.info(
            "captured spend key (%d chars); restarting daemon with --spendkey", len(spend_key_hex)
        )
        self._stop_process(
            self.wow_daemon_process,
            self.wow_daemon_stdout_handle,
            self.wow_daemon_stderr_handle,
        )
        self.wow_daemon_process = None
        time.sleep(1)

        self.logger.info("restarting WOW daemon with --spendkey for hardfork-18 mining")
        self._start_wow_daemon(
            spendkey=spend_key_hex,
            fixed_difficulty=bootstrap_difficulty,
        )
        self._wait_for_daemon_rpc(self.wow_daemon, "WOW daemon")
        if self.wow_generate_blocks > 0:
            self._prime_wow_wallet()
            if self.wow_fixed_difficulty != bootstrap_difficulty:
                self.logger.info(
                    "restarting WOW daemon after bootstrap with runtime fixed difficulty %s "
                    "(bootstrap used %s)",
                    self.wow_fixed_difficulty,
                    bootstrap_difficulty,
                )
                self._stop_process(
                    self.wow_daemon_process,
                    self.wow_daemon_stdout_handle,
                    self.wow_daemon_stderr_handle,
                )
                self.wow_daemon_process = None
                time.sleep(1)
                self._start_wow_daemon(spendkey=spend_key_hex)
                self._wait_for_daemon_rpc(self.wow_daemon, "WOW daemon")
            if self.role == "bob":
                self._configure_bob_wow_retry_mining_wallet()

    def _start_wow_daemon(
        self,
        spendkey: str = "",
        *,
        fixed_difficulty: Optional[int] = None,
    ) -> None:
        cmd = [
            self.wow_daemon_binary,
            "--data-dir", f"/tmp/wownero-{self.agent_id}",
            *self._wow_daemon_network_args(),
            "--rpc-bind-ip", self.rpc_host,
            "--rpc-bind-port", str(self.wow_daemon_port),
            "--confirm-external-bind",
            "--rpc-access-control-origins=*",
            "--p2p-bind-ip", self.rpc_host,
            "--p2p-bind-port", str(self.wow_p2p_port),
            "--non-interactive",
            "--log-level", "1",
            "--max-log-file-size", "0",
            "--no-zmq",
            "--disable-rpc-ban",
            "--allow-local-ip",
        ]
        if self.wow_offline:
            cmd.append("--offline")
        effective_fixed_difficulty = (
            self.wow_fixed_difficulty
            if fixed_difficulty is None
            else fixed_difficulty
        )
        if effective_fixed_difficulty > 0:
            cmd.extend(["--fixed-difficulty", str(effective_fixed_difficulty)])
        if spendkey:
            cmd.extend(["--spendkey", spendkey])
        self.logger.info("starting WOW daemon: %s", " ".join(cmd))
        (
            self.wow_daemon_stdout_handle,
            self.wow_daemon_stderr_handle,
        ) = self._open_log_handles("wow-runtime-logs", f"{self.agent_id}.daemon")
        self.wow_daemon_process = subprocess.Popen(
            cmd,
            stdout=self.wow_daemon_stdout_handle,
            stderr=self.wow_daemon_stderr_handle,
        )
        time.sleep(2.0)

    def _start_wow_wallet_rpc(self) -> None:
        wow_wallet_dir = self._shared_wallet_dir(self.wow_wallet_name)
        cmd = [
            self.wow_wallet_binary,
            *self._wow_wallet_network_args(),
            f"--daemon-address={self.wow_daemon}",
            f"--rpc-bind-port={self.wow_wallet_rpc_port}",
            f"--rpc-bind-ip={self.rpc_host}",
            "--disable-rpc-login",
            "--trusted-daemon",
            f"--wallet-dir={wow_wallet_dir}",
            f"--wow-shared-ringdb-dir={self.shared_dir}/wow-ringdb",
            "--confirm-external-bind",
            "--allow-mismatched-daemon-version",
            "--log-level=1",
            "--daemon-ssl-allow-any-cert",
        ]
        self.logger.info("starting WOW wallet RPC: %s", " ".join(cmd))
        (
            self.wow_wallet_stdout_handle,
            self.wow_wallet_stderr_handle,
        ) = self._open_log_handles("wow-runtime-logs", f"{self.agent_id}.wallet")
        self.wow_wallet_process = subprocess.Popen(
            cmd,
            stdout=self.wow_wallet_stdout_handle,
            stderr=self.wow_wallet_stderr_handle,
        )
        time.sleep(2.0)

    def _wait_for_daemon_rpc(self, url: str, label: str) -> None:
        last_error = "unknown error"
        for _ in range(20):
            try:
                self._daemon_json_rpc(url, "get_block_count")
                return
            except RuntimeError as exc:
                last_error = str(exc)
                time.sleep(1.0)
        raise RuntimeError(f"{label} did not become ready: {last_error}")

    def _wait_for_wallet_rpc(self, url: str, label: str) -> None:
        last_error = "unknown error"
        for _ in range(20):
            try:
                self._wallet_rpc_call_at(url, "get_version")
                return
            except RuntimeError as exc:
                last_error = str(exc)
                time.sleep(1.0)
        raise RuntimeError(f"{label} did not become ready: {last_error}")

    def _prime_wow_wallet(self) -> None:
        target_height = self.wow_generate_blocks
        current_height = self._daemon_json_rpc(self.wow_daemon, "get_block_count").get("count", 0)
        if isinstance(current_height, int) and current_height >= target_height:
            return
        baseline_height = int(current_height) if isinstance(current_height, int) else None

        wallet_address = self._wow_wallet_address()
        if int(current_height) >= target_height:
            return

        self.logger.info(
            "mining WOW local-chain blocks until height %s for wallet %s",
            target_height,
            wallet_address,
        )
        # Under Shadow, WOW /start_mining can accept the request and keep mining
        # without ever returning a clean HTTP response. Bootstrap still needs a
        # deterministic target-height loop, but the initial dispatch must be
        # tolerant of that non-returning RPC.
        self._start_wow_mining(
            wallet_address,
            baseline_height=baseline_height,
            tolerate_async_response=True,
        )
        try:
            max_polls = max(
                1200,
                int(1200 / self.wow_bootstrap_poll_interval_secs),
            )
            for _ in range(max_polls):
                current_height = self._daemon_json_rpc(self.wow_daemon, "get_block_count").get("count", 0)
                if isinstance(current_height, int) and current_height >= target_height:
                    self.logger.info(
                        "WOW local-chain reached bootstrap target at height %s; stopping mining",
                        current_height,
                    )
                    break
                time.sleep(self.wow_bootstrap_poll_interval_secs)
            else:
                raise RuntimeError(
                    f"WOW local-chain mining did not reach target height {target_height}"
                )
        finally:
            stop_height = int(current_height) if isinstance(current_height, int) else target_height
            self._request_wow_stop_mining(tolerate_async_response=True)
            self._wait_for_wow_height_to_stabilize(stop_height)

    def _generate_wow_blocks(self, count: int) -> int:
        """Mine exactly ``count`` WOW blocks.

        Returns the new daemon height after the call (or ``-1`` on failure).
        Used by retry-loop call sites that need to make slow, bounded
        progress on Bob's WOW chain without leaving ``start_mining`` running
        indefinitely under Shadow. The unbounded ``find-block -> log ->
        find-block`` pattern of ``start_mining`` at ``wow_fixed_difficulty=1``
        floods ``bob.daemon.stdout.log`` and crushes Shadow's sim ratio.

        Try the daemon's discrete ``generateblocks`` RPC first. Shadow's
        monerosim wrappers expose it for XMR and may also allow it for WOW
        even in fakechain mode when the special ``pre_pow_blob=sim`` marker
        is present. If WOW still rejects that RPC, fall back to the older
        bounded ``start_mining`` / ``stop_mining`` cycle.
        """
        if count <= 0 or not self.wow_local_daemon:
            return -1
        try:
            wallet_address = self._wow_bounded_mining_address()
        except Exception as exc:
            self.logger.warning(
                "WOW bounded mining could not resolve wallet address: %s",
                exc,
            )
            return -1

        try:
            initial = self._current_wow_height()
        except Exception as exc:
            self.logger.warning(
                "WOW bounded mining could not read initial height: %s",
                exc,
            )
            return -1

        try:
            result = self._daemon_json_rpc(
                self.wow_daemon,
                "generateblocks",
                {
                    "amount_of_blocks": int(count),
                    "wallet_address": wallet_address,
                    "pre_pow_blob": "sim",
                },
            )
        except Exception as exc:
            self.logger.info(
                "WOW generateblocks unavailable or rejected for %s block(s); "
                "falling back to bounded start/stop mining: %s",
                count,
                exc,
            )
        else:
            final_height = result.get("height", initial)
            if not isinstance(final_height, int):
                try:
                    final_height = int(final_height)
                except (TypeError, ValueError):
                    final_height = initial
            produced = max(final_height - initial, 0)
            self.logger.info(
                "WOW bounded mining produced %s block(s) via generateblocks "
                "(requested=%s initial=%s final=%s)",
                produced,
                count,
                initial,
                final_height,
            )
            return final_height

        target = initial + int(count)

        try:
            self._start_wow_mining(
                wallet_address,
                baseline_height=initial,
                tolerate_async_response=True,
            )
        except Exception as exc:
            self.logger.warning(
                "WOW bounded mining could not start: %s",
                exc,
            )
            return -1

        # Poll for the target height. Each poll is short (matching the
        # bounded-mining interval) so we stop mining as soon as the chain has
        # advanced ``count`` blocks. Cap polls so a stuck daemon does not hang
        # the retry indefinitely.
        bounded_poll_interval = max(
            min(self.wow_bounded_mining_poll_interval_secs, 0.05),
            0.001,
        )
        max_polls = max(
            200,
            int(60 / bounded_poll_interval),
        )
        current_height = initial
        reached = False
        for _ in range(max_polls):
            try:
                current_height = self._daemon_json_rpc(
                    self.wow_daemon,
                    "get_block_count",
                ).get("count", 0)
            except Exception as exc:
                self.logger.warning(
                    "WOW bounded mining height poll failed: %s",
                    exc,
                )
                break
            if isinstance(current_height, int) and current_height >= target:
                reached = True
                break
            time.sleep(bounded_poll_interval)

        try:
            self._request_wow_stop_mining(tolerate_async_response=True)
        except Exception as exc:
            self.logger.warning(
                "WOW bounded mining stop_mining dispatch failed: %s",
                exc,
            )

        try:
            stabilized = self._wait_for_wow_height_to_stabilize(
                int(current_height) if isinstance(current_height, int) else target,
            )
        except Exception as exc:
            self.logger.warning(
                "WOW bounded mining did not stabilize cleanly: %s",
                exc,
            )
            stabilized = current_height if isinstance(current_height, int) else -1

        actual_produced = max(stabilized - initial, 0) if isinstance(stabilized, int) else 0
        if reached:
            self.logger.info(
                "WOW bounded mining produced %s block(s) (requested=%s initial=%s final=%s)",
                actual_produced,
                count,
                initial,
                stabilized,
            )
        else:
            self.logger.warning(
                "WOW bounded mining did not reach target +%s blocks "
                "(initial=%s, final=%s, produced=%s)",
                count,
                initial,
                stabilized,
                actual_produced,
            )
        return int(stabilized) if isinstance(stabilized, int) else -1

    def _configure_bob_wow_retry_mining_wallet(self) -> None:
        if self.wow_retry_mining_address and self.wow_retry_mining_spend_key_hex:
            return

        self.logger.info(
            "preparing dedicated WOW retry-mining wallet so Bob's bounded bursts stop crediting the lock-wow spend wallet"
        )

        open_params = {"filename": self.wow_retry_mining_wallet_name, "password": ""}
        create_params = {**open_params, "language": "English"}

        try:
            self._wow_wallet_rpc_call("open_wallet", open_params)
        except RuntimeError as exc:
            message = str(exc).lower()
            if (
                "wallet not found" not in message
                and "wallet file not found" not in message
                and "file not found" not in message
                and "no such file or directory" not in message
            ):
                raise
            self._wow_wallet_rpc_call("create_wallet", create_params)

        result = self._wow_wallet_rpc_call(
            "get_address",
            {"account_index": 0, "address_index": [0]},
        )
        addresses = result.get("addresses")
        if not isinstance(addresses, list) or not addresses:
            raise RuntimeError("WOW retry-mining wallet RPC get_address returned no addresses")
        retry_address = str(addresses[0].get("address", "")).strip()
        if not retry_address:
            raise RuntimeError("WOW retry-mining wallet RPC get_address returned an empty address")

        retry_spend_key_hex = self._query_wow_spend_key_hex()
        self.wow_retry_mining_address = retry_address
        self.wow_retry_mining_spend_key_hex = retry_spend_key_hex

        self._wow_wallet_rpc_call(
            "open_wallet",
            {"filename": self.wow_wallet_name, "password": ""},
        )
        self.logger.info(
            "prepared dedicated WOW retry-mining wallet %s at address %s",
            self.wow_retry_mining_wallet_name,
            retry_address,
        )

        self.logger.info(
            "restarting WOW daemon with dedicated retry-mining spendkey so Bob's fresh-height bounded bursts no longer fund the lock-wow spend wallet"
        )
        self._stop_process(
            self.wow_daemon_process,
            self.wow_daemon_stdout_handle,
            self.wow_daemon_stderr_handle,
        )
        self.wow_daemon_process = None
        time.sleep(1)
        self._start_wow_daemon(spendkey=retry_spend_key_hex)
        self._wait_for_daemon_rpc(self.wow_daemon, "WOW daemon")

    def _wow_bounded_mining_address(self) -> str:
        if self.role == "bob" and self.wow_retry_mining_address:
            return self.wow_retry_mining_address
        return self._wow_wallet_address()

    def _generate_xmr_blocks(
        self,
        count: int,
        wallet_address: Optional[str] = None,
    ) -> int:
        """Mine exactly ``count`` XMR blocks via the daemon's generateblocks RPC."""
        if count <= 0:
            return -1
        if wallet_address is None:
            try:
                wallet_address = self._wallet_address()
            except Exception as exc:
                self.logger.warning(
                    "XMR bounded mining could not resolve wallet address: %s",
                    exc,
                )
                return -1

        try:
            initial = self._daemon_json_rpc(
                self.xmr_daemon,
                "get_block_count",
            ).get("count", 0)
        except Exception as exc:
            self.logger.warning(
                "XMR bounded mining could not read initial height: %s",
                exc,
            )
            return -1
        if not isinstance(initial, int):
            self.logger.warning(
                "XMR bounded mining initial height not an int: %r",
                initial,
            )
            return -1

        try:
            result = self._daemon_json_rpc(
                self.xmr_daemon,
                "generateblocks",
                {
                    "amount_of_blocks": int(count),
                    "wallet_address": wallet_address,
                    "pre_pow_blob": "sim",
                },
            )
        except Exception as exc:
            self.logger.warning(
                "XMR bounded mining could not generate %s block(s): %s",
                count,
                exc,
            )
            return -1

        final_height = result.get("height", initial)
        if not isinstance(final_height, int):
            try:
                final_height = self._daemon_json_rpc(
                    self.xmr_daemon,
                    "get_block_count",
                ).get("count", initial)
            except Exception:
                final_height = initial

        if not isinstance(final_height, int):
            self.logger.warning(
                "XMR bounded mining final height not an int: %r",
                final_height,
            )
            return -1

        self.logger.info(
            "XMR bounded mining produced %s block(s) (initial=%s, final=%s)",
            max(final_height - initial, 0),
            initial,
            final_height,
        )
        return final_height

    def _wow_tx_confirmed(self, tx_hash_hex: str) -> bool:
        try:
            tx_status = self._daemon_rpc_call(
                f"{self.wow_daemon}/get_transactions",
                {
                    "txs_hashes": [tx_hash_hex],
                    "decode_as_json": False,
                    "prune": True,
                },
            )
        except Exception as exc:
            self.logger.debug("WOW tx confirmation probe failed: %s", exc)
            return False

        txs = tx_status.get("txs")
        if not isinstance(txs, list) or not txs:
            return False

        tx = txs[0]
        if not isinstance(tx, dict):
            return False

        if tx.get("in_pool", True):
            return False

        block_height = tx.get("block_height")
        if not isinstance(block_height, int):
            return False

        try:
            current_height = self._daemon_json_rpc(
                self.wow_daemon,
                "get_block_count",
            ).get("count", 0)
        except Exception as exc:
            self.logger.debug("WOW tx confirmation height probe failed: %s", exc)
            return False

        return (
            isinstance(current_height, int)
            and current_height >= block_height
            and (current_height - block_height) >= 1
        )

    def _current_wow_height(self) -> int:
        current_height = self._daemon_json_rpc(
            self.wow_daemon,
            "get_block_count",
        ).get("count", 0)
        if not isinstance(current_height, int):
            raise RuntimeError(
                f"WOW get_block_count returned non-int height: {current_height!r}"
            )
        return current_height

    def _start_wow_background_mining(self, *, auto_stop: bool = True) -> None:
        if not self.wow_local_daemon or self.wow_background_mining:
            return

        wallet_address = self._wow_wallet_address()
        self.logger.info(
            "starting WOW background mining for confirmations at wallet %s",
            wallet_address,
        )
        current_height = self._daemon_json_rpc(self.wow_daemon, "get_block_count").get("count", 0)
        baseline_height = int(current_height) if isinstance(current_height, int) else None
        self._start_wow_mining(
            wallet_address,
            baseline_height=baseline_height,
            tolerate_async_response=True,
        )
        self.wow_background_mining = True
        if auto_stop:
            timer = threading.Timer(self.wow_mining_burst_seconds, self._stop_wow_background_mining)
            timer.daemon = True
            self.wow_mining_timer = timer
            timer.start()

    def _stop_wow_background_mining(self) -> None:
        timer = self.wow_mining_timer
        self.wow_mining_timer = None
        if timer is not None:
            timer.cancel()

        if not self.wow_background_mining:
            return

        try:
            self._request_wow_stop_mining(tolerate_async_response=True)
        except Exception as exc:
            self.logger.warning("failed to stop WOW background mining cleanly: %s", exc)
        finally:
            self.wow_background_mining = False

    def _run_cli_with_wow_confirmation_mining(
        self,
        args: List[str],
        timeout: int = 240,
        *,
        known_tx_hash: Optional[str] = None,
        start_immediately: bool = False,
    ) -> str:
        if not self.wow_local_daemon:
            return self._run_cli(args, timeout=timeout)

        stop_event = threading.Event()
        start_event = threading.Event()
        burst_interval = max(self.wow_confirmation_mining_interval_secs, 0.1)
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        tx_hash_hex: Optional[str] = (
            known_tx_hash.lower() if isinstance(known_tx_hash, str) and known_tx_hash else None
        )

        def pump_confirmation_bursts() -> None:
            nonlocal tx_hash_hex
            while not stop_event.is_set():
                if start_event.wait(0.1):
                    break
            if stop_event.is_set():
                return
            self.logger.info("starting output-triggered WOW confirmation mining bursts")
            while not stop_event.is_set():
                try:
                    mined_height = self._generate_wow_blocks(1)
                    if mined_height < 0:
                        self.logger.warning(
                            "WOW confirmation mining burst did not advance the chain"
                        )
                    elif tx_hash_hex and self._wow_tx_confirmed(tx_hash_hex):
                        self.logger.info(
                            "WOW tx %s confirmed after bounded burst; stopping extra mining",
                            tx_hash_hex,
                        )
                        break
                except Exception as exc:
                    self.logger.warning(
                        "WOW confirmation mining burst failed: %s",
                        exc,
                    )
                if stop_event.wait(burst_interval):
                    break

        self.logger.info(
            "enabling bounded WOW confirmation mining overlap "
            "(burst=%ss interval=%ss output_trigger=tx_hash_or_wait_line)",
            self.wow_mining_burst_seconds,
            self.wow_confirmation_mining_interval_secs,
        )
        if start_immediately and tx_hash_hex:
            self.logger.info(
                "starting bounded WOW confirmation mining immediately for known tx %s",
                tx_hash_hex,
            )
            start_event.set()
        worker = threading.Thread(
            target=pump_confirmation_bursts,
            name=f"{self.agent_id}-wow-confirmation-miner",
            daemon=True,
        )
        worker.start()
        cmd = [
            self.binary,
            "--password", self.password,
            "--db", self.db,
            "--proof-harness",
            "--transport", "sharechain",
            "--node-url", self._node_url(),
            *[arg for arg in args if arg],
        ]
        self.logger.info("running xmr-wow command: %s", " ".join(cmd))

        def read_stream(stream: Any, sink: List[str], label: str) -> None:
            nonlocal tx_hash_hex
            try:
                for raw_line in iter(stream.readline, ""):
                    line = raw_line.rstrip()
                    sink.append(line)
                    if line:
                        self.logger.debug("xmr-wow %s: %s", label, line)
                    if label == "stdout" and "WOW lock tx:" in line:
                        match = re.search(r"WOW lock tx:\s*([0-9a-fA-F]{64})", line)
                        if match is not None:
                            tx_hash_hex = match.group(1).lower()
                    if label == "stdout" and (
                        "WOW lock tx:" in line
                        or "Waiting for WOW confirmation..." in line
                    ):
                        start_event.set()
            finally:
                stream.close()

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        stdout_thread = threading.Thread(
            target=read_stream,
            args=(proc.stdout, stdout_lines, "stdout"),
            name=f"{self.agent_id}-xmr-wow-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=read_stream,
            args=(proc.stderr, stderr_lines, "stderr"),
            name=f"{self.agent_id}-xmr-wow-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
                raise RuntimeError(
                    "xmr-wow timed out while lock-wow confirmation mining overlap "
                    f"was active after {timeout}s"
                )
        finally:
            stop_event.set()
            worker.join(
                timeout=max(
                    self.wow_confirmation_mining_interval_secs,
                    self.wow_mining_burst_seconds,
                    0.1,
                )
                + 1.0
            )
            stdout_thread.join(timeout=1.0)
            stderr_thread.join(timeout=1.0)
            self._stop_wow_background_mining()

        stdout_text = "\n".join(stdout_lines).strip()
        stderr_text = "\n".join(stderr_lines).strip()
        if proc.returncode != 0:
            raise RuntimeError(
                f"xmr-wow exited with {proc.returncode}: "
                f"stdout={stdout_text!r} stderr={stderr_text!r}"
            )
        return stdout_text

    def _xmr_confirmation_wallet_address(self) -> str:
        if self.role == "bob":
            counterparty_info = self.read_shared_state(
                f"{self.counterparty}_user_info.json"
            )
            if isinstance(counterparty_info, dict):
                counterparty_address = str(
                    counterparty_info.get("wallet_address", "")
                ).strip()
                if counterparty_address:
                    return counterparty_address
        return self._wallet_address()

    def _run_cli_with_xmr_confirmation_mining(
        self,
        args: List[str],
        timeout: int = 240,
    ) -> str:
        stop_event = threading.Event()
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        burst_interval = 1.0
        max_attempts = 60
        wallet_address = self._xmr_confirmation_wallet_address()

        def pump_confirmation_blocks() -> None:
            if stop_event.wait(1.0):
                return
            self.logger.info(
                "starting bounded XMR confirmation mining overlap "
                "(wallet=%s attempts=%s interval=%ss)",
                wallet_address,
                max_attempts,
                burst_interval,
            )
            for attempt in range(max_attempts):
                if stop_event.is_set():
                    return
                try:
                    mined_height = self._generate_xmr_blocks(
                        1,
                        wallet_address=wallet_address,
                    )
                    if mined_height < 0:
                        self.logger.warning(
                            "XMR confirmation mining burst did not advance the chain"
                        )
                    else:
                        self.logger.info(
                            "XMR confirmation mining burst %s/%s advanced to height %s",
                            attempt + 1,
                            max_attempts,
                            mined_height,
                        )
                except Exception as exc:
                    self.logger.warning(
                        "XMR confirmation mining burst failed: %s",
                        exc,
                    )
                if stop_event.wait(burst_interval):
                    return

        cmd = [
            self.binary,
            "--password", self.password,
            "--db", self.db,
            "--proof-harness",
            "--transport", "sharechain",
            "--node-url", self._node_url(),
            *[arg for arg in args if arg],
        ]
        self.logger.info(
            "running xmr-wow command with XMR confirmation overlap: %s",
            " ".join(cmd),
        )
        env = os.environ.copy()
        if self.vts_squarings_per_second:
            env["XMR_WOW_VTS_SQUARINGS_PER_SECOND"] = self.vts_squarings_per_second
        if self.vts_modulus_bits:
            env["XMR_WOW_VTS_MODULUS_BITS"] = self.vts_modulus_bits

        def read_stream(stream: Any, sink: List[str], label: str) -> None:
            try:
                for raw_line in iter(stream.readline, ""):
                    line = raw_line.rstrip()
                    sink.append(line)
                    if line:
                        self.logger.debug("xmr-wow %s: %s", label, line)
            finally:
                stream.close()

        worker = threading.Thread(
            target=pump_confirmation_blocks,
            name=f"{self.agent_id}-xmr-confirmation-miner",
            daemon=True,
        )
        worker.start()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        stdout_thread = threading.Thread(
            target=read_stream,
            args=(proc.stdout, stdout_lines, "stdout"),
            name=f"{self.agent_id}-xmr-wow-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=read_stream,
            args=(proc.stderr, stderr_lines, "stderr"),
            name=f"{self.agent_id}-xmr-wow-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
                raise RuntimeError(
                    "xmr-wow timed out while claim-xmr XMR confirmation mining "
                    f"overlap was active after {timeout}s"
                )
        finally:
            stop_event.set()
            worker.join(timeout=burst_interval + 1.0)
            stdout_thread.join(timeout=1.0)
            stderr_thread.join(timeout=1.0)

        stdout_text = "\n".join(stdout_lines).strip()
        stderr_text = "\n".join(stderr_lines).strip()
        if proc.returncode != 0:
            raise RuntimeError(
                f"xmr-wow exited with {proc.returncode}: "
                f"stdout={stdout_text!r} stderr={stderr_text!r}"
            )
        return stdout_text

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

    def _wallet_rpc_url(self) -> str:
        if self.wallet_rpc_port is None:
            raise RuntimeError("wallet RPC port missing from agent context")
        return f"http://{self.rpc_host}:{self.wallet_rpc_port}/json_rpc"

    def _wow_wallet_network_args(self) -> List[str]:
        if self.wow_network == "mainnet":
            return []
        if self.wow_network == "testnet":
            return ["--testnet"]
        if self.wow_network == "stagenet":
            return ["--stagenet"]
        if self.wow_network == "regtest":
            return ["--regtest"]
        raise RuntimeError(f"unsupported WOW network mode: {self.wow_network}")

    def _wow_daemon_network_args(self) -> List[str]:
        args = self._wow_wallet_network_args()
        if self.wow_keep_fakechain:
            args.append("--keep-fakechain")
        return args

    def _wow_wallet_rpc_url(self) -> str:
        return f"http://{self.rpc_host}:{self.wow_wallet_rpc_port}/json_rpc"

    def _ensure_wallet_ready(self) -> str:
        if self.wallet_address is not None:
            return self.wallet_address

        open_params = {"filename": self.wallet_name, "password": ""}
        create_params = {**open_params, "language": "English"}

        try:
            self._wallet_rpc_call("open_wallet", open_params)
        except RuntimeError as exc:
            message = str(exc).lower()
            if (
                "wallet not found" not in message
                and "wallet file not found" not in message
                and "file not found" not in message
                and "no such file or directory" not in message
            ):
                raise
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

    def _ensure_wow_wallet_ready(self) -> str:
        if self.wow_wallet_address is not None:
            return self.wow_wallet_address

        open_params = {"filename": self.wow_wallet_name, "password": ""}
        create_params = {**open_params, "language": "English"}

        try:
            self._wow_wallet_rpc_call("open_wallet", open_params)
        except RuntimeError as exc:
            message = str(exc).lower()
            if (
                "wallet not found" not in message
                and "wallet file not found" not in message
                and "file not found" not in message
                and "no such file or directory" not in message
            ):
                raise
            self._wow_wallet_rpc_call("create_wallet", create_params)

        result = self._wow_wallet_rpc_call(
            "get_address",
            {"account_index": 0, "address_index": [0]},
        )
        addresses = result.get("addresses")
        if not isinstance(addresses, list) or not addresses:
            raise RuntimeError("WOW wallet RPC get_address returned no addresses")
        address = str(addresses[0].get("address", "")).strip()
        if not address:
            raise RuntimeError("WOW wallet RPC get_address returned an empty address")
        self.wow_wallet_address = address
        self.wow_wallet_address_cache = address
        return address

    def _wallet_rpc_call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._wallet_rpc_call_at(self._wallet_rpc_url(), method, params)

    def _wow_wallet_rpc_call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._wallet_rpc_call_at(self._wow_wallet_rpc_url(), method, params)

    def _query_wow_spend_key_hex(self) -> str:
        result = self._wow_wallet_rpc_call("query_key", {"key_type": "spend_key"})
        key = str(result.get("key", "")).strip()
        if len(key) != 64:
            raise RuntimeError(
                f"WOW wallet RPC query_key spend_key returned unexpected value (len={len(key)})"
            )
        return key

    def _wow_wallet_balances(self) -> Tuple[int, int]:
        self._wow_wallet_rpc_call("refresh")
        result = self._wow_wallet_rpc_call("get_balance", {"account_index": 0})
        balance = int(result.get("balance", 0))
        unlocked = int(result.get("unlocked_balance", 0))
        return balance, unlocked

    def _wow_wallet_height(self) -> int:
        result = self._wow_wallet_rpc_call("get_height")
        height = result.get("height", 0)
        if not isinstance(height, int):
            try:
                height = int(height)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"WOW wallet RPC get_height returned non-int height: {height!r}"
                ) from exc
        return height

    def _wait_for_wow_wallet_refresh_to_settle(
        self,
        *,
        label: str,
        target_height: Optional[int] = None,
        timeout_secs: float = 20.0,
        quiet_refreshes_required: int = 3,
        stable_height_polls_required: int = 3,
    ) -> bool:
        deadline = time.monotonic() + timeout_secs
        quiet_refreshes = 0
        stable_height_polls = 0
        last_blocks_fetched: Optional[int] = None
        last_wallet_height: Optional[int] = None

        while time.monotonic() < deadline:
            try:
                refresh_result = self._wow_wallet_rpc_call("refresh")
            except RuntimeError as exc:
                quiet_refreshes = 0
                stable_height_polls = 0
                self.logger.info(
                    "WOW wallet refresh for %s is not ready yet: %s",
                    label,
                    exc,
                )
                time.sleep(0.25)
                continue

            raw_blocks_fetched = refresh_result.get("blocks_fetched", 0)
            try:
                blocks_fetched = int(raw_blocks_fetched)
            except (TypeError, ValueError):
                blocks_fetched = 0

            try:
                wallet_height = self._wow_wallet_height()
            except RuntimeError as exc:
                quiet_refreshes = 0
                stable_height_polls = 0
                self.logger.info(
                    "WOW wallet height probe for %s is not ready yet: %s",
                    label,
                    exc,
                )
                time.sleep(0.25)
                continue

            if blocks_fetched > 0:
                quiet_refreshes = 0
                stable_height_polls = 0
                if (
                    blocks_fetched != last_blocks_fetched
                    or wallet_height != last_wallet_height
                ):
                    self.logger.info(
                        "WOW wallet still catching up for %s (blocks_fetched=%s wallet_height=%s%s)",
                        label,
                        blocks_fetched,
                        wallet_height,
                        f" target_height={target_height}"
                        if target_height is not None
                        else "",
                    )
            elif target_height is not None and wallet_height < target_height:
                quiet_refreshes = 0
                stable_height_polls = 0
                if wallet_height != last_wallet_height:
                    self.logger.info(
                        "WOW wallet refreshed quietly for %s but is still below daemon height (wallet_height=%s target_height=%s)",
                        label,
                        wallet_height,
                        target_height,
                    )
            else:
                quiet_refreshes += 1
                if wallet_height == last_wallet_height:
                    stable_height_polls += 1
                else:
                    stable_height_polls = 1
                if (
                    quiet_refreshes >= quiet_refreshes_required
                    and stable_height_polls >= stable_height_polls_required
                ):
                    self.logger.info(
                        "WOW wallet refresh settled for %s after %d quiet poll(s) at wallet height %s%s",
                        label,
                        quiet_refreshes,
                        wallet_height,
                        f" (target_height={target_height})"
                        if target_height is not None
                        else "",
                    )
                    return True

            last_blocks_fetched = blocks_fetched
            last_wallet_height = wallet_height
            time.sleep(0.25)

        self.logger.info(
            "WOW wallet refresh did not settle for %s within %.1fs%s",
            label,
            timeout_secs,
            (
                f" (last wallet height {last_wallet_height}, target_height={target_height})"
                if target_height is not None
                else ""
            ),
        )
        return False

    def _wallet_balances(self) -> Tuple[int, int]:
        self._wallet_rpc_call("refresh")
        result = self._wallet_rpc_call("get_balance", {"account_index": 0})
        balance = int(result.get("balance", 0))
        unlocked = int(result.get("unlocked_balance", 0))
        return balance, unlocked

    def _wallet_rpc_call_at(
        self,
        url: str,
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
            url,
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

    def _wallet_mnemonic(self) -> str:
        mnemonic = self.wallet_mnemonic_cache
        if mnemonic:
            return mnemonic

        self._ensure_wallet_ready()
        configured = str(self.attributes.get("mnemonic", "")).strip()
        if configured and not configured.startswith("SHADOW_"):
            self.wallet_mnemonic_cache = configured
            return configured

        result = self._wallet_rpc_call("query_key", {"key_type": "mnemonic"})
        mnemonic = str(result.get("key", "")).strip()
        if not mnemonic:
            raise RuntimeError("wallet RPC query_key did not return a mnemonic")
        self.wallet_mnemonic_cache = mnemonic
        return mnemonic

    def _wow_wallet_mnemonic(self) -> str:
        mnemonic = self.wow_wallet_mnemonic_cache
        if mnemonic:
            return mnemonic

        self._ensure_wow_wallet_ready()
        configured = str(self.attributes.get("wow_mnemonic", "")).strip()
        if configured and not configured.startswith("SHADOW_"):
            self.wow_wallet_mnemonic_cache = configured
            return configured

        result = self._wow_wallet_rpc_call("query_key", {"key_type": "mnemonic"})
        mnemonic = str(result.get("key", "")).strip()
        if not mnemonic:
            raise RuntimeError("WOW wallet RPC query_key did not return a mnemonic")
        self.wow_wallet_mnemonic_cache = mnemonic
        return mnemonic

    def _wallet_address(self) -> str:
        address = self.wallet_address_cache
        if address:
            return address

        self._ensure_wallet_ready()
        result = self._wallet_rpc_call(
            "get_address",
            {"account_index": 0, "address_index": [0]},
        )
        addresses = result.get("addresses")
        if isinstance(addresses, list) and addresses:
            address = str(addresses[0].get("address", "")).strip()
        else:
            address = str(result.get("address", "")).strip()
        if not address:
            raise RuntimeError("wallet RPC get_address did not return an address")
        self.wallet_address = address
        self.wallet_address_cache = address
        return address

    def _wow_wallet_address(self) -> str:
        address = self.wow_wallet_address_cache
        if address:
            return address

        self._ensure_wow_wallet_ready()
        result = self._wow_wallet_rpc_call(
            "get_address",
            {"account_index": 0, "address_index": [0]},
        )
        addresses = result.get("addresses")
        if isinstance(addresses, list) and addresses:
            address = str(addresses[0].get("address", "")).strip()
        else:
            address = str(result.get("address", "")).strip()
        if not address:
            raise RuntimeError("WOW wallet RPC get_address did not return an address")
        self.wow_wallet_address = address
        self.wow_wallet_address_cache = address
        return address

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
        url: str,
        payload: Dict[str, Any],
        ok_statuses: Optional[set[str]] = None,
        timeout_secs: float = 20,
    ) -> Dict[str, Any]:
        request = urlrequest.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlrequest.urlopen(request, timeout=timeout_secs) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"daemon RPC call {url} failed: {exc}") from exc

        if not isinstance(decoded, dict):
            raise RuntimeError(f"daemon RPC call {url} returned invalid payload")

        statuses = ok_statuses or {"OK"}
        status = decoded.get("status")
        if not isinstance(status, str) or status not in statuses:
            raise RuntimeError(f"daemon RPC call {url} returned status {status!r}")
        return decoded

    def _daemon_rpc_call_in_background(
        self,
        url: str,
        payload: Dict[str, Any],
        *,
        ok_statuses: Optional[set[str]] = None,
        timeout_secs: float = 20,
        failure_log_level: int = logging.INFO,
    ) -> None:
        def runner() -> None:
            try:
                self._daemon_rpc_call(
                    url,
                    payload,
                    ok_statuses=ok_statuses,
                    timeout_secs=timeout_secs,
                )
            except Exception as exc:
                self.logger.log(
                    failure_log_level,
                    "background daemon RPC call %s did not return cleanly: %s",
                    url,
                    exc,
                )

        thread = threading.Thread(
            target=runner,
            name=f"{self.agent_id}-daemon-rpc",
            daemon=True,
        )
        thread.start()

    def _request_wow_stop_mining(self, *, tolerate_async_response: bool = False) -> None:
        url = f"{self.wow_daemon}/stop_mining"
        if tolerate_async_response:
            self._daemon_rpc_call_in_background(
                url,
                {},
                ok_statuses={"OK", "Mining never started"},
                timeout_secs=20,
                failure_log_level=logging.WARNING,
            )
            self.logger.info(
                "WOW stop_mining dispatched asynchronously; waiting for height to stabilize"
            )
            return

        self._daemon_rpc_call(
            url,
            {},
            ok_statuses={"OK", "Mining never started"},
        )

    def _wait_for_wow_height_to_stabilize(
        self,
        initial_height: int,
        *,
        stable_polls_required: int = 5,
        max_extra_blocks: int = 32,
    ) -> int:
        last_height = initial_height
        stable_polls = 0
        max_polls = max(
            200,
            int(10 / self.wow_bootstrap_poll_interval_secs),
        )
        for _ in range(max_polls):
            time.sleep(self.wow_bootstrap_poll_interval_secs)
            current_height = self._daemon_json_rpc(
                self.wow_daemon,
                "get_block_count",
            ).get("count", 0)
            if not isinstance(current_height, int):
                continue
            if current_height == last_height:
                stable_polls += 1
                if stable_polls >= stable_polls_required:
                    self.logger.info(
                        "WOW local-chain height stabilized at %s after stop_mining",
                        current_height,
                    )
                    return current_height
                continue

            if current_height > initial_height + max_extra_blocks:
                raise RuntimeError(
                    "WOW local-chain continued mining after stop_mining "
                    f"(height {current_height}, stop requested at {initial_height})"
                )

            last_height = current_height
            stable_polls = 0

        raise RuntimeError(
            "WOW local-chain height did not stabilize after stop_mining "
            f"(last observed height {last_height})"
        )

    def _start_wow_mining(
        self,
        wallet_address: str,
        *,
        baseline_height: Optional[int] = None,
        tolerate_async_response: bool = False,
    ) -> None:
        payload = {
            "miner_address": wallet_address,
            "threads_count": 1,
            "do_background_mining": False,
            "ignore_battery": True,
        }
        if tolerate_async_response:
            self._daemon_rpc_call_in_background(
                f"{self.wow_daemon}/start_mining",
                payload,
                timeout_secs=20,
            )
            self.logger.info(
                "WOW start_mining dispatched asynchronously%s; continuing without waiting for RPC completion",
                "" if baseline_height is None else f" from baseline height {baseline_height}",
            )
            return

        try:
            self._daemon_rpc_call(
                f"{self.wow_daemon}/start_mining",
                payload,
                timeout_secs=2 if tolerate_async_response else 20,
            )
            return
        except RuntimeError as exc:
            if not tolerate_async_response:
                raise

            try:
                time.sleep(1.0)
                current_height = self._daemon_json_rpc(
                    self.wow_daemon,
                    "get_block_count",
                ).get("count", 0)
            except RuntimeError:
                raise exc

            if isinstance(baseline_height, int) and isinstance(current_height, int) and current_height > baseline_height:
                self.logger.info(
                    "WOW start_mining did not return cleanly, but height advanced from %s to %s; continuing",
                    baseline_height,
                    current_height,
                )
                return

            if "timed out" in str(exc):
                self.logger.info(
                    "WOW start_mining timed out before responding; continuing to poll height"
                )
                return

            raise

    def _generate_wow_destination(self) -> str:
        if self.generated_wow_destination:
            return self.generated_wow_destination

        output = self._run_cli([
            "generate-wallet",
            "--network", "wow-mainnet",
        ])
        self.generated_wow_destination = self._extract_required(
            r"Address:\s*(\S+)",
            output,
        )
        return self.generated_wow_destination

    def _resolved_destination(self) -> str:
        configured = self.destination.strip()
        if configured and not configured.startswith("SHADOW_"):
            return configured
        if self.role == "alice":
            if self.wow_local_daemon:
                return self._wow_wallet_address()
            return self._generate_wow_destination()
        return self._wallet_address()

    def _resolved_refund_address(self, attr_name: str) -> str:
        configured = str(self.attributes.get(attr_name, self.destination)).strip()
        if configured and not configured.startswith("SHADOW_"):
            return configured
        if attr_name == "bob_refund_address":
            return self._wow_wallet_address()
        return self._wallet_address()

    @staticmethod
    def _optional_arg(flag: str, value: Any) -> List[str]:
        if value is None:
            return []
        text = str(value).strip()
        if not text:
            return []
        return [flag, text]

    def _default_daemon_url(self) -> str:
        if self.daemon_rpc_port is None:
            return self.xmr_daemon
        return f"http://{self.rpc_host}:{self.daemon_rpc_port}"

    @staticmethod
    def _coerce_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _is_retryable_error(exc: Exception, *markers: str) -> bool:
        message = str(exc)
        return any(marker in message for marker in markers)

    def _parse_node_peers(self, raw_node_peers: Any) -> List[str]:
        if isinstance(raw_node_peers, list):
            return [str(peer).strip() for peer in raw_node_peers if str(peer).strip()]

        if not isinstance(raw_node_peers, str):
            return []

        text = raw_node_peers.strip()
        if not text:
            return []

        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                inner = text[1:-1].strip()
                if not inner:
                    return []
                return [peer.strip().strip("\"'") for peer in inner.split(",") if peer.strip()]
            if isinstance(parsed, list):
                return [str(peer).strip() for peer in parsed if str(peer).strip()]
            return []

        return [peer.strip().strip("\"'") for peer in text.split(",") if peer.strip()]

    def _resolve_repo_path(self, path: str) -> str:
        candidate = Path(path)
        if candidate.is_absolute():
            return str(candidate)

        repo_root = Path(__file__).resolve().parents[2]
        repo_candidate = repo_root / candidate
        if repo_candidate.exists():
            return str(repo_candidate)
        return path

    def _resolve_peer_address(self, peer: str) -> str:
        if ":" not in peer:
            return peer

        host, port = peer.rsplit(":", 1)
        if all(part.isdigit() for part in host.split(".")):
            return peer

        registry_path = self.shared_dir / "agent_registry.json"
        try:
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return peer

        for agent in registry.get("agents", []):
            if agent.get("id") == host and agent.get("ip_addr"):
                return f"{agent['ip_addr']}:{port}"
        return peer

    def _resolve_host(self, host: str) -> str:
        text = host.strip()
        if not text:
            return self.rpc_host
        if all(part.isdigit() for part in text.split(".")):
            return text
        resolved = self._resolve_peer_address(f"{text}:1")
        return resolved.rsplit(":", 1)[0]

    def _open_log_handles(self, directory: str, stem: str) -> Tuple[Any, Any]:
        log_dir = self.shared_dir / directory
        log_dir.mkdir(parents=True, exist_ok=True)
        stdout_handle = open(
            log_dir / f"{stem}.stdout.log",
            "a",
            encoding="utf-8",
        )
        stderr_handle = open(
            log_dir / f"{stem}.stderr.log",
            "a",
            encoding="utf-8",
        )
        return stdout_handle, stderr_handle

    def _stop_process(
        self,
        process: Optional[subprocess.Popen[str]],
        stdout_handle: Optional[Any],
        stderr_handle: Optional[Any],
    ) -> None:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if stdout_handle is not None:
            stdout_handle.close()
        if stderr_handle is not None:
            stderr_handle.close()

    def _run_cli(self, args: List[str], timeout: int = 240) -> str:
        cmd = [
            self.binary,
            "--password", self.password,
            "--db", self.db,
            "--proof-harness",
            "--transport", "sharechain",
            "--node-url", self._node_url(),
            *[arg for arg in args if arg],
        ]
        self.logger.info("running xmr-wow command: %s", " ".join(cmd))
        env = os.environ.copy()
        if self.vts_squarings_per_second:
            env["XMR_WOW_VTS_SQUARINGS_PER_SECOND"] = self.vts_squarings_per_second
        if self.vts_modulus_bits:
            env["XMR_WOW_VTS_MODULUS_BITS"] = self.vts_modulus_bits
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=timeout,
        )
        if proc.stdout:
            self.logger.debug("xmr-wow stdout: %s", proc.stdout.strip())
        if proc.stderr:
            self.logger.debug("xmr-wow stderr: %s", proc.stderr.strip())
        if proc.returncode != 0:
            raise RuntimeError(
                f"xmr-wow exited with {proc.returncode}: stdout={proc.stdout.strip()!r} stderr={proc.stderr.strip()!r}"
            )
        return proc.stdout

    def _extract_required(self, pattern: str, output: str) -> str:
        match = re.search(pattern, output)
        if match is None:
            raise RuntimeError(f"pattern not found in xmr-wow output: {pattern}")
        return match.group(1)

    def _extract_swap_id(self, output: str) -> str:
        matches = re.findall(r"(?:Temp )?Swap ID:\s*([0-9a-fA-F]{64})", output)
        if matches:
            return matches[-1]  # Use the LAST match (post-import real swap_id)

        fallback = self._latest_swap_id_from_db()
        if fallback is not None:
            self.logger.info("swap id not present in CLI output; using latest id from db")
            return fallback

        raise RuntimeError("swap id not present in CLI output or db")

    def _extract_wow_lock_tx_hash(self, text: str) -> Optional[str]:
        patterns = (
            r"WOW lock tx:\s*([0-9a-fA-F]{64})",
            r"Transaction\s+([0-9a-fA-F]{64})\s+may still confirm later",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match is not None:
                return match.group(1).lower()
        return None

    def _remember_pending_wow_lock_tx(self, text: str) -> Optional[str]:
        tx_hash = self._extract_wow_lock_tx_hash(text)
        if tx_hash is None:
            return None
        if tx_hash != self.pending_wow_lock_tx_hash:
            self.logger.info(
                "remembering pending WOW lock tx %s for confirmation-overlap retry",
                tx_hash,
            )
        self.pending_wow_lock_tx_hash = tx_hash
        return tx_hash

    def _latest_swap_id_from_db(self) -> Optional[str]:
        latest = self._latest_swap_record_from_db()
        if latest is None:
            return None
        return latest[0]

    def _latest_base_heights_from_db(self) -> Tuple[Optional[int], Optional[int]]:
        try:
            conn = sqlite3.connect(self.db)
            try:
                row = conn.execute(
                    "SELECT state FROM swaps ORDER BY updated DESC LIMIT 1"
                ).fetchone()
            finally:
                conn.close()
        except sqlite3.Error:
            return None, None

        if row is None or row[0] is None:
            return None, None

        try:
            state = json.loads(str(row[0]))
        except json.JSONDecodeError:
            return None, None

        params = state.get("params", {})
        timing = params.get("refund_timing", {})
        xmr_height = timing.get("xmr_base_height")
        wow_height = timing.get("wow_base_height")
        return (
            int(xmr_height) if isinstance(xmr_height, int) else None,
            int(wow_height) if isinstance(wow_height, int) else None
        )

    def _latest_swap_record_from_db(self) -> Optional[Tuple[str, str]]:
        try:
            conn = sqlite3.connect(self.db)
            try:
                row = conn.execute(
                    "SELECT hex(swap_id), state FROM swaps ORDER BY updated DESC LIMIT 1"
                ).fetchone()
            finally:
                conn.close()
        except sqlite3.Error:
            return None

        if row is None or row[0] is None or row[1] is None:
            return None

        try:
            state = json.loads(str(row[1]))
        except json.JSONDecodeError:
            return None

        phase = state.get("phase")
        if not isinstance(phase, str):
            return None
        return str(row[0]).lower(), phase

    def _record_result(self, payload: Dict[str, Any]) -> None:
        path = f"{self.RESULT_FILE_PREFIX}_{self.agent_id}.json"
        self.write_shared_state(path, payload)


def main() -> None:
    parser = XmrWowSharechainAgent.create_argument_parser(
        "XMR/WOW sharechain agent for Monerosim"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    agent = XmrWowSharechainAgent(
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
