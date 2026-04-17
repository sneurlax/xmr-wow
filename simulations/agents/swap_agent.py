#!/usr/bin/env python3
"""
Swap Agent for XMR-WOW Atomic Swap Simulation (monerosim/Shadow).

This agent implements the atomic swap protocol steps against real monerod/wallet
RPC endpoints running inside a Shadow network simulation. It follows the
monerosim agent pattern (extends BaseAgent) and maps directly to the XMR-WOW
swap protocol steps:

    1. Key Generation -- generate Ed25519 key pair for swap contribution
    2. Key Exchange   -- send/receive key material with counterparty
    3. Address Derivation -- derive joint spend addresses on both chains
    4. Lock           -- transfer funds to joint address
    5. Verify Lock    -- confirm counterparty's lock on the other chain
    6. Claim          -- sweep funds using revealed secret (or refund)

The agent is designed to run inside Shadow with real monerod wallet RPC. It is
NOT intended for standalone use outside of a Shadow simulation.

Usage within monerosim:
    script: agents.swap_agent

Attributes (set in monerosim YAML config):
    role:                  "alice" or "bob"
    swap_amount:           Amount to swap (in XMR/WOW, e.g. "1.0")
    counterparty:          Agent ID of the counterparty (e.g. "bob")
    chain:                 Which chain this agent operates on ("xmr" or "wow")
    lock_confirmations:    Number of confirmations before lock is considered valid
    refund_timeout_blocks: Block height delta after which refund is allowed
    mode:                  Optional. "refund_test" to simulate counterparty failure.
"""

import hashlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# When running inside monerosim's agent framework, these imports resolve
# from the monerosim agents/ package. For standalone development/testing,
# a stub or the real monerosim package must be on PYTHONPATH.
try:
    from .base_agent import BaseAgent
    from .monero_rpc import RPCError
except ImportError:
    # Fallback for syntax checking / standalone development
    class BaseAgent:  # type: ignore[no-redef]
        """Minimal stub for standalone syntax validation."""
        def __init__(self, agent_id: str, **kwargs: Any) -> None:
            self.agent_id = agent_id
            self.running = True
            self.logger = logging.getLogger(agent_id)
            self.wallet_rpc = None
            self.daemon_rpc = None
            self.attributes: Dict[str, Any] = {}
            self._shared_dir = Path("/tmp/monerosim_shared")

        @property
        def shared_dir(self) -> Path:
            return self._shared_dir

        def _setup_agent(self) -> None:
            pass

        def run_iteration(self) -> float:
            return 60.0

        def interruptible_sleep(self, duration: float) -> None:
            time.sleep(min(duration, 1.0))

        def write_shared_state(self, filename: str, data: Dict[str, Any],
                               use_lock: bool = True) -> None:
            filepath = self.shared_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

        def read_shared_state(self, filename: str,
                              use_lock: bool = False) -> Optional[Dict[str, Any]]:
            filepath = self.shared_dir / filename
            if filepath.exists():
                with open(filepath, 'r') as f:
                    return json.load(f)
            return None

        @staticmethod
        def create_argument_parser(description: str, **kwargs: Any):
            import argparse
            parser = argparse.ArgumentParser(description=description)
            parser.add_argument('--id', required=True)
            parser.add_argument('--shared-dir', type=Path,
                                default=Path("/tmp/monerosim_shared"))
            parser.add_argument('--rpc-host', default='127.0.0.1')
            parser.add_argument('--daemon-rpc-port', type=int)
            parser.add_argument('--wallet-rpc-port', type=int)
            parser.add_argument('--p2p-port', type=int)
            parser.add_argument('--log-level', default='INFO')
            parser.add_argument('--attributes', nargs=2, action='append',
                                default=[])
            return parser

    class RPCError(Exception):  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Monero/Wownero use 12 decimal places (piconero).
ATOMIC_UNITS_PER_COIN = 10**12

# How long to wait between poll iterations (seconds).
POLL_INTERVAL = 10

# Maximum time to wait for counterparty messages (seconds).
MESSAGE_TIMEOUT = 600

# File naming conventions for inter-agent messaging via shared state.
SWAP_STATE_PREFIX = "swap_state_"
SWAP_MSG_PREFIX = "swap_msg_"


class SwapAgent(BaseAgent):
    """Agent implementing XMR-WOW atomic swap protocol steps.

    Each instance represents one party (Alice or Bob) in the swap. The agent
    communicates with its counterparty via shared state files in the monerosim
    shared directory, and executes on-chain operations via monerod wallet RPC.

    Protocol mapping:
        Alice (XMR side):
            1. generate_keys()       -- create Ed25519 key contribution
            2. send_init_message()   -- publish public key to shared state
            3. receive_init_message() -- read Bob's public key
            4. lock_funds()          -- transfer swap_amount to joint address
            5. (wait for Bob's lock on WOW chain)
            6. claim_funds()         -- sweep WOW using adaptor signature secret

        Bob (WOW side):
            1. generate_keys()       -- create Ed25519 key contribution
            2. receive_init_message() -- read Alice's public key
            3. send_init_message()   -- publish public key to shared state
            4. verify_lock()         -- confirm Alice's XMR lock
            5. lock_funds()          -- transfer swap_amount to joint address
            6. (wait for Alice to claim, revealing secret)
            7. claim_funds()         -- sweep XMR using revealed secret
    """

    # Swap protocol states (linear progression)
    STATE_INIT = "init"
    STATE_KEYS_GENERATED = "keys_generated"
    STATE_KEYS_EXCHANGED = "keys_exchanged"
    STATE_LOCKED = "locked"
    STATE_COUNTERPARTY_LOCKED = "counterparty_locked"
    STATE_CLAIMED = "claimed"
    STATE_REFUNDED = "refunded"
    STATE_FAILED = "failed"

    def __init__(self, agent_id: str, **kwargs: Any) -> None:
        super().__init__(agent_id=agent_id, **kwargs)

        # Protocol state
        self.state = self.STATE_INIT
        self.role: Optional[str] = None          # "alice" or "bob"
        self.counterparty_id: Optional[str] = None
        self.chain: Optional[str] = None         # "xmr" or "wow"
        self.swap_amount: float = 0.0
        self.lock_confirmations: int = 10
        self.refund_timeout_blocks: int = 76
        self.mode: Optional[str] = None          # None or "refund_test"

        # Cryptographic material (hex-encoded strings)
        self.private_key: Optional[str] = None
        self.public_key: Optional[str] = None
        self.counterparty_public_key: Optional[str] = None
        self.joint_address: Optional[str] = None
        self.secret: Optional[str] = None        # adaptor signature secret

        # On-chain state
        self.lock_tx_hash: Optional[str] = None
        self.lock_height: Optional[int] = None
        self.wallet_address: Optional[str] = None

        # Activity gating (reuse monerosim activity_start_time pattern)
        self.activity_started = False

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def _setup_agent(self) -> None:
        """Parse swap-specific configuration from agent attributes."""
        self.role = self.attributes.get("role", "alice")
        self.counterparty_id = self.attributes.get("counterparty", "")
        self.chain = self.attributes.get("chain", "xmr")
        self.swap_amount = float(self.attributes.get("swap_amount", "1.0"))
        self.lock_confirmations = int(
            self.attributes.get("lock_confirmations", "10")
        )
        self.refund_timeout_blocks = int(
            self.attributes.get("refund_timeout_blocks", "76")
        )
        self.mode = self.attributes.get("mode")

        self.logger.info(
            f"SwapAgent configured: role={self.role}, chain={self.chain}, "
            f"amount={self.swap_amount}, counterparty={self.counterparty_id}, "
            f"mode={self.mode or 'normal'}"
        )

        # Obtain wallet address
        if self.wallet_rpc:
            try:
                self.wallet_address = self.wallet_rpc.get_address()
                self.logger.info(f"Wallet address: {self.wallet_address}")
            except Exception as e:
                self.logger.warning(f"Could not get wallet address yet: {e}")

    def run_iteration(self) -> float:
        """Execute one step of the swap protocol state machine.

        Returns the recommended sleep duration before the next iteration.
        """
        # Gate on activity_start_time (bootstrap period)
        if not self.activity_started:
            activity_start = int(self.attributes.get("activity_start_time", "0"))
            if activity_start > 0:
                # In Shadow, time.time() returns seconds since SHADOW_EPOCH
                current_time = time.time()
                # Shadow epoch is 2000-01-01 = 946684800
                shadow_epoch = 946684800
                if current_time < shadow_epoch + activity_start:
                    remaining = (shadow_epoch + activity_start) - current_time
                    self.logger.debug(
                        f"Waiting {remaining:.0f}s for activity start"
                    )
                    return min(300.0, remaining)
            self.activity_started = True
            self.logger.info("Activity start time reached, beginning swap protocol")

        # State machine dispatch
        try:
            if self.state == self.STATE_INIT:
                self.generate_keys()
                self.state = self.STATE_KEYS_GENERATED
                return 1.0

            elif self.state == self.STATE_KEYS_GENERATED:
                self.send_init_message(self.counterparty_id)
                received = self.receive_init_message()
                if received:
                    self.state = self.STATE_KEYS_EXCHANGED
                    return 1.0
                return POLL_INTERVAL

            elif self.state == self.STATE_KEYS_EXCHANGED:
                if self.role == "alice":
                    # Alice locks first (on XMR chain)
                    self.lock_funds(self.joint_address, self.swap_amount)
                    self.state = self.STATE_LOCKED
                    return POLL_INTERVAL
                else:
                    # Bob waits for Alice's lock, then locks on WOW chain
                    if self.verify_lock(self.joint_address, self.swap_amount):
                        # In refund_test mode, Bob goes offline after
                        # verifying Alice's lock (does NOT lock himself).
                        if self.mode == "refund_test":
                            self.logger.info(
                                "REFUND TEST: Bob going offline after "
                                "verifying Alice's lock"
                            )
                            self.state = self.STATE_FAILED
                            self.running = False
                            return 0.0
                        self.lock_funds(self.joint_address, self.swap_amount)
                        self.state = self.STATE_LOCKED
                        return POLL_INTERVAL
                    return POLL_INTERVAL

            elif self.state == self.STATE_LOCKED:
                if self.role == "alice":
                    # Alice waits for Bob's lock on WOW chain
                    if self.verify_lock(self.joint_address, self.swap_amount):
                        self.state = self.STATE_COUNTERPARTY_LOCKED
                        return 1.0
                    # If refund_test mode: after timeout, refund
                    if self.mode == "refund_test":
                        if self._check_refund_timeout():
                            self.wait_for_refund(self.refund_timeout_blocks)
                            self.state = self.STATE_REFUNDED
                            return 0.0
                    return POLL_INTERVAL
                else:
                    # Bob waits for Alice to claim (revealing the secret)
                    secret = self._poll_for_revealed_secret()
                    if secret:
                        self.secret = secret
                        self.claim_funds(self.joint_address, secret)
                        self.state = self.STATE_CLAIMED
                        return 0.0
                    return POLL_INTERVAL

            elif self.state == self.STATE_COUNTERPARTY_LOCKED:
                # Alice claims WOW, revealing the secret
                self.claim_funds(self.joint_address, self.secret)
                self.state = self.STATE_CLAIMED
                return 0.0

            elif self.state in (
                self.STATE_CLAIMED, self.STATE_REFUNDED, self.STATE_FAILED
            ):
                self.logger.info(f"Swap complete: state={self.state}")
                self._write_swap_result()
                self.running = False
                return 0.0

        except Exception as e:
            self.logger.error(f"Error in swap iteration: {e}", exc_info=True)
            return 30.0

        return POLL_INTERVAL

    # ------------------------------------------------------------------
    # Swap Protocol Methods
    # ------------------------------------------------------------------

    def generate_keys(self) -> None:
        """Generate Ed25519 key pair for this party's swap contribution.

        In a real XMR-WOW swap, this generates a KeyContribution (private
        scalar + public point). Here we simulate with random 32-byte keys
        since the actual crypto happens in the Rust xmr-wow-crypto crate.

        Protocol mapping:
            - Alice: generates (a, A) where A = a*G
            - Bob:   generates (b, B) where B = b*G
            - Joint spend key: S = A + B
        """
        self.private_key = secrets.token_hex(32)
        # Derive a deterministic "public key" from the private key.
        # In production, this would be scalar multiplication on Ed25519.
        self.public_key = hashlib.sha256(
            bytes.fromhex(self.private_key)
        ).hexdigest()

        # Generate the adaptor signature secret (only Alice holds this).
        # In the real protocol, this is the discrete log used in the
        # adaptor signature scheme.
        if self.role == "alice":
            self.secret = secrets.token_hex(32)

        # Derive a simulated joint address from our public key.
        # In production, this requires both parties' public keys combined.
        # We use a placeholder until key exchange completes.
        self.joint_address = None

        self.logger.info(
            f"Generated keys: public_key={self.public_key[:16]}..."
        )

    def send_init_message(self, peer: Optional[str]) -> None:
        """Send key material to the counterparty via shared state file.

        In a real XMR-WOW swap, this would be a manual copy-paste of the
        protocol message. In the Shadow simulation, we use the monerosim
        shared state directory for inter-agent communication.

        Args:
            peer: Agent ID of the counterparty.
        """
        if not peer:
            self.logger.error("No counterparty specified")
            return

        message = {
            "from": self.agent_id,
            "to": peer,
            "type": "key_exchange",
            "public_key": self.public_key,
            "role": self.role,
            "chain": self.chain,
            "swap_amount": self.swap_amount,
            "timestamp": time.time(),
        }

        filename = f"{SWAP_MSG_PREFIX}{self.agent_id}_to_{peer}.json"
        self.write_shared_state(filename, message)
        self.logger.info(
            f"Sent init message to {peer}: "
            f"public_key={self.public_key[:16]}..."
        )

    def receive_init_message(self) -> bool:
        """Receive and validate counterparty key material from shared state.

        Polls the shared state directory for a message from the counterparty.
        On success, derives the joint address from both parties' public keys.

        Returns:
            True if counterparty message was received and validated.
        """
        if not self.counterparty_id:
            self.logger.error("No counterparty ID configured")
            return False

        filename = (
            f"{SWAP_MSG_PREFIX}{self.counterparty_id}_to_{self.agent_id}.json"
        )
        message = self.read_shared_state(filename)

        if not message:
            self.logger.debug(
                f"No message from {self.counterparty_id} yet"
            )
            return False

        # Validate message
        counterparty_key = message.get("public_key")
        if not counterparty_key:
            self.logger.error("Counterparty message missing public_key")
            return False

        self.counterparty_public_key = counterparty_key

        # Derive simulated joint address from both public keys.
        # In production, this is: joint_spend = A + B (EdwardsPoint addition)
        # Then CryptoNote address encoding with a view key.
        combined = self.public_key + self.counterparty_public_key
        self.joint_address = hashlib.sha256(
            combined.encode()
        ).hexdigest()[:64]

        self.logger.info(
            f"Received counterparty key from {self.counterparty_id}: "
            f"{counterparty_key[:16]}..., "
            f"joint_address={self.joint_address[:16]}..."
        )
        return True

    def lock_funds(self, joint_address: Optional[str],
                   amount: float) -> bool:
        """Transfer funds to the joint address (lock step).

        Calls the wallet RPC to create a transfer to the joint address.
        In production, this sends to the CryptoNote address derived from
        the joint spend key.

        Protocol mapping:
            - Alice locks XMR to joint address on chain A
            - Bob locks WOW to joint address on chain B

        Args:
            joint_address: The derived joint spend address (hex).
            amount: Amount to lock in coins (not atomic units).

        Returns:
            True if the lock transaction was broadcast successfully.
        """
        if not self.wallet_rpc:
            self.logger.error("No wallet RPC connection for lock")
            return False

        if not joint_address:
            self.logger.error("No joint address for lock")
            return False

        amount_atomic = int(amount * ATOMIC_UNITS_PER_COIN)
        self.logger.info(
            f"Locking {amount} coins ({amount_atomic} atomic) "
            f"to {joint_address[:16]}..."
        )

        try:
            # In a real Shadow simulation, we would transfer to an actual
            # Monero address derived from the joint spend key. Here we use
            # the wallet's own address as a placeholder (the important thing
            # is that the RPC call succeeds and a real on-chain tx is created).
            if not self.wallet_address:
                self.wallet_address = self.wallet_rpc.get_address()

            result = self.wallet_rpc.transfer(
                destinations=[{
                    "address": self.wallet_address,
                    "amount": amount_atomic,
                }],
                priority=1,
            )

            self.lock_tx_hash = result.get("tx_hash", "")
            self.logger.info(
                f"Lock transaction broadcast: tx_hash={self.lock_tx_hash}"
            )

            # Record lock height for refund timeout calculation
            if self.daemon_rpc:
                self.lock_height = self.daemon_rpc.get_height()
                self.logger.info(f"Lock height: {self.lock_height}")

            # Publish lock info for counterparty verification
            lock_info = {
                "agent_id": self.agent_id,
                "tx_hash": self.lock_tx_hash,
                "joint_address": joint_address,
                "amount": amount,
                "amount_atomic": amount_atomic,
                "lock_height": self.lock_height,
                "timestamp": time.time(),
            }
            self.write_shared_state(
                f"{SWAP_STATE_PREFIX}{self.agent_id}_lock.json", lock_info
            )

            return True

        except Exception as e:
            self.logger.error(f"Failed to lock funds: {e}")
            return False

    def verify_lock(self, joint_address: Optional[str],
                    expected_amount: float) -> bool:
        """Verify that the counterparty has locked funds to the joint address.

        Polls the shared state for the counterparty's lock transaction info,
        then checks confirmations via daemon RPC.

        Protocol mapping:
            - Bob verifies Alice's XMR lock before locking WOW
            - Alice verifies Bob's WOW lock before claiming

        In production, this uses view key scanning to verify the exact
        output amount at the joint address. In simulation, we check the
        shared state file and confirmation count.

        Args:
            joint_address: The joint spend address to verify.
            expected_amount: Expected lock amount in coins.

        Returns:
            True if the counterparty's lock is confirmed.
        """
        if not self.counterparty_id:
            return False

        # Read counterparty's lock info from shared state
        lock_info = self.read_shared_state(
            f"{SWAP_STATE_PREFIX}{self.counterparty_id}_lock.json"
        )

        if not lock_info:
            self.logger.debug(
                f"No lock info from {self.counterparty_id} yet"
            )
            return False

        # Verify amount matches
        locked_amount = lock_info.get("amount", 0)
        if abs(locked_amount - expected_amount) > 0.001:
            self.logger.error(
                f"Lock amount mismatch: expected={expected_amount}, "
                f"got={locked_amount}"
            )
            return False

        # Check confirmations
        tx_hash = lock_info.get("tx_hash", "")
        lock_height = lock_info.get("lock_height", 0)

        if self.daemon_rpc and lock_height:
            current_height = self.daemon_rpc.get_height()
            confirmations = current_height - lock_height

            if confirmations < self.lock_confirmations:
                self.logger.debug(
                    f"Lock has {confirmations}/{self.lock_confirmations} "
                    f"confirmations"
                )
                return False

        self.logger.info(
            f"Counterparty lock verified: tx={tx_hash[:16]}..., "
            f"amount={locked_amount}"
        )
        return True

    def claim_funds(self, joint_address: Optional[str],
                    secret: Optional[str]) -> bool:
        """Sweep funds from the joint address using the revealed secret.

        Protocol mapping:
            - Alice claims WOW by constructing a transaction with the adaptor
              signature. Broadcasting this reveals the secret scalar.
            - Bob extracts the secret from Alice's claim transaction, then
              uses it to claim XMR.

        In production, claiming uses adaptor signature completion:
            1. Alice signs with her partial key + adaptor secret -> reveals s
            2. Bob extracts s from Alice's WOW claim tx
            3. Bob signs with his partial key + s -> claims XMR

        Args:
            joint_address: The joint address to sweep from.
            secret: The adaptor signature secret (hex-encoded scalar).

        Returns:
            True if claim was successful.
        """
        if not secret:
            self.logger.error("No secret available for claim")
            return False

        self.logger.info(
            f"Claiming funds from {joint_address[:16] if joint_address else '??'}... "
            f"with secret={secret[:16]}..."
        )

        # Publish the secret so the counterparty can extract it.
        # In production, the secret is revealed on-chain via the adaptor
        # signature. In simulation, we publish it to shared state.
        claim_info = {
            "agent_id": self.agent_id,
            "role": self.role,
            "secret": secret,
            "joint_address": joint_address,
            "timestamp": time.time(),
        }
        self.write_shared_state(
            f"{SWAP_STATE_PREFIX}{self.agent_id}_claim.json", claim_info
        )

        self.logger.info("Claim published (secret revealed to counterparty)")
        return True

    def wait_for_refund(self, timelock_height: int) -> bool:
        """Wait until the refund timelock height is reached, then refund.

        Protocol mapping:
            - Alice's refund path: if Bob disappears after Alice locks,
              Alice waits for lock_height + refund_timeout_blocks, then
              sweeps her XMR back using her partial key alone.
            - The timelock ensures Bob has enough time to claim before
              Alice can refund.

        Args:
            timelock_height: Number of blocks after lock before refund
                             is allowed.

        Returns:
            True if refund was executed.
        """
        if not self.daemon_rpc:
            self.logger.error("No daemon RPC for refund height check")
            return False

        if not self.lock_height:
            self.logger.error("No lock height recorded, cannot calculate refund height")
            return False

        refund_height = self.lock_height + timelock_height
        self.logger.info(
            f"Waiting for refund height {refund_height} "
            f"(current lock_height={self.lock_height}, "
            f"timeout={timelock_height} blocks)"
        )

        # Poll until refund height is reached
        max_wait = 7200  # 2 hours max wait
        start = time.time()
        while time.time() - start < max_wait and self.running:
            current_height = self.daemon_rpc.get_height()
            if current_height >= refund_height:
                self.logger.info(
                    f"Refund height reached: {current_height} >= "
                    f"{refund_height}"
                )
                # Execute refund (in production: sweep with partial key)
                refund_info = {
                    "agent_id": self.agent_id,
                    "role": self.role,
                    "refund_height": refund_height,
                    "actual_height": current_height,
                    "lock_tx_hash": self.lock_tx_hash,
                    "timestamp": time.time(),
                }
                self.write_shared_state(
                    f"{SWAP_STATE_PREFIX}{self.agent_id}_refund.json",
                    refund_info,
                )
                self.logger.info("Refund executed successfully")
                return True

            remaining = refund_height - current_height
            self.logger.debug(
                f"Waiting for refund: {remaining} blocks remaining "
                f"(height {current_height}/{refund_height})"
            )
            self.interruptible_sleep(POLL_INTERVAL)

        self.logger.error("Refund timeout exceeded")
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_refund_timeout(self) -> bool:
        """Check if the refund timeout has been reached."""
        if not self.daemon_rpc or not self.lock_height:
            return False
        current_height = self.daemon_rpc.get_height()
        refund_height = self.lock_height + self.refund_timeout_blocks
        return current_height >= refund_height

    def _poll_for_revealed_secret(self) -> Optional[str]:
        """Poll shared state for the counterparty's revealed secret.

        In production, Bob would extract the secret from Alice's on-chain
        claim transaction by comparing the adaptor signature with the
        pre-signature.

        Returns:
            The hex-encoded secret if found, None otherwise.
        """
        if not self.counterparty_id:
            return None

        claim_info = self.read_shared_state(
            f"{SWAP_STATE_PREFIX}{self.counterparty_id}_claim.json"
        )
        if claim_info:
            secret = claim_info.get("secret")
            if secret:
                self.logger.info(
                    f"Counterparty secret revealed: {secret[:16]}..."
                )
                return secret
        return None

    def _write_swap_result(self) -> None:
        """Write final swap result to shared state for analysis."""
        result = {
            "agent_id": self.agent_id,
            "role": self.role,
            "chain": self.chain,
            "state": self.state,
            "swap_amount": self.swap_amount,
            "lock_tx_hash": self.lock_tx_hash,
            "lock_height": self.lock_height,
            "mode": self.mode,
            "timestamp": time.time(),
        }
        self.write_shared_state(
            f"{SWAP_STATE_PREFIX}{self.agent_id}_result.json", result
        )
        self.logger.info(f"Swap result written: state={self.state}")


def main() -> None:
    """Main entry point for swap agent."""
    parser = SwapAgent.create_argument_parser(
        "Swap Agent for XMR-WOW Atomic Swap Simulation"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    agent = SwapAgent(
        agent_id=args.id,
        shared_dir=args.shared_dir,
        daemon_rpc_port=args.daemon_rpc_port,
        wallet_rpc_port=args.wallet_rpc_port,
        p2p_port=getattr(args, 'p2p_port', None),
        rpc_host=args.rpc_host,
        log_level=args.log_level,
        attributes=args.attributes,
    )
    agent.run()


if __name__ == "__main__":
    main()
