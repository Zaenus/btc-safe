"""
Quantum canary monitor.

Watches a known address with an exposed public key on the Bitcoin blockchain.
If the canary address ever spends funds, it's evidence that a cryptographically
relevant quantum computer (CRQC) exists and can derive private keys from
exposed public keys.

This provides an early-warning signal for the network to activate
post-quantum migration protocols.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

# Default canary address: Satoshi-era P2PK address with exposed public key
# 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (Bitcoin genesis block reward)
DEFAULT_CANARY_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


@dataclass
class CanaryAlert:
    """An alert triggered when a canary address spends funds."""

    address: str
    block_height: int | None
    block_hash: str | None
    timestamp: float
    transaction_id: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "timestamp": self.timestamp,
            "transaction_id": self.transaction_id,
            "message": self.message,
        }


@dataclass
class CanaryMonitor:
    """Monitors canary addresses for quantum attack evidence."""

    address: str = DEFAULT_CANARY_ADDRESS
    checked_blocks: list[int] = field(default_factory=list)
    last_block_height: int | None = None
    alerts: list[CanaryAlert] = field(default_factory=list)
    triggered: bool = False

    def check_spent(self, current_block_height: int, transactions: list[dict[str, Any]]) -> list[CanaryAlert]:
        """
        Check if the canary address has spent funds in new transactions.

        Args:
            current_block_height: The latest block height to check up to.
            transactions: List of transactions from new blocks, each with
                'txid', 'block_height', 'block_hash', 'inputs' (list of
                addresses spent), and 'outputs'.

        Returns:
            A list of new CanaryAlert instances.
        """
        new_alerts: list[CanaryAlert] = []

        for tx in transactions:
            inputs = tx.get("inputs", [])
            if self.address in inputs:
                alert = CanaryAlert(
                    address=self.address,
                    block_height=tx.get("block_height"),
                    block_hash=tx.get("block_hash"),
                    timestamp=time.time(),
                    transaction_id=tx.get("txid"),
                    message=(
                        f"QUANTUM ALERT: Canary address {self.address} spent funds "
                        f"at block {tx.get('block_height')}. This suggests a "
                        f"cryptographically relevant quantum computer exists."
                    ),
                )
                new_alerts.append(alert)
                self.alerts.append(alert)
                self.triggered = True

        if current_block_height is not None:
            self.last_block_height = current_block_height
            self.checked_blocks.append(current_block_height)

        return new_alerts

    def is_triggered(self) -> bool:
        """Return True if the canary has ever been triggered."""
        return self.triggered

    def save_state(self, path: str) -> None:
        """Save monitor state to a JSON file."""
        state = {
            "address": self.address,
            "last_block_height": self.last_block_height,
            "checked_blocks": self.checked_blocks,
            "triggered": self.triggered,
            "alerts": [a.to_dict() for a in self.alerts],
        }
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    @classmethod
    def load_state(cls, path: str) -> "CanaryMonitor":
        """Load monitor state from a JSON file."""
        with open(path, "r") as f:
            state = json.load(f)
        monitor = cls(
            address=state.get("address", DEFAULT_CANARY_ADDRESS),
            last_block_height=state.get("last_block_height"),
            checked_blocks=state.get("checked_blocks", []),
            triggered=state.get("triggered", False),
        )
        for a in state.get("alerts", []):
            monitor.alerts.append(
                CanaryAlert(
                    address=a["address"],
                    block_height=a.get("block_height"),
                    block_hash=a.get("block_hash"),
                    timestamp=a["timestamp"],
                    transaction_id=a.get("transaction_id"),
                    message=a["message"],
                )
            )
        return monitor


def create_canary_monitor(address: str = DEFAULT_CANARY_ADDRESS) -> CanaryMonitor:
    """Create a new canary monitor for the given address."""
    return CanaryMonitor(address=address)
