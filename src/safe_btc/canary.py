"""
Quantum canary monitor.

A useful canary must be an output that *nobody* can spend without breaking
secp256k1's discrete-log problem. The default canary is a Taproot output whose
output key is the BIP-341 "nothing up my sleeve" point

    H = lift_x(SHA256(uncompressed G))
      = 50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0

No one knows H's private key, and no script path exists (that would require
finding an internal key and tweak hashing to H). Any spend from it is therefore
strong evidence that someone can compute discrete logs, i.e. a CRQC (or a
classical break of secp256k1).

The previous default, 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (the genesis address),
was a poor canary: the genesis coinbase can never be spent, and anything else
sent there could be spent by whoever holds the key without proving anything.

A canary only works if coins sit at it. Anyone can fund it (a public bounty).
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import segwit_addr

NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
NUMS_CANARY_ADDRESSES = {
    "mainnet": segwit_addr.encode("bc", 1, NUMS_H),
    "testnet": segwit_addr.encode("tb", 1, NUMS_H),
}
DEFAULT_CANARY_ADDRESS = NUMS_CANARY_ADDRESSES["mainnet"]
DEFAULT_ESPLORA_URL = "https://mempool.space/api"


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


def _alert(address: str, txid: str | None, height: int | None, block_hash: str | None) -> CanaryAlert:
    where = f"at block {height}" if height is not None else "in the mempool"
    return CanaryAlert(
        address=address,
        block_height=height,
        block_hash=block_hash,
        timestamp=time.time(),
        transaction_id=txid,
        message=(
            f"QUANTUM ALERT: canary {address} was spent {where} (tx {txid}). "
            "Its key has no known owner, so this indicates secp256k1 discrete logs "
            "can be computed."
        ),
    )


@dataclass
class CanaryMonitor:
    """Monitors a canary address for evidence of a broken secp256k1."""

    address: str = DEFAULT_CANARY_ADDRESS
    last_block_height: int | None = None
    alerts: list[CanaryAlert] = field(default_factory=list)
    triggered: bool = False

    def _record(self, alert: CanaryAlert) -> CanaryAlert | None:
        if any(a.transaction_id == alert.transaction_id for a in self.alerts):
            return None
        self.alerts.append(alert)
        self.triggered = True
        return alert

    def check_spent(
        self, current_block_height: int | None, transactions: list[dict[str, Any]]
    ) -> list[CanaryAlert]:
        """
        Check already-fetched transactions (e.g. from your own node).

        Each transaction is a dict with 'txid', 'block_height', 'block_hash'
        and 'inputs' (the list of addresses its inputs spend from).
        """
        new = []
        for tx in transactions:
            if self.address in tx.get("inputs", []):
                a = self._record(_alert(self.address, tx.get("txid"), tx.get("block_height"), tx.get("block_hash")))
                if a:
                    new.append(a)
        if current_block_height is not None:
            self.last_block_height = current_block_height
        return new

    def poll_esplora(
        self,
        base_url: str = DEFAULT_ESPLORA_URL,
        fetch_json: Callable[[str], Any] | None = None,
    ) -> list[CanaryAlert]:
        """
        Poll an Esplora-compatible API (mempool.space, blockstream.info, or your
        own instance) for spends from the canary, including unconfirmed ones.

        Note: querying a third-party server tells it which address you watch.
        """
        fetch = fetch_json or _http_get_json
        base = base_url.rstrip("/")
        new: list[CanaryAlert] = []
        # The summary counts are complete; the tx list below is paginated.
        stats = fetch(f"{base}/address/{self.address}")
        spent = sum(
            (stats.get(k) or {}).get("spent_txo_count", 0) for k in ("chain_stats", "mempool_stats")
        )
        try:
            self.last_block_height = int(fetch(f"{base}/blocks/tip/height"))
        except (ValueError, TypeError):
            pass
        if spent == 0:
            return new
        txs = fetch(f"{base}/address/{self.address}/txs")
        for tx in txs:
            spends = any(
                (vin.get("prevout") or {}).get("scriptpubkey_address") == self.address
                for vin in tx.get("vin", [])
            )
            if spends:
                status = tx.get("status", {})
                a = self._record(
                    _alert(self.address, tx.get("txid"), status.get("block_height"), status.get("block_hash"))
                )
                if a:
                    new.append(a)
        if not self.alerts:
            # Spent per the summary, but the spend was not on the first page.
            a = self._record(_alert(self.address, None, None, None))
            if a:
                new.append(a)
        return new

    def is_triggered(self) -> bool:
        return self.triggered

    def save_state(self, path: str) -> None:
        state = {
            "address": self.address,
            "last_block_height": self.last_block_height,
            "triggered": self.triggered,
            "alerts": [a.to_dict() for a in self.alerts],
        }
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    @classmethod
    def load_state(cls, path: str) -> "CanaryMonitor":
        with open(path) as f:
            state = json.load(f)
        monitor = cls(
            address=state.get("address", DEFAULT_CANARY_ADDRESS),
            last_block_height=state.get("last_block_height"),
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


def _http_get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "safe-btc-canary"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body.strip()


def create_canary_monitor(address: str = DEFAULT_CANARY_ADDRESS) -> CanaryMonitor:
    """Create a new canary monitor for the given address."""
    return CanaryMonitor(address=address)
