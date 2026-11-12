"""
Legacy wallet → quantum-resistant address migration helper.

Scans legacy Bitcoin addresses and identifies which ones have exposed public
keys (vulnerable to quantum attacks) versus which ones are still hidden-key
(safe until spent). Generates a migration plan with corresponding PQ addresses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .keys import KeyPair, generate_key_from_entropy
from .pq_addresses import address_from_public_key, is_valid_address


@dataclass
class LegacyAddressInfo:
    """Information about a legacy Bitcoin address and its quantum risk."""

    address: str
    address_type: str  # "p2pk", "p2pkh", "p2wpkh", "p2tr", "unknown"
    public_key_exposed: bool
    quantum_risk: str  # "high", "low", "none"
    reason: str
    pq_address: str | None = None


@dataclass
class MigrationPlan:
    """A plan for migrating legacy addresses to quantum-resistant addresses."""

    legacy_addresses: list[LegacyAddressInfo] = field(default_factory=list)
    pq_addresses: list[str] = field(default_factory=list)
    total_legacy: int = 0
    high_risk_count: int = 0
    low_risk_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_legacy": self.total_legacy,
            "high_risk_count": self.high_risk_count,
            "low_risk_count": self.low_risk_count,
            "legacy_addresses": [
                {
                    "address": a.address,
                    "address_type": a.address_type,
                    "public_key_exposed": a.public_key_exposed,
                    "quantum_risk": a.quantum_risk,
                    "reason": a.reason,
                    "pq_address": a.pq_address,
                }
                for a in self.legacy_addresses
            ],
            "pq_addresses": self.pq_addresses,
        }

    def save_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


def classify_legacy_address(address: str) -> LegacyAddressInfo:
    """
    Classify a legacy Bitcoin address by its quantum risk.

    Risk categories:
    - "high": Public key is visible on-chain (P2PK, or reused P2PKH/P2WPKH
      after spending). A CRQC can derive the private key.
    - "low": Public key is hidden behind a hash (unspent P2PKH/P2WPKH).
      Safe until the address is spent from.
    - "none": Already quantum-resistant or not applicable.

    Args:
        address: A legacy Bitcoin address string.

    Returns:
        A LegacyAddressInfo with classification.
    """
    # Basic address type detection by prefix/format
    # This is a heuristic - real classification requires blockchain data
    address = address.strip()

    if address.startswith("1"):
        # P2PKH (legacy) - public key hidden until spent
        # Cannot determine if reused without blockchain data
        return LegacyAddressInfo(
            address=address,
            address_type="p2pkh",
            public_key_exposed=False,
            quantum_risk="low",
            reason="P2PKH: public key hidden behind RIPEMD160(SHA256(pk)). "
            "Vulnerable only after spending reveals the public key.",
        )
    elif address.startswith("3"):
        # P2SH - could be multisig or wrapped segwit
        return LegacyAddressInfo(
            address=address,
            address_type="p2sh",
            public_key_exposed=False,
            quantum_risk="low",
            reason="P2SH: redeem script hidden. Risk depends on inner script type.",
        )
    elif address.startswith("bc1q"):
        # Bech32 SegWit v0 (P2WPKH or P2WSH)
        if len(address) == 42:
            # Likely P2WPKH
            return LegacyAddressInfo(
                address=address,
                address_type="p2wpkh",
                public_key_exposed=False,
                quantum_risk="low",
                reason="P2WPKH: public key hidden in witness until spent.",
            )
        else:
            # Likely P2WSH
            return LegacyAddressInfo(
                address=address,
                address_type="p2wsh",
                public_key_exposed=False,
                quantum_risk="low",
                reason="P2WSH: script hash hidden. Risk depends on spending conditions.",
            )
    elif address.startswith("bc1p"):
        # Taproot (BIP-341)
        return LegacyAddressInfo(
            address=address,
            address_type="p2tr",
            public_key_exposed=False,
            quantum_risk="low",
            reason="Taproot: output key hidden in Merkle root until spent. "
            "Key path spend reveals the public key.",
        )
    elif address.startswith("1") and len(address) in (34, 35):
        # Could be P2PK (rare in modern usage)
        return LegacyAddressInfo(
            address=address,
            address_type="p2pk",
            public_key_exposed=True,
            quantum_risk="high",
            reason="P2PK: public key directly visible on-chain. "
            "HIGH RISK: vulnerable to quantum attack.",
        )
    else:
        return LegacyAddressInfo(
            address=address,
            address_type="unknown",
            public_key_exposed=False,
            quantum_risk="unknown",
            reason="Unable to determine address type.",
        )


def create_migration_plan(
    legacy_addresses: list[str],
    generate_pq: bool = True,
) -> MigrationPlan:
    """
    Create a migration plan for a list of legacy addresses.

    Args:
        legacy_addresses: List of legacy Bitcoin address strings.
        generate_pq: Whether to generate corresponding PQ addresses.

    Returns:
        A MigrationPlan with classifications and optional PQ addresses.
    """
    plan = MigrationPlan()
    plan.total_legacy = len(legacy_addresses)

    for addr in legacy_addresses:
        info = classify_legacy_address(addr)
        plan.legacy_addresses.append(info)

        if info.quantum_risk == "high":
            plan.high_risk_count += 1
        elif info.quantum_risk == "low":
            plan.low_risk_count += 1

        if generate_pq and info.quantum_risk in ("high", "low"):
            keypair = generate_key_from_entropy()
            pq_addr = address_from_public_key(keypair.public_key)
            info.pq_address = pq_addr
            plan.pq_addresses.append(pq_addr)

    return plan


def scan_wallet_file(wallet_path: str) -> MigrationPlan:
    """
    Scan a wallet file for legacy addresses and create a migration plan.

    This is a placeholder for future wallet format support (bitcoind wallet.dat,
    Electrum, etc.). Currently supports plain text files with one address per line.

    Args:
        wallet_path: Path to a file containing legacy addresses (one per line).

    Returns:
        A MigrationPlan.
    """
    addresses: list[str] = []
    with open(wallet_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if is_valid_address(line) or line.startswith(("1", "3", "bc1")):
                    addresses.append(line)

    return create_migration_plan(addresses)
