"""
Legacy wallet -> witness v3 migration helper.

Classifies Bitcoin addresses by quantum exposure and builds a migration plan
whose destination addresses are derived from a BIP-39 seed, so every
destination can be re-derived (and spent) later from the mnemonic alone.

Exposure model
--------------
* "high": the public key is already visible on-chain: P2PK, Taproot (the
  output key sits in the scriptPubKey itself), or any address that has been
  spent from before (the spend revealed the key / script).
* "low": the key is hidden behind a hash until the first spend (unspent,
  never-reused P2PKH / P2SH / P2WPKH / P2WSH, and P2MR). Still exposed to a
  short-range attack while a spend sits in the mempool.
* "none": witness v3 (this proposal); remains safe after spending.
* "unknown": not recognized.

Whether an address has been spent from requires blockchain data; pass those
addresses in ``spent_from`` (the CLI flag is ``--spent-from``). The same applies
when the key is public for another reason, e.g. it was also used in a P2PK
output: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa looks like an ordinary P2PKH
address, but its key is public via the genesis block's P2PK output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import segwit_addr
from .hashing import hash256
from .keys import default_path, derive_keypair, seed_fingerprint
from .pq_addresses import DEFAULT_NETWORK, NETWORK_HRPS, address_from_public_key

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

BASE58_VERSIONS = {
    0x00: ("p2pkh", "mainnet"),
    0x05: ("p2sh", "mainnet"),
    0x6F: ("p2pkh", "testnet"),
    0xC4: ("p2sh", "testnet"),
}


def base58check_decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hash256(payload)[:4] != checksum:
        return None
    return payload


@dataclass
class LegacyAddressInfo:
    """Information about an address and its quantum exposure."""

    address: str
    address_type: str  # p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr, p2mr, p2pq, unknown
    public_key_exposed: bool
    quantum_risk: str  # "high", "low", "none", "unknown"
    reason: str
    network: str | None = None
    pq_address: str | None = None
    pq_derivation_path: str | None = None


_REASONS = {
    "p2pk": "P2PK: the public key is in the output script itself. Directly attackable by a CRQC.",
    "p2pkh": "P2PKH: key hidden behind HASH160 until the first spend reveals it.",
    "p2sh": "P2SH: script hidden until the first spend; risk then depends on the keys in it.",
    "p2wpkh": "P2WPKH: key hidden until the first spend reveals it in the witness.",
    "p2wsh": "P2WSH: script hidden until the first spend; risk then depends on the keys in it.",
    "p2tr": "Taproot: the tweaked output public key is in the scriptPubKey, so it is exposed "
    "from the moment the output is created, spent or not.",
    "p2mr": "P2MR (BIP-360): no key-path key in the output; leaves are revealed only when spent.",
    "p2pq": "Witness v3 (ML-DSA-65): stays quantum-resistant even after its key is revealed.",
}


def normalize_address(address: str) -> str:
    """Canonical form for comparisons: bech32/bech32m is case-insensitive, base58 is not."""
    address = address.strip()
    if address.lower().startswith(("bc1", "tb1", "bcrt1")):
        return address.lower()
    return address


def _info(address: str, kind: str, network: str | None, spent: bool) -> LegacyAddressInfo:
    if kind == "p2pq":
        return LegacyAddressInfo(address, kind, spent, "none", _REASONS[kind], network)
    exposed = kind in ("p2pk", "p2tr") or spent
    reason = _REASONS[kind]
    if spent and kind not in ("p2pk", "p2tr"):
        reason += " This address HAS been spent from, so its key/script is public."
    return LegacyAddressInfo(address, kind, exposed, "high" if exposed else "low", reason, network)


def classify_legacy_address(address: str, spent_from: bool = False) -> LegacyAddressInfo:
    """
    Classify an address (or a hex public key, for P2PK) by quantum exposure.

    Args:
        address: base58, bech32/bech32m address, or a hex SEC public key.
        spent_from: True if the address has been spent from before.
    """
    address = address.strip()

    # P2PK outputs have no address; accept the raw public key instead.
    if len(address) in (66, 130) and all(c in "0123456789abcdefABCDEF" for c in address):
        if address[:2] in ("02", "03") and len(address) == 66 or address[:2] == "04" and len(address) == 130:
            return _info(address, "p2pk", None, spent_from)

    payload = base58check_decode(address)
    if payload is not None and len(payload) == 21 and payload[0] in BASE58_VERSIONS:
        kind, network = BASE58_VERSIONS[payload[0]]
        return _info(address, kind, network, spent_from)

    for network, hrp in NETWORK_HRPS.items():
        version, program = segwit_addr.decode(hrp, address)
        if version is None or program is None:
            continue
        net = "testnet" if network == "signet" else network
        if version == 0:
            return _info(address, "p2wpkh" if len(program) == 20 else "p2wsh", net, spent_from)
        if version == 1 and len(program) == 32:
            return _info(address, "p2tr", net, spent_from)
        if version == 2 and len(program) == 32:
            return _info(address, "p2mr", net, spent_from)
        if version == 3 and len(program) == 32:
            return _info(address, "p2pq", net, spent_from)
        break

    return LegacyAddressInfo(address, "unknown", False, "unknown", "Unable to determine address type.")


@dataclass
class MigrationPlan:
    """A plan for moving coins to witness v3 addresses."""

    legacy_addresses: list[LegacyAddressInfo] = field(default_factory=list)
    pq_addresses: list[str] = field(default_factory=list)
    network: str = DEFAULT_NETWORK
    seed_fingerprint: str | None = None
    total_legacy: int = 0
    high_risk_count: int = 0
    low_risk_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "seed_fingerprint": self.seed_fingerprint,
            "total_legacy": self.total_legacy,
            "high_risk_count": self.high_risk_count,
            "low_risk_count": self.low_risk_count,
            "legacy_addresses": [
                {
                    "address": a.address,
                    "address_type": a.address_type,
                    "network": a.network,
                    "public_key_exposed": a.public_key_exposed,
                    "quantum_risk": a.quantum_risk,
                    "reason": a.reason,
                    "pq_address": a.pq_address,
                    "pq_derivation_path": a.pq_derivation_path,
                }
                for a in self.legacy_addresses
            ],
            "pq_addresses": self.pq_addresses,
        }

    def save_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


def create_migration_plan(
    legacy_addresses: list[str],
    master_seed: bytes | None = None,
    network: str = DEFAULT_NETWORK,
    account: int = 0,
    start_index: int = 0,
    spent_from: set[str] | None = None,
) -> MigrationPlan:
    """
    Classify addresses and, if ``master_seed`` is given, assign each at-risk
    address a destination derived at ``m/3'/coin'/account'/index'``.

    The plan contains no secrets. Destinations are reproducible from the seed
    (BIP-39 seed bytes, see :func:`safe_btc.keys.mnemonic_to_seed`).
    """
    spent_from = {normalize_address(a) for a in (spent_from or set())}
    plan = MigrationPlan(network=network, total_legacy=len(legacy_addresses))
    if master_seed is not None:
        plan.seed_fingerprint = seed_fingerprint(master_seed).hex()
    index = start_index

    for addr in legacy_addresses:
        info = classify_legacy_address(addr, spent_from=normalize_address(addr) in spent_from)
        plan.legacy_addresses.append(info)
        if info.quantum_risk == "high":
            plan.high_risk_count += 1
        elif info.quantum_risk == "low":
            plan.low_risk_count += 1

        if master_seed is not None and info.quantum_risk in ("high", "low"):
            path = default_path(network, account, index)
            keypair = derive_keypair(master_seed, path)
            info.pq_address = address_from_public_key(keypair.public_key, network)
            info.pq_derivation_path = path
            plan.pq_addresses.append(info.pq_address)
            index += 1

    # Highest risk first: those coins should move first.
    order = {"high": 0, "low": 1, "none": 2, "unknown": 3}
    plan.legacy_addresses.sort(key=lambda a: order[a.quantum_risk])
    return plan


def read_address_file(path: str) -> list[str]:
    """Read one address per line; blank lines and '#' comments are ignored."""
    with open(path) as f:
        return [s for s in (line.strip() for line in f) if s and not s.startswith("#")]


def scan_wallet_file(
    wallet_path: str, master_seed: bytes | None = None, network: str = DEFAULT_NETWORK
) -> MigrationPlan:
    """Build a migration plan from a text file with one address per line."""
    return create_migration_plan(read_address_file(wallet_path), master_seed, network)
