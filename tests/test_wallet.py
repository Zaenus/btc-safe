"""Address classification and migration plans."""

from __future__ import annotations

import json

import pytest

from safe_btc.keys import derive_keypair, mnemonic_to_seed
from safe_btc.pq_addresses import address_from_public_key
from safe_btc.wallet import base58check_decode, classify_legacy_address, create_migration_plan, scan_wallet_file

P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
P2WSH = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
TESTNET_P2PKH = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
GENESIS_PUBKEY = (
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)


@pytest.mark.parametrize(
    "addr,kind,risk",
    [
        (P2PKH, "p2pkh", "low"),
        (P2SH, "p2sh", "low"),
        (P2WPKH, "p2wpkh", "low"),
        (P2WSH, "p2wsh", "low"),
        (P2TR, "p2tr", "high"),
        (TESTNET_P2PKH, "p2pkh", "low"),
        (GENESIS_PUBKEY, "p2pk", "high"),
        ("02" + "11" * 32, "p2pk", "high"),
        ("hello", "unknown", "unknown"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "unknown", "unknown"),  # bad checksum
    ],
)
def test_classification(addr, kind, risk):
    info = classify_legacy_address(addr)
    assert (info.address_type, info.quantum_risk) == (kind, risk)


def test_taproot_is_exposed_even_unspent():
    """Regression: 0.1 called Taproot 'low' risk."""
    info = classify_legacy_address(P2TR)
    assert info.public_key_exposed and "scriptPubKey" in info.reason


def test_spent_from_raises_risk():
    info = classify_legacy_address(P2WPKH, spent_from=True)
    assert info.quantum_risk == "high" and info.public_key_exposed


def test_witness_v3_is_none(keypair):
    info = classify_legacy_address(address_from_public_key(keypair.public_key))
    assert (info.address_type, info.quantum_risk) == ("p2pq", "none")


def test_base58check():
    assert base58check_decode(P2PKH)[0] == 0
    assert base58check_decode("0OIl") is None


def test_migration_destinations_are_recoverable(mnemonic):
    """Regression: 0.1 generated random keys for destinations and discarded them."""
    seed = mnemonic_to_seed(mnemonic)
    plan = create_migration_plan([P2PKH, P2TR, "junk"], seed, "testnet")
    assert plan.high_risk_count == 1 and plan.low_risk_count == 1
    assert len(plan.pq_addresses) == 2
    assert plan.legacy_addresses[0].address == P2TR  # highest risk first
    for info in plan.legacy_addresses[:2]:
        kp = derive_keypair(seed, info.pq_derivation_path)
        assert address_from_public_key(kp.public_key, "testnet") == info.pq_address
    assert len(set(plan.pq_addresses)) == 2
    blob = json.dumps(plan.to_dict())
    assert "seed\"" not in blob and mnemonic.split()[0] not in blob


def test_migration_without_seed_only_classifies():
    plan = create_migration_plan([P2PKH, P2TR])
    assert plan.pq_addresses == []
    assert all(a.pq_address is None for a in plan.legacy_addresses)


def test_scan_wallet_file(tmp_path, mnemonic):
    f = tmp_path / "addrs.txt"
    f.write_text(f"# my coins\n{P2WPKH}\n\n{P2TR}\n")
    plan = scan_wallet_file(str(f), mnemonic_to_seed(mnemonic))
    assert plan.total_legacy == 2 and len(plan.pq_addresses) == 2


def test_spent_from_is_case_insensitive_for_bech32():
    plan = create_migration_plan([P2WPKH.upper()], spent_from={P2WPKH.lower()})
    assert plan.legacy_addresses[0].quantum_risk == "high"
    plan = create_migration_plan([P2WPKH.lower()], spent_from={P2WPKH.upper()})
    assert plan.legacy_addresses[0].quantum_risk == "high"
