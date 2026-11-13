"""Wallet integration helpers and size/fee estimation."""

from __future__ import annotations

import json
import os
import stat

import pytest

from safe_btc.pq_addresses import compute_commitment, script_pubkey
from safe_btc.transaction import OutPoint, Transaction, TxIn, TxOut
from safe_btc.wallet_integration import (
    PQ_INPUT_WEIGHT,
    BitcoinCoreRPC,
    ElectrumWallet,
    HardwareWalletInterface,
    estimate_pq_transaction_fee,
    estimate_pq_vsize,
    max_pq_inputs_per_block,
)


def test_size_constants():
    assert PQ_INPUT_WEIGHT == 5433
    assert max_pq_inputs_per_block() == 736


def test_estimates_include_witness_discount():
    """Regression: 0.1 counted witness bytes at full weight (~5,384 vB for 1-in/2-out)."""
    assert estimate_pq_vsize(1, 2) == 1455
    assert estimate_pq_transaction_fee(1, 2, 10) == 14_550
    assert estimate_pq_transaction_fee(1, 2, 1.5) == 2183  # rounds up


def test_estimate_matches_real_transaction(keypair):
    spk = script_pubkey(compute_commitment(keypair.public_key))
    for n_in in (1, 2, 5):
        tx = Transaction(
            inputs=[TxIn(OutPoint(bytes([i]) * 32, 0), witness=[b"\x00" * 3309, b"\x01" * 1953]) for i in range(n_in)],
            outputs=[TxOut(1, spk), TxOut(1, b"\x00\x14" + b"\x00" * 20)],
        )
        assert estimate_pq_vsize(n_in, [34, 22]) == tx.vsize()


def test_electrum_add_get_and_atomic_save(tmp_path, keypair):
    path = tmp_path / "wallet.json"
    path.write_text(json.dumps({"keystore": {}, "wallet_type": "standard"}))
    os.chmod(path, 0o600)
    w = ElectrumWallet(str(path))
    assert w.is_electrum_wallet()
    info = w.add_pq_address(keypair, label="pq", derivation_path="m/3'/1'/0'/0'")
    assert info.address.startswith("tb1r")
    w.save()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    again = ElectrumWallet(str(path)).get_pq_addresses()
    assert [a.address for a in again] == [info.address]
    assert "seed" not in path.read_text()
    assert [p.name for p in tmp_path.iterdir()] == ["wallet.json"]


def test_electrum_rejects_encrypted(tmp_path):
    path = tmp_path / "enc"
    path.write_bytes(b"BIE1\x00\x01binary")
    with pytest.raises(ValueError, match="encrypted"):
        ElectrumWallet(str(path)).load()


def test_rpc_url_parsing():
    rpc = BitcoinCoreRPC("http://user:pass@127.0.0.1:18443")
    assert rpc.url == "http://127.0.0.1:18443/" and rpc._auth == ("user", "pass")
    assert BitcoinCoreRPC("https://node.example").url == "https://node.example:8332/"
    with pytest.raises(ValueError):
        BitcoinCoreRPC("localhost:8332")


def test_hardware_wallet_stub():
    hw = HardwareWalletInterface("ledger")
    with pytest.raises(NotImplementedError):
        hw.connect()


def test_rpc_url_percent_encoding_and_ipv6():
    rpc = BitcoinCoreRPC("http://user:p%40ss@[::1]:18443")
    assert rpc._auth == ("user", "p@ss")
    assert rpc.url == "http://[::1]:18443/"
