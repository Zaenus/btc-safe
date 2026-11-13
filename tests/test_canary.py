"""Quantum canary."""

from __future__ import annotations

import hashlib

from safe_btc import segwit_addr
from safe_btc.canary import (
    DEFAULT_CANARY_ADDRESS,
    NUMS_CANARY_ADDRESSES,
    NUMS_H,
    CanaryMonitor,
)

G_UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


def test_nums_point_is_bip341_h():
    assert hashlib.sha256(G_UNCOMPRESSED).digest() == NUMS_H
    p = 2**256 - 2**32 - 977
    x = int.from_bytes(NUMS_H, "big")
    assert pow((x**3 + 7) % p, (p - 1) // 2, p) == 1  # x is on secp256k1


def test_default_canary_is_nums_taproot_output():
    assert DEFAULT_CANARY_ADDRESS == NUMS_CANARY_ADDRESSES["mainnet"]
    version, program = segwit_addr.decode("bc", DEFAULT_CANARY_ADDRESS)
    assert version == 1 and bytes(program) == NUMS_H


def _fake_esplora(spent: bool, on_first_page: bool = True):
    addr = DEFAULT_CANARY_ADDRESS
    funding = {"txid": "aa" * 32, "vin": [{"prevout": {"scriptpubkey_address": "bc1qother"}}],
               "status": {"block_height": 100}}
    spend = {"txid": "bb" * 32, "vin": [{"prevout": {"scriptpubkey_address": addr}}],
             "status": {"block_height": 200, "block_hash": "cc" * 32}}
    pages = {
        f"/address/{addr}": {"chain_stats": {"spent_txo_count": int(spent)}, "mempool_stats": {"spent_txo_count": 0}},
        f"/address/{addr}/txs": [spend, funding] if spent and on_first_page else [funding],
        "/blocks/tip/height": 900_000,
    }
    calls = []

    def fetch(url):
        calls.append(url)
        return pages[url.replace("http://x", "")]

    return fetch, calls


def test_poll_quiet():
    fetch, calls = _fake_esplora(spent=False)
    m = CanaryMonitor()
    assert m.poll_esplora("http://x", fetch) == []
    assert not m.is_triggered() and m.last_block_height == 900_000
    assert not any(c.endswith("/txs") for c in calls)


def test_poll_detects_spend_once():
    fetch, _ = _fake_esplora(spent=True)
    m = CanaryMonitor()
    alerts = m.poll_esplora("http://x", fetch)
    assert len(alerts) == 1 and alerts[0].transaction_id == "bb" * 32 and alerts[0].block_height == 200
    assert m.poll_esplora("http://x", fetch) == []  # no duplicate alerts
    assert m.is_triggered()


def test_poll_spend_beyond_first_page_still_alerts():
    fetch, _ = _fake_esplora(spent=True, on_first_page=False)
    m = CanaryMonitor()
    assert len(m.poll_esplora("http://x", fetch)) == 1 and m.is_triggered()


def test_check_spent_and_state_roundtrip(tmp_path):
    m = CanaryMonitor()
    assert m.check_spent(10, [{"txid": "t1", "inputs": ["bc1qx"]}]) == []
    alerts = m.check_spent(11, [{"txid": "t2", "block_height": 11, "inputs": [m.address]}])
    assert len(alerts) == 1
    path = tmp_path / "state.json"
    m.save_state(str(path))
    loaded = CanaryMonitor.load_state(str(path))
    assert loaded.is_triggered() and loaded.last_block_height == 11 and len(loaded.alerts) == 1
