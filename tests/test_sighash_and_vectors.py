"""Sighash (vs. official BIP-341 vectors) and the BIP's own test vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from safe_btc.consensus import PolicyError, ValidationError, check_policy, verify_input
from safe_btc.pq_addresses import address_from_public_key, compute_commitment, script_pubkey
from safe_btc.keys import derive_seed, mnemonic_to_seed
from safe_btc.pq_signatures import MLDSA65
from safe_btc.transaction import (
    OutPoint,
    Transaction,
    TxIn,
    TxOut,
    sig_msg,
    signature_hash,
    signature_hash_bip341,
)

ROOT = Path(__file__).resolve().parent.parent
BIP341 = json.loads((ROOT / "tests" / "data" / "bip341_wallet_test_vectors.json").read_text())
VECTORS = json.loads((ROOT / "docs" / "bip" / "0001-test-vectors.json").read_text())


def _bip341_cases():
    for case in BIP341["keyPathSpending"]:
        for spend in case["inputSpending"]:
            yield case["given"], spend


@pytest.mark.parametrize("given,spend", list(_bip341_cases()))
def test_sigmsg_matches_bip341(given, spend):
    """Our SigMsg is byte-identical to Taproot's; only the hash tag differs."""
    tx = Transaction.deserialize(bytes.fromhex(given["rawUnsignedTx"]))
    assert tx.serialize().hex() == given["rawUnsignedTx"]
    spent = [TxOut(u["amountSats"], bytes.fromhex(u["scriptPubKey"])) for u in given["utxosSpent"]]
    idx, ht = spend["given"]["txinIndex"], spend["given"]["hashType"]
    assert sig_msg(tx, idx, spent, ht).hex() == spend["intermediary"]["sigMsg"]
    assert signature_hash_bip341(tx, idx, spent, ht).hex() == spend["intermediary"]["sigHash"]
    assert signature_hash(tx, idx, spent, ht).hex() != spend["intermediary"]["sigHash"]


def _txouts(items):
    return [TxOut(o["value"], bytes.fromhex(o["scriptPubKey"])) for o in items]


@pytest.mark.parametrize("key", VECTORS["keys"])
def test_vector_keys(key):
    pk, _ = MLDSA65.keypair_from_seed(bytes.fromhex(key["seed"]))
    assert pk.hex() == key["public_key"]
    assert hashlib.sha256(pk).hexdigest() == key["public_key_sha256"]
    assert compute_commitment(pk).hex() == key["commitment"]
    assert script_pubkey(compute_commitment(pk)).hex() == key["scriptPubKey"]
    for net, addr in key["addresses"].items():
        assert address_from_public_key(pk, net) == addr


@pytest.mark.parametrize("d", VECTORS["derivation"])
def test_vector_derivation(d):
    xi = derive_seed(mnemonic_to_seed(d["mnemonic"], d["passphrase"]), d["path"])
    assert xi.hex() == d["keygen_seed"]
    pk, _ = MLDSA65.keypair_from_seed(xi)
    assert hashlib.sha256(pk).hexdigest() == d["public_key_sha256"]
    assert address_from_public_key(pk, "testnet") == d["address_testnet"]


@pytest.mark.parametrize("v", VECTORS["sighash"])
def test_vector_sighash(v):
    tx = Transaction.deserialize(bytes.fromhex(v["tx"]))
    spent = _txouts(v["spent_outputs"])
    annex = bytes.fromhex(v["annex"]) if v["annex"] else None
    assert sig_msg(tx, v["input_index"], spent, v["hash_type"], annex).hex() == v["sig_msg"]
    assert signature_hash(tx, v["input_index"], spent, v["hash_type"], annex).hex() == v["sighash"]


@pytest.mark.parametrize("v", VECTORS["spends"], ids=[v["description"] for v in VECTORS["spends"]])
def test_vector_spend(v):
    tx = Transaction.deserialize(bytes.fromhex(v["tx"]))
    spent = _txouts(v["spent_outputs"])
    if not v["valid"]:
        with pytest.raises(ValidationError):
            verify_input(tx, v["input_index"], spent)
        return
    result = verify_input(tx, v["input_index"], spent)
    assert result.upgradable == v["upgradable"]
    if v["standard"]:
        check_policy(tx, v["input_index"], spent)
    else:
        with pytest.raises(PolicyError):
            check_policy(tx, v["input_index"], spent)


def test_vectors_cover_required_cases():
    descs = " ".join(v["description"] for v in VECTORS["spends"])
    for needle in ("annex", "0x00", "commitment", "SIGHASH_SINGLE", "upgrade hook", "message-signing context"):
        assert needle in descs


def test_dilithium_py_cross_check():
    """Independent implementation agrees on seeded keygen and signatures."""
    ml = pytest.importorskip("dilithium_py.ml_dsa")
    seed = hashlib.sha256(b"cross check").digest()
    pk_ref, sk_ref = ml.ML_DSA_65.key_derive(seed)
    pk, _ = MLDSA65.keypair_from_seed(seed)
    assert pk == pk_ref
    sig = MLDSA65.sign(seed, b"msg", b"ctx")
    assert ml.ML_DSA_65.verify(pk_ref, b"msg", sig, ctx=b"ctx")
    sig_ref = ml.ML_DSA_65.sign(sk_ref, b"msg", ctx=b"ctx", deterministic=True)
    assert MLDSA65.verify(pk, b"msg", sig_ref, b"ctx")


def test_transaction_roundtrip_with_witness():
    v = next(s for s in VECTORS["spends"] if s["valid"] and not s["upgradable"])
    raw = bytes.fromhex(v["tx"])
    tx = Transaction.deserialize(raw)
    assert tx.serialize() == raw
    assert tx.txid() != tx.wtxid()


@pytest.mark.parametrize(
    "mutate,match",
    [
        # scriptSig length 0 encoded non-minimally as fd 00 00
        (lambda raw: raw[:41] + bytes.fromhex("fd0000") + raw[42:], "non-canonical"),
        # absurd CompactSize for the input count
        (lambda raw: raw[:4] + bytes.fromhex("ffffffffffffffffff"), "MAX_SIZE|non-canonical"),
    ],
)
def test_deserialize_rejects_noncanonical(mutate, match):
    tx = Transaction(inputs=[TxIn(OutPoint(b"\x01" * 32, 0))], outputs=[TxOut(1, b"\x51")])
    raw = tx.serialize()
    with pytest.raises(ValueError, match=match):
        Transaction.deserialize(mutate(raw))


def test_deserialize_rejects_superfluous_witness():
    tx = Transaction(inputs=[TxIn(OutPoint(b"\x01" * 32, 0))], outputs=[TxOut(1, b"\x51")])
    raw = tx.serialize()  # no witness -> legacy encoding
    segwit_empty = raw[:4] + b"\x00\x01" + raw[4:-4] + b"\x00" + raw[-4:]
    with pytest.raises(ValueError, match="superfluous"):
        Transaction.deserialize(segwit_empty)


def test_deserialize_errors_are_value_errors():
    for bad in (b"", b"\x02\x00\x00\x00\xfd", b"\x02\x00\x00\x00\x01" + b"\x00" * 10):
        with pytest.raises(ValueError):
            Transaction.deserialize(bad)
