"""PSBT (BIP-174 v0) with proprietary post-quantum fields."""

from __future__ import annotations

import io

import pytest

from safe_btc.consensus import ValidationError, verify_input
from safe_btc.keys import parse_path
from safe_btc.pq_addresses import compute_commitment, script_pubkey
from safe_btc.psbt import MAGIC, PQPsbt, _parse_prop_key, _prop_key, _read_map
from safe_btc.transaction import OutPoint, Transaction, TxIn, TxOut


def _setup(keypair, keypair2):
    spk1 = script_pubkey(compute_commitment(keypair.public_key))
    spk2 = script_pubkey(compute_commitment(keypair2.public_key))
    tx = Transaction(
        inputs=[TxIn(OutPoint(b"\x01" * 32, 0)), TxIn(OutPoint(b"\x02" * 32, 3))],
        outputs=[TxOut(150_000, spk2), TxOut(40_000, bytes.fromhex("0014" + "33" * 20))],
    )
    spent = [TxOut(100_000, spk1), TxOut(100_000, spk2)]
    return tx, spent


def test_proprietary_keys_do_not_collide_with_bip174(keypair, keypair2):
    """Regression: 0.1 proposed input types 0x07/0x08 (FINAL_SCRIPTSIG/WITNESS)."""
    for sub in (0, 1, 2):
        key = _prop_key(sub)
        assert key[0] == 0xFC
        assert _parse_prop_key(key) == sub
    tx, spent = _setup(keypair, keypair2)
    psbt = PQPsbt.create(tx, spent)
    psbt.sign_input(0, keypair, derivation=(b"\x00" * 4, "m/3'/1'/0'/0'"))
    f = io.BytesIO(psbt.serialize()[len(MAGIC):])
    list(_read_map(f))  # global map
    input_keys = [k for k, _ in _read_map(f)]
    assert input_keys[0] == b"\x01"  # WITNESS_UTXO
    assert all(k[0] == 0xFC for k in input_keys[1:])
    assert len(input_keys) == 4


def test_sign_finalize_extract(keypair, keypair2):
    tx, spent = _setup(keypair, keypair2)
    psbt = PQPsbt.create(tx, spent)
    assert psbt.fee() == 10_000
    psbt.sign_input(0, keypair, derivation=(b"\xaa\xbb\xcc\xdd", "m/3'/1'/0'/0'"))
    assert not psbt.is_fully_signed()
    psbt.sign_input(1, keypair2, hash_type=0x01)
    assert psbt.is_fully_signed()

    again = PQPsbt.from_base64(psbt.to_base64())
    assert again.serialize() == psbt.serialize()
    assert again.inputs[0].derivation == (b"\xaa\xbb\xcc\xdd", parse_path("m/3'/1'/0'/0'"))

    again.finalize()
    final = PQPsbt.parse(again.serialize())
    signed = final.extract()
    for i in range(2):
        assert not verify_input(signed, i, spent).upgradable
    assert len(signed.inputs[1].witness[0]) == 3310
    # input 1 carries an explicit hash type byte, one witness byte more than the estimate
    assert 0 <= signed.vsize() - psbt.estimated_vsize() <= 1


def test_wrong_key_refused(keypair, keypair2):
    tx, spent = _setup(keypair, keypair2)
    psbt = PQPsbt.create(tx, spent)
    with pytest.raises(ValueError, match="does not match"):
        psbt.sign_input(0, keypair2)


def test_sighash_type_request_respected(keypair, keypair2):
    tx, spent = _setup(keypair, keypair2)
    psbt = PQPsbt.create(tx, spent)
    psbt.inputs[0].sighash_type = 0x83
    with pytest.raises(ValueError, match="hash type"):
        psbt.sign_input(0, keypair)
    psbt.sign_input(0, keypair, hash_type=0x83)


def test_missing_witness_utxo(keypair, keypair2):
    tx, _ = _setup(keypair, keypair2)
    with pytest.raises(ValueError, match="WITNESS_UTXO"):
        PQPsbt(tx).sign_input(0, keypair)


def test_extract_rejects_tampering(keypair, keypair2):
    tx, spent = _setup(keypair, keypair2)
    psbt = PQPsbt.create(tx, spent)
    psbt.sign_input(0, keypair)
    psbt.sign_input(1, keypair2)
    psbt.finalize()
    psbt.tx.outputs[0].value += 1
    with pytest.raises(ValidationError):
        psbt.extract()


def test_unknown_fields_round_trip(keypair, keypair2):
    tx, spent = _setup(keypair, keypair2)
    psbt = PQPsbt.create(tx, spent)
    psbt.unknown_global.append((b"\xfc\x05other\x00", b"\x02"))
    psbt.inputs[1].unknown.append((b"\x13", b"\x00" * 64))
    psbt.outputs[0].unknown.append((b"\xfc\x03abc\x00", b"x"))
    again = PQPsbt.parse(psbt.serialize())
    assert again.serialize() == psbt.serialize()


def test_parse_rejects_garbage():
    with pytest.raises(ValueError):
        PQPsbt.parse(b"notapsbt")


def _raw_psbt(global_kvs, input_kvs, tx):
    from safe_btc.psbt import _kv
    out = bytearray(MAGIC) + _kv(b"\x00", tx.serialize(include_witness=False))
    for k, v in global_kvs:
        out += _kv(k, v)
    out += b"\x00"
    for k, v in input_kvs:
        out += _kv(k, v)
    out += b"\x00" + b"\x00" * len(tx.outputs)
    return bytes(out)


@pytest.mark.parametrize(
    "global_kvs,input_kvs,match",
    [
        ([], [(b"\x01\xaa", b"")], "keydata"),                     # fixed type with keydata
        ([(b"\xfb", b"\x02\x00\x00\x00")], [], "version"),          # PSBT v2 marker
        ([], [(b"\x03", b"\x01\x00")], "4 bytes"),                  # bad SIGHASH_TYPE length
        ([], [(b"\xfc\x07safebtc\x01", b"A"), (b"\xfc\x07safebtc\xfd\x01\x00", b"B")], "CompactSize"),
    ],
)
def test_parse_rejects_malformed_maps(keypair, keypair2, global_kvs, input_kvs, match):
    tx, _ = _setup(keypair, keypair2)
    tx.inputs = tx.inputs[:1]
    with pytest.raises(ValueError, match=match):
        PQPsbt.parse(_raw_psbt(global_kvs, input_kvs, tx))


def test_parse_rejects_duplicate_keys(keypair, keypair2):
    tx, _ = _setup(keypair, keypair2)
    tx.inputs = tx.inputs[:1]
    kv = (b"\xfc\x07safebtc\x01", b"A")
    with pytest.raises(ValueError, match="duplicate"):
        PQPsbt.parse(_raw_psbt([], [kv, (kv[0], b"B")], tx))
