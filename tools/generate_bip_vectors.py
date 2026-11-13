#!/usr/bin/env python3
"""
Generate docs/bip/0001-test-vectors.json for the witness v3 BIP draft.

Signatures use FIPS 204 *deterministic* ML-DSA signing from dilithium-py (an
independent implementation), so re-running this script reproduces the file
byte for byte. Every vector is then re-checked with safe-btc's own validator
(OpenSSL-backed), so the file is cross-checked across two implementations.

    pip install -e ".[dev]"
    python tools/generate_bip_vectors.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

from safe_btc.consensus import ValidationError, check_policy, PolicyError, verify_input
from safe_btc.hashing import tagged_hash
from safe_btc.keys import derive_seed, mnemonic_to_seed
from safe_btc.pq_addresses import (
    COMMIT_TAG,
    KEY_TYPE_ML_DSA_65,
    NETWORK_HRPS,
    address_from_public_key,
    compute_commitment,
    key_blob,
    script_pubkey,
)
from safe_btc.pq_signatures import CONTEXT_MSG, CONTEXT_TX, MLDSA65
from safe_btc.transaction import (
    PQ_SIGHASH_TAG,
    VALID_HASH_TYPES,
    OutPoint,
    Transaction,
    TxIn,
    TxOut,
    sig_msg,
    signature_hash,
)

OUT = Path(__file__).resolve().parent.parent / "docs" / "bip" / "0001-test-vectors.json"


def seed_for(label: str) -> bytes:
    return hashlib.sha256(b"safe-btc test vector " + label.encode()).digest()


class Key:
    def __init__(self, label: str):
        self.seed = seed_for(label)
        self.pk, self.sk = ML_DSA_65.key_derive(self.seed)
        assert self.pk == MLDSA65.keypair_from_seed(self.seed)[0], "OpenSSL/dilithium-py keygen mismatch"
        self.blob = key_blob(self.pk)
        self.spk = script_pubkey(compute_commitment(self.pk))

    def sign(self, msg: bytes, ctx: bytes = CONTEXT_TX) -> bytes:
        return ML_DSA_65.sign(self.sk, msg, ctx=ctx, deterministic=True)


def txout_json(o: TxOut) -> dict:
    return {"value": o.value, "scriptPubKey": o.script_pubkey.hex()}


def main() -> int:
    k1, k2 = Key("key 1"), Key("key 2")

    # --- keys ------------------------------------------------------------------
    keys = []
    for k in (k1, k2):
        keys.append(
            {
                "seed": k.seed.hex(),
                "key_type": KEY_TYPE_ML_DSA_65,
                "public_key_sha256": hashlib.sha256(k.pk).hexdigest(),
                "public_key": k.pk.hex(),
                "commitment": compute_commitment(k.pk).hex(),
                "scriptPubKey": k.spk.hex(),
                "addresses": {net: address_from_public_key(k.pk, net) for net in ("mainnet", "testnet", "regtest")},
            }
        )

    # --- derivation ---------------------------------------------------------------
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    derivation = []
    for passphrase, path in [("", "m/3'/0'/0'/0'"), ("", "m/3'/1'/0'/0'"), ("TREZOR", "m/3'/1'/0'/1'")]:
        xi = derive_seed(mnemonic_to_seed(mnemonic, passphrase), path)
        pk = MLDSA65.keypair_from_seed(xi)[0]
        derivation.append(
            {
                "mnemonic": mnemonic,
                "passphrase": passphrase,
                "path": path,
                "keygen_seed": xi.hex(),
                "public_key_sha256": hashlib.sha256(pk).hexdigest(),
                "address_testnet": address_from_public_key(pk, "testnet"),
            }
        )

    # --- sighash ------------------------------------------------------------------
    p2wpkh = TxOut(70_000, bytes.fromhex("0014" + "a1" * 20))
    spent3 = [TxOut(100_000, k1.spk), p2wpkh, TxOut(250_000, k2.spk)]
    tx3 = Transaction(
        version=2,
        inputs=[
            TxIn(OutPoint(hashlib.sha256(b"prev0").digest(), 0), sequence=0xFFFFFFFD),
            TxIn(OutPoint(hashlib.sha256(b"prev1").digest(), 7), sequence=0xFFFFFFFE),
            TxIn(OutPoint(hashlib.sha256(b"prev2").digest(), 1), sequence=0),
        ],
        outputs=[TxOut(300_000, k2.spk), TxOut(110_000, bytes.fromhex("5120" + "b2" * 32))],
        locktime=900_000,
    )
    sighashes = []
    for hash_type in sorted(VALID_HASH_TYPES):
        for annex in (None, bytes.fromhex("50aabbcc")):
            for idx in (0, 2):
                if hash_type & 3 == 3 and idx >= len(tx3.outputs):
                    continue
                sighashes.append(
                    {
                        "tx": tx3.serialize().hex(),
                        "spent_outputs": [txout_json(o) for o in spent3],
                        "input_index": idx,
                        "hash_type": hash_type,
                        "annex": annex.hex() if annex else None,
                        "sig_msg": sig_msg(tx3, idx, spent3, hash_type, annex).hex(),
                        "sighash": signature_hash(tx3, idx, spent3, hash_type, annex).hex(),
                    }
                )

    # --- spends -------------------------------------------------------------------
    spends = []

    def base_tx(n_in: int = 1, outputs: list[TxOut] | None = None) -> Transaction:
        return Transaction(
            version=2,
            inputs=[TxIn(OutPoint(hashlib.sha256(b"funding %d" % i).digest(), i)) for i in range(n_in)],
            outputs=outputs if outputs is not None else [TxOut(90_000, k2.spk)],
            locktime=0,
        )

    def add(desc, tx, spent, idx, valid, standard=None, upgradable=False, error=None):
        try:
            res = verify_input(tx, idx, spent)
            got_valid, got_upg, got_err = True, res.upgradable, None
        except ValidationError as e:
            got_valid, got_upg, got_err = False, False, str(e)
        assert got_valid == valid, (desc, got_err)
        assert got_upg == upgradable, desc
        if valid:
            try:
                check_policy(tx, idx, spent)
                got_std = True
            except PolicyError:
                got_std = False
            assert standard is None or got_std == standard, desc
        else:
            got_std = False
        spends.append(
            {
                "description": desc,
                "tx": tx.serialize().hex(),
                "spent_outputs": [txout_json(o) for o in spent],
                "input_index": idx,
                "valid": valid,
                "upgradable": upgradable,
                "standard": got_std,
                "error": got_err,
            }
        )

    def signed(key, tx, spent, idx, hash_type=0, annex=None, ctx=CONTEXT_TX):
        sig = key.sign(signature_hash(tx, idx, spent, hash_type, annex), ctx)
        return sig + (bytes([hash_type]) if hash_type else b"")

    spent = [TxOut(100_000, k1.spk)]

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0), k1.blob]
    add("valid: SIGHASH_DEFAULT (3309-byte signature)", tx, spent, 0, True, standard=True)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0, 0x01), k1.blob]
    add("valid: explicit SIGHASH_ALL (3310-byte signature)", tx, spent, 0, True, standard=True)

    spent2 = [TxOut(100_000, k1.spk), TxOut(60_000, k2.spk)]
    names = {0x00: "SIGHASH_DEFAULT", 0x01: "SIGHASH_ALL", 0x02: "SIGHASH_NONE", 0x03: "SIGHASH_SINGLE",
             0x81: "SIGHASH_ALL|ANYONECANPAY", 0x82: "SIGHASH_NONE|ANYONECANPAY",
             0x83: "SIGHASH_SINGLE|ANYONECANPAY"}
    for ht in sorted(VALID_HASH_TYPES):
        tx = base_tx(2, [TxOut(50_000, k2.spk), TxOut(100_000, k1.spk)])
        tx.inputs[0].witness = [signed(k1, tx, spent2, 0, ht), k1.blob]
        tx.inputs[1].witness = [signed(k2, tx, spent2, 1, 0x02), k2.blob]
        add(f"valid: {names[ht]}, input 0 of 2", tx, spent2, 0, True, standard=True)
    add("valid: SIGHASH_NONE, input 1 of 2", tx, spent2, 1, True, standard=True)

    annex = bytes.fromhex("50deadbeef")
    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0, 0, annex), k1.blob, annex]
    add("valid but non-standard: annex present (committed in the sighash)", tx, spent, 0, True, standard=False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0, 0, annex), k1.blob, bytes.fromhex("50deadbeee")]
    add("invalid: annex differs from the one signed", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0, ctx=CONTEXT_MSG), k1.blob]
    add("invalid: signature made with the message-signing context", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0) + b"\x00", k1.blob]
    add("invalid: explicit hash type byte 0x00", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0, 0x01)[:-1] + b"\x04", k1.blob]
    add("invalid: undefined hash type 0x04", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k2, tx, spent, 0), k2.blob]
    add("invalid: valid signature by a key that does not match the commitment", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [b"\x01", signed(k1, tx, spent, 0), k1.blob]
    add("invalid: ML-DSA-65 spend with three witness elements", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0), k1.blob, b"\x01"]
    add("invalid: extra element after the key blob (last element must be the key blob)", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0)[:-1], k1.blob]
    add("invalid: truncated signature (3308 bytes)", tx, spent, 0, False)

    tx = base_tx(); sig = signed(k1, tx, spent, 0); tx.outputs[0].value -= 1
    tx.inputs[0].witness = [sig, k1.blob]
    add("invalid: transaction modified after signing", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0), k1.blob]; tx.inputs[0].script_sig = b"\x51"
    add("invalid: non-empty scriptSig", tx, spent, 0, False)

    tx = base_tx(2, [TxOut(150_000, k2.spk)])
    # Sign what a lenient implementation might compute (SigMsg without
    # sha_single_output), so this vector actually tests the rule.
    padded = Transaction.deserialize(tx.serialize())
    padded.outputs.append(TxOut(0, b"\x6a"))
    lenient = tagged_hash(PQ_SIGHASH_TAG, sig_msg(padded, 1, spent2, 0x03)[:-32])
    tx.inputs[1].witness = [k2.sign(lenient) + b"\x03", k2.blob]
    add("invalid: SIGHASH_SINGLE without a corresponding output", tx, spent2, 1, False)

    tx = base_tx(); tx.inputs[0].witness = []
    add("invalid: empty witness", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [k1.blob]
    add("invalid: key blob without a signature (1 element)", tx, spent, 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0), b""]
    add("invalid: empty key blob", tx, spent, 0, False)

    short_blob = bytes([KEY_TYPE_ML_DSA_65]) + k1.pk[:-1]
    spk_short = script_pubkey(tagged_hash(COMMIT_TAG, short_blob))
    tx = base_tx(); tx.inputs[0].witness = [b"\x00" * 3309, short_blob]
    add("invalid: ML-DSA-65 key blob with a 1,951-byte public key", tx, [TxOut(100_000, spk_short)], 0, False)

    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, spent, 0, 0x01) + b"\x01", k1.blob]
    add("invalid: 3,311-byte signature", tx, spent, 0, False)

    blob50 = bytes([0x50]) + k1.pk
    spk50 = script_pubkey(tagged_hash(COMMIT_TAG, blob50))
    tx = base_tx(); tx.inputs[0].witness = [signed(k1, tx, [TxOut(100_000, spk50)], 0), blob50]
    add("invalid: key blob starting with 0x50 is parsed as an annex", tx, [TxOut(100_000, spk50)], 0, False)

    tx = base_tx(); tx.inputs[0].witness = [b"junk", blob50, b"\x50"]
    add("invalid: key type 0x50 with an annex (reserved key type)", tx, [TxOut(100_000, spk50)], 0, False)

    blob_future = bytes([0x02]) + b"future scheme public key"
    spk_future = script_pubkey(tagged_hash(COMMIT_TAG, blob_future))
    tx = base_tx(); tx.inputs[0].witness = [b"anything", blob_future]
    add("valid (upgrade hook), non-standard: undefined key type 0x02", tx, [TxOut(100_000, spk_future)], 0,
        True, standard=False, upgradable=True)

    tx = base_tx(); tx.inputs[0].witness = [b"a", b"b", b"c", blob_future]
    add("valid (upgrade hook), non-standard: undefined key type 0x02 with 4 elements", tx,
        [TxOut(100_000, spk_future)], 0, True, standard=False, upgradable=True)

    spk20 = bytes([0x53, 20]) + b"\x33" * 20
    tx = base_tx(); tx.inputs[0].witness = []
    add("valid (upgrade hook), non-standard: 20-byte witness v3 program", tx, [TxOut(100_000, spk20)], 0,
        True, standard=False, upgradable=True)

    doc = {
        "title": "Test vectors for the witness v3 ML-DSA-65 BIP draft",
        "generator": "tools/generate_bip_vectors.py (deterministic ML-DSA signing via dilithium-py)",
        "constants": {
            "witness_version": 3,
            "key_type_ml_dsa_65": KEY_TYPE_ML_DSA_65,
            "commit_tag": COMMIT_TAG,
            "sighash_tag": PQ_SIGHASH_TAG,
            "fips204_context_tx": CONTEXT_TX.decode(),
            "fips204_context_msg": CONTEXT_MSG.decode(),
            "hrps": NETWORK_HRPS,
        },
        "keys": keys,
        "derivation": derivation,
        "sighash": sighashes,
        "spends": spends,
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wrote {OUT} ({len(keys)} keys, {len(derivation)} derivations, "
          f"{len(sighashes)} sighashes, {len(spends)} spends)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
