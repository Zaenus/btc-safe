"""
BIP-174 (PSBT v0) support for spending witness v3 outputs.

Standard fields used: PSBT_GLOBAL_UNSIGNED_TX (0x00), PSBT_IN_WITNESS_UTXO
(0x01), PSBT_IN_SIGHASH_TYPE (0x03), PSBT_IN_FINAL_SCRIPTWITNESS (0x08).

Post-quantum fields have no assigned type numbers yet, so they live under the
proprietary type 0xFC with identifier ``b"safebtc"`` (BIP-174 allows this for
experimental fields and requires other software to pass them through):

=========  ==========================  ====================================
subtype    name                        value
=========  ==========================  ====================================
0x00       PQ_KEY_BLOB                 key_type || public_key
0x01       PQ_SIGNATURE                signature [|| hash_type]
0x02       PQ_DERIVATION               fingerprint(4) || path (u32 LE each)
=========  ==========================  ====================================

Earlier versions of this code proposed types 0x07/0x08, which collide with
PSBT_IN_FINAL_SCRIPTSIG and PSBT_IN_FINAL_SCRIPTWITNESS.

Signing computes the sighash itself from the unsigned transaction and the
WITNESS_UTXO of every input; callers never pass in a "message to sign".
"""

from __future__ import annotations

import base64
import io
import struct
from dataclasses import dataclass, field

from .consensus import verify_input
from .keys import parse_path
from .pq_addresses import KEY_TYPE_ML_DSA_65, compute_commitment, key_blob, parse_script_pubkey
from .pq_signatures import CONTEXT_TX, PUBLIC_KEY_SIZE, SIGNATURE_SIZE, KeyPair, MLDSA65
from .transaction import (
    SIGHASH_DEFAULT,
    VALID_HASH_TYPES,
    Transaction,
    TxOut,
    deserialize_witness,
    read_bytes,
    ser_bytes,
    ser_compact_size,
    read_compact_size,
    serialize_witness,
    signature_hash,
)

MAGIC = b"psbt\xff"

PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_VERSION = 0xFB
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
PSBT_PROPRIETARY = 0xFC

PROPRIETARY_ID = b"safebtc"
PQ_KEY_BLOB = 0x00
PQ_SIGNATURE = 0x01
PQ_DERIVATION = 0x02


def _prop_key(subtype: int) -> bytes:
    return bytes([PSBT_PROPRIETARY]) + ser_bytes(PROPRIETARY_ID) + ser_compact_size(subtype)


def _parse_prop_key(key: bytes) -> int | None:
    """Return our subtype if ``key`` is one of our proprietary keys, else None."""
    if not key or key[0] != PSBT_PROPRIETARY:
        return None
    f = io.BytesIO(key[1:])
    try:
        ident = read_bytes(f)
        subtype = read_compact_size(f)
    except ValueError:
        return None
    if ident != PROPRIETARY_ID or f.read():
        return None
    return subtype


@dataclass
class PsbtInput:
    witness_utxo: TxOut | None = None
    sighash_type: int | None = None
    key_blob: bytes | None = None
    signature: bytes | None = None
    derivation: tuple[bytes, list[int]] | None = None  # (fingerprint, path)
    final_witness: list[bytes] | None = None
    unknown: list[tuple[bytes, bytes]] = field(default_factory=list)


@dataclass
class PsbtOutput:
    unknown: list[tuple[bytes, bytes]] = field(default_factory=list)


class PQPsbt:
    """A PSBT whose inputs spend witness v3 (ML-DSA-65) outputs."""

    def __init__(
        self,
        tx: Transaction,
        inputs: list[PsbtInput] | None = None,
        outputs: list[PsbtOutput] | None = None,
    ):
        if any(i.script_sig or i.witness for i in tx.inputs):
            raise ValueError("PSBT unsigned transaction must have empty scriptSigs and witnesses")
        self.tx = tx
        self.inputs = inputs or [PsbtInput() for _ in tx.inputs]
        self.outputs = outputs or [PsbtOutput() for _ in tx.outputs]
        self.unknown_global: list[tuple[bytes, bytes]] = []
        if len(self.inputs) != len(tx.inputs) or len(self.outputs) != len(tx.outputs):
            raise ValueError("input/output map count does not match the transaction")

    @classmethod
    def create(cls, tx: Transaction, spent_outputs: list[TxOut]) -> "PQPsbt":
        """Create a PSBT, recording the output each input spends."""
        if len(spent_outputs) != len(tx.inputs):
            raise ValueError("need exactly one spent output per input")
        psbt = cls(tx)
        for pin, utxo in zip(psbt.inputs, spent_outputs):
            pin.witness_utxo = utxo
        return psbt

    # --- roles ------------------------------------------------------------------

    def spent_outputs(self) -> list[TxOut]:
        missing = [i for i, p in enumerate(self.inputs) if p.witness_utxo is None]
        if missing:
            raise ValueError(f"inputs {missing} lack WITNESS_UTXO (needed for the sighash)")
        return [p.witness_utxo for p in self.inputs]  # type: ignore[misc]

    def sign_input(
        self,
        index: int,
        keypair: KeyPair,
        hash_type: int = SIGHASH_DEFAULT,
        derivation: tuple[bytes, str] | None = None,
    ) -> None:
        """Sign input ``index`` with an ML-DSA-65 key (Signer role)."""
        if not 0 <= index < len(self.inputs):
            raise IndexError(f"input index {index} out of range")
        if hash_type not in VALID_HASH_TYPES:
            raise ValueError(f"invalid hash type 0x{hash_type:02x}")
        pin = self.inputs[index]
        if pin.sighash_type is not None and pin.sighash_type != hash_type:
            raise ValueError("hash type differs from the PSBT_IN_SIGHASH_TYPE requested")
        spent = self.spent_outputs()
        commitment = parse_script_pubkey(spent[index].script_pubkey)
        if commitment is None:
            raise ValueError(f"input {index} does not spend a witness v3 output")
        if commitment != compute_commitment(keypair.public_key, KEY_TYPE_ML_DSA_65):
            raise ValueError(f"key does not match the output spent by input {index}")
        msg = signature_hash(self.tx, index, spent, hash_type)
        sig = MLDSA65.sign(keypair.seed, msg, CONTEXT_TX)
        if hash_type != SIGHASH_DEFAULT:
            sig += bytes([hash_type])
        pin.key_blob = key_blob(keypair.public_key, KEY_TYPE_ML_DSA_65)
        pin.signature = sig
        if derivation is not None:
            fingerprint, path = derivation
            pin.derivation = (fingerprint, parse_path(path))

    def finalize(self) -> None:
        """Move signatures into PSBT_IN_FINAL_SCRIPTWITNESS (Finalizer role)."""
        for i, pin in enumerate(self.inputs):
            if pin.final_witness is not None:
                continue
            if pin.signature is None or pin.key_blob is None:
                raise ValueError(f"input {i} is not signed")
            pin.final_witness = [pin.signature, pin.key_blob]
            pin.signature = pin.key_blob = pin.derivation = pin.sighash_type = None

    def is_fully_signed(self) -> bool:
        return all(p.final_witness is not None or p.signature is not None for p in self.inputs)

    def extract(self) -> Transaction:
        """Return the signed transaction after checking every input (Extractor)."""
        spent = self.spent_outputs()
        tx = Transaction.deserialize(self.tx.serialize())
        for i, pin in enumerate(self.inputs):
            if pin.final_witness is None:
                raise ValueError(f"input {i} is not finalized")
            tx.inputs[i].witness = list(pin.final_witness)
        for i in range(len(tx.inputs)):
            if parse_script_pubkey(spent[i].script_pubkey) is not None:
                verify_input(tx, i, spent)
        return tx

    def fee(self) -> int:
        return sum(o.value for o in self.spent_outputs()) - sum(o.value for o in self.tx.outputs)

    def estimated_vsize(self) -> int:
        """vsize once every input carries a default-sighash ML-DSA-65 witness."""
        tx = Transaction.deserialize(self.tx.serialize())
        for inp in tx.inputs:
            inp.witness = [b"\x00" * SIGNATURE_SIZE, b"\x00" * (1 + PUBLIC_KEY_SIZE)]
        return tx.vsize()

    # --- serialization ------------------------------------------------------------

    def serialize(self) -> bytes:
        out = bytearray(MAGIC)
        out += _kv(bytes([PSBT_GLOBAL_UNSIGNED_TX]), self.tx.serialize(include_witness=False))
        for k, v in self.unknown_global:
            out += _kv(k, v)
        out += b"\x00"
        for pin in self.inputs:
            if pin.witness_utxo is not None:
                out += _kv(bytes([PSBT_IN_WITNESS_UTXO]), pin.witness_utxo.serialize())
            if pin.sighash_type is not None:
                out += _kv(bytes([PSBT_IN_SIGHASH_TYPE]), struct.pack("<I", pin.sighash_type))
            if pin.final_witness is not None:
                out += _kv(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), serialize_witness(pin.final_witness))
            if pin.key_blob is not None:
                out += _kv(_prop_key(PQ_KEY_BLOB), pin.key_blob)
            if pin.signature is not None:
                out += _kv(_prop_key(PQ_SIGNATURE), pin.signature)
            if pin.derivation is not None:
                fp, path = pin.derivation
                out += _kv(_prop_key(PQ_DERIVATION), fp + b"".join(struct.pack("<I", c) for c in path))
            for k, v in pin.unknown:
                out += _kv(k, v)
            out += b"\x00"
        for pout in self.outputs:
            for k, v in pout.unknown:
                out += _kv(k, v)
            out += b"\x00"
        return bytes(out)

    def to_base64(self) -> str:
        return base64.b64encode(self.serialize()).decode()

    @classmethod
    def parse(cls, data: bytes) -> "PQPsbt":
        """Parse a PSBT v0; any malformed input raises ValueError."""
        try:
            return cls._parse(data)
        except (struct.error, OverflowError, IndexError) as e:
            raise ValueError(f"malformed PSBT: {e}") from None

    @classmethod
    def _parse(cls, data: bytes) -> "PQPsbt":
        f = io.BytesIO(data)
        if f.read(5) != MAGIC:
            raise ValueError("not a PSBT (bad magic)")
        tx = None
        unknown_global = []
        for k, v in _read_map(f):
            _check_key_length(k, {PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION})
            if k == bytes([PSBT_GLOBAL_UNSIGNED_TX]):
                tx = Transaction.deserialize(v)
                if tx.has_witness() or any(i.script_sig for i in tx.inputs):
                    raise ValueError("PSBT unsigned transaction must not carry signatures")
                if v != tx.serialize(include_witness=False):
                    raise ValueError("PSBT unsigned transaction must use the legacy encoding")
            elif k == bytes([PSBT_GLOBAL_VERSION]):
                if v != b"\x00\x00\x00\x00":
                    raise ValueError("only PSBT version 0 is supported")
                unknown_global.append((k, v))
            else:
                unknown_global.append((k, v))
        if tx is None:
            raise ValueError("PSBT lacks the unsigned transaction")
        inputs = []
        for _ in tx.inputs:
            pin = PsbtInput()
            for k, v in _read_map(f):
                _check_key_length(k, {PSBT_IN_WITNESS_UTXO, PSBT_IN_SIGHASH_TYPE, PSBT_IN_FINAL_SCRIPTWITNESS})
                sub = _parse_prop_key(k)
                if k == bytes([PSBT_IN_WITNESS_UTXO]):
                    pin.witness_utxo = TxOut.deserialize(v)
                elif k == bytes([PSBT_IN_SIGHASH_TYPE]):
                    if len(v) != 4:
                        raise ValueError("PSBT_IN_SIGHASH_TYPE must be 4 bytes")
                    pin.sighash_type = struct.unpack("<I", v)[0]
                elif k == bytes([PSBT_IN_FINAL_SCRIPTWITNESS]):
                    pin.final_witness = deserialize_witness(v)
                elif sub == PQ_KEY_BLOB:
                    pin.key_blob = v
                elif sub == PQ_SIGNATURE:
                    pin.signature = v
                elif sub == PQ_DERIVATION:
                    if len(v) < 4 or (len(v) - 4) % 4:
                        raise ValueError("malformed PQ_DERIVATION")
                    path = [struct.unpack("<I", v[i : i + 4])[0] for i in range(4, len(v), 4)]
                    pin.derivation = (v[:4], path)
                else:
                    pin.unknown.append((k, v))
            inputs.append(pin)
        outputs = [PsbtOutput(unknown=list(_read_map(f))) for _ in tx.outputs]
        if f.read():
            raise ValueError("trailing data after PSBT")
        psbt = cls(tx, inputs, outputs)
        psbt.unknown_global = unknown_global
        return psbt

    @classmethod
    def from_base64(cls, s: str) -> "PQPsbt":
        return cls.parse(base64.b64decode(s, validate=True))


def _kv(key: bytes, value: bytes) -> bytes:
    return ser_bytes(key) + ser_bytes(value)


def _check_key_length(key: bytes, single_byte_types: set[int]) -> None:
    """Fixed-type keys defined without keydata must be exactly one byte (BIP-174)."""
    if key[0] in single_byte_types and len(key) != 1:
        raise ValueError(f"key type 0x{key[0]:02x} must not carry keydata")


def _canonical_key(key: bytes) -> bytes:
    """Re-encode a key so duplicates that differ only in encoding are caught."""
    sub = _parse_prop_key(key)
    if key and key[0] == PSBT_PROPRIETARY and sub is None:
        f = io.BytesIO(key[1:])
        ident = read_bytes(f)
        subtype = read_compact_size(f)
        return bytes([PSBT_PROPRIETARY]) + ser_bytes(ident) + ser_compact_size(subtype) + f.read()
    return key


def _read_map(f: io.BytesIO):
    seen = set()
    while True:
        key = read_bytes(f)
        if not key:
            return
        canonical = _canonical_key(key)
        if canonical in seen:
            raise ValueError("duplicate key in PSBT map")
        seen.add(canonical)
        yield key, read_bytes(f)
