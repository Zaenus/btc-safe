"""
Minimal Bitcoin transaction model, serialization and signature hashing.

The witness v3 signature message reuses BIP-341's ``SigMsg`` construction
verbatim (so implementations can share code with Taproot), but hashes it under
a different tag::

    sighash = TaggedHash("PQSighash", 0x00 || SigMsg(hash_type, ext_flag=0))

``SigMsg`` commits to every input's amount and scriptPubKey, which closes the
fee-lying attack that BIP-143 left open for hardware wallets. Because the tag
differs from "TapSighash", a Taproot sighash can never equal a witness v3
sighash. ``signature_hash_bip341`` exposes the same code with the Taproot tag so
it can be checked against the official BIP-341 test vectors.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field

from .hashing import hash256, sha256, tagged_hash

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
VALID_HASH_TYPES = frozenset({0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83})

PQ_SIGHASH_TAG = "PQSighash"
TAP_SIGHASH_TAG = "TapSighash"

ANNEX_TAG = 0x50


# --- serialization primitives -------------------------------------------------


def ser_compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


MAX_SIZE = 0x02000000  # Bitcoin Core's limit for any serialized length


def read_compact_size(f: io.BytesIO) -> int:
    """Read a CompactSize, rejecting non-minimal encodings and values > MAX_SIZE."""
    first = _read_exact(f, 1)[0]
    if first < 0xFD:
        n = first
    elif first == 0xFD:
        n = struct.unpack("<H", _read_exact(f, 2))[0]
        if n < 0xFD:
            raise ValueError("non-canonical CompactSize")
    elif first == 0xFE:
        n = struct.unpack("<I", _read_exact(f, 4))[0]
        if n <= 0xFFFF:
            raise ValueError("non-canonical CompactSize")
    else:
        n = struct.unpack("<Q", _read_exact(f, 8))[0]
        if n <= 0xFFFFFFFF:
            raise ValueError("non-canonical CompactSize")
    if n > MAX_SIZE:
        raise ValueError("CompactSize exceeds MAX_SIZE")
    return n


def ser_bytes(b: bytes) -> bytes:
    return ser_compact_size(len(b)) + b


def read_bytes(f: io.BytesIO) -> bytes:
    return _read_exact(f, read_compact_size(f))


def _read_exact(f: io.BytesIO, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise ValueError("unexpected end of data")
    return data


# --- transaction model --------------------------------------------------------


@dataclass
class OutPoint:
    txid: bytes  # 32 bytes, internal (little-endian) byte order
    vout: int

    @classmethod
    def from_hex_txid(cls, txid_hex: str, vout: int) -> "OutPoint":
        """Build from a txid as displayed by explorers/RPC (big-endian hex)."""
        return cls(bytes.fromhex(txid_hex)[::-1], vout)

    def serialize(self) -> bytes:
        if len(self.txid) != 32:
            raise ValueError("txid must be 32 bytes")
        return self.txid + struct.pack("<I", self.vout)


@dataclass
class TxIn:
    prevout: OutPoint
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFD
    witness: list[bytes] = field(default_factory=list)


@dataclass
class TxOut:
    value: int  # satoshis
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return struct.pack("<q", self.value) + ser_bytes(self.script_pubkey)

    @classmethod
    def deserialize(cls, data: bytes) -> "TxOut":
        f = io.BytesIO(data)
        out = cls._read(f)
        if f.read():
            raise ValueError("trailing data after TxOut")
        return out

    @classmethod
    def _read(cls, f: io.BytesIO) -> "TxOut":
        value = struct.unpack("<q", _read_exact(f, 8))[0]
        return cls(value, read_bytes(f))


@dataclass
class Transaction:
    version: int = 2
    inputs: list[TxIn] = field(default_factory=list)
    outputs: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    def has_witness(self) -> bool:
        return any(inp.witness for inp in self.inputs)

    def serialize(self, include_witness: bool = True) -> bytes:
        with_wit = include_witness and self.has_witness()
        parts = [struct.pack("<i", self.version)]
        if with_wit:
            parts.append(b"\x00\x01")
        parts.append(ser_compact_size(len(self.inputs)))
        for inp in self.inputs:
            parts += [inp.prevout.serialize(), ser_bytes(inp.script_sig), struct.pack("<I", inp.sequence)]
        parts.append(ser_compact_size(len(self.outputs)))
        parts += [out.serialize() for out in self.outputs]
        if with_wit:
            for inp in self.inputs:
                parts.append(serialize_witness(inp.witness))
        parts.append(struct.pack("<I", self.locktime))
        return b"".join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> "Transaction":
        """Parse a transaction; any malformed input raises ValueError."""
        try:
            return cls._deserialize(data)
        except (struct.error, OverflowError, MemoryError) as e:
            raise ValueError(f"malformed transaction: {e}") from None

    @classmethod
    def _deserialize(cls, data: bytes) -> "Transaction":
        f = io.BytesIO(data)
        version = struct.unpack("<i", _read_exact(f, 4))[0]
        n_in = read_compact_size(f)
        segwit = False
        if n_in == 0:
            flag = _read_exact(f, 1)[0]
            if flag != 1:
                raise ValueError("invalid segwit flag")
            segwit = True
            n_in = read_compact_size(f)
        inputs = []
        for _ in range(n_in):
            txid = _read_exact(f, 32)
            vout = struct.unpack("<I", _read_exact(f, 4))[0]
            script_sig = read_bytes(f)
            sequence = struct.unpack("<I", _read_exact(f, 4))[0]
            inputs.append(TxIn(OutPoint(txid, vout), script_sig, sequence))
        outputs = [TxOut._read(f) for _ in range(read_compact_size(f))]
        if segwit:
            for inp in inputs:
                inp.witness = [read_bytes(f) for _ in range(read_compact_size(f))]
            if not any(inp.witness for inp in inputs):
                raise ValueError("superfluous witness record")
        locktime = struct.unpack("<I", _read_exact(f, 4))[0]
        if f.read():
            raise ValueError("trailing data after transaction")
        return cls(version, inputs, outputs, locktime)

    def txid(self) -> str:
        return hash256(self.serialize(include_witness=False))[::-1].hex()

    def wtxid(self) -> str:
        return hash256(self.serialize())[::-1].hex()

    def weight(self) -> int:
        base = len(self.serialize(include_witness=False))
        total = len(self.serialize())
        return base * 3 + total

    def vsize(self) -> int:
        return (self.weight() + 3) // 4


def serialize_witness(stack: list[bytes]) -> bytes:
    return ser_compact_size(len(stack)) + b"".join(ser_bytes(item) for item in stack)


def deserialize_witness(data: bytes) -> list[bytes]:
    f = io.BytesIO(data)
    stack = [read_bytes(f) for _ in range(read_compact_size(f))]
    if f.read():
        raise ValueError("trailing data after witness")
    return stack


# --- signature hashing --------------------------------------------------------


class SighashError(ValueError):
    pass


def sig_msg(
    tx: Transaction,
    input_index: int,
    spent_outputs: list[TxOut],
    hash_type: int,
    annex: bytes | None = None,
    ext_flag: int = 0,
) -> bytes:
    """
    BIP-341 ``SigMsg(hash_type, ext_flag)``, prefixed with the epoch byte 0x00.

    ``spent_outputs[i]`` must be the output spent by ``tx.inputs[i]``.
    """
    if hash_type not in VALID_HASH_TYPES:
        raise SighashError(f"invalid hash type 0x{hash_type:02x}")
    if len(spent_outputs) != len(tx.inputs):
        raise SighashError("need exactly one spent output per input")
    if not 0 <= input_index < len(tx.inputs):
        raise SighashError("input index out of range")

    out_type = SIGHASH_ALL if hash_type == SIGHASH_DEFAULT else hash_type & 3
    anyone_can_pay = bool(hash_type & SIGHASH_ANYONECANPAY)

    m = bytearray(b"\x00")  # epoch
    m.append(hash_type)
    m += struct.pack("<i", tx.version)
    m += struct.pack("<I", tx.locktime)
    if not anyone_can_pay:
        m += sha256(b"".join(i.prevout.serialize() for i in tx.inputs))
        m += sha256(b"".join(struct.pack("<q", o.value) for o in spent_outputs))
        m += sha256(b"".join(ser_bytes(o.script_pubkey) for o in spent_outputs))
        m += sha256(b"".join(struct.pack("<I", i.sequence) for i in tx.inputs))
    if out_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        m += sha256(b"".join(o.serialize() for o in tx.outputs))
    annex_present = annex is not None
    m.append(ext_flag * 2 + int(annex_present))
    if anyone_can_pay:
        inp = tx.inputs[input_index]
        m += inp.prevout.serialize()
        m += spent_outputs[input_index].serialize()
        m += struct.pack("<I", inp.sequence)
    else:
        m += struct.pack("<I", input_index)
    if annex_present:
        m += sha256(ser_bytes(annex))
    if out_type == SIGHASH_SINGLE:
        if input_index >= len(tx.outputs):
            raise SighashError("SIGHASH_SINGLE without a corresponding output")
        m += sha256(tx.outputs[input_index].serialize())
    return bytes(m)


def signature_hash(
    tx: Transaction,
    input_index: int,
    spent_outputs: list[TxOut],
    hash_type: int = SIGHASH_DEFAULT,
    annex: bytes | None = None,
) -> bytes:
    """The 32-byte message signed by a witness v3 input."""
    return tagged_hash(PQ_SIGHASH_TAG, sig_msg(tx, input_index, spent_outputs, hash_type, annex))


def signature_hash_bip341(
    tx: Transaction,
    input_index: int,
    spent_outputs: list[TxOut],
    hash_type: int = SIGHASH_DEFAULT,
    annex: bytes | None = None,
) -> bytes:
    """Taproot key-path sighash (for cross-checking against BIP-341 vectors)."""
    return tagged_hash(TAP_SIGHASH_TAG, sig_msg(tx, input_index, spent_outputs, hash_type, annex))
