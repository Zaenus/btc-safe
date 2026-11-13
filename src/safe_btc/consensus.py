"""
Reference validation rules for spending witness version 3 outputs.

This mirrors the "Spending rules" section of docs/bip/0001-pq-address-format.md
and is what the BIP test vectors are checked against. It is a specification
aid, not node software.

Consensus rules (when spending a *native* output whose scriptPubKey is
``OP_3 <program>``; P2SH-wrapped witness v3 programs are left unencumbered, as
BIP-341 does for v1):

1. The input's scriptSig must be empty.
2. If the program is not 32 bytes, the spend succeeds (left for future upgrades,
   exactly like BIP-341 does for witness v1).
3. If the witness stack has at least two elements and the last one starts with
   0x50, the last element is the annex and is removed (BIP-341 rule).
4. At least one element must remain. The last one is ``key_blob``.
5. ``key_blob`` must be non-empty, and
   ``TaggedHash("PQKeyCommit", key_blob)`` must equal the program.
6. ``key_type = key_blob[0]``. If ``key_type`` is 0x50, fail. If it is not
   defined, the spend succeeds regardless of the other elements (upgrade hook
   for future signature schemes; non-standard by policy).
7. For ``key_type = 0x01`` (ML-DSA-65):
   * the stack must be exactly ``[signature, key_blob]``;
   * the public key (``key_blob[1:]``) must be exactly 1,952 bytes;
   * the signature must be 3,309 bytes (hash type SIGHASH_DEFAULT) or 3,310
     bytes, where the last byte is the hash type and must be a valid,
     non-zero BIP-341 hash type;
   * ``ML-DSA.Verify(pk, sighash, sig, ctx="bitcoin:pq:tx")`` must succeed, where
     ``sighash = TaggedHash("PQSighash", 0x00 || SigMsg(hash_type, 0))``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hashing import tagged_hash
from .pq_addresses import COMMIT_TAG, KEY_TYPE_ML_DSA_65, KEY_TYPE_RESERVED_ANNEX, KEY_TYPES, OP_3
from .pq_signatures import CONTEXT_TX, MLDSA65, PUBLIC_KEY_SIZE, SIGNATURE_SIZE
from .transaction import (
    ANNEX_TAG,
    SIGHASH_DEFAULT,
    SighashError,
    Transaction,
    TxOut,
    VALID_HASH_TYPES,
    signature_hash,
)


class ValidationError(Exception):
    """A witness v3 spend that violates consensus rules."""


class PolicyError(Exception):
    """A spend that is consensus-valid but non-standard (not relayed)."""


@dataclass
class SpendResult:
    upgradable: bool  # True if the spend succeeded via an upgrade hook
    hash_type: int | None = None


def is_witness_v3(spk: bytes) -> bool:
    """True if ``spk`` is ``OP_3 <2..40 byte push>``."""
    return 4 <= len(spk) <= 42 and spk[0] == OP_3 and spk[1] == len(spk) - 2


def split_annex(witness: list[bytes]) -> tuple[list[bytes], bytes | None]:
    if len(witness) >= 2 and witness[-1] and witness[-1][0] == ANNEX_TAG:
        return witness[:-1], witness[-1]
    return list(witness), None


def verify_input(
    tx: Transaction,
    input_index: int,
    spent_outputs: list[TxOut],
) -> SpendResult:
    """
    Apply the consensus rules above to a native witness v3 input.
    Raises ``ValidationError`` on failure.
    """
    if len(spent_outputs) != len(tx.inputs):
        raise ValidationError("need exactly one spent output per input")
    spk = spent_outputs[input_index].script_pubkey
    if not is_witness_v3(spk):
        raise ValidationError("spent output is not a witness v3 program")
    inp = tx.inputs[input_index]
    if inp.script_sig:
        raise ValidationError("scriptSig must be empty for native witness programs")

    program = spk[2:]
    if len(program) != 32:
        return SpendResult(upgradable=True)

    stack, annex = split_annex(inp.witness)
    if not stack:
        raise ValidationError("empty witness stack")
    blob = stack[-1]
    if not blob:
        raise ValidationError("empty key blob")
    if tagged_hash(COMMIT_TAG, blob) != program:
        raise ValidationError("key blob does not match the output commitment")

    key_type = blob[0]
    if key_type == KEY_TYPE_RESERVED_ANNEX:
        raise ValidationError("key type 0x50 is reserved")
    if key_type not in KEY_TYPES:
        return SpendResult(upgradable=True)

    assert key_type == KEY_TYPE_ML_DSA_65
    if len(stack) != 2:
        raise ValidationError(f"expected 2 witness elements, got {len(stack)}")
    sig = stack[0]
    public_key = blob[1:]
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValidationError("wrong ML-DSA-65 public key length")
    if len(sig) == SIGNATURE_SIZE:
        hash_type = SIGHASH_DEFAULT
    elif len(sig) == SIGNATURE_SIZE + 1:
        hash_type = sig[-1]
        sig = sig[:-1]
        if hash_type == SIGHASH_DEFAULT or hash_type not in VALID_HASH_TYPES:
            raise ValidationError(f"invalid explicit hash type 0x{hash_type:02x}")
    else:
        raise ValidationError("wrong ML-DSA-65 signature length")

    try:
        msg = signature_hash(tx, input_index, spent_outputs, hash_type, annex)
    except SighashError as e:
        raise ValidationError(str(e)) from None
    if not MLDSA65.verify(public_key, msg, sig, CONTEXT_TX):
        raise ValidationError("ML-DSA-65 signature verification failed")
    return SpendResult(upgradable=False, hash_type=hash_type)


def check_policy(tx: Transaction, input_index: int, spent_outputs: list[TxOut]) -> None:
    """
    Standardness rules proposed for relay (on top of consensus):

    * no annex (as for Taproot today);
    * the key type must be defined (no upgrade-hook spends);
    * witness program must be 32 bytes.
    """
    spk = spent_outputs[input_index].script_pubkey
    if len(spk) != 34:
        raise PolicyError("non-32-byte witness v3 programs are non-standard")
    stack, annex = split_annex(tx.inputs[input_index].witness)
    if annex is not None:
        raise PolicyError("annex is non-standard")
    if not stack or not stack[-1] or stack[-1][0] not in KEY_TYPES:
        raise PolicyError("undefined key type is non-standard")
