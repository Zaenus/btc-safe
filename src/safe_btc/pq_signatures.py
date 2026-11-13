"""
ML-DSA-65 (FIPS 204) post-quantum signatures for Bitcoin witness v3.

Backed by OpenSSL through the ``cryptography`` package. Keys are derived from
a 32-byte seed (FIPS 204 ``ML-DSA.KeyGen_internal(xi)``), so the 32-byte seed is
the only secret that needs to be stored or backed up.

Domain separation
-----------------
FIPS 204 "pure" ML-DSA signs ``M' = 0x00 || len(ctx) || ctx || M``. We use a
distinct, non-empty context string for each purpose so a signature produced
for one purpose can never be replayed as a signature for another:

* ``CONTEXT_TX``  - transaction signatures (the message is the 32-byte sighash)
* ``CONTEXT_MSG`` - off-chain message signing (``safe-btc sign``)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

# ML-DSA-65 parameter sizes (FIPS 204, Table 2)
PUBLIC_KEY_SIZE = 1952
SIGNATURE_SIZE = 3309
SEED_SIZE = 32
# Size of the expanded secret key in FIPS 204 encoding. We never store it; the
# 32-byte seed is the private key. Kept for documentation and size tables.
EXPANDED_SECRET_KEY_SIZE = 4032

# FIPS 204 context strings (domain separation, see module docstring).
CONTEXT_TX = b"bitcoin:pq:tx"
CONTEXT_MSG = b"bitcoin:pq:msg"


class MLDSA65:
    """ML-DSA-65 signature scheme (FIPS 204, NIST security category 3)."""

    @staticmethod
    def keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
        """Deterministically derive (public_key, seed) from a 32-byte seed."""
        if len(seed) != SEED_SIZE:
            raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
        sk = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
        return sk.public_key().public_bytes_raw(), bytes(seed)

    @staticmethod
    def keypair() -> tuple[bytes, bytes]:
        """Generate a random key pair. Returns (public_key, seed)."""
        return MLDSA65.keypair_from_seed(os.urandom(SEED_SIZE))

    @staticmethod
    def sign(seed: bytes, message: bytes, context: bytes) -> bytes:
        """Sign ``message`` under FIPS 204 ``context`` (hedged/randomized signing)."""
        if len(context) > 255:
            raise ValueError("context must be at most 255 bytes")
        sk = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
        return sk.sign(message, context)

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes, context: bytes) -> bool:
        """Verify an ML-DSA-65 signature. Never raises on malformed input."""
        if len(public_key) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
            return False
        try:
            pk = mldsa.MLDSA65PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message, context)
            return True
        except (InvalidSignature, ValueError):
            return False

    @staticmethod
    def sizes() -> dict[str, int]:
        """Return the parameter sizes for ML-DSA-65."""
        return {
            "public_key": PUBLIC_KEY_SIZE,
            "seed": SEED_SIZE,
            "expanded_secret_key": EXPANDED_SECRET_KEY_SIZE,
            "signature": SIGNATURE_SIZE,
        }


@dataclass
class KeyPair:
    """An ML-DSA-65 key pair. ``seed`` is the private key (32 bytes)."""

    public_key: bytes
    seed: bytes = field(repr=False)

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        pk, sd = MLDSA65.keypair_from_seed(seed)
        return cls(public_key=pk, seed=sd)

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new random key pair (not recoverable from a mnemonic)."""
        return cls.from_seed(os.urandom(SEED_SIZE))

    def sign(self, message: bytes, context: bytes = CONTEXT_MSG) -> bytes:
        return MLDSA65.sign(self.seed, message, context)

    def verify(self, message: bytes, signature: bytes, context: bytes = CONTEXT_MSG) -> bool:
        return MLDSA65.verify(self.public_key, message, signature, context)


def generate_keypair() -> KeyPair:
    """Generate a new random ML-DSA-65 key pair."""
    return KeyPair.generate()


def sign_message(seed: bytes, message: bytes) -> bytes:
    """Sign an off-chain message (uses ``CONTEXT_MSG``)."""
    return MLDSA65.sign(seed, message, CONTEXT_MSG)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an off-chain message signature (uses ``CONTEXT_MSG``)."""
    return MLDSA65.verify(public_key, message, signature, CONTEXT_MSG)
