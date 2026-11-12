"""
ML-DSA-65 (FIPS 204 / Dilithium) post-quantum signature wrapper.

Provides key generation, signing, and verification for Bitcoin-compatible
post-quantum signatures. Uses the pqcrypto library (NIST-standardized ML-DSA).
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcrypto.sign import ml_dsa_65 as _mldsa

# ML-DSA-65 parameter sizes
PUBLIC_KEY_SIZE = _mldsa.PUBLIC_KEY_SIZE  # 1952 bytes
SECRET_KEY_SIZE = _mldsa.SECRET_KEY_SIZE  # 4032 bytes
SIGNATURE_SIZE = _mldsa.SIGNATURE_SIZE    # 3309 bytes


class MLDSA65:
    """ML-DSA-65 post-quantum signature scheme (FIPS 204)."""

    @staticmethod
    def keypair() -> tuple[bytes, bytes]:
        """Generate a new ML-DSA-65 key pair.

        Returns:
            A tuple of (public_key, secret_key) as raw bytes.
        """
        return _mldsa.keygen()

    @staticmethod
    def sign(secret_key: bytes, message: bytes, context: bytes | None = None) -> bytes:
        """Sign a message with an ML-DSA-65 secret key.

        Args:
            secret_key: The ML-DSA-65 secret key (4032 bytes).
            message: The message to sign (typically a transaction hash).
            context: Optional FIPS 204 context string (max 255 bytes).

        Returns:
            The signature as raw bytes (3309 bytes for ML-DSA-65).
        """
        return _mldsa.sign(secret_key, message, context=context)

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes, context: bytes | None = None) -> bool:
        """Verify an ML-DSA-65 signature.

        Args:
            public_key: The ML-DSA-65 public key (1952 bytes).
            message: The signed message.
            signature: The signature to verify.
            context: Optional FIPS 204 context string.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            _mldsa.verify(public_key, message, signature, context=context)
            return True
        except Exception:
            return False

    @staticmethod
    def sizes() -> dict[str, int]:
        """Return the parameter sizes for ML-DSA-65."""
        return {
            "public_key": PUBLIC_KEY_SIZE,
            "secret_key": SECRET_KEY_SIZE,
            "signature": SIGNATURE_SIZE,
        }


@dataclass
class KeyPair:
    """An ML-DSA-65 key pair with metadata."""

    public_key: bytes
    secret_key: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new random key pair."""
        pk, sk = MLDSA65.keypair()
        return cls(public_key=pk, secret_key=sk)

    def sign(self, message: bytes) -> bytes:
        """Sign a message with this key pair's secret key."""
        return MLDSA65.sign(self.secret_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against this key pair's public key."""
        return MLDSA65.verify(self.public_key, message, signature)


def generate_keypair() -> KeyPair:
    """Generate a new ML-DSA-65 key pair."""
    return KeyPair.generate()


def sign_message(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message with an ML-DSA-65 secret key."""
    return MLDSA65.sign(secret_key, message)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature."""
    return MLDSA65.verify(public_key, message, signature)
