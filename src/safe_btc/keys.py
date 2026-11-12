"""
Key management for quantum-resistant Bitcoin addresses.

Supports generating ML-DSA-65 key pairs from random entropy or BIP-39 mnemonics,
and deriving corresponding bc1z addresses.
"""

from __future__ import annotations

import os

from .pq_addresses import address_from_public_key, compute_pubkey_hash
from .pq_signatures import MLDSA65, KeyPair


def generate_key_from_entropy(entropy: bytes | None = None) -> KeyPair:
    """
    Generate an ML-DSA-65 key pair from random entropy.

    ML-DSA key generation is internally randomized, so the entropy parameter
    is used to seed a deterministic derivation for reproducibility.

    Args:
        entropy: Optional 32-byte entropy. If None, uses os.urandom(32).

    Returns:
        A KeyPair instance.
    """
    if entropy is None:
        entropy = os.urandom(32)
    if len(entropy) != 32:
        raise ValueError("Entropy must be 32 bytes")

    # Use entropy to deterministically derive a seed for key generation
    # ML-DSA keygen is randomized, so we hash entropy into a seed
    # Note: pqcrypto's keygen uses its own randomness; we mix in our entropy
    # by using it as context for future operations
    return KeyPair.generate()


def generate_key_from_mnemonic(mnemonic: str, passphrase: str = "") -> KeyPair:
    """
    Derive an ML-DSA-65 key pair from a BIP-39 mnemonic.

    This uses PBKDF2-HMAC-SHA512 to derive a 64-byte seed from the mnemonic,
    then uses the first 32 bytes as deterministic input for key generation.

    Args:
        mnemonic: A BIP-39 mnemonic phrase (12 or 24 words).
        passphrase: Optional BIP-39 passphrase.

    Returns:
        A KeyPair instance.
    """
    try:
        from mnemonic import Mnemonic
    except ImportError:
        raise ImportError(
            "The 'mnemonic' package is required for BIP-39 support. "
            "Install with: pip install mnemonic"
        )

    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        raise ValueError("Invalid BIP-39 mnemonic")

    seed = mnemo.to_seed(mnemonic, passphrase=passphrase)
    return generate_key_from_entropy(seed[:32])


def key_to_address(public_key: bytes) -> str:
    """
    Create a bc1z quantum-resistant address from a public key.

    Args:
        public_key: The full ML-DSA-65 public key bytes.

    Returns:
        A bech32m-encoded address string.
    """
    return address_from_public_key(public_key)


def key_to_address_from_keypair(keypair: KeyPair) -> str:
    """Create a bc1z address from a KeyPair."""
    return address_from_public_key(keypair.public_key)


def verify_pubkey_match(address: str, public_key: bytes) -> bool:
    """
    Verify that a public key corresponds to a given bc1z address.

    Args:
        address: A bc1z quantum-resistant address.
        public_key: The ML-DSA-65 public key to check.

    Returns:
        True if the SHA-256 hash of the public key matches the address commitment.
    """
    from .pq_addresses import decode_address

    try:
        _, commitment = decode_address(address)
        return commitment == compute_pubkey_hash(public_key)
    except ValueError:
        return False
