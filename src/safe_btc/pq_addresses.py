"""
bech32m encoding/decoding for quantum-resistant Bitcoin addresses.

Address format: bc1z<version><data>

The data payload is a SHA-256 hash of the ML-DSA-65 public key (32 bytes).
At spend time, the full public key (1952 bytes) is revealed in the witness
and verified against this commitment.

Uses the reference bech32 implementation (Pieter Wuille).
"""

from __future__ import annotations

import hashlib

import bech32

# Human-readable part for quantum-resistant addresses
HRP = "bc1z"

# Witness version for post-quantum addresses
WITNESS_VERSION_PQ = 0x02

# Length of the SHA-256 hash commitment (32 bytes)
COMMITMENT_LEN = 32


def encode_address(pubkey_hash: bytes, version: int = WITNESS_VERSION_PQ) -> str:
    """
    Encode a quantum-resistant Bitcoin address.

    Args:
        pubkey_hash: 32-byte SHA-256 hash of the ML-DSA-65 public key.
        version: Witness version byte (default: 0x02 for post-quantum).

    Returns:
        A bech32-encoded address string (e.g., bc1z1...).

    Raises:
        ValueError: If pubkey_hash is not 32 bytes.
    """
    if len(pubkey_hash) != COMMITMENT_LEN:
        raise ValueError(f"pubkey_hash must be {COMMITMENT_LEN} bytes, got {len(pubkey_hash)}")

    addr = bech32.encode(HRP, version, pubkey_hash)
    if addr is None:
        raise ValueError("Failed to encode address")
    return addr


def decode_address(address: str) -> tuple[int, bytes]:
    """
    Decode a quantum-resistant Bitcoin address.

    Args:
        address: A bech32-encoded address string.

    Returns:
        A tuple of (version, pubkey_hash) where pubkey_hash is 32 bytes.

    Raises:
        ValueError: If the address is invalid.
    """
    result = bech32.decode(HRP, address)
    if result == (None, None):
        raise ValueError("Invalid bech32 address")

    version, data = result
    if version != WITNESS_VERSION_PQ:
        raise ValueError(f"Unexpected witness version {version}, expected {WITNESS_VERSION_PQ}")
    if len(data) != COMMITMENT_LEN:
        raise ValueError(f"Expected {COMMITMENT_LEN}-byte commitment, got {len(data)}")

    return version, bytes(data)


def is_valid_address(address: str) -> bool:
    """Check if a string is a valid quantum-resistant address."""
    try:
        decode_address(address)
        return True
    except ValueError:
        return False


def compute_pubkey_hash(public_key: bytes) -> bytes:
    """
    Compute the SHA-256 hash commitment of an ML-DSA-65 public key.

    Args:
        public_key: The full ML-DSA-65 public key bytes (1952 bytes for ML-DSA-65).

    Returns:
        32-byte SHA-256 hash of the public key.
    """
    return hashlib.sha256(public_key).digest()


def address_from_public_key(public_key: bytes, version: int = WITNESS_VERSION_PQ) -> str:
    """
    Create a quantum-resistant address from an ML-DSA-65 public key.

    Args:
        public_key: The full ML-DSA-65 public key bytes.
        version: Witness version byte.

    Returns:
        A bech32-encoded address string.
    """
    pubkey_hash = compute_pubkey_hash(public_key)
    return encode_address(pubkey_hash, version)
