"""Hash helpers shared across the package (BIP-340 style tagged hashes)."""

from __future__ import annotations

import hashlib


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Bitcoin's double SHA-256."""
    return sha256(sha256(data))


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_digest = sha256(tag.encode())
    return sha256(tag_digest + tag_digest + data)
