"""Shared fixtures."""

from __future__ import annotations

import hashlib

import pytest

from safe_btc.pq_signatures import KeyPair

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@pytest.fixture(scope="session")
def keypair() -> KeyPair:
    return KeyPair.from_seed(hashlib.sha256(b"fixture key 1").digest())


@pytest.fixture(scope="session")
def keypair2() -> KeyPair:
    return KeyPair.from_seed(hashlib.sha256(b"fixture key 2").digest())


@pytest.fixture
def mnemonic() -> str:
    return MNEMONIC
