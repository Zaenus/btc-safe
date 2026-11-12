"""Test configuration and fixtures for safe-btc tests."""

import pytest

from safe_btc.pq_addresses import encode_address, WITNESS_VERSION_PQ
from safe_btc.pq_signatures import MLDSA65


@pytest.fixture
def keypair():
    """Generate a fresh ML-DSA-65 key pair for each test."""
    return MLDSA65.keypair()


@pytest.fixture
def sample_address(keypair):
    """Generate a sample bc1z address from a key pair."""
    pk, _ = keypair
    return encode_address(__import__("safe_btc.pq_addresses", fromlist=["compute_pubkey_hash"]).compute_pubkey_hash(pk), WITNESS_VERSION_PQ)
