"""Tests for safe-btc quantum-resistant address formats and signatures."""

from __future__ import annotations

import pytest

from safe_btc import (
    MLDSA65,
    KeyPair,
    address_from_public_key,
    generate_keypair,
    is_valid_address,
)
from safe_btc.keys import (
    generate_key_from_entropy,
    key_to_address,
    verify_pubkey_match,
)
from safe_btc.pq_addresses import (
    COMMITMENT_LEN,
    HRP,
    WITNESS_VERSION_PQ,
    address_from_public_key as _addr_from_pk,
    compute_pubkey_hash,
    decode_address,
    encode_address,
    is_valid_address as _is_valid_address,
)


class TestMLDSA65Signatures:
    """Tests for ML-DSA-65 signing and verification."""

    def test_keypair_generation(self):
        pk, sk = MLDSA65.keypair()
        assert len(pk) == MLDSA65.sizes()["public_key"]
        assert len(sk) == MLDSA65.sizes()["secret_key"]

    def test_sign_and_verify(self):
        pk, sk = MLDSA65.keypair()
        message = b"Hello Bitcoin quantum-safe"
        sig = MLDSA65.sign(sk, message)
        assert len(sig) == MLDSA65.sizes()["signature"]
        assert MLDSA65.verify(pk, message, sig) is True

    def test_verify_rejects_tampered_signature(self):
        pk, sk = MLDSA65.keypair()
        message = b"Hello Bitcoin quantum-safe"
        sig = MLDSA65.sign(sk, message)
        tampered = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        assert MLDSA65.verify(pk, message, tampered) is False

    def test_verify_rejects_wrong_message(self):
        pk, sk = MLDSA65.keypair()
        sig = MLDSA65.sign(sk, b"message one")
        assert MLDSA65.verify(pk, b"message two", sig) is False

    def test_verify_rejects_wrong_public_key(self):
        pk1, sk1 = MLDSA65.keypair()
        pk2, _ = MLDSA65.keypair()
        message = b"test message"
        sig = MLDSA65.sign(sk1, message)
        assert MLDSA65.verify(pk2, message, sig) is False

    def test_key_pair_dataclass(self):
        kp = KeyPair.generate()
        assert len(kp.public_key) == 1952
        assert len(kp.secret_key) == 4032
        message = b"test"
        sig = kp.sign(message)
        assert kp.verify(message, sig) is True
        assert kp.verify(b"wrong", sig) is False

    def test_generate_keypair_function(self):
        kp = generate_keypair()
        assert isinstance(kp, KeyPair)


class TestPQAddresses:
    """Tests for bech32m quantum-resistant address encoding."""

    def test_encode_decode_roundtrip(self):
        # Use a deterministic public key hash
        pubkey_hash = bytes(range(COMMITMENT_LEN))  # 32 bytes: 0x00, 0x01, ..., 0x1f
        addr = encode_address(pubkey_hash, WITNESS_VERSION_PQ)
        assert addr.startswith(HRP)
        version, decoded_hash = decode_address(addr)
        assert version == WITNESS_VERSION_PQ
        assert decoded_hash == pubkey_hash

    def test_address_from_public_key(self):
        pk, _ = MLDSA65.keypair()
        addr = address_from_public_key(pk)
        assert addr.startswith(HRP)
        version, commitment = decode_address(addr)
        assert version == WITNESS_VERSION_PQ
        assert commitment == compute_pubkey_hash(pk)

    def test_is_valid_address(self):
        pk, _ = MLDSA65.keypair()
        addr = address_from_public_key(pk)
        assert is_valid_address(addr) is True
        assert is_valid_address("bc1z00000000000000000000000000000000000000000") is False
        assert is_valid_address("not an address") is False
        assert is_valid_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3d4") is False  # SegWit, not PQ

    def test_invalid_hash_length(self):
        with pytest.raises(ValueError):
            encode_address(b"too_short", WITNESS_VERSION_PQ)
        with pytest.raises(ValueError):
            encode_address(b"x" * 33, WITNESS_VERSION_PQ)

    def test_tampered_address_rejected(self):
        pk, _ = MLDSA65.keypair()
        addr = address_from_public_key(pk)
        # Tamper with a character
        tampered = addr[:-1] + ("q" if addr[-1] != "q" else "p")
        with pytest.raises(ValueError):
            decode_address(tampered)

    def test_compute_pubkey_hash_deterministic(self):
        pk, _ = MLDSA65.keypair()
        h1 = compute_pubkey_hash(pk)
        h2 = compute_pubkey_hash(pk)
        assert h1 == h2
        assert len(h1) == 32


class TestKeys:
    """Tests for key management."""

    def test_generate_key_from_entropy(self):
        entropy = bytes(range(32))
        kp = generate_key_from_entropy(entropy)
        assert len(kp.public_key) == 1952
        assert len(kp.secret_key) == 4032

    def test_key_to_address(self):
        pk, _ = MLDSA65.keypair()
        addr = key_to_address(pk)
        assert addr.startswith("bc1z")

    def test_verify_pubkey_match(self):
        pk, _ = MLDSA65.keypair()
        addr = address_from_public_key(pk)
        assert verify_pubkey_match(addr, pk) is True
        pk2, _ = MLDSA65.keypair()
        assert verify_pubkey_match(addr, pk2) is False


class TestCLI:
    """Tests for CLI commands."""

    def test_info_command(self):
        from safe_btc.cli import main
        assert main(["info"]) == 0
