"""Tests for signature aggregation."""

from __future__ import annotations

import pytest

from safe_btc.aggregation import (
    AggregatedSignature,
    MockSNARK,
    SignatureAggregator,
    aggregate_signatures,
    verify_aggregated_signature,
)
from safe_btc.pq_signatures import KeyPair, MLDSA65


class TestMockSNARK:
    """Tests for the mock SNARK implementation."""

    def test_setup_returns_keys(self):
        keys = MockSNARK.setup()
        assert "proving_key" in keys
        assert "verification_key" in keys
        assert len(keys["proving_key"]) > 0
        assert len(keys["verification_key"]) > 0

    def test_prove_and_verify(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        msg1 = b"transaction 1"
        msg2 = b"transaction 2"
        sig1 = kp1.sign(msg1)
        sig2 = kp2.sign(msg2)

        keys = MockSNARK.setup()
        proof = MockSNARK.prove(
            [kp1.public_key, kp2.public_key],
            [msg1, msg2],
            [sig1, sig2],
            keys["proving_key"],
        )

        assert len(proof) == 192  # SNARK_PROOF_SIZE

        # Compute commitment root (as the prover would)
        commitment_root = MockSNARK._compute_merkle_root(
            [kp1.public_key, kp2.public_key], [msg1, msg2], [sig1, sig2]
        )

        valid = MockSNARK.verify(
            proof,
            [kp1.public_key, kp2.public_key],
            [msg1, msg2],
            keys["verification_key"],
            commitment_root=commitment_root,
        )
        assert valid is True

    def test_verify_rejects_wrong_proof(self):
        kp = KeyPair.generate()
        msg = b"test"
        sig = kp.sign(msg)

        keys = MockSNARK.setup()
        proof = MockSNARK.prove(
            [kp.public_key], [msg], [sig], keys["proving_key"]
        )

        # Tampered proof
        tampered = proof[:-1] + bytes([proof[-1] ^ 0xFF])
        valid = MockSNARK.verify(
            tampered,
            [kp.public_key],
            [msg],
            keys["verification_key"],
        )
        assert valid is False

    def test_prove_rejects_invalid_signature(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        msg1 = b"msg1"
        msg2 = b"msg2"
        sig1 = kp1.sign(msg1)
        # Create an invalid signature by signing with wrong key
        sig2 = kp1.sign(msg2)  # kp1 signing kp2's message - invalid for kp2

        keys = MockSNARK.setup()
        with pytest.raises(ValueError):
            MockSNARK.prove(
                [kp1.public_key, kp2.public_key],
                [msg1, msg2],
                [sig1, sig2],
                keys["proving_key"],
            )


class TestAggregatedSignature:
    """Tests for the AggregatedSignature dataclass."""

    def test_size_comparison(self):
        n = 5
        individual_size = n * MLDSA65.sizes()["signature"]
        agg_size = 192 + n * 1952 + 32  # proof + pubkeys + commitment

        assert agg_size < individual_size
        ratio = agg_size / individual_size
        assert ratio < 1.0  # Compression achieved

    def test_compression_ratio(self):
        # With 10 signatures
        n = 10
        pk_list = [KeyPair.generate().public_key for _ in range(n)]
        msg_list = [b"msg%d" % i for i in range(n)]
        sig_list = [MLDSA65.sign(kp.secret_key, m)
                    for kp, m in zip([KeyPair.generate() for _ in range(n)], msg_list)]
        # Fix: regenerate properly
        kps = [KeyPair.generate() for _ in range(n)]
        pk_list = [kp.public_key for kp in kps]
        sig_list = [kp.sign(m) for kp, m in zip(kps, msg_list)]

        agg = AggregatedSignature(
            snark_proof=b"\x00" * 192,
            public_keys=pk_list,
            messages=msg_list,
            n_signatures=n,
            commitment_root=b"\x00" * 32,
        )

        assert agg.size_bytes() < agg.individual_size_bytes()
        assert agg.compression_ratio() < 1.0

    def test_to_from_dict(self):
        kp = KeyPair.generate()
        msg = b"test message"
        sig = kp.sign(msg)

        agg = AggregatedSignature(
            snark_proof=b"\x01" * 192,
            public_keys=[kp.public_key],
            messages=[msg],
            n_signatures=1,
            commitment_root=b"\x02" * 32,
        )

        d = agg.to_dict()
        agg2 = AggregatedSignature.from_dict(d)

        assert agg2.snark_proof == agg.snark_proof
        assert agg2.public_keys == agg.public_keys
        assert agg2.messages == agg.messages
        assert agg2.n_signatures == agg.n_signatures
        assert agg2.commitment_root == agg.commitment_root


class TestSignatureAggregator:
    """Tests for the SignatureAggregator class."""

    def test_aggregate_and_verify(self):
        aggregator = SignatureAggregator()
        n = 3
        kps = [KeyPair.generate() for _ in range(n)]
        messages = [b"tx%d" % i for i in range(n)]
        signatures = [kp.sign(m) for kp, m in zip(kps, messages)]

        agg = aggregator.aggregate(
            [kp.public_key for kp in kps],
            messages,
            signatures,
        )

        assert agg.n_signatures == n
        assert len(agg.snark_proof) == 192
        assert aggregator.verify(agg) is True

    def test_aggregate_rejects_mismatched_lengths(self):
        aggregator = SignatureAggregator()
        kp = KeyPair.generate()
        with pytest.raises(ValueError):
            aggregator.aggregate(
                [kp.public_key, kp.public_key],
                [b"msg1"],
                [kp.sign(b"msg1")],
            )

    def test_aggregate_rejects_empty(self):
        aggregator = SignatureAggregator()
        with pytest.raises(ValueError):
            aggregator.aggregate([], [], [])

    def test_batch_verify(self):
        aggregator = SignatureAggregator()
        aggs = []
        for _ in range(3):
            kp = KeyPair.generate()
            msg = b"test"
            sig = kp.sign(msg)
            agg = aggregator.aggregate([kp.public_key], [msg], [sig])
            aggs.append(agg)

        results = aggregator.batch_verify(aggs)
        assert all(results)

    def test_compression_stats(self):
        aggregator = SignatureAggregator()
        n = 10
        kps = [KeyPair.generate() for _ in range(n)]
        messages = [b"tx%d" % i for i in range(n)]
        signatures = [kp.sign(m) for kp, m in zip(kps, messages)]

        agg = aggregator.aggregate(
            [kp.public_key for kp in kps],
            messages,
            signatures,
        )

        stats = aggregator.compression_stats(agg)
        assert stats["n_signatures"] == n
        assert stats["aggregated_size_bytes"] < stats["individual_size_bytes"]
        assert stats["compression_ratio"] < 1.0
        assert stats["space_reduction_percent"] > 0
        assert stats["bytes_saved"] > 0

    def test_single_signature_aggregation(self):
        """Aggregation with a single signature still works."""
        aggregator = SignatureAggregator()
        kp = KeyPair.generate()
        msg = b"single tx"
        sig = kp.sign(msg)

        agg = aggregator.aggregate([kp.public_key], [msg], [sig])
        assert agg.n_signatures == 1
        assert aggregator.verify(agg) is True


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_aggregate_signatures_function(self):
        kps = [KeyPair.generate() for _ in range(2)]
        messages = [b"a", b"b"]
        signatures = [kp.sign(m) for kp, m in zip(kps, messages)]

        agg = aggregate_signatures(
            [kp.public_key for kp in kps],
            messages,
            signatures,
        )
        assert agg.n_signatures == 2

    def test_verify_aggregated_signature_function(self):
        kp = KeyPair.generate()
        msg = b"test"
        sig = kp.sign(msg)

        agg = aggregate_signatures([kp.public_key], [msg], [sig])
        assert verify_aggregated_signature(agg) is True
