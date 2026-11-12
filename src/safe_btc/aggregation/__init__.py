"""
Signature aggregation for post-quantum Bitcoin addresses.

ML-DSA-65 signatures are ~3,309 bytes each, making individual PQ transactions
prohibitively expensive. This module provides SNARK-wrapped signature
aggregation: multiple ML-DSA signatures are compressed into a single
zero-knowledge proof that can be verified on-chain.

This is a prototype implementation. Production use requires a compiled
SNARK circuit (e.g., using Circom, Noir, or SP1) and a trusted setup.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..pq_signatures import MLDSA65, KeyPair


# Mock SNARK parameters — in production these come from a trusted setup
SNARK_PROOF_SIZE = 192  # bytes (typical Groth16 proof size)
SNARK_VERIFICATION_KEY_SIZE = 1024  # bytes


@dataclass
class AggregatedSignature:
    """
    An aggregated post-quantum signature.

    Instead of storing N individual ML-DSA signatures (N * 3309 bytes),
    stores a single SNARK proof (~192 bytes) plus the public keys.
    """

    # The SNARK proof that N signatures are valid
    snark_proof: bytes

    # The public keys corresponding to the aggregated signatures
    public_keys: list[bytes]

    # The messages (transaction hashes) that were signed
    messages: list[bytes]

    # Number of aggregated signatures
    n_signatures: int

    # Merkle root of (pubkey, message, signature) tuples for binding
    commitment_root: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "snark_proof": self.snark_proof.hex(),
            "public_keys": [pk.hex() for pk in self.public_keys],
            "messages": [msg.hex() for msg in self.messages],
            "n_signatures": self.n_signatures,
            "commitment_root": self.commitment_root.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AggregatedSignature":
        return cls(
            snark_proof=bytes.fromhex(data["snark_proof"]),
            public_keys=[bytes.fromhex(pk) for pk in data["public_keys"]],
            messages=[bytes.fromhex(msg) for msg in data["messages"]],
            n_signatures=data["n_signatures"],
            commitment_root=bytes.fromhex(data["commitment_root"]),
        )

    def size_bytes(self) -> int:
        """Total on-chain size of this aggregated signature."""
        return (
            len(self.snark_proof)
            + sum(len(pk) for pk in self.public_keys)
            + len(self.commitment_root)
        )

    def individual_size_bytes(self) -> int:
        """Size if stored as N individual ML-DSA signatures."""
        return self.n_signatures * MLDSA65.sizes()["signature"]

    def compression_ratio(self) -> float:
        """Compression ratio vs individual signatures."""
        return self.size_bytes() / self.individual_size_bytes()


class MockSNARK:
    """
    A mock SNARK implementation for prototype demonstration.

    In production, this would be replaced with a real zk-SNARK (e.g., Groth16,
    PLONK, or SP1 STARK) with a compiled circuit for ML-DSA-65 verification.

    The circuit would take:
    - Public inputs: commitment_root, N public keys, N messages
    - Private inputs: N ML-DSA signatures
    - Constraint: For each i, ML-DSA.Verify(pk[i], msg[i], sig[i]) == true
    """

    @staticmethod
    def setup() -> dict[str, bytes]:
        """
        Generate mock proving and verification keys.

        Returns a dict with 'proving_key' and 'verification_key'.
        """
        return {
            "proving_key": hashlib.sha256(b"proving_key_setup").digest() * 16,
            "verification_key": hashlib.sha256(b"verification_key_setup").digest() * 16,
        }

    @staticmethod
    def _setup_hash() -> bytes:
        """Combined setup hash used by both prove and verify."""
        return hashlib.sha256(b"mock_snark_setup_v1").digest()

    @staticmethod
    def prove(
        public_keys: list[bytes],
        messages: list[bytes],
        signatures: list[bytes],
        proving_key: bytes,
    ) -> bytes:
        """
        Generate a mock SNARK proof that all signatures are valid.

        Args:
            public_keys: List of ML-DSA public keys.
            messages: List of signed messages.
            signatures: List of ML-DSA signatures.
            proving_key: The proving key from setup (used for domain separation).

        Returns:
            A mock SNARK proof (192 bytes).
        """
        # Verify all signatures before creating proof
        for pk, msg, sig in zip(public_keys, messages, signatures):
            if not MLDSA65.verify(pk, msg, sig):
                raise ValueError("Invalid signature in aggregation")

        # Compute commitment root
        commitment_root = MockSNARK._compute_merkle_root(
            public_keys, messages, signatures
        )

        # Mock proof: deterministic hash of all inputs
        # proving_key provides domain separation but prove/verify must agree
        proof_data = (
            MockSNARK._setup_hash()
            + commitment_root
            + b"".join(public_keys)
            + b"".join(messages)
        )
        proof = hashlib.sha256(proof_data).digest() * 6  # 192 bytes
        return proof[: SNARK_PROOF_SIZE]

    @staticmethod
    def verify(
        proof: bytes,
        public_keys: list[bytes],
        messages: list[bytes],
        verification_key: bytes,
        commitment_root: bytes | None = None,
    ) -> bool:
        """
        Verify a mock SNARK proof.

        Args:
            proof: The SNARK proof.
            public_keys: List of ML-DSA public keys (public input).
            messages: List of signed messages (public input).
            verification_key: The verification key from setup.
            commitment_root: Optional pre-computed commitment root. If None,
                it is recomputed (less secure for mock, use stored value).

        Returns:
            True if the proof is valid.
        """
        if len(proof) != SNARK_PROOF_SIZE:
            return False

        if commitment_root is None:
            commitment_root = MockSNARK._compute_merkle_root(
                public_keys,
                messages,
                [b"\x00" * MLDSA65.sizes()["signature"]] * len(public_keys),
            )

        # Recompute expected proof using same inputs as prove
        proof_data = (
            MockSNARK._setup_hash()
            + commitment_root
            + b"".join(public_keys)
            + b"".join(messages)
        )
        expected_proof = hashlib.sha256(proof_data).digest() * 6
        expected_proof = expected_proof[: SNARK_PROOF_SIZE]

        return proof == expected_proof

    @staticmethod
    def _compute_merkle_root(
        public_keys: list[bytes],
        messages: list[bytes],
        signatures: list[bytes],
    ) -> bytes:
        """Compute a Merkle root binding (pubkey, msg, sig) tuples."""
        leaves = []
        for pk, msg, sig in zip(public_keys, messages, signatures):
            leaf = hashlib.sha256(pk + msg + sig).digest()
            leaves.append(leaf)

        if not leaves:
            return hashlib.sha256(b"empty").digest()

        # Simple Merkle tree
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])  # duplicate last for odd count
            new_leaves = []
            for i in range(0, len(leaves), 2):
                new_leaves.append(hashlib.sha256(leaves[i] + leaves[i + 1]).digest())
            leaves = new_leaves

        return leaves[0]


class SignatureAggregator:
    """
    Aggregates multiple ML-DSA-65 signatures into a single SNARK proof.

    Usage:
        aggregator = SignatureAggregator()
        keys = [KeyPair.generate() for _ in range(5)]
        messages = [b"tx1", b"tx2", ...]
        sigs = [k.sign(m) for k, m in zip(keys, messages)]

        agg_sig = aggregator.aggregate(
            [k.public_key for k in keys],
            messages,
            sigs
        )

        # On-chain: verify agg_sig instead of N individual signatures
        assert aggregator.verify(agg_sig)
    """

    def __init__(self) -> None:
        self.setup_data = MockSNARK.setup()

    def aggregate(
        self,
        public_keys: list[bytes],
        messages: list[bytes],
        signatures: list[bytes],
    ) -> AggregatedSignature:
        """
        Aggregate N ML-DSA signatures into a single SNARK proof.

        Args:
            public_keys: List of ML-DSA public keys.
            messages: List of signed messages.
            signatures: List of ML-DSA signatures (must correspond to keys/msgs).

        Returns:
            An AggregatedSignature containing the SNARK proof.
        """
        if not (len(public_keys) == len(messages) == len(signatures)):
            raise ValueError("public_keys, messages, and signatures must have equal length")

        if not public_keys:
            raise ValueError("At least one signature required for aggregation")

        # Generate SNARK proof
        snark_proof = MockSNARK.prove(
            public_keys, messages, signatures, self.setup_data["proving_key"]
        )

        # Compute commitment root
        commitment_root = MockSNARK._compute_merkle_root(
            public_keys, messages, signatures
        )

        return AggregatedSignature(
            snark_proof=snark_proof,
            public_keys=list(public_keys),
            messages=list(messages),
            n_signatures=len(public_keys),
            commitment_root=commitment_root,
        )

    def verify(self, agg_sig: AggregatedSignature) -> bool:
        """
        Verify an aggregated signature.

        Args:
            agg_sig: The AggregatedSignature to verify.

        Returns:
            True if the SNARK proof is valid.
        """
        return MockSNARK.verify(
            agg_sig.snark_proof,
            agg_sig.public_keys,
            agg_sig.messages,
            self.setup_data["verification_key"],
            commitment_root=agg_sig.commitment_root,
        )

    def batch_verify(
        self, agg_signatures: list[AggregatedSignature]
    ) -> list[bool]:
        """
        Verify multiple aggregated signatures.

        Args:
            agg_signatures: List of AggregatedSignature instances.

        Returns:
            List of booleans indicating validity of each.
        """
        return [self.verify(agg) for agg in agg_signatures]

    def compression_stats(self, agg_sig: AggregatedSignature) -> dict[str, Any]:
        """Return compression statistics for an aggregated signature."""
        individual = agg_sig.individual_size_bytes()
        aggregated = agg_sig.size_bytes()
        return {
            "n_signatures": agg_sig.n_signatures,
            "individual_size_bytes": individual,
            "aggregated_size_bytes": aggregated,
            "bytes_saved": individual - aggregated,
            "compression_ratio": round(agg_sig.compression_ratio(), 4),
            "space_reduction_percent": round(
                (1 - agg_sig.compression_ratio()) * 100, 2
            ),
        }


def aggregate_signatures(
    public_keys: list[bytes],
    messages: list[bytes],
    signatures: list[bytes],
) -> AggregatedSignature:
    """
    Convenience function to aggregate ML-DSA signatures.

    Args:
        public_keys: List of ML-DSA public keys.
        messages: List of signed messages.
        signatures: List of ML-DSA signatures.

    Returns:
        An AggregatedSignature.
    """
    aggregator = SignatureAggregator()
    return aggregator.aggregate(public_keys, messages, signatures)


def verify_aggregated_signature(
    agg_sig: AggregatedSignature,
    proving_key: bytes | None = None,
) -> bool:
    """
    Convenience function to verify an aggregated signature.

    Args:
        agg_sig: The AggregatedSignature to verify.
        proving_key: Optional proving key (uses default if None).

    Returns:
        True if valid.
    """
    aggregator = SignatureAggregator()
    if proving_key is not None:
        aggregator.setup_data["proving_key"] = proving_key
    return aggregator.verify(agg_sig)
