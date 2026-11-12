"""safe-btc: Quantum-resistant tools for Bitcoin."""

from .keys import KeyPair
from .pq_addresses import (
    COMMITMENT_LEN,
    HRP,
    WITNESS_VERSION_PQ,
    address_from_public_key,
    decode_address,
    encode_address,
    is_valid_address,
)
from .pq_signatures import MLDSA65, generate_keypair, sign_message, verify_signature

__version__ = "0.1.0"
__all__ = [
    "COMMITMENT_LEN",
    "HRP",
    "WITNESS_VERSION_PQ",
    "KeyPair",
    "address_from_public_key",
    "decode_address",
    "encode_address",
    "is_valid_address",
    "MLDSA65",
    "generate_keypair",
    "sign_message",
    "verify_signature",
]
