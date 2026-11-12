"""safe-btc: Quantum-resistant tools for Bitcoin."""

from .keys import KeyPair
from .pq_addresses import encode_address, decode_address, is_valid_address, address_from_public_key
from .pq_signatures import MLDSA65, generate_keypair, sign_message, verify_signature

__version__ = "0.1.0"
__all__ = [
    "KeyPair",
    "encode_address",
    "decode_address",
    "is_valid_address",
    "address_from_public_key",
    "MLDSA65",
    "generate_keypair",
    "sign_message",
    "verify_signature",
]
