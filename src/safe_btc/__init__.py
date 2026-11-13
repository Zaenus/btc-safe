"""safe-btc: post-quantum (witness v3, ML-DSA-65) tooling for Bitcoin."""

from .keys import derive_keypair, generate_key_from_mnemonic, mnemonic_to_seed
from .pq_addresses import (
    COMMITMENT_LEN,
    DEFAULT_NETWORK,
    HRP,
    KEY_TYPE_ML_DSA_65,
    WITNESS_VERSION_PQ,
    address_from_public_key,
    compute_commitment,
    decode_address,
    encode_address,
    is_valid_address,
    script_pubkey,
)
from .pq_signatures import (
    CONTEXT_MSG,
    CONTEXT_TX,
    MLDSA65,
    KeyPair,
    generate_keypair,
    sign_message,
    verify_signature,
)

__version__ = "0.2.0"
__all__ = [
    "COMMITMENT_LEN",
    "CONTEXT_MSG",
    "CONTEXT_TX",
    "DEFAULT_NETWORK",
    "HRP",
    "KEY_TYPE_ML_DSA_65",
    "WITNESS_VERSION_PQ",
    "KeyPair",
    "MLDSA65",
    "address_from_public_key",
    "compute_commitment",
    "decode_address",
    "derive_keypair",
    "encode_address",
    "generate_key_from_mnemonic",
    "generate_keypair",
    "is_valid_address",
    "mnemonic_to_seed",
    "script_pubkey",
    "sign_message",
    "verify_signature",
]
