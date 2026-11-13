"""
Witness version 3 post-quantum outputs and their bech32m addresses.

Output script:  ``OP_3 OP_PUSHBYTES_32 <commitment>``  (hex ``5320`` + 32 bytes)
Address:        bech32m (BIP-350), witness version 3 -> ``bc1r...`` / ``tb1r...``

The commitment is a tagged hash of a one-byte key type followed by the public
key::

    commitment = TaggedHash("PQKeyCommit", key_type || public_key)

The key type byte lets later soft forks add other signature schemes (e.g.
ML-DSA-44, FN-DSA, SLH-DSA) to witness version 3 without using up another
witness version. See ``docs/bip/0001-pq-address-format.md``.

The commitment exists to keep outputs small (32 bytes instead of 1,953). It is
not what makes the output quantum-resistant: unlike P2WPKH, a witness v3 output
remains safe after its public key and signatures have been revealed.

WARNING: witness version 3 is not active on any Bitcoin network. Under today's
consensus rules, coins sent to a witness v3 output can be taken by anyone
(e.g. a miner). This module therefore defaults to testnet, and the CLI refuses
to produce mainnet addresses unless explicitly told to.
"""

from __future__ import annotations

from . import segwit_addr
from .hashing import tagged_hash
from .pq_signatures import PUBLIC_KEY_SIZE

WITNESS_VERSION_PQ = 3
COMMITMENT_LEN = 32
OP_3 = 0x53

# Key type registry. 0x01 is the only type defined by the draft BIP. Unknown
# key types are left unencumbered by consensus (upgrade hook, like OP_SUCCESS).
# 0x50 can never be used: a 2-element witness whose last element starts with
# 0x50 is parsed as [sig, annex] by the BIP-341 annex rule.
KEY_TYPE_ML_DSA_65 = 0x01
KEY_TYPE_RESERVED_ANNEX = 0x50
KEY_TYPES = {KEY_TYPE_ML_DSA_65: ("ML-DSA-65", PUBLIC_KEY_SIZE)}

COMMIT_TAG = "PQKeyCommit"

NETWORK_HRPS = {
    "mainnet": "bc",
    "testnet": "tb",
    "signet": "tb",
    "regtest": "bcrt",
}
DEFAULT_NETWORK = "testnet"

# Backwards-compatible alias: the HRP of the default network.
HRP = NETWORK_HRPS[DEFAULT_NETWORK]


def hrp_for(network: str) -> str:
    try:
        return NETWORK_HRPS[network]
    except KeyError:
        raise ValueError(
            f"unknown network {network!r}; expected one of {sorted(NETWORK_HRPS)}"
        ) from None


def key_blob(public_key: bytes, key_type: int = KEY_TYPE_ML_DSA_65, allow_undefined: bool = False) -> bytes:
    """
    The witness element that reveals the key: ``key_type || public_key``.

    Undefined key types are refused: under the spending rules they are an
    upgrade hook, so an output committing to one can be spent by anyone.
    ``allow_undefined`` exists only for building test vectors.
    """
    if key_type == KEY_TYPE_RESERVED_ANNEX:
        raise ValueError("key type 0x50 is reserved (collides with the annex marker)")
    if key_type not in KEY_TYPES:
        if not allow_undefined:
            raise ValueError(
                f"key type 0x{key_type:02x} is not defined; outputs using it would be anyone-can-spend"
            )
    elif len(public_key) != KEY_TYPES[key_type][1]:
        raise ValueError(
            f"{KEY_TYPES[key_type][0]} public key must be {KEY_TYPES[key_type][1]} bytes, "
            f"got {len(public_key)}"
        )
    return bytes([key_type]) + public_key


def compute_commitment(public_key: bytes, key_type: int = KEY_TYPE_ML_DSA_65) -> bytes:
    """``TaggedHash("PQKeyCommit", key_type || public_key)`` for a defined key type."""
    return tagged_hash(COMMIT_TAG, key_blob(public_key, key_type))


# Old name kept for API compatibility.
compute_pubkey_hash = compute_commitment


def script_pubkey(commitment: bytes) -> bytes:
    """``OP_3 OP_PUSHBYTES_32 <commitment>``."""
    if len(commitment) != COMMITMENT_LEN:
        raise ValueError(f"commitment must be {COMMITMENT_LEN} bytes, got {len(commitment)}")
    return bytes([OP_3, COMMITMENT_LEN]) + commitment


def parse_script_pubkey(spk: bytes) -> bytes | None:
    """Return the commitment if ``spk`` is a 32-byte witness v3 program, else None."""
    if len(spk) == 2 + COMMITMENT_LEN and spk[0] == OP_3 and spk[1] == COMMITMENT_LEN:
        return spk[2:]
    return None


def encode_address(
    commitment: bytes,
    network: str = DEFAULT_NETWORK,
    version: int = WITNESS_VERSION_PQ,
) -> str:
    """Encode a witness v3 commitment as a bech32m address."""
    if len(commitment) != COMMITMENT_LEN:
        raise ValueError(f"commitment must be {COMMITMENT_LEN} bytes, got {len(commitment)}")
    addr = segwit_addr.encode(hrp_for(network), version, commitment)
    if addr is None:
        raise ValueError("failed to encode address")
    return addr


def decode_address(address: str, network: str | None = None) -> tuple[int, bytes]:
    """
    Decode a witness v3 address into ``(version, commitment)``.

    If ``network`` is None, any known network HRP is accepted.
    """
    networks = [network] if network else list(NETWORK_HRPS)
    for net in networks:
        version, program = segwit_addr.decode(hrp_for(net), address)
        if version is not None:
            break
    else:
        raise ValueError("invalid bech32m segwit address")
    if version != WITNESS_VERSION_PQ:
        raise ValueError(f"witness version {version} is not {WITNESS_VERSION_PQ}")
    if program is None or len(program) != COMMITMENT_LEN:
        raise ValueError(f"expected a {COMMITMENT_LEN}-byte witness program")
    return version, bytes(program)


def address_network(address: str) -> str | None:
    """Return 'mainnet', 'testnet' (covers signet) or 'regtest' for an address."""
    lowered = address.lower()
    if lowered.startswith("bcrt1"):
        return "regtest"
    if lowered.startswith("bc1"):
        return "mainnet"
    if lowered.startswith("tb1"):
        return "testnet"
    return None


def is_valid_address(address: str, network: str | None = None) -> bool:
    """True if ``address`` is a valid witness v3 bech32m address."""
    try:
        decode_address(address, network)
        return True
    except ValueError:
        return False


def address_from_public_key(
    public_key: bytes,
    network: str = DEFAULT_NETWORK,
    key_type: int = KEY_TYPE_ML_DSA_65,
) -> str:
    """Derive the witness v3 address for a public key."""
    return encode_address(compute_commitment(public_key, key_type), network)
