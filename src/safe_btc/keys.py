"""
Key management for witness v3 (ML-DSA-65) addresses.

Derivation
----------
ML-DSA has no equivalent of BIP-32's public (non-hardened) derivation, so there
are no xpubs or watch-only wallets derived from a single public key. We use
hardened-only derivation in the style of SLIP-10:

    I = HMAC-SHA512(key=b"ML-DSA seed", msg=bip39_seed)      -> (k, c) = (I[:32], I[32:])
    child: I = HMAC-SHA512(key=c, msg=0x00 || k || ser32(i | 0x80000000))

The 32-byte ``k`` at the end of the path is the FIPS 204 key generation seed
``xi``. Default path: ``m/3'/coin'/account'/index'`` (coin 0 = mainnet,
1 = test networks). Purpose ``3'`` is a placeholder tied to the witness version
until a purpose number is assigned.

Key files
---------
Key files store the 32-byte seed (the private key), never the 4,032-byte
expanded key. They are created with mode 0600 and are never overwritten
unless ``overwrite=True``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import struct
import tempfile

from .pq_addresses import (
    DEFAULT_NETWORK,
    KEY_TYPE_ML_DSA_65,
    address_from_public_key,
    compute_commitment,
    decode_address,
)
from .pq_signatures import SEED_SIZE, KeyPair

MASTER_HMAC_KEY = b"ML-DSA seed"
HARDENED = 0x80000000
PURPOSE = 3
KEY_FILE_FORMAT = "safe-btc-key/2"


def coin_type(network: str) -> int:
    return 0 if network == "mainnet" else 1


def default_path(network: str = DEFAULT_NETWORK, account: int = 0, index: int = 0) -> str:
    return f"m/{PURPOSE}'/{coin_type(network)}'/{account}'/{index}'"


_PATH_COMPONENT = re.compile(r"^[0-9]+['h]$", re.ASCII)


def parse_path(path: str) -> list[int]:
    """Parse ``m/a'/b'/...``. Only hardened, ASCII-decimal components are allowed."""
    parts = path.split("/")
    if not parts or parts[0] != "m":
        raise ValueError("derivation path must start with 'm'")
    out = []
    for p in parts[1:]:
        if not _PATH_COMPONENT.match(p):
            raise ValueError(
                f"invalid path component {p!r}: use hardened decimal components like 3' "
                "(ML-DSA supports hardened derivation only)"
            )
        n = int(p[:-1])
        if n >= HARDENED:
            raise ValueError(f"path component out of range: {p}")
        out.append(n | HARDENED)
    return out


def master_key(seed: bytes) -> tuple[bytes, bytes]:
    if not 16 <= len(seed) <= 64:
        raise ValueError("master seed must be 16-64 bytes")
    i = hmac.new(MASTER_HMAC_KEY, seed, hashlib.sha512).digest()
    return i[:32], i[32:]


def derive_seed(master_seed: bytes, path: str) -> bytes:
    """Derive the 32-byte ML-DSA key-generation seed at ``path``."""
    k, c = master_key(master_seed)
    for index in parse_path(path):
        i = hmac.new(c, b"\x00" + k + struct.pack(">I", index), hashlib.sha512).digest()
        k, c = i[:32], i[32:]
    return k


def seed_fingerprint(master_seed: bytes) -> bytes:
    """4-byte identifier of a master seed (for PSBT derivation records)."""
    k, c = master_key(master_seed)
    return hashlib.sha256(b"safe-btc/fingerprint" + k + c).digest()[:4]


def derive_keypair(master_seed: bytes, path: str) -> KeyPair:
    return KeyPair.from_seed(derive_seed(master_seed, path))


# --- BIP-39 ------------------------------------------------------------------


def _mnemonic_module():
    from mnemonic import Mnemonic

    return Mnemonic("english")


def new_mnemonic(strength_bits: int = 256) -> str:
    """Generate a new BIP-39 mnemonic (24 words by default)."""
    return _mnemonic_module().generate(strength=strength_bits)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    m = _mnemonic_module()
    normalized = " ".join(mnemonic.split())
    if not m.check(normalized):
        raise ValueError("invalid BIP-39 mnemonic (bad word or checksum)")
    return m.to_seed(normalized, passphrase=passphrase)


def generate_key_from_mnemonic(
    mnemonic: str,
    passphrase: str = "",
    path: str | None = None,
    network: str = DEFAULT_NETWORK,
) -> KeyPair:
    """Derive an ML-DSA-65 key pair from a BIP-39 mnemonic (fully recoverable)."""
    return derive_keypair(mnemonic_to_seed(mnemonic, passphrase), path or default_path(network))


def generate_key_from_entropy(entropy: bytes | None = None) -> KeyPair:
    """
    Create a key pair from a 32-byte seed. The same entropy always gives the
    same key. With no entropy, a random seed is used (back it up!).
    """
    if entropy is None:
        entropy = os.urandom(SEED_SIZE)
    if len(entropy) != SEED_SIZE:
        raise ValueError(f"entropy must be {SEED_SIZE} bytes")
    return KeyPair.from_seed(entropy)


# --- addresses -----------------------------------------------------------------


def key_to_address(public_key: bytes, network: str = DEFAULT_NETWORK) -> str:
    return address_from_public_key(public_key, network)


def key_to_address_from_keypair(keypair: KeyPair, network: str = DEFAULT_NETWORK) -> str:
    return address_from_public_key(keypair.public_key, network)


def verify_pubkey_match(address: str, public_key: bytes, key_type: int = KEY_TYPE_ML_DSA_65) -> bool:
    """True if ``public_key`` is the key committed to by ``address``."""
    try:
        _, commitment = decode_address(address)
        return commitment == compute_commitment(public_key, key_type)
    except ValueError:
        return False


# --- key files -----------------------------------------------------------------


def save_key_file(
    path: str,
    keypair: KeyPair,
    network: str = DEFAULT_NETWORK,
    derivation_path: str | None = None,
    overwrite: bool = False,
) -> dict:
    """Write a key file with mode 0600. Refuses to overwrite unless asked."""
    data = {
        "format": KEY_FILE_FORMAT,
        "scheme": "ML-DSA-65 (FIPS 204)",
        "network": network,
        "seed": keypair.seed.hex(),
        "public_key": keypair.public_key.hex(),
        "address": address_from_public_key(keypair.public_key, network),
        "derivation_path": derivation_path,
    }
    # Write to a fresh 0600 temp file in the same directory, then move it into
    # place. The seed is never written to a file with looser permissions, and
    # an existing symlink at ``path`` is replaced rather than followed.
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".safe-btc-key-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        if overwrite:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)  # atomic; fails if path exists (even as a symlink)
            os.unlink(tmp)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return data


def load_key_file(path: str) -> tuple[KeyPair, dict]:
    with open(path) as f:
        data = json.load(f)
    if data.get("format") != KEY_FILE_FORMAT:
        if "secret_key" in data:
            raise ValueError(
                "this is a safe-btc 0.1 key file (random, non-recoverable key with an "
                "address that used the wrong checksum). Generate a new key with "
                "'safe-btc generate-key'."
            )
        raise ValueError("unrecognized key file format")
    keypair = KeyPair.from_seed(bytes.fromhex(data["seed"]))
    if keypair.public_key.hex() != data["public_key"]:
        raise ValueError("key file is corrupt: public key does not match seed")
    return keypair, data
