"""Witness v3 address encoding, BIP-350 conformance and signatures."""

from __future__ import annotations

import pytest

from safe_btc import segwit_addr
from safe_btc.pq_addresses import (
    COMMITMENT_LEN,
    KEY_TYPE_ML_DSA_65,
    address_from_public_key,
    address_network,
    compute_commitment,
    decode_address,
    encode_address,
    is_valid_address,
    key_blob,
    parse_script_pubkey,
    script_pubkey,
)
from safe_btc.pq_signatures import CONTEXT_MSG, CONTEXT_TX, MLDSA65, PUBLIC_KEY_SIZE, SIGNATURE_SIZE

# --- BIP-350 test vectors (https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)

VALID_BECH32M = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]

INVALID_BECH32M = [
    "\x201xj0phk",
    "\x7f1g6xzxy",
    "\x801vctc34",
    "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    "qyrz8wqd2c9m",
    "1qyrz8wqd2c9m",
    "y1b0jsk6g",
    "lt1igcx5c0",
    "in1muywd",
    "mm1crxm3i",
    "au1s5cgom",
    "M1VUXWEZ",
    "16plkw9",
    "1p2gdwpf",
]

VALID_SEGWIT = [
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
     "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
    ("BC1SW50QGDZ25J", "6002751e"),
    ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
    ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
     "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
     "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
     "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
]

INVALID_SEGWIT = [
    "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    "bc1pw5dgrnzv",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
    "bc1gmk9yu",
]


@pytest.mark.parametrize("s", VALID_BECH32M)
def test_bip350_valid_bech32m(s):
    hrp, data, spec = segwit_addr.bech32_decode(s)
    assert spec == segwit_addr.Encoding.BECH32M


@pytest.mark.parametrize("s", INVALID_BECH32M)
def test_bip350_invalid_bech32m(s):
    _, _, spec = segwit_addr.bech32_decode(s)
    assert spec != segwit_addr.Encoding.BECH32M


@pytest.mark.parametrize("addr,spk_hex", VALID_SEGWIT)
def test_bip350_valid_segwit_addresses(addr, spk_hex):
    hrp = "bc" if addr.lower().startswith("bc") else "tb"
    version, program = segwit_addr.decode(hrp, addr)
    assert version is not None
    spk = bytes([version + 0x50 if version else 0, len(program)]) + bytes(program)
    assert spk.hex() == spk_hex
    assert segwit_addr.encode(hrp, version, bytes(program)) == addr.lower()


@pytest.mark.parametrize("addr", INVALID_SEGWIT)
def test_bip350_invalid_segwit_addresses(addr):
    assert segwit_addr.decode("bc", addr) == (None, None)
    assert segwit_addr.decode("tb", addr) == (None, None)


# --- witness v3 addresses


def _checksum_const(addr: str) -> int:
    hrp, rest = addr.rsplit("1", 1)
    data = [segwit_addr.CHARSET.find(c) for c in rest]
    return segwit_addr.bech32_polymod(segwit_addr.bech32_hrp_expand(hrp) + data)


def test_address_uses_bech32m_not_bech32(keypair):
    """Regression: 0.1 produced Bech32 (BIP-173) checksums for witness v3."""
    for net in ("mainnet", "testnet", "regtest"):
        addr = address_from_public_key(keypair.public_key, net)
        assert _checksum_const(addr) == segwit_addr.BECH32M_CONST


@pytest.mark.parametrize("net,prefix", [("mainnet", "bc1r"), ("testnet", "tb1r"), ("signet", "tb1r"), ("regtest", "bcrt1r")])
def test_prefixes(keypair, net, prefix):
    addr = address_from_public_key(keypair.public_key, net)
    assert addr.startswith(prefix)
    assert is_valid_address(addr)
    assert address_network(addr) == ("testnet" if net == "signet" else net)


def test_default_network_is_testnet(keypair):
    assert address_from_public_key(keypair.public_key).startswith("tb1r")


def test_roundtrip(keypair):
    commitment = compute_commitment(keypair.public_key)
    addr = encode_address(commitment, "mainnet")
    assert decode_address(addr) == (3, commitment)
    assert decode_address(addr, "mainnet") == (3, commitment)
    with pytest.raises(ValueError):
        decode_address(addr, "testnet")


def test_rejects_other_witness_versions():
    taproot = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    assert not is_valid_address(taproot)
    assert not is_valid_address("not an address")


def test_commitment_binds_key_type(keypair):
    from safe_btc.hashing import tagged_hash

    c1 = compute_commitment(keypair.public_key, KEY_TYPE_ML_DSA_65)
    assert len(c1) == COMMITMENT_LEN
    other = tagged_hash("PQKeyCommit", key_blob(keypair.public_key, 0x02, allow_undefined=True))
    assert c1 != other


@pytest.mark.parametrize("key_type", [0x00, 0x02, 0x77])
def test_undefined_key_types_refused(keypair, key_type):
    """Outputs with undefined key types are anyone-can-spend (upgrade hook)."""
    with pytest.raises(ValueError, match="not defined"):
        address_from_public_key(keypair.public_key, "testnet", key_type=key_type)
    with pytest.raises(ValueError):
        compute_commitment(b"", key_type)


def test_key_blob_validation(keypair):
    assert key_blob(keypair.public_key) == b"\x01" + keypair.public_key
    with pytest.raises(ValueError):
        key_blob(keypair.public_key[:-1])
    with pytest.raises(ValueError):
        key_blob(keypair.public_key, 0x50)


def test_script_pubkey_is_op3_push32(keypair):
    commitment = compute_commitment(keypair.public_key)
    spk = script_pubkey(commitment)
    assert spk.hex().startswith("5320") and len(spk) == 34
    assert parse_script_pubkey(spk) == commitment
    assert parse_script_pubkey(b"\x51\x20" + commitment) is None


def test_encode_rejects_bad_length():
    with pytest.raises(ValueError):
        encode_address(b"\x00" * 31)


# --- ML-DSA-65 wrapper


def test_sizes(keypair):
    assert len(keypair.public_key) == PUBLIC_KEY_SIZE
    assert len(keypair.seed) == 32
    assert len(keypair.sign(b"m")) == SIGNATURE_SIZE


def test_contexts_are_domain_separated(keypair):
    sig = MLDSA65.sign(keypair.seed, b"\x00" * 32, CONTEXT_MSG)
    assert MLDSA65.verify(keypair.public_key, b"\x00" * 32, sig, CONTEXT_MSG)
    assert not MLDSA65.verify(keypair.public_key, b"\x00" * 32, sig, CONTEXT_TX)
    assert not MLDSA65.verify(keypair.public_key, b"\x00" * 32, sig, b"")


def test_verify_never_raises(keypair):
    assert not MLDSA65.verify(b"\x00" * 10, b"m", b"\x00" * 10, CONTEXT_MSG)
    assert not MLDSA65.verify(keypair.public_key, b"m", b"\x00" * SIGNATURE_SIZE, CONTEXT_MSG)
    assert not MLDSA65.verify(b"\xff" * PUBLIC_KEY_SIZE, b"m", b"\x00" * SIGNATURE_SIZE, CONTEXT_MSG)


def test_wrong_key_rejected(keypair, keypair2):
    sig = keypair.sign(b"hello")
    assert keypair.verify(b"hello", sig)
    assert not keypair2.verify(b"hello", sig)
    assert not keypair.verify(b"hellO", sig)
