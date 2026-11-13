"""Key derivation, mnemonic recovery and key files."""

from __future__ import annotations

import json
import os
import stat

import pytest

from safe_btc.keys import (
    default_path,
    derive_keypair,
    derive_seed,
    generate_key_from_entropy,
    generate_key_from_mnemonic,
    load_key_file,
    mnemonic_to_seed,
    new_mnemonic,
    parse_path,
    save_key_file,
    seed_fingerprint,
    verify_pubkey_match,
)
from safe_btc.pq_addresses import address_from_public_key


def test_entropy_is_deterministic():
    """Regression: 0.1 ignored the entropy and returned a random key."""
    e = b"\x01" * 32
    assert generate_key_from_entropy(e).public_key == generate_key_from_entropy(e).public_key
    assert generate_key_from_entropy(e).public_key != generate_key_from_entropy(b"\x02" * 32).public_key


def test_mnemonic_restores_same_key(mnemonic):
    """Regression: 0.1 produced a different key on every 'restore'."""
    a = generate_key_from_mnemonic(mnemonic)
    b = generate_key_from_mnemonic(" ".join(mnemonic.split()) + "  ")
    assert a.public_key == b.public_key
    assert generate_key_from_mnemonic(mnemonic, "pass").public_key != a.public_key


def test_mnemonic_checksum_enforced(mnemonic):
    with pytest.raises(ValueError):
        mnemonic_to_seed(mnemonic.replace("about", "abandon"))


def test_new_mnemonic_is_24_words():
    m = new_mnemonic()
    assert len(m.split()) == 24
    mnemonic_to_seed(m)


def test_paths_differ_and_are_hardened_only(mnemonic):
    seed = mnemonic_to_seed(mnemonic)
    assert derive_seed(seed, "m/3'/1'/0'/0'") != derive_seed(seed, "m/3'/1'/0'/1'")
    assert derive_seed(seed, "m/3h/1h/0h/0h") == derive_seed(seed, "m/3'/1'/0'/0'")
    with pytest.raises(ValueError):
        parse_path("m/3'/1'/0'/0")
    with pytest.raises(ValueError):
        parse_path("3'/1'")


def test_default_path_coin_type():
    assert default_path("mainnet", 0, 5) == "m/3'/0'/0'/5'"
    assert default_path("testnet", 2, 0) == "m/3'/1'/2'/0'"


def test_fingerprint_is_stable(mnemonic):
    seed = mnemonic_to_seed(mnemonic)
    assert seed_fingerprint(seed) == seed_fingerprint(seed)
    assert len(seed_fingerprint(seed)) == 4


def test_key_file_roundtrip_and_permissions(tmp_path, mnemonic):
    kp = derive_keypair(mnemonic_to_seed(mnemonic), "m/3'/1'/0'/0'")
    path = tmp_path / "k.json"
    data = save_key_file(str(path), kp, "testnet", "m/3'/1'/0'/0'")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert "secret_key" not in data and len(bytes.fromhex(data["seed"])) == 32
    loaded, meta = load_key_file(str(path))
    assert loaded.public_key == kp.public_key
    assert meta["address"] == address_from_public_key(kp.public_key, "testnet")


def test_key_file_not_overwritten(tmp_path, keypair):
    path = tmp_path / "k.json"
    save_key_file(str(path), keypair)
    with pytest.raises(FileExistsError):
        save_key_file(str(path), keypair)
    save_key_file(str(path), keypair, overwrite=True)


def test_legacy_key_file_rejected(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"public_key": "00", "secret_key": "00", "address": "bc1r..."}))
    with pytest.raises(ValueError, match="0.1 key file"):
        load_key_file(str(path))


def test_corrupt_key_file_detected(tmp_path, keypair, keypair2):
    path = tmp_path / "k.json"
    save_key_file(str(path), keypair)
    data = json.loads(path.read_text())
    data["public_key"] = keypair2.public_key.hex()
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="corrupt"):
        load_key_file(str(path))


def test_verify_pubkey_match(keypair, keypair2):
    addr = address_from_public_key(keypair.public_key)
    assert verify_pubkey_match(addr, keypair.public_key)
    assert not verify_pubkey_match(addr, keypair2.public_key)
    assert not verify_pubkey_match("garbage", keypair.public_key)


def test_overwrite_never_exposes_seed(tmp_path, keypair):
    """Regression: overwrite wrote the seed into a 0644 file before chmod."""
    path = tmp_path / "k.json"
    path.write_text("old")
    os.chmod(path, 0o644)
    save_key_file(str(path), keypair, overwrite=True)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["k.json"]


def test_symlink_is_replaced_not_followed(tmp_path, keypair):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    link = tmp_path / "k.json"
    link.symlink_to(victim)
    with pytest.raises(FileExistsError):
        save_key_file(str(link), keypair)
    save_key_file(str(link), keypair, overwrite=True)
    assert victim.read_text() == "precious"
    assert not link.is_symlink()


@pytest.mark.parametrize("path", ["m/٣'/1'", "m/1_0'/2'", "m/ 2'", "m/2'/", "m/-1'"])
def test_parse_path_is_strict(path):
    with pytest.raises(ValueError):
        parse_path(path)
