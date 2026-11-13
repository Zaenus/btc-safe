"""CLI smoke tests."""

from __future__ import annotations

import json

import pytest

from safe_btc.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_info(capsys):
    code, out, _ = run(capsys, "info")
    assert code == 0 and "bc1r" in out and "witness v3" in out and "bc1z" not in out


def test_generate_key_to_stdout(capsys):
    """Regression: 0.1 crashed with UnboundLocalError without -o."""
    code, out, err = run(capsys, "generate-key")
    assert code == 0
    data = json.loads(out)
    assert data["address"].startswith("tb1r")
    assert "RECOVERY PHRASE" in err


def test_mainnet_requires_opt_in(capsys, tmp_path, mnemonic):
    mf = tmp_path / "m.txt"
    mf.write_text(mnemonic)
    code, _, err = run(capsys, "generate-key", "--network", "mainnet", "--mnemonic-file", str(mf))
    assert code == 1 and "anyone-can-spend" in err
    code, out, _ = run(capsys, "generate-key", "--network", "mainnet", "--allow-mainnet", "--mnemonic-file", str(mf))
    assert code == 0 and json.loads(out)["address"].startswith("bc1r")


def test_restore_is_deterministic_and_sign_verify(capsys, tmp_path, mnemonic):
    mf = tmp_path / "m.txt"
    mf.write_text(mnemonic)
    k1, k2 = tmp_path / "k1.json", tmp_path / "k2.json"
    assert run(capsys, "generate-key", "--mnemonic-file", str(mf), "-o", str(k1))[0] == 0
    assert run(capsys, "generate-key", "--mnemonic-file", str(mf), "-o", str(k2))[0] == 0
    d1, d2 = json.loads(k1.read_text()), json.loads(k2.read_text())
    assert d1["address"] == d2["address"]

    code, _, err = run(capsys, "generate-key", "--mnemonic-file", str(mf), "-o", str(k1))
    assert code == 1 and "exists" in err

    code, out, _ = run(capsys, "address", "--from-key", str(k1))
    assert out.strip() == d1["address"]

    code, sig, _ = run(capsys, "sign", "--key", str(k1), "--message", "hello")
    assert code == 0
    args = ["verify", "--address", d1["address"], "--public-key", d1["public_key"], "--signature", sig.strip()]
    assert run(capsys, *args, "--message", "hello")[0] == 0
    assert run(capsys, *args, "--message", "hellO")[0] == 1


def test_migrate(capsys, tmp_path, mnemonic):
    mf = tmp_path / "m.txt"
    mf.write_text(mnemonic)
    out_file = tmp_path / "plan.json"
    taproot = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    code, out, _ = run(capsys, "migrate", "--addresses", f"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa,{taproot}",
                       "--mnemonic-file", str(mf), "-o", str(out_file))
    assert code == 0 and "[HIGH" in out
    plan = json.loads(out_file.read_text())
    assert all(a["pq_derivation_path"] for a in plan["legacy_addresses"])

    code, _, err = run(capsys, "migrate", "--addresses", taproot)
    assert code == 1 and "recovery phrase" in err
    assert run(capsys, "migrate", "--addresses", taproot, "--classify-only")[0] == 0


def test_canary_offline(capsys):
    code, out, _ = run(capsys, "canary")
    assert code == 0 and "bc1p2zffkaxp5py4fdutfdsrt6t6tcrc5ks09rkfd428hlhf4n5q8tqqwv7ahk" in out


def test_no_command(capsys):
    assert run(capsys)[0] == 1


@pytest.mark.parametrize("cmd", ["sign", "verify"])
def test_message_required(capsys, tmp_path, keypair, cmd):
    from safe_btc.keys import save_key_file

    k = tmp_path / "k.json"
    save_key_file(str(k), keypair)
    args = ["--key", str(k)] if cmd == "sign" else [
        "--address", "tb1rrk6amt25z9j9tu8luxnsws678zcatudly0ang6rd5xj0d5l3alaqj44gka",
        "--public-key", keypair.public_key.hex(), "--signature", "00"]
    code, _, err = run(capsys, cmd, *args)
    assert code == 1 and "--message" in err
