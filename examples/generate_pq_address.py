#!/usr/bin/env python3
"""
Example: create a recoverable witness v3 key, then receive and spend (testnet).

1. Derive an ML-DSA-65 key from a BIP-39 mnemonic
2. Show its bech32m tb1r address and scriptPubKey
3. Build a PSBT spending a (pretend) UTXO, sign, finalize, extract
4. Check the result against the reference consensus rules
"""

from safe_btc.consensus import verify_input
from safe_btc.keys import default_path, generate_key_from_mnemonic, new_mnemonic
from safe_btc.pq_addresses import address_from_public_key, compute_commitment, script_pubkey
from safe_btc.psbt import PQPsbt
from safe_btc.transaction import OutPoint, Transaction, TxIn, TxOut


def main() -> None:
    mnemonic = new_mnemonic()
    path = default_path("testnet")
    key = generate_key_from_mnemonic(mnemonic, path=path)
    again = generate_key_from_mnemonic(mnemonic, path=path)
    print(f"Recovery phrase:  {mnemonic}")
    print(f"Derivation path:  {path}")
    print(f"Recoverable:      {key.public_key == again.public_key}")

    spk = script_pubkey(compute_commitment(key.public_key))
    print(f"Address:          {address_from_public_key(key.public_key, 'testnet')}")
    print(f"scriptPubKey:     {spk.hex()}")

    utxo = TxOut(100_000, spk)
    tx = Transaction(
        inputs=[TxIn(OutPoint.from_hex_txid("11" * 32, 0))],
        outputs=[TxOut(98_000, bytes.fromhex("0014" + "00" * 20))],
    )
    psbt = PQPsbt.create(tx, [utxo])
    psbt.sign_input(0, key)
    psbt.finalize()
    signed = psbt.extract()

    print(f"Signed tx:        {signed.vsize()} vB, fee {psbt.fee()} sat, txid {signed.txid()}")
    print(f"Consensus check:  {verify_input(signed, 0, [utxo])}")


if __name__ == "__main__":
    main()
