# btc-safe

Post-quantum output format, reference implementation and tooling for Bitcoin.
The repository is `btc-safe`; the Python package and CLI are `safe-btc`.

> **Research software.** The witness v3 output type described here is **not
> active** on any Bitcoin network. Coins sent to a mainnet `bc1r` address today
> can be taken by anyone. The tools default to testnet.

> **Status: on hold.** The BIP draft in this repository is a personal research
> draft. It has not been submitted and is not seeking adoption. Bitcoin's
> post-quantum design work is converging elsewhere: see the Delving Bitcoin
> [PQC output type discussion](https://delvingbitcoin.org/t/pqc-output-type-discussion/2749),
> [BIP-360 (P2MR)](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki)
> and [SHRINCS](https://github.com/SHRINCS/shrincs-bip/blob/main/SHRINCS.md).
> The code is kept as a reference implementation, test-vector source and
> exposure tool.

## The problem

Bitcoin's ECDSA and Schnorr signatures (secp256k1) can be broken by Shor's
algorithm on a cryptographically relevant quantum computer (CRQC):

* **Long-exposure attacks** hit keys already on-chain: P2PK, Taproot (the output
  key is in the scriptPubKey), and any address that has been spent from or
  reused, plus bare multisig. That was 7,159,718 BTC (35.6% of supply) at
  block 975,029 on 2026-11-08, per ChainQuery's weekly
  [UTXO-set walk](https://chainquery.com/reports/quantum-exposure); BIP-361
  cited more than 34% in March 2026.
* **Short-exposure attacks** hit any secp256k1 spend while it waits in the
  mempool, including never-reused P2WPKH.

Migration has to be done **before** a CRQC exists: soft forks take years to
activate, and moving tens of millions of UTXOs takes months of block space.

## The proposal

A new witness version 3 output spent with **ML-DSA-65** (FIPS 204):

* Output: `OP_3 <TaggedHash("PQKeyCommit", key_type || pubkey)>`, encoded as a
  **bech32m** address: `bc1r...` (mainnet), `tb1r...` (testnet/signet),
  `bcrt1r...` (regtest).
* Witness: `<signature[||hash_type]> <key_type || pubkey>`, with the signature
  over a BIP-341-style sighash (tag `"PQSighash"`) and FIPS 204 context
  `"bitcoin:pq:tx"`.
* **Unlike P2WPKH, a `bc1r` output stays quantum-resistant after its public key
  and signatures are revealed.** The hash commitment keeps outputs small; it is
  not what provides security. Address reuse is safe against quantum attack
  (though still bad for privacy).
* A key type byte lets future soft forks add ML-DSA-44, SLH-DSA, FN-DSA or
  hybrid keys without spending another witness version.

Read the [BIP draft](docs/bip/0001-pq-address-format.md) (personal research draft, not submitted) and its
[test vectors](docs/bip/0001-test-vectors.json). It builds on echelonresearch's
earlier [witness v3 draft](https://delvingbitcoin.org/t/bip-draft-witness-version-3-ml-dsa-65-post-quantum-key-path-spending/2422)
(Delving Bitcoin, April 2026), which introduced the `bc1r` ML-DSA-65 output and
the `"PQSighash"` tag; the BIP lists what differs.

## Installation

```bash
git clone https://github.com/Zaenus/btc-safe.git
cd btc-safe
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Requires Python 3.10+ and `cryptography` 50 or newer (ML-DSA via OpenSSL).

## Quick start

```bash
safe-btc info                                   # parameters, sizes, status

# New recoverable key (prints a 24-word recovery phrase once, on stderr)
safe-btc generate-key -o my-key.json
safe-btc address --from-key my-key.json          # tb1r...

# Restore / derive more addresses from the phrase
safe-btc generate-key --restore --index 1 -o key-1.json

# Off-chain message signing (separate FIPS 204 context from transactions)
safe-btc sign --key my-key.json --message "hello"
safe-btc verify --address tb1r... --public-key <hex> --signature <hex> --message "hello"

# Classify addresses by quantum exposure and plan recoverable destinations
safe-btc migrate --addresses 1Abc...,bc1p... --mnemonic-file phrase.txt -o plan.json

# Watch the NUMS-key canary (any spend means secp256k1 is broken)
safe-btc canary --poll
```

Building and signing a spend (library):

```python
from safe_btc.keys import generate_key_from_mnemonic
from safe_btc.pq_addresses import compute_commitment, script_pubkey
from safe_btc.psbt import PQPsbt
from safe_btc.transaction import OutPoint, Transaction, TxIn, TxOut

key = generate_key_from_mnemonic(phrase)
utxo = TxOut(100_000, script_pubkey(compute_commitment(key.public_key)))
tx = Transaction(inputs=[TxIn(OutPoint.from_hex_txid(txid, 0))],
                 outputs=[TxOut(98_000, destination_script)])
psbt = PQPsbt.create(tx, [utxo])
psbt.sign_input(0, key)          # computes the sighash itself
psbt.finalize()
signed = psbt.extract()          # checked against the consensus rules
```

## Project structure

```
src/safe_btc/
  pq_signatures.py     ML-DSA-65 (seeded keygen, FIPS 204 contexts)
  pq_addresses.py      commitment, scriptPubKey, bech32m addresses, networks
  segwit_addr.py       BIP-173/350 reference code (vendored)
  transaction.py       tx serialization, BIP-341-style signature message
  consensus.py         reference spending rules and relay policy
  psbt.py              BIP-174 PSBTs with proprietary PQ fields
  keys.py              BIP-39 + hardened derivation, key files (0600)
  wallet.py            exposure classifier, recoverable migration plans
  canary.py            NUMS-key canary with Esplora polling
  wallet_integration/  Electrum file helper, Core RPC, size/fee estimates
  cli.py               command-line interface
docs/
  bip/                 BIP draft + test vectors
  address-format.md    implementer summary
  migration-guide.md   user guide
  research/            signature aggregation notes
tools/generate_bip_vectors.py
tests/                 includes official BIP-341 and BIP-350 vectors
```

## Roadmap

| Milestone | Status |
|---|---|
| ML-DSA-65 keys, seeded and recoverable from BIP-39 | Done |
| bech32m witness v3 addresses (BIP-350 vectors pass) | Done |
| BIP-341-style sighash (checked against BIP-341 vectors) | Done |
| Reference spending rules, relay policy, test vectors | Done (draft) |
| PSBT support (proprietary fields) | Done (prototype) |
| Migration planner, NUMS canary | Done |
| BIP submission / community review | On hold (see Status above) |
| Decide ML-DSA-44 vs -65, hybrid key type | Open |
| Bitcoin Core patch (regtest) and validation benchmarks | Planned |
| Signature aggregation | Research only ([notes](docs/research/signature-aggregation.md)) |

See [CHANGELOG.md](CHANGELOG.md) for what changed in 0.2.

## License

MIT. `src/safe_btc/segwit_addr.py` is MIT-licensed code by Pieter Wuille.
