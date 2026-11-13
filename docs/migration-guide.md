# Migration Guide: Legacy to Witness v3 (Post-Quantum) Outputs

> **Status:** witness v3 is a draft proposal and is **not active** on Bitcoin
> mainnet. Today, coins sent to a mainnet `bc1r` address can be taken by anyone.
> Everything below is for testnet, signet and regtest until a soft fork
> activates.

## Why migrate, and why early

Bitcoin's ECDSA and Schnorr signatures can be broken by a cryptographically
relevant quantum computer (CRQC) once the public key is known. Two things make
waiting until a CRQC exists a bad plan:

* Moving coins takes block space. Every 10 million UTXOs need roughly 1,200
  full blocks of nothing but migration transactions. Everyone moving at once
  would take months.
* Even never-reused P2WPKH coins reveal their key when spent, so they can be
  attacked during the minutes the spend waits in the mempool.

Witness v3 outputs avoid both problems: they stay secure after the key and
signatures are public.

## Risk levels

| Address type | Key visible on-chain? | Quantum risk |
|---|---|---|
| P2PK | Yes, always | **High** |
| Taproot (P2TR, `bc1p`) | Yes, always (output key is in the scriptPubKey) | **High** |
| Any address already spent from or reused | Yes (revealed by the spend) | **High** |
| Unspent, never-used P2PKH / P2SH / P2WPKH / P2WSH | No, until spent | Low (exposed while a spend is in the mempool) |
| P2MR (BIP-360, `bc1z`) | No, until a leaf is spent | Low (depends on the leaf's signature scheme) |
| Witness v3 (`bc1r`) | Yes, after spending | **None**: stays safe after the key is revealed |

## Steps

### 1. Create a recoverable key

```bash
safe-btc generate-key -o my-pq-key.json
```

This prints a new 24-word recovery phrase **once**, on stderr. Write it down;
it is the only backup. The key file (mode 0600) holds the 32-byte seed for
`m/3'/1'/0'/0'`. To restore, or derive more addresses from an existing phrase:

```bash
safe-btc generate-key --restore --index 1 -o key-1.json      # prompts for the phrase
safe-btc generate-key --mnemonic-file phrase.txt -o key-0.json
```

Avoid `--mnemonic "word word ..."`: it leaves the phrase in your shell history.

### 2. Plan the migration

```bash
safe-btc migrate --wallet my-addresses.txt --mnemonic-file phrase.txt \
    --spent-from 1Abc...,bc1q... -o migration-plan.json
```

* Addresses are classified by actually decoding them (base58check, bech32,
  bech32m), not by guessing from the prefix.
* For P2PK coins, pass the hex public key instead of an address.
* `--spent-from` lists addresses you have spent from before; they are high risk.
* Each at-risk address gets its own destination, derived from your recovery
  phrase at `m/3'/coin'/account'/index'`. The plan file contains no secrets, and
  every destination can be re-derived from the phrase.
* Use `--classify-only` to only assess risk.

High-risk entries are listed first: move those first.

### 3. Move the coins

Send each balance to its destination with your existing wallet. Because the
legacy key is revealed when you spend, do this well before a CRQC is expected.

### 4. Spending from witness v3

Spends are built as PSBTs (`safe_btc.psbt.PQPsbt`). The signer computes the
sighash itself from the transaction and the amounts and scripts of all inputs,
so a compromised host cannot make it sign for a different fee.

## Monitoring

```bash
safe-btc canary --poll --state-file canary.json
```

The default canary is a Taproot output whose key is the BIP-341 NUMS point:
nobody knows its private key. If coins sitting there ever move, someone can
compute secp256k1 discrete logs. The command exits with status 2 when
triggered. `--esplora-url` selects the API server (the default is
mempool.space; querying it reveals which address you watch).

## Costs

| Transaction | Approximate size |
|---|---|
| P2WPKH, 1 input, 2 outputs | ~141 vB |
| Taproot key path, 1 input, 2 outputs | ~154 vB |
| Witness v3 (ML-DSA-65), 1 input, 2 outputs | ~1,455 vB |

A witness v3 input weighs 5,433 WU (~1,358 vB), about 20 times a P2WPKH input
(~68 vB); a whole simple transaction is about 10 times larger. Consolidating UTXOs before migrating reduces later spending costs.
`safe-btc info` prints current figures.
