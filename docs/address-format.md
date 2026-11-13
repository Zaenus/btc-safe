# Witness v3 Address Format (`bc1r`)

This is a short summary for implementers. The normative text is the BIP draft,
[`bip/0001-pq-address-format.md`](bip/0001-pq-address-format.md), and the test
vectors are in [`bip/0001-test-vectors.json`](bip/0001-test-vectors.json).

## Overview

A witness v3 output commits to an ML-DSA-65 (FIPS 204) public key. Spending
reveals the key and an ML-DSA-65 signature.

**The output remains quantum-resistant after the key and signatures are
revealed.** This is the key difference from P2WPKH, which also hides a key
behind a hash but is only safe while that key stays hidden. Here the hash keeps
the output small (34 bytes instead of about 1,955); it is not what provides
security. Reusing an address is therefore safe against a quantum attacker,
although it still hurts privacy.

## Encoding

```
key_blob     = 0x01 || ml_dsa_65_public_key          (1 + 1,952 bytes)
commitment   = TaggedHash("PQKeyCommit", key_blob)  (32 bytes, BIP-340 tagged hash)
scriptPubKey = 0x53 0x20 <commitment>                (OP_3 OP_PUSHBYTES_32)
address      = bech32m(hrp, witness_version = 3, program = commitment)
```

| Part | Value |
|---|---|
| HRP | `bc` (mainnet), `tb` (testnet, signet), `bcrt` (regtest) |
| Separator | `1` |
| Witness version | 3, a single 5-bit symbol written as `r` |
| Program | 32-byte commitment (52 five-bit symbols) |
| Checksum | 6 symbols, **bech32m** (BIP-350), as required for versions 1-16 |

Mainnet addresses are 62 characters and start with `bc1r`. Note that the
witness version is a separate symbol, not a byte prepended to the program.

Version 0.1 of safe-btc produced witness v3 addresses with the older bech32
(BIP-173) checksum. Those strings are invalid; any BIP-350 decoder rejects them.

## Witness at spend time

```
<signature>  <key_blob>  [<annex>]
```

* `signature`: 3,309 bytes (SIGHASH_DEFAULT) or 3,310 bytes (last byte is the
  hash type)
* `key_blob`: `0x01 || public_key` (1,953 bytes)
* optional annex as in BIP-341 (non-standard)

The signature covers `TaggedHash("PQSighash", 0x00 || SigMsg)`, with `SigMsg`
exactly as in BIP-341, and uses the FIPS 204 context string `"bitcoin:pq:tx"`.

## Sizes (ML-DSA-65)

| Item | Size |
|---|---|
| Public key | 1,952 bytes |
| Private key (seed) | 32 bytes (expanded form: 4,032 bytes, never stored) |
| Signature | 3,309 bytes |
| Output | 43 bytes |
| Input | 5,433 WU, about 1,358 vB |

## Safety

Witness v3 is **not active** on any network. Coins sent to a mainnet `bc1r`
address today can be taken by anyone. safe-btc defaults to testnet and refuses
to print mainnet addresses without `--allow-mainnet`.
