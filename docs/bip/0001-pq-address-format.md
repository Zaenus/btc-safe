# BIP-XXXX: Post-Quantum Address Format (bc1z)

**Authors:** Zaenus <zaenus@users.noreply.github.com>
**Status:** Draft
**Type:** Standards Track
**Created:** 2026-11-12
**License:** MIT

## Abstract

This BIP proposes a new quantum-resistant address format for Bitcoin using
ML-DSA-65 (FIPS 204) post-quantum signatures. The format uses a new witness
version (0x02) and commits to a SHA-256 hash of the ML-DSA-65 public key,
revealing the full public key only at spend time in the witness.

## Motivation

Bitcoin's current signature algorithms (ECDSA/secp256k1 and Schnorr/secp256k1)
are vulnerable to Shor's algorithm on a cryptographically relevant quantum
computer (CRQC). Once a public key is revealed on-chain, a quantum attacker
can derive the private key and spend the funds.

Approximately 6.9 million BTC (~$586B) sits in addresses with exposed public
keys that would be directly vulnerable to a CRQC.

## Specification

### Address Format

Quantum-resistant addresses use the `bc1z` human-readable part (HRP) and
bech32 encoding:

```
bc1z<version><data>
```

| Component | Size | Description |
|-----------|------|-------------|
| HRP | 4 chars | `bc1z` |
| Separator | 1 char | `1` (bech32 standard) |
| Witness version | 5 bits | `0x02` (post-quantum) |
| Witness program | 32 bytes | SHA-256(ml_dsa_public_key) |
| Checksum | 6 chars | Bech32 checksum |

### ScriptPubKey

For a `bc1z` address, the scriptPubKey is:

```
0x02 <32-byte SHA-256 commitment>
```

This is a witness version 2 program with a 32-byte commitment.

### Spending

To spend from a `bc1z` output, the witness stack contains:

```
<ml_dsa_signature (3309 bytes)> <ml_dsa_public_key (1952 bytes)>
```

Validation rules:

1. Compute `SHA-256(public_key)` and verify it matches the commitment in the scriptPubKey.
2. Verify the ML-DSA-65 signature against the message (transaction hash per BIP-143/BIP-341) using the public key.
3. If both checks pass, the spend is valid.

### Signature Size Impact

| Signature Type | Size |
|----------------|------|
| ECDSA (legacy) | ~72 bytes |
| Schnorr (Taproot) | ~64 bytes |
| ML-DSA-65 | 3,309 bytes |

ML-DSA-65 signatures are approximately 46× larger than ECDSA signatures. This
increases transaction fees for quantum-resistant spends. Signature aggregation
(see Phase 2B) is recommended to mitigate this.

### Backward Compatibility

This is a soft fork. Old nodes will see `bc1z` outputs as anyone-can-spend
(witness version > 1). To prevent fund loss, old nodes must upgrade before
accepting `bc1z` transactions in blocks.

## Deployment

Activation via BIP-9-style version bits or BIP-8-style lock-in-on-expiry.
Suggested bit: TBD.

## Test Vectors

Test vectors will be provided in the reference implementation at
`tests/test_bip_vectors.py`.

## Reference Implementation

https://github.com/Zaenus/btc-safe

## Copyright

This document is licensed under the MIT License.
