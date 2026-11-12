# BIP-XXXX: Post-Quantum Address Format (bc1r)

**Authors:** Zaenus <zaenus@users.noreply.github.com>
**Status:** Draft
**Type:** Standards Track
**Created:** 2026-11-12
**License:** MIT
**Discussion:** https://delvingbitcoin.org/t/witness-v3-ml-dsa-65-address-format (April 2026 thread)

## Abstract

This BIP proposes a new quantum-resistant address format for Bitcoin using
ML-DSA-65 (FIPS 204) post-quantum signatures. The format uses a new witness
version (0x03) and bech32m encoding (BIP-350), committing to a SHA-256 hash
of the ML-DSA-65 public key. The full public key is revealed only at spend
time in the witness.

## Motivation

Bitcoin's current signature algorithms (ECDSA/secp256k1 and Schnorr/secp256k1)
are vulnerable to Shor's algorithm on a cryptographically relevant quantum
computer (CRQC). Once a public key is revealed on-chain, a quantum attacker
can derive the private key and spend the funds.

Approximately 6.9 million BTC (~$586B) sits in addresses with exposed public
keys that would be directly vulnerable to a CRQC.

## Specification

### Address Format

Quantum-resistant addresses use the `bc` human-readable part (HRP) and
bech32m encoding (BIP-350). Witness version 0x03 encodes as the character
"r", so addresses start with `bc1r...`:

```
bc1r<version><data>
```

| Component | Size | Description |
|-----------|------|-------------|
| HRP | 2 chars | `bc` |
| Separator | 1 char | `1` (bech32m standard) |
| Witness version | 5 bits | `0x03` (post-quantum, encodes as "r") |
| Witness program | 32 bytes | SHA-256(ml_dsa_public_key) |
| Checksum | 6 chars | Bech32m checksum |

**Note:** Witness version 0x02 (addresses starting with `bc1z`) is allocated
to BIP-360 (P2MR). This proposal uses witness version 0x03.

### ScriptPubKey

For a `bc1r` address, the scriptPubKey is:

```
0x03 <32-byte SHA-256 commitment>
```

This is a witness version 3 program with a 32-byte commitment.

### Spending

To spend from a `bc1r` output, the witness stack contains:

```
<ml_dsa_signature (3,309 bytes)> <ml_dsa_public_key (1,952 bytes)>
```

Validation rules:

1. Compute `SHA-256(public_key)` and verify it matches the commitment in the scriptPubKey.
2. Verify the ML-DSA-65 signature against the message hash using BIP-143
   sighash semantics (consistent with SegWit v0) and the public key.
3. If both checks pass, the spend is valid.

### Sighash

The signature message is the BIP-143 sighash digest (the same digest used
for SegWit v0 transactions), adapted for witness version 3 programs. The
sighash type defaults to SIGHASH_ALL.

### Signature Size Impact

| Signature Type | Size |
|----------------|------|
| ECDSA (legacy) | ~72 bytes |
| Schnorr (Taproot) | ~64 bytes |
| ML-DSA-65 | 3,309 bytes |

ML-DSA-65 signatures are approximately 46× larger than ECDSA signatures.
This increases transaction fees for quantum-resistant spends. To mitigate
this, signature aggregation (e.g., SNARK-wrapped ML-DSA proofs) is
recommended. **Note: Any aggregation scheme requires a real zk-SNARK
circuit with a trusted setup; the safe-btc repo contains only a mock
prototype for interface demonstration.**

### Backward Compatibility

This is a soft fork. Old nodes will see `bc1r` outputs as anyone-can-spend
(witness version > 1). To prevent fund loss, old nodes must upgrade before
accepting `bc1r` transactions in blocks.

## Deployment

Activation via BIP-9-style version bits or BIP-8-style lock-in-on-expiry.
Suggested bit: TBD.

## Test Vectors

Test vectors will be provided in the reference implementation at
`tests/test_bip_vectors.py`.

## Reference Implementation

https://github.com/Zaenus/btc-safe

## Related Discussion

- April 2026 Delving Bitcoin thread on witness-v3 ML-DSA-65 address format
- BIP-360 (P2MR, witness version 0x02)
- BIP-361 (three-phase quantum migration plan)

## Copyright

This document is licensed under the MIT License.
