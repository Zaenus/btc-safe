# Quantum-Resistant Address Format Specification

This document specifies the `bc1z` address format for quantum-resistant
Bitcoin addresses using ML-DSA-65 (FIPS 204) post-quantum signatures.

## Overview

The `bc1z` address format commits to a SHA-256 hash of an ML-DSA-65
public key. The full public key is revealed at spend time (in the witness)
and verified against this commitment before signature verification.

This follows the same pattern as P2WPKH (SegWit v0), where the address
contains a hash of the public key and the full public key is provided
in the witness at spend time.

## Address Structure

```
bc1z<version><data><checksum>
```

| Component | Size | Description |
|-----------|------|-------------|
| HRP | 4 chars | `bc1z` (fixed) |
| Separator | 1 char | `1` (bech32m standard) |
| Version | 5 bits | Witness version `0x02` (post-quantum) |
| Data | 32 bytes | SHA-256(public_key) commitment |
| Checksum | 6 chars | Bech32m checksum |

## Encoding

1. Compute `commitment = SHA-256(ml_dsa_public_key)` (32 bytes)
2. Construct data payload: `version_byte || commitment` (33 bytes total)
3. Convert from 8-bit to 5-bit groups (bech32m conversion)
4. Append 6-symbol bech32m checksum
5. Encode using bech32m character set
6. Prepend HRP `bc1z`

## Spend-time Validation

When spending from a `bc1z` address:

1. The witness contains: `ml_dsa_public_key (1952 bytes) || ml_dsa_signature (3309 bytes)`
2. Hash the provided public key: `SHA-256(pubkey)`
3. Verify the hash matches the address commitment
4. Verify the ML-DSA-65 signature against the public key and message

## Parameter Sizes (ML-DSA-65)

| Parameter | Size |
|-----------|------|
| Public key | 1,952 bytes |
| Secret key | 4,032 bytes |
| Signature | 3,309 bytes |
| Commitment hash | 32 bytes |

## Security Considerations

- The commitment hash provides 128-bit collision resistance (birthday bound on SHA-256)
- ML-DSA-65 provides approximately 192-bit security against quantum attacks
- The full public key is 1,952 bytes — significantly larger than ECDSA's ~33 bytes
  This increases transaction size and fee costs for PQ transactions
- Addresses are ~54 characters long, comparable to Taproot addresses

## Future Work

- Support for ML-DSA-44 (smaller keys/sigs, ~128-bit security)
- Support for ML-DSA-87 (larger keys/sigs, ~256-bit security)
- Support for FN-DSA (Falcon) for smaller signatures (~600-1300 bytes)
- Signature aggregation via SNARKs to reduce on-chain data
