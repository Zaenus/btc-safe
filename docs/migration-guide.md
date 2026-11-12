# Migration Guide: Legacy to Quantum-Resistant Addresses

This guide explains how to migrate Bitcoin funds from legacy (ECDSA/Schnorr)
addresses to quantum-resistant `bc1z` addresses using ML-DSA-65.

## Why Migrate

Bitcoin's current signature algorithms (ECDSA/secp256k1 and Schnorr/secp256k1)
are vulnerable to Shor's algorithm on a cryptographically relevant quantum
computer (CRQC). Once a public key is revealed on-chain, a quantum attacker
can derive the private key and spend the funds.

### Risk Levels

| Address Type | Public Key on Chain? | Quantum Risk |
|-------------|---------------------|--------------|
| P2PK | Yes (always) | HIGH |
| Reused P2PKH/P2WPKH | Yes (after first spend) | HIGH |
| Unspent P2PKH/P2WPKH | No | LOW (until spent) |
| Taproot (key path) | Yes (if key path spent) | MEDIUM |
| `bc1z` (PQ) | No (hash only) | NONE |

## Migration Steps

### 1. Generate a PQ Key Pair

```bash
safe-btc generate-key --output my-pq-key.json
```

This creates:
- `public_key`: Hex-encoded ML-DSA-65 public key (1952 bytes)
- `secret_key`: Hex-encoded ML-DSA-65 secret key (4032 bytes) — **keep secret!**
- `address`: Your new `bc1z` quantum-resistant address

### 2. Create a Migration Plan

If you have multiple legacy addresses:

```bash
safe-btc migrate --addresses 1Abc...,3Def...,bc1q... --output migration-plan.json
```

Or from a wallet file:

```bash
safe-btc migrate --wallet my-wallet.txt --output migration-plan.json
```

### 3. Move Funds

For each legacy address, create a transaction sending funds to the corresponding
`bc1z` address. Sign with your legacy keys and broadcast to the network.

**Important:** Once you spend from a legacy address, its public key is revealed
on-chain. Move funds to PQ addresses before a CRQC exists.

### 4. Verify Your PQ Address

```bash
safe-btc address --from-key my-pq-key.json
```

## Monitoring for Quantum Threats

Use the quantum canary to detect when a CRQC becomes operational:

```bash
safe-btc canary --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

If the canary address (which has an exposed public key) ever spends funds,
it's evidence that a quantum computer can break ECDSA.

## Cost Considerations

PQ transactions are significantly larger than legacy transactions:

| Transaction Type | Approximate Size |
|-----------------|------------------|
| Legacy P2PKH | ~250 vbytes |
| P2WPKH (SegWit) | ~140 vbytes |
| PQ `bc1z` | ~3,500+ vbytes |

Expect higher fees for PQ transactions until signature aggregation
(SNARK-wrapped signatures) is implemented.

## Disclaimer

This is pre-consensus reference software. The `bc1z` address format is
not yet recognized by Bitcoin nodes or wallets. Use only for testing and
development until a BIP is proposed and activated.
