# btc-safe

Quantum-resistant address formats and tools for Bitcoin.

## Mission

Build practical, off-chain tooling to prepare Bitcoin for the post-quantum era — starting with quantum-resistant address formats using ML-DSA (FIPS 204), then progressing toward a consensus-layer BIP.

## The Problem

Bitcoin's digital signatures (ECDSA/secp256k1 and Schnorr/secp256k1) are vulnerable to Shor's algorithm on a cryptographically relevant quantum computer (CRQC). Once a public key appears on-chain, a sufficiently powerful quantum computer can derive the private key and spend the funds.

- **Exposed-key addresses** (P2PK, reused P2PKH/P2WPKH after spending, Taproot): directly vulnerable
- **Hidden-key addresses** (unspent P2PKH/P2WPKH): safe until spent, but the public key is revealed at spend time

## The Approach

**Phase 1 — Off-chain reference implementation (current):**
- ML-DSA-65 (FIPS 204) post-quantum signatures
- `bc1z` bech32m address format committing to a SHA-256 hash of the ML-DSA public key
- Key generation, signing, verification
- Legacy → PQ migration helper
- Quantum canary monitor (early warning of CRQC capability)

**Phase 2 — Consensus proposal (BIP):**
- New witness version for post-quantum addresses
- Soft-fork specification
- Migration path for existing UTXOs

## Installation

```bash
git clone https://github.com/Zaenus/btc-safe.git
cd btc-safe
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick Start

```bash
# Generate a new ML-DSA-65 key pair and PQ address
safe-btc generate-key --output my-key.json
safe-btc address --from-key my-key.json

# Sign a transaction hash
safe-btc sign --key my-key.json --tx-hash <hex>

# Verify a signature
safe-btc verify --address bc1z... --signature <hex> --tx-hash <hex>

# Scan a legacy wallet for quantum exposure
safe-btc migrate --legacy-wallet wallet.dat --output migration-plan.json

# Watch a quantum canary address
safe-btc canary --watch-address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

## Project Structure

```
safe-btc/
├── src/safe_btc/          # Core library
│   ├── __init__.py
│   ├── pq_addresses.py    # bc1z bech32m address encoding
│   ├── pq_signatures.py   # ML-DSA sign/verify wrapper
│   ├── keys.py            # Key generation and management
│   ├── wallet.py          # Legacy → PQ migration helper
│   ├── canary.py          # Quantum canary monitor
│   └── cli.py             # Command-line interface
├── tests/                 # Test suite
├── docs/                  # Specifications and guides
├── examples/              # Example scripts
└── pyproject.toml         # Project configuration
```

## Roadmap

| Phase | Milestone | Status |
|-------|-----------|--------|
| 1 | ML-DSA-65 reference implementation | In progress |
| 1 | `bc1z` address format (bech32m) | In progress |
| 1 | Migration helper + canary monitor | Planned |
| 1 | Test suite (90%+ coverage) | Planned |
| 2 | BIP draft for PQ witness version | Planned |
| 2 | Signature aggregation (SNARK-wrapped) | Future |

## License

MIT License. See [LICENSE](LICENSE) for details.
