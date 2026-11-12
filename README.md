# btc-safe

Quantum-resistant address formats and tools for Bitcoin.

## Mission

Build practical tooling to prepare Bitcoin for the post-quantum era — starting
with quantum-resistant address formats using ML-DSA (FIPS 204), signature
aggregation to reduce on-chain size, wallet integration, and a consensus-layer
BIP proposal.

## The Problem

Bitcoin's digital signatures (ECDSA/secp256k1 and Schnorr/secp256k1) are
vulnerable to Shor's algorithm on a cryptographically relevant quantum
computer (CRQC). Once a public key appears on-chain, a sufficiently powerful
quantum computer can derive the private key and spend the funds.

- **Exposed-key addresses** (P2PK, reused P2PKH/P2WPKH after spending, Taproot): directly vulnerable
- **Hidden-key addresses** (unspent P2PKH/P2WPKH): safe until spent, but the public key is revealed at spend time

## The Approach

**Phase 1 — Off-chain reference implementation (complete):**
- ML-DSA-65 (FIPS 204) post-quantum signatures
- `bc1z` bech32 address format committing to a SHA-256 hash of the ML-DSA public key
- Key generation, signing, verification
- Legacy → PQ migration helper
- Quantum canary monitor (early warning of CRQC capability)
- Test suite (43 tests, all passing)

**Phase 2 — Consensus preparation (in progress):**
- BIP draft for PQ witness version (`docs/bip/`)
- Signature aggregation via SNARK-wrapped ML-DSA (compresses 3,309-byte sigs to ~192-byte proofs)
- Wallet integration (Electrum, Bitcoin Core RPC, hardware wallets, PSBT support)

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
# → bc1z1z8ux3d4xxv0c08wtkhzc5my9daudk2zkdnmdq9ufrafjh9fg7024qct96fd

# Sign a transaction hash
safe-btc sign --key my-key.json --tx-hash <hex>

# Verify a signature
safe-btc verify --address bc1z... --signature <hex> --public-key <hex> --tx-hash <hex>

# Aggregate multiple PQ signatures (compression: ~53KB → ~2KB)
python3 -c "
from safe_btc.aggregation import aggregate_signatures
agg = aggregate_signatures(pubkeys, messages, signatures)
print(agg.compression_ratio())  # e.g. 0.04 = 96% space savings
"

# Create a migration plan for legacy addresses
safe-btc migrate --addresses 1Abc...,3Def... --output plan.json

# Watch a quantum canary address
safe-btc canary --watch-address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

## Project Structure

```
safe-btc/
├── src/safe_btc/          # Core library
│   ├── __init__.py
│   ├── pq_addresses.py    # bc1z bech32 address encoding
│   ├── pq_signatures.py   # ML-DSA sign/verify wrapper
│   ├── keys.py            # Key generation and management
│   ├── wallet.py          # Legacy → PQ migration helper
│   ├── canary.py          # Quantum canary monitor
│   ├── cli.py             # Command-line interface
│   ├── aggregation/       # Signature aggregation (SNARK-wrapped)
│   └── wallet_integration/# Wallet adapters (Electrum, Bitcoin Core, PSBT)
├── tests/                 # Test suite (43 tests)
├── docs/                  # Specifications and guides
│   ├── address-format.md  # bc1z spec
│   ├── migration-guide.md # Legacy → PQ migration
│   └── bip/               # BIP drafts
├── examples/              # Example scripts
├── pyproject.toml         # Project configuration
└── LICENSE                # MIT License
```

## Roadmap

| Phase | Milestone | Status |
|-------|-----------|--------|
| 1 | ML-DSA-65 reference implementation | Complete |
| 1 | `bc1z` address format (bech32) | Complete |
| 1 | Migration helper + canary monitor | Complete |
| 1 | Test suite (43 tests) | Complete |
| 2 | BIP draft for PQ witness version | Complete (draft) |
| 2 | Signature aggregation (SNARK-wrapped) | Complete (prototype) |
| 2 | Wallet integration (Electrum, Core RPC, PSBT) | Complete (prototype) |
| 3 | BIP submission and community review | Planned |
| 3 | Signature aggregation with real SNARK circuit | Future |

## License

MIT License. See [LICENSE](LICENSE) for details.
