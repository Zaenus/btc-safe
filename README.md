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
- `bc1r` bech32m address format (BIP-350, witness version 0x03) committing to a SHA-256 hash of the ML-DSA public key
- Key generation, signing, verification
- Legacy → PQ migration helper
- Quantum canary monitor (early warning of CRQC capability)
- Test suite (43 tests, all passing)

**Phase 2 — Consensus preparation (in progress):**
- BIP draft for PQ witness version (`docs/bip/`)
- Signature aggregation via SNARK-wrapped ML-DSA (compresses 3,309-byte sigs to ~192-byte proofs — **mock prototype only**)
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
# → bc1r1...

# Sign a transaction hash
safe-btc sign --key my-key.json --tx-hash <hex>

# Verify a signature (uses BIP-143 sighash)
safe-btc verify --address bc1r... --signature <hex> --public-key <hex> --tx-hash <hex>

# Aggregate multiple PQ signatures (mock SNARK prototype — not for on-chain use)
python3 -c "
from safe_btc.aggregation import aggregate_signatures
agg = aggregate_signatures(pubkeys, messages, signatures)
print(agg.compression_ratio())  # illustrative only
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
│   ├── pq_addresses.py    # bc1r bech32m address encoding (witness v3)
│   ├── pq_signatures.py   # ML-DSA sign/verify wrapper
│   ├── keys.py            # Key generation and management
│   ├── wallet.py          # Legacy → PQ migration helper
│   ├── canary.py          # Quantum canary monitor
│   ├── cli.py             # Command-line interface
│   ├── aggregation/       # Signature aggregation (mock SNARK prototype)
│   └── wallet_integration/# Wallet adapters (Electrum, Bitcoin Core, PSBT)
├── tests/                 # Test suite (43 tests)
├── docs/                  # Specifications and guides
│   ├── address-format.md  # bc1r spec
│   ├── migration-guide.md # Legacy → PQ migration
│   └── bip/               # BIP draft
├── examples/              # Example scripts
├── pyproject.toml         # Project configuration
└── LICENSE                # MIT License
```

## Roadmap

| Phase | Milestone | Status |
|-------|-----------|--------|
| 1 | ML-DSA-65 reference implementation | Complete |
| 1 | `bc1r` address format (bech32m, witness v3) | Complete |
| 1 | Migration helper + canary monitor | Complete |
| 1 | Test suite (43 tests) | Complete |
| 2 | BIP draft for PQ witness version | Complete (draft) |
| 2 | Signature aggregation (mock SNARK) | Complete (prototype, not for production) |
| 2 | Wallet integration (Electrum, Core RPC, PSBT) | Complete (prototype) |
| 3 | BIP submission and community review | Planned |
| 3 | Real SNARK circuit (Circom/Noir/SP1) | Future |

## Address Format Notes

- **HRP:** `bc` (same as all native segwit addresses)
- **Witness version:** `0x03` (encodes as `r` in bech32m → addresses start with `bc1r`)
- **Encoding:** bech32m (BIP-350)
- **Commitment:** SHA-256 hash of ML-DSA-65 public key (32 bytes)
- **Witness at spend:** `<ML-DSA signature> <ML-DSA public key>`
- **Sighash:** BIP-143
- **Note:** Witness version 0x02 (`bc1z`) is allocated to BIP-360 (P2MR). This format uses 0x03.

## License

MIT License. See [LICENSE](LICENSE) for details.
