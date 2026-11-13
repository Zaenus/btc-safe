# Contributing to safe-btc

Thank you for your interest in helping build quantum-resistant tooling for Bitcoin! This project is in its early stages, and contributions of all kinds are welcome.

## How to Contribute

### Reporting Issues
- Use GitHub Issues to report bugs or suggest features
- For security vulnerabilities, please see [Security Policy](#security-policy) below

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Add or update tests as needed
5. Ensure all tests pass
6. Submit a pull request with a clear description

### Code Style
- Follow PEP 8 for Python code
- Use type hints where practical
- Write docstrings for public functions and classes
- Keep functions small and focused

### Development Setup
```bash
# Clone the repo
git clone https://github.com/Zaenus/btc-safe.git
cd btc-safe

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with dev dependencies (pytest, dilithium-py for cross-checks)
pip install -e ".[dev]"

# Run tests
pytest

# If you change the spec or consensus code, regenerate the BIP vectors
# and commit the result (CI checks that they are reproducible)
python tools/generate_bip_vectors.py
```

## Areas for Contribution

### High Priority
- **Spec review**: read `docs/bip/0001-pq-address-format.md` and its open
  questions (ML-DSA-44 vs -65, hybrid key type, witness discount)
- **Bitcoin Core patch**: implement the spending rules on regtest and
  benchmark ML-DSA-65 verification
- **Test vectors**: independent implementations that check
  `docs/bip/0001-test-vectors.json`

### Medium Priority
- **Wallet integration**: PSBT field assignment, hardware wallet signing
- **Canary**: more data sources (Bitcoin Core RPC, Electrum servers)
- **Documentation**: guides and examples

### Research
- **Signature aggregation**: see `docs/research/signature-aggregation.md`
  (must be post-quantum sound and need no trusted setup)
- **Multisig**: P2MR leaves with post-quantum signature opcodes

### Rules for changes
- Never make mainnet witness v3 addresses the default.
- Any change to consensus rules must update the BIP text, `consensus.py`
  and the test vectors together.

## Security Policy

If you discover a security vulnerability, please do NOT open a public issue. Instead, contact the maintainer directly through GitHub. We will acknowledge receipt within 48 hours and work with you on disclosure.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Community

- **Repository**: https://github.com/Zaenus/btc-safe
- **Issues**: https://github.com/Zaenus/btc-safe/issues
- **Discussions**: https://github.com/Zaenus/btc-safe/discussions
