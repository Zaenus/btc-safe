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

# Install dependencies
pip install -e .

# Install dev dependencies
pip install pytest

# Run tests
pytest
```

## Areas for Contribution

### High Priority
- **ML-DSA signature integration**: Refine the PQ signature wrapper
- **Address format**: Finalize the `bc1z` bech32m address specification
- **Migration tools**: Build legacy → PQ address migration helpers
- **Canary monitor**: Implement on-chain quantum threat detection

### Medium Priority
- **Wallet integration**: Python library for managing PQ keys
- **CLI improvements**: More commands, better output formatting
- **Documentation**: Specs, guides, examples

### Future (Post-BIP)
- **Consensus integration**: Soft-fork proposal (BIP) for new witness version
- **Signature aggregation**: SNARK-wrapped PQ signatures to reduce block space
- **Multi-sig**: PQ multisig address formats

## Security Policy

If you discover a security vulnerability, please do NOT open a public issue. Instead, contact the maintainer directly through GitHub. We will acknowledge receipt within 48 hours and work with you on disclosure.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Community

- **Repository**: https://github.com/Zaenus/btc-safe
- **Issues**: https://github.com/Zaenus/btc-safe/issues
- **Discussions**: https://github.com/Zaenus/btc-safe/discussions
