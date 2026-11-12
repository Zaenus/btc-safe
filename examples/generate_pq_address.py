#!/usr/bin/env python3
"""
Example: Generate a quantum-resistant Bitcoin address.

This script demonstrates:
1. Generating an ML-DSA-65 key pair
2. Deriving a bc1r address from the public key (bech32m, witness v3)
3. Signing and verifying a message (BIP-143 sighash)
"""

from safe_btc import (
    MLDSA65,
    KeyPair,
    address_from_public_key,
    generate_keypair,
    is_valid_address,
)


def main():
    print("=== safe-btc: Quantum-Resistant Address Example ===\n")

    # 1. Generate a new ML-DSA-65 key pair
    keypair = generate_keypair()
    print(f"Public key size:  {len(keypair.public_key)} bytes")
    print(f"Secret key size:  {len(keypair.secret_key)} bytes")

    # 2. Derive a bc1r quantum-resistant address
    address = address_from_public_key(keypair.public_key)
    print(f"\nQuantum-resistant address: {address}")
    print(f"Valid bc1r address: {is_valid_address(address)}")

    # 3. Sign a message (e.g., a transaction hash)
    message = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    signature = keypair.sign(message)
    print(f"\nSignature size: {len(signature)} bytes")

    # 4. Verify the signature
    valid = keypair.verify(message, signature)
    print(f"Signature valid: {valid}")

    # 5. Verify with tampered message
    valid_tampered = keypair.verify(b"tampered", signature)
    print(f"Tampered signature valid: {valid_tampered}")

    print("\nDone! Your bc1r address is ready for post-quantum Bitcoin.")


if __name__ == "__main__":
    main()
