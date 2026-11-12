"""
Command-line interface for safe-btc.

Provides commands for generating quantum-resistant keys, addresses,
signing/verifying, migration planning, and canary monitoring.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from .canary import DEFAULT_CANARY_ADDRESS, create_canary_monitor
from .keys import (
    KeyPair,
    generate_key_from_entropy,
    generate_key_from_mnemonic,
    key_to_address,
    key_to_address_from_keypair,
)
from .pq_addresses import (
    address_from_public_key,
    compute_pubkey_hash,
    decode_address,
    encode_address,
    is_valid_address,
)
from .pq_signatures import MLDSA65, KeyPair as _KeyPair, verify_signature
from .wallet import create_migration_plan, scan_wallet_file


def _cmd_generate_key(args: argparse.Namespace) -> int:
    """Generate a new ML-DSA-65 key pair."""
    if args.mnemonic:
        keypair = generate_key_from_mnemonic(args.mnemonic, passphrase=args.passphrase or "")
    else:
        keypair = generate_key_from_entropy()

    output = {
        "public_key": keypair.public_key.hex(),
        "secret_key": keypair.secret_key.hex(),
        "address": key_to_address_from_keypair(keypair),
        "scheme": "ML-DSA-65 (FIPS 204)",
    }

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"Key pair saved to {args.output}")
        print(f"  Address: {output['address']}")
    else:
        print(json.dumps(output, indent=2))

    return 0


def _cmd_address(args: argparse.Namespace) -> int:
    """Display the quantum-resistant address for a key."""
    if args.from_key:
        import json
        with open(args.from_key, "r") as f:
            data = json.load(f)
        pk = bytes.fromhex(data["public_key"])
        addr = address_from_public_key(pk)
    elif args.from_pubkey:
        pk = bytes.fromhex(args.from_pubkey)
        addr = address_from_public_key(pk)
    else:
        print("Error: specify --from-key or --from-pubkey", file=sys.stderr)
        return 1

    print(addr)
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    """Sign a transaction hash with a key."""
    import json

    with open(args.key, "r") as f:
        data = json.load(f)
    sk = bytes.fromhex(data["secret_key"])

    if args.tx_hash:
        msg = bytes.fromhex(args.tx_hash)
    elif args.tx_file:
        with open(args.tx_file, "rb") as f:
            msg = f.read()
    else:
        print("Error: specify --tx-hash or --tx-file", file=sys.stderr)
        return 1

    sig = MLDSA65.sign(sk, msg)
    print(sig.hex())
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify a signature against an address."""
    # Decode address to get commitment
    try:
        _, commitment = decode_address(args.address)
    except ValueError as e:
        print(f"Error: invalid address: {e}", file=sys.stderr)
        return 1

    # Load signature
    sig = bytes.fromhex(args.signature)

    # Load message
    if args.tx_hash:
        msg = bytes.fromhex(args.tx_hash)
    elif args.tx_file:
        with open(args.tx_file, "rb") as f:
            msg = f.read()
    else:
        print("Error: specify --tx-hash or --tx-file", file=sys.stderr)
        return 1

    # Note: verification requires the full public key, which is not in the address
    # The address only contains a hash commitment. The user must provide the pubkey.
    if args.public_key:
        pk = bytes.fromhex(args.public_key)
        # Verify pubkey matches address commitment
        from .keys import verify_pubkey_match
        if not verify_pubkey_match(args.address, pk):
            print("Error: public key does not match address commitment", file=sys.stderr)
            return 1
        valid = MLDSA65.verify(pk, msg, sig)
    else:
        print(
            "Error: --public-key is required (address only contains a hash commitment; "
            "the full public key must be provided at spend time)",
            file=sys.stderr,
        )
        return 1

    if valid:
        print("Signature valid")
        return 0
    else:
        print("Signature invalid")
        return 1


def _cmd_migrate(args: argparse.Namespace) -> int:
    """Create a migration plan for legacy addresses."""
    addresses: list[str] = []

    if args.wallet:
        plan = scan_wallet_file(args.wallet)
    elif args.addresses:
        addresses = [a.strip() for a in args.addresses.split(",")]
        plan = create_migration_plan(addresses)
    else:
        print("Error: specify --wallet or --addresses", file=sys.stderr)
        return 1

    print(f"Total legacy addresses: {plan.total_legacy}")
    print(f"  High risk:  {plan.high_risk_count}")
    print(f"  Low risk:   {plan.low_risk_count}")
    print(f"  PQ addresses generated: {len(plan.pq_addresses)}")
    print()

    for info in plan.legacy_addresses:
        risk_marker = "HIGH" if info.quantum_risk == "high" else "low"
        print(f"  [{risk_marker}] {info.address} ({info.address_type})")
        if info.pq_address:
            print(f"        → {info.pq_address}")
        print(f"        {info.reason}")

    if args.output:
        plan.save_json(args.output)
        print(f"\nMigration plan saved to {args.output}")

    return 0


def _cmd_canary(args: argparse.Namespace) -> int:
    """Check or monitor a quantum canary address."""
    monitor = create_canary_monitor(args.address or DEFAULT_CANARY_ADDRESS)

    if args.check_state:
        import json
        if args.state_file:
            try:
                from .canary import CanaryMonitor
                monitor = CanaryMonitor.load_state(args.state_file)
            except FileNotFoundError:
                print(f"State file not found: {args.state_file}")
                return 1
        print(f"Canary address: {monitor.address}")
        print(f"Triggered: {monitor.is_triggered()}")
        print(f"Last block checked: {monitor.last_block_height}")
        print(f"Alerts: {len(monitor.alerts)}")
        for alert in monitor.alerts:
            print(f"  - Block {alert.block_height}: {alert.message}")
        return 0

    print(f"Canary address: {monitor.address}")
    print("Note: Canary monitoring requires blockchain data (bitcoind RPC or similar).")
    print("Use --check-state to review a saved state file.")
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    """Show project information and parameter sizes."""
    sizes = MLDSA65.sizes()
    print("safe-btc — Quantum-resistant tools for Bitcoin")
    print()
    print("Signature scheme: ML-DSA-65 (FIPS 204)")
    print()
    print("Parameter sizes:")
    print(f"  Public key:  {sizes['public_key']} bytes")
    print(f"  Secret key:  {sizes['secret_key']} bytes")
    print(f"  Signature:   {sizes['signature']} bytes")
    print()
    print("Address format: bc1z (bech32m, witness version 2)")
    print("  Data: 32-byte SHA-256 hash of ML-DSA-65 public key")
    print()
    print("Phase: Off-chain reference implementation (pre-BIP)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="safe-btc",
        description="Quantum-resistant tools for Bitcoin",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # info
    subparsers.add_parser("info", help="Show project information")

    # generate-key
    p_gen = subparsers.add_parser("generate-key", help="Generate a new ML-DSA-65 key pair")
    p_gen.add_argument("--mnemonic", help="BIP-39 mnemonic phrase (optional)")
    p_gen.add_argument("--passphrase", help="BIP-39 passphrase (optional)")
    p_gen.add_argument("--output", "-o", help="Output file path (JSON)")

    # address
    p_addr = subparsers.add_parser("address", help="Derive bc1z address from a public key")
    p_addr.add_argument("--from-key", help="Key file (JSON) to derive address from")
    p_addr.add_argument("--from-pubkey", help="Hex-encoded public key")

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign a message/transaction hash")
    p_sign.add_argument("--key", required=True, help="Key file (JSON)")
    p_sign.add_argument("--tx-hash", help="Hex-encoded transaction hash to sign")
    p_sign.add_argument("--tx-file", help="File containing message to sign")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify a signature")
    p_verify.add_argument("--address", required=True, help="bc1z address")
    p_verify.add_argument("--signature", required=True, help="Hex-encoded signature")
    p_verify.add_argument("--public-key", help="Hex-encoded ML-DSA-65 public key")
    p_verify.add_argument("--tx-hash", help="Hex-encoded transaction hash")
    p_verify.add_argument("--tx-file", help="File containing signed message")

    # migrate
    p_mig = subparsers.add_parser("migrate", help="Create a legacy→PQ migration plan")
    p_mig.add_argument("--wallet", help="Wallet file (one address per line)")
    p_mig.add_argument("--addresses", help="Comma-separated list of legacy addresses")
    p_mig.add_argument("--output", "-o", help="Output migration plan (JSON)")

    # canary
    p_can = subparsers.add_parser("canary", help="Quantum canary monitor")
    p_can.add_argument("--address", default=DEFAULT_CANARY_ADDRESS, help="Canary address to watch")
    p_can.add_argument("--check-state", action="store_true", help="Check saved state")
    p_can.add_argument("--state-file", help="Path to saved state file")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    command_map = {
        "info": _cmd_info,
        "generate-key": _cmd_generate_key,
        "address": _cmd_address,
        "sign": _cmd_sign,
        "verify": _cmd_verify,
        "migrate": _cmd_migrate,
        "canary": _cmd_canary,
    }

    return command_map[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
