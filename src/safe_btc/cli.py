"""
Command-line interface for safe-btc.

Commands: info, generate-key, address, sign, verify, migrate, canary.

Mainnet guard: witness v3 is not active on mainnet; coins sent to a ``bc1r``
address today can be taken by anyone. Every command that would print a mainnet
witness v3 address requires ``--allow-mainnet``.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .canary import DEFAULT_ESPLORA_URL, NUMS_CANARY_ADDRESSES, CanaryMonitor, create_canary_monitor
from .keys import (
    default_path,
    derive_keypair,
    load_key_file,
    mnemonic_to_seed,
    new_mnemonic,
    save_key_file,
    verify_pubkey_match,
)
from .pq_addresses import DEFAULT_NETWORK, NETWORK_HRPS, address_from_public_key, decode_address
from .pq_signatures import CONTEXT_MSG, CONTEXT_TX, MLDSA65
from .wallet import create_migration_plan, read_address_file
from .wallet_integration import PQ_INPUT_WEIGHT, estimate_pq_vsize, max_pq_inputs_per_block

MAINNET_WARNING = (
    "Refusing to create a mainnet witness v3 address. Witness v3 is NOT active on "
    "Bitcoin mainnet: coins sent to a bc1r address today are anyone-can-spend and "
    "can be stolen by miners. Use --network testnet/signet/regtest, or pass "
    "--allow-mainnet if you only need the string for research."
)


def _check_network(args: argparse.Namespace) -> bool:
    if args.network == "mainnet" and not args.allow_mainnet:
        print(f"Error: {MAINNET_WARNING}", file=sys.stderr)
        return False
    return True


def _read_mnemonic(args: argparse.Namespace) -> str | None:
    if getattr(args, "mnemonic_file", None):
        with open(args.mnemonic_file) as f:
            return f.read().strip()
    if getattr(args, "mnemonic", None):
        print(
            "Warning: --mnemonic leaves your seed in shell history; prefer --mnemonic-file or --restore.",
            file=sys.stderr,
        )
        return args.mnemonic
    if getattr(args, "restore", False):
        return getpass.getpass("BIP-39 mnemonic: ")
    return None


def _read_passphrase(args: argparse.Namespace) -> str:
    if getattr(args, "ask_passphrase", False):
        return getpass.getpass("BIP-39 passphrase: ")
    if getattr(args, "passphrase", None):
        print("Warning: --passphrase leaves it in shell history; prefer --ask-passphrase.", file=sys.stderr)
        return args.passphrase
    return ""


def _read_message(args: argparse.Namespace) -> bytes | None:
    if args.message is not None:
        return args.message.encode()
    if args.message_hex is not None:
        return bytes.fromhex(args.message_hex)
    if args.message_file is not None:
        with open(args.message_file, "rb") as f:
            return f.read()
    return None


def _cmd_generate_key(args: argparse.Namespace) -> int:
    if not _check_network(args):
        return 1
    mnemonic = _read_mnemonic(args)
    created = mnemonic is None
    if created:
        mnemonic = new_mnemonic()
    try:
        seed = mnemonic_to_seed(mnemonic, _read_passphrase(args))
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    path = args.path or default_path(args.network, args.account, args.index)
    keypair = derive_keypair(seed, path)
    address = address_from_public_key(keypair.public_key, args.network)

    if created:
        print("NEW RECOVERY PHRASE - write it down and store it offline.", file=sys.stderr)
        print("It is the only way to recover this key:\n", file=sys.stderr)
        print(f"  {mnemonic}\n", file=sys.stderr)

    if args.output:
        try:
            save_key_file(args.output, keypair, args.network, path, overwrite=args.force)
        except FileExistsError:
            print(f"Error: {args.output} exists (use --force to overwrite)", file=sys.stderr)
            return 1
        print(f"Key saved to {args.output} (mode 0600)")
        print(f"  Path:    {path}")
        print(f"  Address: {address}")
    else:
        print("Warning: printing the private seed to stdout; use -o to write a key file.", file=sys.stderr)
        print(
            json.dumps(
                {
                    "network": args.network,
                    "derivation_path": path,
                    "address": address,
                    "public_key": keypair.public_key.hex(),
                    "seed": keypair.seed.hex(),
                },
                indent=2,
            )
        )
    return 0


def _cmd_address(args: argparse.Namespace) -> int:
    if not _check_network(args):
        return 1
    if args.from_key:
        keypair, _ = load_key_file(args.from_key)
        pk = keypair.public_key
    elif args.from_pubkey:
        pk = bytes.fromhex(args.from_pubkey)
    else:
        print("Error: specify --from-key or --from-pubkey", file=sys.stderr)
        return 1
    try:
        print(address_from_public_key(pk, args.network))
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    keypair, _ = load_key_file(args.key)
    msg = _read_message(args)
    if msg is None:
        print("Error: specify --message, --message-hex or --message-file", file=sys.stderr)
        return 1
    print(MLDSA65.sign(keypair.seed, msg, CONTEXT_MSG).hex())
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        decode_address(args.address)
    except ValueError as e:
        print(f"Error: invalid address: {e}", file=sys.stderr)
        return 1
    msg = _read_message(args)
    if msg is None:
        print("Error: specify --message, --message-hex or --message-file", file=sys.stderr)
        return 1
    pk = bytes.fromhex(args.public_key)
    if not verify_pubkey_match(args.address, pk):
        print("Error: public key does not match the address commitment", file=sys.stderr)
        return 1
    if MLDSA65.verify(pk, msg, bytes.fromhex(args.signature), CONTEXT_MSG):
        print("Signature valid")
        return 0
    print("Signature invalid")
    return 1


def _cmd_migrate(args: argparse.Namespace) -> int:
    if args.wallet:
        addresses = read_address_file(args.wallet)
    elif args.addresses:
        addresses = [a.strip() for a in args.addresses.split(",") if a.strip()]
    else:
        print("Error: specify --wallet or --addresses", file=sys.stderr)
        return 1
    spent = {a.strip() for a in (args.spent_from or "").split(",") if a.strip()}

    master_seed = None
    if not args.classify_only:
        if not _check_network(args):
            return 1
        mnemonic = _read_mnemonic(args)
        if mnemonic is None:
            print(
                "Error: destination addresses are derived from your recovery phrase so they "
                "can be spent later. Pass --mnemonic-file/--restore, or --classify-only.",
                file=sys.stderr,
            )
            return 1
        try:
            master_seed = mnemonic_to_seed(mnemonic, _read_passphrase(args))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    plan = create_migration_plan(addresses, master_seed, args.network, args.account, args.start_index, spent)
    print(f"Total addresses: {plan.total_legacy}")
    print(f"  High risk: {plan.high_risk_count}")
    print(f"  Low risk:  {plan.low_risk_count}")
    print(f"  PQ destinations: {len(plan.pq_addresses)}")
    print()
    for info in plan.legacy_addresses:
        print(f"  [{info.quantum_risk.upper():7}] {info.address} ({info.address_type})")
        if info.pq_address:
            print(f"            -> {info.pq_address}  [{info.pq_derivation_path}]")
        print(f"            {info.reason}")
    if args.output:
        plan.save_json(args.output)
        print(f"\nMigration plan saved to {args.output}")
    return 0


def _cmd_canary(args: argparse.Namespace) -> int:
    if args.state_file and args.check_state:
        try:
            monitor = CanaryMonitor.load_state(args.state_file)
        except FileNotFoundError:
            print(f"State file not found: {args.state_file}", file=sys.stderr)
            return 1
    else:
        monitor = create_canary_monitor(args.address)

    if args.poll:
        try:
            new = monitor.poll_esplora(args.esplora_url)
        except OSError as e:
            print(f"Error: could not reach {args.esplora_url}: {e}", file=sys.stderr)
            return 1
        for alert in new:
            print(alert.message)
        if args.state_file:
            monitor.save_state(args.state_file)

    print(f"Canary address:     {monitor.address}")
    print(f"Triggered:          {monitor.is_triggered()}")
    print(f"Last block checked: {monitor.last_block_height}")
    for alert in monitor.alerts:
        print(f"  - {alert.message}")
    if not args.poll and not args.check_state:
        print("Use --poll to query an Esplora API, or --check-state with --state-file.")
    return 2 if monitor.is_triggered() else 0


def _cmd_info(args: argparse.Namespace) -> int:
    sizes = MLDSA65.sizes()
    print("safe-btc - post-quantum tooling for Bitcoin (research software)")
    print()
    print("Signature scheme: ML-DSA-65 (FIPS 204, NIST category 3)")
    print(f"  Public key:  {sizes['public_key']} bytes")
    print(f"  Private key: {sizes['seed']}-byte seed (expanded form: {sizes['expanded_secret_key']} bytes)")
    print(f"  Signature:   {sizes['signature']} bytes")
    print(f"  FIPS 204 contexts: tx={CONTEXT_TX.decode()!r}  message={CONTEXT_MSG.decode()!r}")
    print()
    print("Output: witness v3, OP_3 <32-byte TaggedHash('PQKeyCommit', key_type || pubkey)>")
    print("Address: bech32m (BIP-350) - bc1r... mainnet, tb1r... testnet/signet, bcrt1r... regtest")
    print("Witness: <signature[||hash_type]> <key_type || pubkey>")
    print()
    print(f"Weight per ML-DSA-65 input: {PQ_INPUT_WEIGHT} WU (~{PQ_INPUT_WEIGHT / 4:.0f} vB)")
    print(f"1-input, 2-output tx:       ~{estimate_pq_vsize(1, 2)} vB")
    print(f"Max ML-DSA-65 inputs/block: ~{max_pq_inputs_per_block()}")
    print()
    print("Status: draft BIP; witness v3 is NOT active on any network.")
    return 0


def _add_network(p: argparse.ArgumentParser) -> None:
    p.add_argument("--network", choices=sorted(NETWORK_HRPS), default=DEFAULT_NETWORK,
                   help=f"network for addresses (default: {DEFAULT_NETWORK})")
    p.add_argument("--allow-mainnet", action="store_true",
                   help="allow mainnet bc1r addresses (unsafe until activation)")


def _add_mnemonic(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--mnemonic-file", help="file containing a BIP-39 mnemonic")
    g.add_argument("--restore", action="store_true", help="prompt for a BIP-39 mnemonic")
    g.add_argument("--mnemonic", help=argparse.SUPPRESS)
    pg = p.add_mutually_exclusive_group()
    pg.add_argument("--ask-passphrase", action="store_true", help="prompt for a BIP-39 passphrase")
    pg.add_argument("--passphrase", help=argparse.SUPPRESS)
    p.add_argument("--account", type=int, default=0, help="account index (default 0)")


def _add_message(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--message", help="UTF-8 message")
    g.add_argument("--message-hex", help="hex-encoded message")
    g.add_argument("--message-file", help="file containing the message")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safe-btc", description="Post-quantum tools for Bitcoin")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    sub.add_parser("info", help="Show parameters, sizes and status")

    p = sub.add_parser("generate-key", help="Create (or restore) a recoverable ML-DSA-65 key")
    _add_network(p)
    _add_mnemonic(p)
    p.add_argument("--index", type=int, default=0, help="address index (default 0)")
    p.add_argument("--path", help="explicit hardened derivation path, e.g. m/3'/1'/0'/0'")
    p.add_argument("--output", "-o", help="key file to write (mode 0600)")
    p.add_argument("--force", action="store_true", help="overwrite an existing key file")

    p = sub.add_parser("address", help="Derive the witness v3 address for a key")
    _add_network(p)
    p.add_argument("--from-key", help="key file")
    p.add_argument("--from-pubkey", help="hex-encoded ML-DSA-65 public key")

    p = sub.add_parser("sign", help="Sign an off-chain message (not a transaction)")
    p.add_argument("--key", required=True, help="key file")
    _add_message(p)

    p = sub.add_parser("verify", help="Verify an off-chain message signature")
    p.add_argument("--address", required=True, help="witness v3 address")
    p.add_argument("--public-key", required=True, help="hex-encoded ML-DSA-65 public key")
    p.add_argument("--signature", required=True, help="hex-encoded signature")
    _add_message(p)

    p = sub.add_parser("migrate", help="Classify addresses and plan a migration")
    _add_network(p)
    _add_mnemonic(p)
    p.add_argument("--wallet", help="file with one address per line")
    p.add_argument("--addresses", help="comma-separated addresses (or hex pubkeys for P2PK)")
    p.add_argument("--spent-from", help="comma-separated addresses that have been spent from")
    p.add_argument("--start-index", type=int, default=0, help="first derivation index")
    p.add_argument("--classify-only", action="store_true", help="only classify; derive no destinations")
    p.add_argument("--output", "-o", help="write the plan as JSON")

    p = sub.add_parser("canary", help="Watch a NUMS-key canary for a secp256k1 break")
    p.add_argument("--address", default=NUMS_CANARY_ADDRESSES["mainnet"], help="canary address")
    p.add_argument("--poll", action="store_true", help="query an Esplora API now")
    p.add_argument("--esplora-url", default=DEFAULT_ESPLORA_URL, help="Esplora API base URL")
    p.add_argument("--state-file", help="state file to read/write")
    p.add_argument("--check-state", action="store_true", help="load state from --state-file")
    return parser


COMMANDS = {
    "info": _cmd_info,
    "generate-key": _cmd_generate_key,
    "address": _cmd_address,
    "sign": _cmd_sign,
    "verify": _cmd_verify,
    "migrate": _cmd_migrate,
    "canary": _cmd_canary,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    try:
        return COMMANDS[args.command](args)
    except (ValueError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
