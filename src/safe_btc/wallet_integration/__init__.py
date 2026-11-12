"""
Wallet integration for quantum-resistant Bitcoin addresses.

Provides abstractions and adapters for integrating bc1z quantum-resistant
addresses with existing Bitcoin wallets:

- Abstract wallet interface
- Electrum wallet file reader/writer
- Bitcoin Core RPC client
- Hardware wallet interface (Ledger, Trezor via HID)
- PSBT (Partially Signed Bitcoin Transaction) support for PQ transactions

This is a prototype integration layer. Production use requires wallet-specific
testing and security audits.
"""

from __future__ import annotations

import abc
import json
import os
from dataclasses import dataclass, field
from typing import Any

from ..keys import KeyPair, address_from_public_key
from ..pq_addresses import is_valid_address
from ..pq_signatures import MLDSA65


@dataclass
class PQAddressInfo:
    """Information about a quantum-resistant address in a wallet."""

    address: str
    public_key: bytes
    derivation_path: str | None
    label: str | None
    created_at: float


@dataclass
class PQTransaction:
    """A quantum-resistant transaction (pre-broadcast)."""

    txid: str | None
    inputs: list[dict[str, Any]]
    outputs: list[dict[str, Any]]
    pq_inputs: list[dict[str, Any]]  # Inputs spending from bc1z addresses
    fee_satoshis: int
    size_vbytes: int
    signed: bool = False


class WalletInterface(abc.ABC):
    """Abstract interface for wallet integrations."""

    @abc.abstractmethod
    def get_pq_addresses(self) -> list[PQAddressInfo]:
        """Return all quantum-resistant addresses in the wallet."""
        ...

    @abc.abstractmethod
    def create_pq_address(self, label: str | None = None) -> PQAddressInfo:
        """Create a new quantum-resistant address."""
        ...

    @abc.abstractmethod
    def sign_pq_transaction(
        self, tx: PQTransaction, derivation_paths: list[str]
    ) -> PQTransaction:
        """Sign a transaction spending from quantum-resistant addresses."""
        ...

    @abc.abstractmethod
    def broadcast(self, tx_hex: str) -> str:
        """Broadcast a signed transaction and return the txid."""
        ...


class ElectrumWallet:
    """
    Read and write Electrum wallet files for quantum-resistant addresses.

    Electrum wallets are JSON files. This adapter adds PQ address support
    by extending the wallet's keystore with ML-DSA-65 keys.

    Note: This is a read/write helper for the wallet file format.
    Actual Electrum integration requires modifying Electrum source code.
    """

    def __init__(self, wallet_path: str):
        self.wallet_path = wallet_path
        self._wallet_data: dict[str, Any] | None = None

    def load(self) -> dict[str, Any]:
        """Load the Electrum wallet file."""
        with open(self.wallet_path, "r") as f:
            self._wallet_data = json.load(f)
        return self._wallet_data

    def save(self, path: str | None = None) -> None:
        """Save the wallet file."""
        if self._wallet_data is None:
            raise ValueError("Wallet not loaded")
        save_path = path or self.wallet_path
        with open(save_path, "w") as f:
            json.dump(self._wallet_data, f, indent=2)

    def add_pq_address(
        self, keypair: KeyPair, label: str | None = None, derivation_path: str | None = None
    ) -> PQAddressInfo:
        """
        Add a quantum-resistant address to the Electrum wallet data.

        Args:
            keypair: The ML-DSA-65 key pair.
            label: Optional label for the address.
            derivation_path: Optional BIP-32 derivation path.

        Returns:
            PQAddressInfo for the added address.
        """
        if self._wallet_data is None:
            self.load()

        address = address_from_public_key(keypair.public_key)

        # Initialize pq_addresses section if not present
        if "pq_addresses" not in self._wallet_data:
            self._wallet_data["pq_addresses"] = {}

        self._wallet_data["pq_addresses"][address] = {
            "public_key": keypair.public_key.hex(),
            "label": label,
            "derivation_path": derivation_path,
            "created_at": __import__("time").time(),
        }

        return PQAddressInfo(
            address=address,
            public_key=keypair.public_key,
            derivation_path=derivation_path,
            label=label,
            created_at=self._wallet_data["pq_addresses"][address]["created_at"],
        )

    def get_pq_addresses(self) -> list[PQAddressInfo]:
        """Return all quantum-resistant addresses from the wallet."""
        if self._wallet_data is None:
            self.load()

        pq_data = self._wallet_data.get("pq_addresses", {})
        results = []
        for address, info in pq_data.items():
            results.append(
                PQAddressInfo(
                    address=address,
                    public_key=bytes.fromhex(info["public_key"]),
                    derivation_path=info.get("derivation_path"),
                    label=info.get("label"),
                    created_at=info.get("created_at", 0),
                )
            )
        return results

    def is_electrum_wallet(self) -> bool:
        """Check if the loaded file is a valid Electrum wallet."""
        if self._wallet_data is None:
            self.load()
        return "keystore" in self._wallet_data and "wallet_type" in self._wallet_data


class BitcoinCoreRPC:
    """
    Bitcoin Core RPC client for quantum-resistant address operations.

    Requires the `python-bitcoinlib` or `bitcoinrpc` package.
    This is a wrapper around bitcoind's JSON-RPC interface.

    Example:
        rpc = BitcoinCoreRPC("http://user:pass@localhost:8332")
        addr = rpc.getnewpqaddress("label")
    """

    def __init__(self, url: str):
        self.url = url
        self._session = None

    def _get_session(self):
        """Lazy-import requests and create a session."""
        if self._session is None:
            try:
                import requests
            except ImportError:
                raise ImportError(
                    "The 'requests' package is required for Bitcoin Core RPC. "
                    "Install with: pip install requests"
                )
            self._session = requests.Session()
            # Parse auth from URL
            from urllib.parse import urlparse

            parsed = urlparse(self.url)
            if parsed.username and parsed.password:
                self._session.auth = (parsed.username, parsed.password)
        return self._session

    def _call(self, method: str, params: list[Any] | None = None) -> Any:
        """Make a JSON-RPC call to bitcoind."""
        import requests

        session = self._get_session()
        payload = {
            "jsonrpc": "1.0",
            "id": "safe-btc",
            "method": method,
            "params": params or [],
        }
        try:
            # Remove auth from URL for the request (use session.auth instead)
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(self.url)
            clean_url = urlunparse(
                (parsed.scheme, parsed.hostname and f"{parsed.hostname}:{parsed.port or 8332}", "", "", "", "")
            )
            response = session.post(clean_url, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            if "error" in result and result["error"] is not None:
                raise RuntimeError(f"RPC error: {result['error']}")
            return result["result"]
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Bitcoin Core at {self.url}: {e}")

    def getnewpqaddress(self, label: str | None = None) -> str:
        """
        Request a new quantum-resistant address from Bitcoin Core.

        This requires bitcoind to be patched with PQ address support
        (see BIP-XXXX). Returns a bc1z address.

        Args:
            label: Optional label for the address.

        Returns:
            A bc1z quantum-resistant address.
        """
        params = [label] if label else []
        return self._call("getnewpqaddress", params)

    def validatepqaddress(self, address: str) -> dict[str, Any]:
        """
        Validate a quantum-resistant address via bitcoind.

        Args:
            address: A bc1z address to validate.

        Returns:
            Validation result dict.
        """
        return self._call("validatepqaddress", [address])

    def listpqaddresses(self) -> list[dict[str, Any]]:
        """List all quantum-resistant addresses in the wallet."""
        return self._call("listpqaddresses", [])

    def signpqtransaction(
        self, tx_hex: str, privkeys: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Sign a transaction spending from quantum-resistant addresses.

        Args:
            tx_hex: Hex-encoded unsigned transaction.
            privkeys: Optional list of ML-DSA secret keys (hex).

        Returns:
            Signed transaction result.
        """
        params = [tx_hex]
        if privkeys:
            params.append(privkeys)
        return self._call("signpqtransaction", params)

    def sendpqtransaction(self, tx_hex: str) -> str:
        """
        Broadcast a signed quantum-resistant transaction.

        Args:
            tx_hex: Hex-encoded signed transaction.

        Returns:
            Transaction ID.
        """
        return self._call("sendpqtransaction", [tx_hex])


class HardwareWalletInterface(WalletInterface):
    """
    Abstract interface for hardware wallets (Ledger, Trezor, etc.).

    Hardware wallet integration requires the device's companion app
    (Ledger Live, Trezor Suite) and HID/USB communication.
    This class defines the interface; device-specific implementations
    must be added per manufacturer.
    """

    def __init__(self, device_type: str):
        """
        Args:
            device_type: One of "ledger", "trezor", "bitbox", "coldcard".
        """
        self.device_type = device_type
        self._connected = False

    def connect(self) -> bool:
        """Connect to the hardware wallet."""
        raise NotImplementedError(
            f"{self.device_type} hardware wallet support not yet implemented"
        )

    def get_pq_addresses(self) -> list[PQAddressInfo]:
        """Return all quantum-resistant addresses on the device."""
        raise NotImplementedError

    def create_pq_address(self, label: str | None = None) -> PQAddressInfo:
        """Create a new quantum-resistant address on the device."""
        raise NotImplementedError

    def sign_pq_transaction(
        self, tx: PQTransaction, derivation_paths: list[str]
    ) -> PQTransaction:
        """Sign a PQ transaction on the hardware device."""
        raise NotImplementedError

    def broadcast(self, tx_hex: str) -> str:
        """Hardware wallets cannot broadcast directly."""
        raise NotImplementedError("Use a node or wallet to broadcast")


@dataclass
class PQPsbtInput:
    """A PSBT input spending from a quantum-resistant address."""

    previous_txid: bytes | str
    previous_output_index: int
    previous_script_pubkey: bytes  # 0x02 + 32-byte commitment
    public_key: bytes | None = None  # ML-DSA-65 public key (1952 bytes)
    signature: bytes | None = None  # ML-DSA-65 signature (3309 bytes)
    derivation_path: str | None = None


@dataclass
class PQPsbtOutput:
    """A PSBT output to a quantum-resistant address."""

    address: str  # bc1z address
    amount_satoshis: int
    script_pubkey: bytes  # 0x02 + 32-byte commitment


class PQPsbt:
    """
    Partially Signed Bitcoin Transaction for quantum-resistant addresses.

    Extends the standard PSBT format (BIP-174) with ML-DSA-65 signature
    fields for spending from bc1z addresses.

    PSBT new fields (proposed):
    - Type 0x07: ML-DSA-65 public key (in input)
    - Type 0x08: ML-DSA-65 signature (in input)
    """

    def __init__(
        self,
        inputs: list[PQPsbtInput],
        outputs: list[PQPsbtOutput],
        fee_satoshis: int = 0,
    ):
        self.inputs = inputs
        self.outputs = outputs
        self.fee_satoshis = fee_satoshis

    def sign_input(self, input_index: int, keypair: KeyPair, message: bytes) -> None:
        """
        Sign a PSBT input with an ML-DSA-65 key.

        Args:
            input_index: Index of the input to sign.
            keypair: The ML-DSA-65 key pair.
            message: The transaction hash to sign (BIP-143 sighash).
        """
        if input_index >= len(self.inputs):
            raise IndexError(f"Input index {input_index} out of range")

        input_ = self.inputs[input_index]
        signature = MLDSA65.sign(keypair.secret_key, message)
        input_.signature = signature
        input_.public_key = keypair.public_key

    def is_fully_signed(self) -> bool:
        """Return True if all PQ inputs have signatures."""
        return all(inp.signature is not None for inp in self.inputs)

    def serialize(self) -> dict[str, Any]:
        """Serialize the PSBT to a JSON-serializable dict."""
        return {
            "inputs": [
                {
                    "previous_txid": (
                        inp.previous_txid.hex()
                        if isinstance(inp.previous_txid, bytes)
                        else inp.previous_txid
                    ),
                    "previous_output_index": inp.previous_output_index,
                    "previous_script_pubkey": inp.previous_script_pubkey.hex(),
                    "public_key": inp.public_key.hex() if inp.public_key else None,
                    "signature": inp.signature.hex() if inp.signature else None,
                    "derivation_path": inp.derivation_path,
                }
                for inp in self.inputs
            ],
            "outputs": [
                {
                    "address": out.address,
                    "amount_satoshis": out.amount_satoshis,
                    "script_pubkey": out.script_pubkey.hex(),
                }
                for out in self.outputs
            ],
            "fee_satoshis": self.fee_satoshis,
            "fully_signed": self.is_fully_signed(),
        }

    @classmethod
    def deserialize(cls, data: dict[str, Any]) -> "PQPsbt":
        """Deserialize from a dict (e.g., from JSON)."""
        inputs = []
        for inp in data["inputs"]:
            inputs.append(
                PQPsbtInput(
                    previous_txid=bytes.fromhex(inp["previous_txid"]),
                    previous_output_index=inp["previous_output_index"],
                    previous_script_pubkey=bytes.fromhex(inp["previous_script_pubkey"]),
                    public_key=(
                        bytes.fromhex(inp["public_key"]) if inp.get("public_key") else None
                    ),
                    signature=(
                        bytes.fromhex(inp["signature"]) if inp.get("signature") else None
                    ),
                    derivation_path=inp.get("derivation_path"),
                )
            )
        outputs = []
        for out in data["outputs"]:
            outputs.append(
                PQPsbtOutput(
                    address=out["address"],
                    amount_satoshis=out["amount_satoshis"],
                    script_pubkey=bytes.fromhex(out["script_pubkey"]),
                )
            )
        return cls(
            inputs=inputs,
            outputs=outputs,
            fee_satoshis=data.get("fee_satoshis", 0),
        )

    def size_vbytes(self) -> int:
        """
        Estimate the transaction size in virtual bytes.

        PQ inputs are much larger than legacy inputs due to the
        1,952-byte public key and 3,309-byte signature in the witness.
        """
        base_overhead = 10  # version, marker, flag, locktime
        output_size = sum(34 for _ in self.outputs)  # 8 bytes amount + ~26 script
        input_size = 0
        for inp in self.inputs:
            # 36 bytes prevout + 4 bytes sequence
            # Witness: 1 (item count) + varint(3309) + 3309 (sig) + varint(1952) + 1952 (pubkey)
            witness_size = 1 + 2 + 3309 + 2 + 1952  # ~5266 bytes
            input_size += 36 + 4 + witness_size
        return base_overhead + output_size + input_size


def create_pq_psbt(
    inputs: list[PQPsbtInput],
    outputs: list[PQPsbtOutput],
    fee_satoshis: int = 0,
) -> PQPsbt:
    """Create a new PQ-PSBT."""
    return PQPsbt(inputs=inputs, outputs=outputs, fee_satoshis=fee_satoshis)


def estimate_pq_transaction_fee(
    n_pq_inputs: int,
    n_outputs: int,
    fee_rate_sat_per_vbyte: int,
) -> int:
    """
    Estimate the fee for a quantum-resistant transaction.

    Args:
        n_pq_inputs: Number of PQ inputs (each ~3.3KB signature + 1.95KB pubkey).
        n_outputs: Number of outputs.
        fee_rate_sat_per_vbyte: Fee rate in satoshis per vbyte.

    Returns:
        Estimated fee in satoshis.
    """
    # Approximate vbytes per PQ input: 36 (prevout) + 4 (sequence) +
    # 1 (item count) + 2 (varint) + 3309 (sig) + 2 (varint) + 1952 (pubkey) ≈ 5306
    vbytes_per_pq_input = 5306
    vbytes_per_output = 34
    base_vbytes = 10

    total_vbytes = base_vbytes + n_pq_inputs * vbytes_per_pq_input + n_outputs * vbytes_per_output
    return total_vbytes * fee_rate_sat_per_vbyte
