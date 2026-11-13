"""
Wallet integration for witness v3 (ML-DSA-65) addresses.

- Abstract wallet interface
- Electrum wallet-file helper (stores PQ public keys alongside a JSON wallet)
- Bitcoin Core RPC client for *proposed* RPCs (needs a patched node)
- Hardware wallet interface stub
- Fee/size estimation that accounts for the segwit witness discount
- PSBT support lives in :mod:`safe_btc.psbt` and is re-exported here

This is a prototype integration layer. Witness v3 is not active on any
network; never send mainnet funds to these addresses.
"""

from __future__ import annotations

import abc
import json
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Any

from ..pq_addresses import DEFAULT_NETWORK, address_from_public_key
from ..pq_signatures import PUBLIC_KEY_SIZE, SIGNATURE_SIZE, KeyPair
from ..psbt import PQPsbt, PsbtInput, PsbtOutput  # noqa: F401  (re-export)
from ..transaction import ser_compact_size


@dataclass
class PQAddressInfo:
    """Information about a quantum-resistant address in a wallet."""

    address: str
    public_key: bytes
    derivation_path: str | None
    label: str | None
    created_at: float


class WalletInterface(abc.ABC):
    """Abstract interface for wallet integrations."""

    @abc.abstractmethod
    def get_pq_addresses(self) -> list[PQAddressInfo]:
        """Return all quantum-resistant addresses in the wallet."""

    @abc.abstractmethod
    def create_pq_address(self, label: str | None = None) -> PQAddressInfo:
        """Create a new quantum-resistant address."""

    @abc.abstractmethod
    def sign_psbt(self, psbt: PQPsbt) -> PQPsbt:
        """Sign every witness v3 input the wallet holds keys for."""

    @abc.abstractmethod
    def broadcast(self, tx_hex: str) -> str:
        """Broadcast a signed transaction and return the txid."""


class ElectrumWallet:
    """
    Read and write Electrum JSON wallet files, adding a ``pq_addresses`` section
    that holds public keys only (secrets stay in safe-btc key files).

    Encrypted Electrum wallets are not JSON and are rejected on load. Saves are
    atomic (write to a temp file, then rename) so a crash cannot truncate the
    wallet. Real Electrum support requires changes to Electrum itself.
    """

    def __init__(self, wallet_path: str, network: str = DEFAULT_NETWORK):
        self.wallet_path = wallet_path
        self.network = network
        self._wallet_data: dict[str, Any] | None = None

    def load(self) -> dict[str, Any]:
        with open(self.wallet_path) as f:
            try:
                self._wallet_data = json.load(f)
            except json.JSONDecodeError:
                raise ValueError("not a JSON wallet (encrypted Electrum wallets are unsupported)")
        return self._wallet_data

    def _data(self) -> dict[str, Any]:
        if self._wallet_data is None:
            self.load()
        assert self._wallet_data is not None
        return self._wallet_data

    def save(self, path: str | None = None) -> None:
        if self._wallet_data is None:
            raise ValueError("Wallet not loaded")
        save_path = path or self.wallet_path
        directory = os.path.dirname(os.path.abspath(save_path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".safe-btc-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self._wallet_data, f, indent=2)
            if os.path.exists(save_path):
                os.chmod(tmp, os.stat(save_path).st_mode & 0o777)
            os.replace(tmp, save_path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def add_pq_address(
        self, keypair: KeyPair, label: str | None = None, derivation_path: str | None = None
    ) -> PQAddressInfo:
        data = self._data()
        address = address_from_public_key(keypair.public_key, self.network)
        entry = {
            "public_key": keypair.public_key.hex(),
            "label": label,
            "derivation_path": derivation_path,
            "created_at": time.time(),
        }
        data.setdefault("pq_addresses", {})[address] = entry
        return PQAddressInfo(address, keypair.public_key, derivation_path, label, entry["created_at"])

    def get_pq_addresses(self) -> list[PQAddressInfo]:
        return [
            PQAddressInfo(
                address=address,
                public_key=bytes.fromhex(info["public_key"]),
                derivation_path=info.get("derivation_path"),
                label=info.get("label"),
                created_at=info.get("created_at", 0),
            )
            for address, info in self._data().get("pq_addresses", {}).items()
        ]

    def is_electrum_wallet(self) -> bool:
        data = self._data()
        return "keystore" in data and "wallet_type" in data


class BitcoinCoreRPC:
    """
    JSON-RPC client for the RPCs a witness v3-aware Bitcoin Core would expose.

    ``getnewpqaddress`` etc. do not exist in any released Bitcoin Core; these
    methods document the proposed interface and need a patched node.
    Generic calls (e.g. ``call("getblockcount")``) work against any node.
    """

    def __init__(self, url: str, timeout: float = 30):
        from urllib.parse import unquote, urlparse, urlunparse

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("RPC URL must look like http://user:pass@host:port")
        self._auth = (unquote(parsed.username), unquote(parsed.password or "")) if parsed.username else None
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        netloc = f"{host}:{parsed.port or 8332}"
        self.url = urlunparse((parsed.scheme, netloc, parsed.path or "/", "", "", ""))
        self.timeout = timeout
        self._session = None

    def _get_session(self):
        if self._session is None:
            try:
                import requests
            except ImportError:
                raise ImportError("Bitcoin Core RPC needs 'requests': pip install safe-btc[rpc]")
            self._session = requests.Session()
            if self._auth:
                self._session.auth = self._auth
        return self._session

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        import requests

        payload = {"jsonrpc": "1.0", "id": "safe-btc", "method": method, "params": params or []}
        try:
            response = self._get_session().post(self.url, json=payload, timeout=self.timeout)
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Bitcoin Core at {self.url}: {e}")
        # Bitcoin Core reports RPC errors as JSON with HTTP 500; auth failures
        # (401) and proxies return non-JSON bodies.
        try:
            result = response.json()
        except ValueError:
            response.raise_for_status()
            raise RuntimeError(f"non-JSON response from {self.url} (HTTP {response.status_code})")
        if result.get("error") is not None:
            raise RuntimeError(f"RPC error: {result['error']}")
        response.raise_for_status()
        return result["result"]

    _call = call  # backwards compatibility

    def getnewpqaddress(self, label: str | None = None) -> str:
        """Proposed RPC: new witness v3 address."""
        return self.call("getnewpqaddress", [label] if label else [])

    def validatepqaddress(self, address: str) -> dict[str, Any]:
        """Proposed RPC."""
        return self.call("validatepqaddress", [address])

    def listpqaddresses(self) -> list[dict[str, Any]]:
        """Proposed RPC."""
        return self.call("listpqaddresses", [])

    def walletprocesspsbt(self, psbt_b64: str) -> dict[str, Any]:
        """Existing RPC; a witness v3-aware wallet would sign PQ inputs here."""
        return self.call("walletprocesspsbt", [psbt_b64])

    def sendrawtransaction(self, tx_hex: str) -> str:
        return self.call("sendrawtransaction", [tx_hex])


class HardwareWalletInterface(WalletInterface):
    """
    Interface for hardware wallets (Ledger, Trezor, BitBox, Coldcard).

    Device notes: ML-DSA-65 signing needs roughly 50-100 KB of RAM in common
    implementations and the device must display the full transaction, since
    the sighash commits to every input amount (no blind signing).
    """

    def __init__(self, device_type: str):
        self.device_type = device_type

    def connect(self) -> bool:
        raise NotImplementedError(f"{self.device_type} support not yet implemented")

    def get_pq_addresses(self) -> list[PQAddressInfo]:
        raise NotImplementedError

    def create_pq_address(self, label: str | None = None) -> PQAddressInfo:
        raise NotImplementedError

    def sign_psbt(self, psbt: PQPsbt) -> PQPsbt:
        raise NotImplementedError

    def broadcast(self, tx_hex: str) -> str:
        raise NotImplementedError("Use a node or wallet to broadcast")


# --- size and fee estimation ------------------------------------------------------

# Non-witness bytes per input: outpoint (36) + empty scriptSig (1) + nSequence (4)
INPUT_BASE_BYTES = 41
# Witness bytes per default-sighash ML-DSA-65 input:
#   item count (1) + compact_size(3309) (3) + 3309 + compact_size(1953) (3) + 1953
PQ_INPUT_WITNESS_BYTES = 1 + 3 + SIGNATURE_SIZE + 3 + (1 + PUBLIC_KEY_SIZE)
PQ_INPUT_WEIGHT = INPUT_BASE_BYTES * 4 + PQ_INPUT_WITNESS_BYTES  # 5,433 WU
PQ_OUTPUT_BYTES = 8 + 1 + 34  # amount + script length + OP_3 0x20 <32>
MAX_BLOCK_WEIGHT = 4_000_000


def estimate_pq_vsize(n_pq_inputs: int, output_script_lens: list[int] | int) -> int:
    """
    Virtual size of a transaction spending ``n_pq_inputs`` witness v3 inputs.

    ``output_script_lens`` is a list of scriptPubKey lengths, or an output count
    (each assumed to be a 34-byte witness v3 / P2WSH / P2TR script).
    """
    if isinstance(output_script_lens, int):
        output_script_lens = [34] * output_script_lens
    base = 4 + 4 + len(ser_compact_size(n_pq_inputs)) + len(ser_compact_size(len(output_script_lens)))
    base += n_pq_inputs * INPUT_BASE_BYTES
    base += sum(8 + len(ser_compact_size(n)) + n for n in output_script_lens)
    witness = (2 + n_pq_inputs * PQ_INPUT_WITNESS_BYTES) if n_pq_inputs else 0
    weight = base * 4 + witness
    return (weight + 3) // 4


def estimate_pq_transaction_fee(n_pq_inputs: int, n_outputs: int, fee_rate_sat_per_vbyte: float) -> int:
    """Fee in satoshis for ``n_pq_inputs`` ML-DSA-65 inputs and ``n_outputs`` outputs."""
    return int(-(-estimate_pq_vsize(n_pq_inputs, n_outputs) * fee_rate_sat_per_vbyte // 1))


def max_pq_inputs_per_block() -> int:
    return MAX_BLOCK_WEIGHT // PQ_INPUT_WEIGHT
