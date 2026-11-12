"""Tests for wallet integration."""

from __future__ import annotations

import json
import os
import tempfile
import pytest

from safe_btc.wallet_integration import (
    ElectrumWallet,
    PQAddressInfo,
    PQPsbt,
    PQPsbtInput,
    PQPsbtOutput,
    create_pq_psbt,
    estimate_pq_transaction_fee,
)
from safe_btc.keys import KeyPair
from safe_btc.pq_addresses import address_from_public_key


class TestPQAddressInfo:
    """Tests for PQAddressInfo dataclass."""

    def test_creation(self):
        info = PQAddressInfo(
            address="bc1z1test",
            public_key=b"\x00" * 1952,
            derivation_path="m/84'/0'/0'/0/0",
            label="test",
            created_at=1234567890.0,
        )
        assert info.address == "bc1z1test"
        assert len(info.public_key) == 1952
        assert info.derivation_path == "m/84'/0'/0'/0/0"
        assert info.label == "test"


class TestElectrumWallet:
    """Tests for Electrum wallet integration."""

    def test_add_and_get_pq_address(self):
        keypair = KeyPair.generate()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"keystore": {}, "wallet_type": "standard"}, f)
            tmp_path = f.name

        try:
            wallet = ElectrumWallet(tmp_path)
            wallet.load()

            info = wallet.add_pq_address(
                keypair, label="my PQ address", derivation_path="m/84'/0'/0'/0/0"
            )

            assert info.address.startswith("bc1z")
            assert info.label == "my PQ address"
            assert info.derivation_path == "m/84'/0'/0'/0/0"

            # Retrieve
            addresses = wallet.get_pq_addresses()
            assert len(addresses) == 1
            assert addresses[0].address == info.address
            assert addresses[0].public_key == keypair.public_key
        finally:
            os.unlink(tmp_path)

    def test_is_electrum_wallet(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"keystore": {}, "wallet_type": "standard"}, f)
            tmp_path = f.name

        try:
            wallet = ElectrumWallet(tmp_path)
            assert wallet.is_electrum_wallet() is True
        finally:
            os.unlink(tmp_path)

    def test_not_electrum_wallet(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"not": "electrum"}, f)
            tmp_path = f.name

        try:
            wallet = ElectrumWallet(tmp_path)
            assert wallet.is_electrum_wallet() is False
        finally:
            os.unlink(tmp_path)


class TestPQPsbt:
    """Tests for PQ-PSBT."""

    def test_create_and_sign(self):
        kp = KeyPair.generate()
        address = address_from_public_key(kp.public_key)

        inp = PQPsbtInput(
            previous_txid=b"\x00" * 32,
            previous_output_index=0,
            previous_script_pubkey=b"\x02" + b"\x01" * 32,
        )
        out = PQPsbtOutput(
            address=address,
            amount_satoshis=50000,
            script_pubkey=b"\x02" + b"\x02" * 32,
        )

        psbt = create_pq_psbt(inputs=[inp], outputs=[out], fee_satoshis=1000)
        assert not psbt.is_fully_signed()

        # Sign the input
        message = b"sighash_1234"
        psbt.sign_input(0, kp, message)
        assert psbt.is_fully_signed()
        assert psbt.inputs[0].signature is not None
        assert psbt.inputs[0].public_key == kp.public_key

    def test_serialize_deserialize_roundtrip(self):
        kp = KeyPair.generate()
        address = address_from_public_key(kp.public_key)

        inp = PQPsbtInput(
            previous_txid=b"\x11" * 32,
            previous_output_index=1,
            previous_script_pubkey=b"\x02" + b"\x01" * 32,
            public_key=kp.public_key,
        )
        out = PQPsbtOutput(
            address=address,
            amount_satoshis=100000,
            script_pubkey=b"\x02" + b"\x02" * 32,
        )

        psbt = create_pq_psbt(inputs=[inp], outputs=[out], fee_satoshis=2000)
        message = b"sighash"
        psbt.sign_input(0, kp, message)

        data = psbt.serialize()
        psbt2 = PQPsbt.deserialize(data)

        assert len(psbt2.inputs) == 1
        assert len(psbt2.outputs) == 1
        assert psbt2.inputs[0].previous_output_index == 1
        assert psbt2.outputs[0].amount_satoshis == 100000
        assert psbt2.outputs[0].address == address
        assert psbt2.is_fully_signed()

    def test_size_vbytes(self):
        kp = KeyPair.generate()
        address = address_from_public_key(kp.public_key)

        inp = PQPsbtInput(
            previous_txid=b"\x00" * 32,
            previous_output_index=0,
            previous_script_pubkey=b"\x02" + b"\x01" * 32,
        )
        out = PQPsbtOutput(
            address=address,
            amount_satoshis=50000,
            script_pubkey=b"\x02" + b"\x02" * 32,
        )

        psbt = create_pq_psbt(inputs=[inp], outputs=[out], fee_satoshis=1000)
        size = psbt.size_vbytes()
        assert size > 5000  # PQ transactions are large
        assert isinstance(size, int)

    def test_sign_input_invalid_index(self):
        kp = KeyPair.generate()
        inp = PQPsbtInput(
            previous_txid=b"\x00" * 32,
            previous_output_index=0,
            previous_script_pubkey=b"\x02" + b"\x01" * 32,
        )
        psbt = create_pq_psbt(inputs=[inp], outputs=[])

        with pytest.raises(IndexError):
            psbt.sign_input(5, kp, b"msg")


class TestFeeEstimation:
    """Tests for PQ transaction fee estimation."""

    def test_estimate_fee(self):
        fee = estimate_pq_transaction_fee(
            n_pq_inputs=1, n_outputs=2, fee_rate_sat_per_vbyte=10
        )
        assert fee > 0
        assert isinstance(fee, int)

    def test_fee_scales_with_inputs(self):
        fee_1 = estimate_pq_transaction_fee(
            n_pq_inputs=1, n_outputs=1, fee_rate_sat_per_vbyte=10
        )
        fee_10 = estimate_pq_transaction_fee(
            n_pq_inputs=10, n_outputs=1, fee_rate_sat_per_vbyte=10
        )
        assert fee_10 > fee_1

    def test_fee_scales_with_feerate(self):
        fee_low = estimate_pq_transaction_fee(
            n_pq_inputs=1, n_outputs=1, fee_rate_sat_per_vbyte=1
        )
        fee_high = estimate_pq_transaction_fee(
            n_pq_inputs=1, n_outputs=1, fee_rate_sat_per_vbyte=100
        )
        assert fee_high == fee_low * 100
