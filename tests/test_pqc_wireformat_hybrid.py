#!/usr/bin/env python3
"""
Additional tests for pqblocks_wire.hybrid to improve coverage.
Focuses on error handling paths and test_all_operations entrypoint.
"""

import sys
import os
import struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import x25519
from pqblocks_wire import generate_mlkem_keypair


class TestHybridErrorPaths:
    """Test hybrid module error handling paths."""

    def test_hybrid_public_key_deserialize_insufficient_data(self):
        """Test HybridPublicKey.deserialize with insufficient data (line 41)."""
        from pqblocks_wire.hybrid import HybridPublicKey

        # Test with less than 36 bytes (32 X25519 + 4 length)
        with pytest.raises(ValueError, match="Insufficient data for hybrid public key"):
            HybridPublicKey.deserialize(b"x" * 30)  # Only 30 bytes

        print("✅ HybridPublicKey.deserialize insufficient data tested")

    def test_hybrid_public_key_deserialize_insufficient_mlkem_data(self):
        """Test HybridPublicKey.deserialize with insufficient ML-KEM data (line 51)."""
        from pqblocks_wire.hybrid import HybridPublicKey

        # Create data with 32 bytes X25519 + 4 bytes length = 36 bytes, but ML-KEM length > 0
        x25519_key = x25519.X25519PrivateKey.generate().public_key()
        data = x25519_key.public_bytes_raw() + struct.pack('>I', 10)  # Say we have 10 bytes ML-KEM
        # But only provide 36 bytes total, not 36 + 10 = 46 bytes needed

        with pytest.raises(ValueError, match="Insufficient data for ML-KEM public key"):
            HybridPublicKey.deserialize(data)

        print("✅ HybridPublicKey.deserialize insufficient ML-KEM data tested")

    def test_hybrid_private_key_deserialize_insufficient_data(self):
        """Test HybridPrivateKey.deserialize with insufficient data (line 85)."""
        from pqblocks_wire.hybrid import HybridPrivateKey

        # Test with less than 36 bytes (32 X25519 + 4 length)
        with pytest.raises(ValueError, match="Insufficient data for hybrid private key"):
            HybridPrivateKey.deserialize(b"x" * 30)  # Only 30 bytes

        print("✅ HybridPrivateKey.deserialize insufficient data tested")

    def test_hybrid_private_key_deserialize_insufficient_mlkem_data(self):
        """Test HybridPrivateKey.deserialize with insufficient ML-KEM data (line 95)."""
        from pqblocks_wire.hybrid import HybridPrivateKey

        # Create data with 32 bytes X25519 + 4 bytes length = 36 bytes, but ML-KEM length > 0
        x25519_key = x25519.X25519PrivateKey.generate()
        data = x25519_key.private_bytes_raw() + struct.pack('>I', 10)  # Say we have 10 bytes ML-KEM
        # But only provide 36 bytes total, not 36 + 10 = 46 bytes needed

        with pytest.raises(ValueError, match="Insufficient data for ML-KEM private key"):
            HybridPrivateKey.deserialize(data)

        print("✅ HybridPrivateKey.deserialize insufficient ML-KEM data tested")

    def test_hybrid_key_exchange_initiator_mlkem_encapsulation_error(self):
        """Test hybrid_key_exchange_initiator ML-KEM encapsulation error path (lines 142-144)."""
        from pqblocks_wire.hybrid import hybrid_key_exchange_initiator

        # Generate keys
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, _ = generate_mlkem_keypair("ML-KEM-768")

        # Mock encapsulate_mlkem to raise an exception
        with patch('pqblocks_wire.encapsulate_mlkem') as mock_encapsulate:
            mock_encapsulate.side_effect = Exception("ML-KEM encapsulation failed")

            with pytest.raises(ValueError, match="ML-KEM encapsulation failed"):
                hybrid_key_exchange_initiator(
                    x25519_private_key=x25519_private,
                    x25519_public_key=x25519_public,
                    mlkem_public_key=mlkem_public
                )

        print("✅ hybrid_key_exchange_initiator ML-KEM encapsulation error tested")

    def test_hybrid_key_exchange_initiator_size_validation_ciphertext(self):
        """Test hybrid_key_exchange_initiator ciphertext size validation (line ~148)."""
        from pqblocks_wire.hybrid import hybrid_key_exchange_initiator

        # Generate keys
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, _ = generate_mlkem_keypair("ML-KEM-768")

        # Mock encapsulate_mlkem to return oversized ciphertext
        with patch('pqblocks_wire.encapsulate_mlkem') as mock_encapsulate:
            # Return ciphertext larger than MAX_MLKEM_CIPHERTEXT (which is 1088 for ML-KEM-768)
            # Provide 32-byte shared secret so shared secret check passes
            mock_encapsulate.return_value = (b"x" * 2000, b"x" * 32)  # Oversized ciphertext, valid shared secret

            with pytest.raises(ValueError, match="ML-KEM ciphertext must be 1088 bytes"):
                hybrid_key_exchange_initiator(
                    x25519_private_key=x25519_private,
                    x25519_public_key=x25519_public,
                    mlkem_public_key=mlkem_public
                )

        print("✅ hybrid_key_exchange_initiator ciphertext size validation tested")

    def test_hybrid_key_exchange_initiator_size_validation_shared_secret(self):
        """Test hybrid_key_exchange_initiator shared secret size validation (line ~144)."""
        from pqblocks_wire.hybrid import hybrid_key_exchange_initiator

        # Generate keys
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, _ = generate_mlkem_keypair("ML-KEM-768")

        # Mock encapsulate_mlkem to return wrong sized shared secret
        with patch('pqblocks_wire.encapsulate_mlkem') as mock_encapsulate:
            # Return shared secret not 32 bytes
            mock_encapsulate.return_value = (b"ciphertext", b"x" * 16)  # Wrong size

            with pytest.raises(ValueError, match="ML-KEM shared secret must be 32 bytes"):
                hybrid_key_exchange_initiator(
                    x25519_private_key=x25519_private,
                    x25519_public_key=x25519_public,
                    mlkem_public_key=mlkem_public
                )

        print("✅ hybrid_key_exchange_initiator shared secret size validation tested")

    def test_hybrid_key_exchange_responder_mlkem_decapsulation_error(self):
        """Test hybrid_key_exchange_responder ML-KEM decapsulation error path (line 197)."""
        from pqblocks_wire.hybrid import hybrid_key_exchange_responder, hybrid_key_exchange_initiator

        # Generate keys for initiator and responder
        x25519_private_init = x25519.X25519PrivateKey.generate()
        x25519_public_init = x25519_private_init.public_key()
        x25519_private_resp = x25519.X25519PrivateKey.generate()
        x25519_public_resp = x25519_private_resp.public_key()
        mlkem_public_resp, mlkem_private_resp = generate_mlkem_keypair("ML-KEM-768")

        # First get a valid initiator message to pass to responder
        mlkem_ciphertext, _ = hybrid_key_exchange_initiator(
            x25519_private_key=x25519_private_init,
            x25519_public_key=x25519_public_resp,
            mlkem_public_key=mlkem_public_resp
        )

        # Mock decapsulate_mlkem to raise an exception
        with patch('pqblocks_wire.decapsulate_mlkem') as mock_decapsulate:
            mock_decapsulate.side_effect = Exception("ML-KEM decapsulation failed")

            with pytest.raises(ValueError, match="ML-KEM decapsulation failed"):
                hybrid_key_exchange_responder(
                    x25519_private_key=x25519_private_resp,
                    x25519_public_key=x25519_public_init,
                    mlkem_private_key=mlkem_private_resp,
                    mlkem_ciphertext=mlkem_ciphertext
                )

        print("✅ hybrid_key_exchange_responder ML-KEM decapsulation error tested")

    def test_hybrid_key_exchange_responder_size_validation_shared_secret(self):
        """Test hybrid_key_exchange_responder shared secret size validation (line ~197)."""
        from pqblocks_wire.hybrid import hybrid_key_exchange_responder, hybrid_key_exchange_initiator

        # Generate keys for initiator and responder
        x25519_private_init = x25519.X25519PrivateKey.generate()
        x25519_public_init = x25519_private_init.public_key()
        x25519_private_resp = x25519.X25519PrivateKey.generate()
        x25519_public_resp = x25519_private_resp.public_key()
        mlkem_public_resp, mlkem_private_resp = generate_mlkem_keypair("ML-KEM-768")

        # First get a valid initiator message to pass to responder
        mlkem_ciphertext, _ = hybrid_key_exchange_initiator(
            x25519_private_key=x25519_private_init,
            x25519_public_key=x25519_public_resp,
            mlkem_public_key=mlkem_public_resp
        )

        # Mock decapsulate_mlkem to return wrong sized shared secret
        with patch('pqblocks_wire.decapsulate_mlkem') as mock_decapsulate:
            # Return shared secret not 32 bytes
            mock_decapsulate.return_value = b"x" * 16  # Wrong size

            with pytest.raises(ValueError, match="ML-KEM shared secret must be 32 bytes"):
                hybrid_key_exchange_responder(
                    x25519_private_key=x25519_private_resp,
                    x25519_public_key=x25519_public_init,
                    mlkem_private_key=mlkem_private_resp,
                    mlkem_ciphertext=mlkem_ciphertext
                )

        print("✅ hybrid_key_exchange_responder shared secret size validation tested")

    def test_classical_fallback_wrong_shared_secret_size(self):
        """Test classical_fallback with wrong X25519 shared secret size (line 238)."""
        from pqblocks_wire.hybrid import classical_fallback

        # cryptography's Rust-backed X25519PrivateKey has read-only
        # attributes, so instance-level patching raises AttributeError.
        # Inject the fault with a stub instead: patch the private-key
        # class reference in the x25519 module so the product's
        # isinstance check accepts the stub, whose exchange() returns
        # a 16-byte secret and exercises the line-238 ValueError.
        class _FakeX25519Private:
            def exchange(self, pub):
                return b"x" * 16  # Wrong size (must be 32)

        # Real peer public key passes the (unpatched) public-key check.
        x25519_public = x25519.X25519PrivateKey.generate().public_key()

        with patch(
            "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey",
            _FakeX25519Private,
        ):
            with pytest.raises(ValueError, match="X25519 shared secret must be 32 bytes"):
                classical_fallback(
                    x25519_private_key=_FakeX25519Private(),
                    x25519_public_key=x25519_public
                )

        print("✅ classical_fallback wrong shared secret size tested")

    def test_legacy_hybrid_key_exchange_mlkem_mismatch_path(self):
        """Test legacy hybrid_key_exchange ML-KEM mismatch path (lines 354-355)."""
        from pqblocks_wire.hybrid import hybrid_key_exchange

        # Generate keys
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, mlkem_private = generate_mlkem_keypair("ML-KEM-768")

        # Mock ML-KEM operations to return different shared secrets
        with patch('pqblocks_wire.encapsulate_mlkem') as mock_encapsulate, \
             patch('pqblocks_wire.decapsulate_mlkem') as mock_decapsulate:

            # Initiator gets one shared secret
            mock_encapsulate.return_value = (b"ciphertext", b"shared_secret_A" * 4)  # 32 bytes
            # Responder gets different shared secret
            mock_decapsulate.return_value = b"shared_secret_B" * 4  # 32 bytes, but different

            with pytest.raises(ValueError, match="ML-KEM encapsulation/decapsulation mismatch"):
                hybrid_key_exchange(
                    x25519_private_key=x25519_private,
                    x25519_public_key=x25519_public,
                    mlkem_public_key=mlkem_public,
                    mlkem_private_key=mlkem_private
                )

        print("✅ legacy hybrid_key_exchange ML-KEM mismatch path tested")


class TestHybridTestAllOperations:
    """Test hybrid test_all_operations entrypoint."""

    def test_hybrid_test_all_operations_entrypoint(self):
        """Test hybrid_test_basic_operations runs without error."""
        from pqblocks_wire.hybrid import hybrid_test_basic_operations
        hybrid_test_basic_operations()
        print("✅ hybrid_test_basic_operations executed successfully")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])