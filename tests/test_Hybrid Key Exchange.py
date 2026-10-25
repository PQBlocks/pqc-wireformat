#!/usr/bin/env python3
"""
Tests for Hybrid Key Exchange (feature 6) - X25519 + ML-KEM hybrid shared secret derivation.

Contract (from spec.md [feature 6]):
- Input: X25519 key pair, ML-KEM key pair
- Output: Combined shared secret derivation
- Contract: Works with classical peers (fallback) and PQC peers
- Tests: test_hybrid_key_exchange(), test_classical_fallback()
"""

import pytest
import sys
import os
import struct

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

pytest.importorskip("pqblocks_wire")

from pqblocks_wire.hybrid import (
    HybridPublicKey, HybridPrivateKey,
    hybrid_key_exchange_initiator, hybrid_key_exchange_responder,
    classical_fallback, generate_hybrid_keypair, hybrid_key_exchange
)
from pqblocks_wire.wireformat import WireFormatError


class TestHybridKeyExchange:
    """Test hybrid key exchange combining X25519 and ML-KEM."""

    def test_hybrid_key_exchange_basic(self):
        """Test basic hybrid key exchange functionality."""
        from pqblocks_wire.hybrid import hybrid_key_exchange
        
        # Generate X25519 key pair
        from cryptography.hazmat.primitives.asymmetric import x25519
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        
        # Get ML-KEM key pair (using available backend)
        from pqblocks_wire import generate_mlkem_keypair
        mlkem_public, mlkem_private = generate_mlkem_keypair("ML-KEM-768")
        
        # Perform hybrid key exchange
        shared_secret = hybrid_key_exchange(
            x25519_private_key=x25519_private,
            x25519_public_key=x25519_public,
            mlkem_public_key=mlkem_public,
            mlkem_private_key=mlkem_private
        )
        
        # Should return bytes of expected length (32 bytes for shared secret)
        assert isinstance(shared_secret, bytes)
        assert len(shared_secret) == 32  # Standard shared secret size

    def test_hybrid_key_exchange_initiator_responder(self):
        """Test full hybrid key exchange between initiator and responder."""
        from pqblocks_wire.hybrid import (
            hybrid_key_exchange_initiator,
            hybrid_key_exchange_responder,
            generate_hybrid_keypair
        )
        
        # Generate hybrid key pairs for both parties
        my_public, my_private = generate_hybrid_keypair()
        peer_public, peer_private = generate_hybrid_keypair()
        
        # Initiator side: generate ciphertext and shared secret
        ct, my_shared_secret = hybrid_key_exchange_initiator(
            x25519_private_key=my_private.x25519_private_key,
            x25519_public_key=peer_public.x25519_public_key,
            mlkem_public_key=peer_public.mlkem_public_key
        )
        
        # Responder side: decode and derive same shared secret
        peer_shared_secret = hybrid_key_exchange_responder(
            x25519_private_key=peer_private.x25519_private_key,
            x25519_public_key=my_public.x25519_public_key,
            mlkem_private_key=peer_private.mlkem_private_key,
            mlkem_ciphertext=ct
        )
        
        # Both should derive the same shared secret
        assert my_shared_secret == peer_shared_secret
        assert len(my_shared_secret) == 32

    def test_classical_fallback_x25519_only(self):
        """Test classical fallback when only X25519 is available."""
        from pqblocks_wire.hybrid import classical_fallback
        
        # Generate X25519 key pair
        from cryptography.hazmat.primitives.asymmetric import x25519
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        
        # Perform classical key exchange (X25519 only)
        shared_secret = classical_fallback(
            x25519_private_key=x25519_private,
            x25519_public_key=x25519_public
        )
        
        # Should return bytes of expected length
        assert isinstance(shared_secret, bytes)
        assert len(shared_secret) == 32

    def test_hybrid_key_exchange_deterministic(self):
        """Test that hybrid key exchange produces deterministic results."""
        from pqblocks_wire.hybrid import hybrid_key_exchange
        
        # This test will be implemented once we have the basic functionality
        pytest.skip("Implement after basic hybrid key exchange works")

    def test_hybrid_key_exchange_invalid_inputs(self):
        """Test error handling for invalid inputs."""
        from pqblocks_wire.hybrid import hybrid_key_exchange
        from pqblocks_wire.wireformat import WireFormatError
        
        # Generate valid X25519 key pair
        from cryptography.hazmat.primitives.asymmetric import x25519
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        
        # Get ML-KEM key pair
        from pqblocks_wire import generate_mlkem_keypair
        mlkem_public, mlkem_private = generate_mlkem_keypair("ML-KEM-768")
        
        # Test with None inputs
        with pytest.raises((TypeError, ValueError)):
            hybrid_key_exchange(
                x25519_private_key=None,
                x25519_public_key=x25519_public,
                mlkem_public_key=mlkem_public,
                mlkem_private_key=mlkem_private
            )
        
        with pytest.raises((TypeError, ValueError)):
            hybrid_key_exchange(
                x25519_private_key=x25519_private,
                x25519_public_key=None,
                mlkem_public_key=mlkem_public,
                mlkem_private_key=mlkem_private
            )
        
        # Test with wrong type inputs
        with pytest.raises(TypeError):
            hybrid_key_exchange(
                x25519_private_key="invalid",
                x25519_public_key=x25519_public,
                mlkem_public_key=mlkem_public,
                mlkem_private_key=mlkem_private
            )

class TestHybridKeySerialization:
    """Test hybrid key serialization/deserialization."""

    def test_public_key_serialize_deserialize(self):
        """Test that hybrid public keys can be serialized and deserialized."""
        from pqblocks_wire.hybrid import generate_hybrid_keypair
        from pqblocks_wire import generate_mlkem_keypair
        from cryptography.hazmat.primitives.asymmetric import x25519
        
        # Generate keys manually to have direct control
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, _ = generate_mlkem_keypair("ML-KEM-768")
        
        hybrid_pub = HybridPublicKey(
            x25519_public_key=x25519_public,
            mlkem_public_key=mlkem_public
        )
        
        # Serialize
        serialized = hybrid_pub.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 36  # 32 bytes X25519 + 4 bytes length + ML-KEM key
        
        # Deserialize
        deserialized = HybridPublicKey.deserialize(serialized)
        # X25519 keys should match
        assert deserialized.x25519_public_key.public_bytes_raw() == x25519_public.public_bytes_raw()
        # ML-KEM keys should match
        assert deserialized.mlkem_public_key == mlkem_public

    def test_private_key_serialize_deserialize(self):
        """Test that hybrid private keys can be serialized and deserialized."""
        from pqblocks_wire.hybrid import generate_hybrid_keypair
        from pqblocks_wire import generate_mlkem_keypair
        from cryptography.hazmat.primitives.asymmetric import x25519
        
        # Generate keys manually to have direct control
        x25519_private = x25519.X25519PrivateKey.generate()
        mlkem_public, mlkem_private = generate_mlkem_keypair("ML-KEM-768")
        
        hybrid_priv = HybridPrivateKey(
            x25519_private_key=x25519_private,
            mlkem_private_key=mlkem_private
        )
        
        # Serialize
        serialized = hybrid_priv.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 36  # 32 bytes X25519 + 4 bytes length + ML-KEM key
        
        # Deserialize
        deserialized = HybridPrivateKey.deserialize(serialized)
        # X25519 keys should match
        assert deserialized.x25519_private_key.private_bytes_raw() == x25519_private.private_bytes_raw()
        # ML-KEM keys should match
        assert deserialized.mlkem_private_key == mlkem_private

    def test_public_key_deserialize_invalid_data(self):
        """Test deserializing corrupted hybrid public key data."""
        # Too short data
        with pytest.raises(ValueError, match="Insufficient data"):
            HybridPublicKey.deserialize(b"")
        
        # Valid length but corrupted data
        fake_data = b"x" * 40  # 40 bytes but not properly formatted
        with pytest.raises((ValueError, Exception)):
            HybridPublicKey.deserialize(fake_data)

    def test_private_key_deserialize_invalid_data(self):
        """Test deserializing corrupted hybrid private key data."""
        # Too short data
        with pytest.raises(ValueError, match="Insufficient data"):
            HybridPrivateKey.deserialize(b"")
        
        # Valid length but corrupted data
        fake_data = b"x" * 40  # 40 bytes but not properly formatted
        with pytest.raises((ValueError, Exception)):
            HybridPrivateKey.deserialize(fake_data)

    def test_hybrid_test_basic_operations(self):
        """Test the hybrid_test_basic_operations function."""
        from pqblocks_wire.hybrid import hybrid_test_basic_operations
        # This should run without raising an exception
        hybrid_test_basic_operations()


class TestHybridErrorHandling:
    """Test error handling paths in hybrid module for coverage."""

    def test_hybrid_initiator_type_errors(self):
        """Test type validation in hybrid_key_exchange_initiator."""
        from pqblocks_wire.hybrid import hybrid_key_exchange_initiator
        from cryptography.hazmat.primitives.asymmetric import x25519
        from pqblocks_wire import generate_mlkem_keypair

        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, _ = generate_mlkem_keypair("ML-KEM-768")

        # Invalid x25519_private_key type
        with pytest.raises(TypeError, match="x25519_private_key must be X25519PrivateKey"):
            hybrid_key_exchange_initiator(
                x25519_private_key="invalid",
                x25519_public_key=x25519_public,
                mlkem_public_key=mlkem_public
            )

        # Invalid x25519_public_key type
        with pytest.raises(TypeError, match="x25519_public_key must be X25519PublicKey"):
            hybrid_key_exchange_initiator(
                x25519_private_key=x25519_private,
                x25519_public_key="invalid",
                mlkem_public_key=mlkem_public
            )

        # Invalid mlkem_public_key type
        with pytest.raises(TypeError, match="mlkem_public_key must be bytes"):
            hybrid_key_exchange_initiator(
                x25519_private_key=x25519_private,
                x25519_public_key=x25519_public,
                mlkem_public_key="invalid"
            )

    def test_hybrid_responder_type_errors(self):
        """Test type validation in hybrid_key_exchange_responder."""
        from pqblocks_wire.hybrid import hybrid_key_exchange_responder
        from cryptography.hazmat.primitives.asymmetric import x25519
        from pqblocks_wire import generate_mlkem_keypair

        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        _, mlkem_private = generate_mlkem_keypair("ML-KEM-768")

        # Invalid x25519_private_key type
        with pytest.raises(TypeError, match="x25519_private_key must be X25519PrivateKey"):
            hybrid_key_exchange_responder(
                x25519_private_key="invalid",
                x25519_public_key=x25519_public,
                mlkem_private_key=mlkem_private,
                mlkem_ciphertext=b"x" * 1088
            )

        # Invalid x25519_public_key type
        with pytest.raises(TypeError, match="x25519_public_key must be X25519PublicKey"):
            hybrid_key_exchange_responder(
                x25519_private_key=x25519_private,
                x25519_public_key="invalid",
                mlkem_private_key=mlkem_private,
                mlkem_ciphertext=b"x" * 1088
            )

        # Invalid mlkem_private_key type
        with pytest.raises(TypeError, match="mlkem_private_key must be bytes"):
            hybrid_key_exchange_responder(
                x25519_private_key=x25519_private,
                x25519_public_key=x25519_public,
                mlkem_private_key="invalid",
                mlkem_ciphertext=b"x" * 1088
            )

        # Invalid mlkem_ciphertext type
        with pytest.raises(TypeError, match="mlkem_ciphertext must be bytes"):
            hybrid_key_exchange_responder(
                x25519_private_key=x25519_private,
                x25519_public_key=x25519_public,
                mlkem_private_key=mlkem_private,
                mlkem_ciphertext="invalid"
            )

    def test_classical_fallback_type_errors(self):
        """Test type validation in classical_fallback."""
        from pqblocks_wire.hybrid import classical_fallback
        from cryptography.hazmat.primitives.asymmetric import x25519

        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()

        # Invalid private key type
        with pytest.raises(TypeError, match="x25519_private_key must be X25519PrivateKey"):
            classical_fallback(
                x25519_private_key="invalid",
                x25519_public_key=x25519_public
            )

        # Invalid public key type
        with pytest.raises(TypeError, match="x25519_public_key must be X25519PublicKey"):
            classical_fallback(
                x25519_private_key=x25519_private,
                x25519_public_key="invalid"
            )

    def test_hybrid_legacy_type_errors(self):
        """Test type validation in legacy hybrid_key_exchange."""
        from pqblocks_wire.hybrid import hybrid_key_exchange
        from cryptography.hazmat.primitives.asymmetric import x25519
        from pqblocks_wire import generate_mlkem_keypair

        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, mlkem_private = generate_mlkem_keypair("ML-KEM-768")

        # Invalid x25519_private_key type
        with pytest.raises(TypeError, match="x25519_private_key must be X25519PrivateKey"):
            hybrid_key_exchange(
                x25519_private_key="invalid",
                x25519_public_key=x25519_public,
                mlkem_public_key=mlkem_public,
                mlkem_private_key=mlkem_private
            )

        # Invalid x25519_public_key type
        with pytest.raises(TypeError, match="x25519_public_key must be X25519PublicKey"):
            hybrid_key_exchange(
                x25519_private_key=x25519_private,
                x25519_public_key="invalid",
                mlkem_public_key=mlkem_public,
                mlkem_private_key=mlkem_private
            )

        # Invalid mlkem_public_key type
        with pytest.raises(TypeError, match="mlkem_public_key must be bytes"):
            hybrid_key_exchange(
                x25519_private_key=x25519_private,
                x25519_public_key=x25519_public,
                mlkem_public_key="invalid",
                mlkem_private_key=mlkem_private
            )

        # Invalid mlkem_private_key type
        with pytest.raises(TypeError, match="mlkem_private_key must be bytes"):
            hybrid_key_exchange(
                x25519_private_key=x25519_private,
                x25519_public_key=x25519_public,
                mlkem_public_key=mlkem_public,
                mlkem_private_key="invalid"
            )

    def test_public_key_deserialize_edge_cases(self):
        """Test edge cases in HybridPublicKey.deserialize for coverage."""
        from pqblocks_wire.hybrid import HybridPublicKey
        from cryptography.hazmat.primitives.asymmetric import x25519
        from pqblocks_wire import generate_mlkem_keypair

        # Valid key for reference
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, _ = generate_mlkem_keypair("ML-KEM-768")
        valid_key = HybridPublicKey(x25519_public_key=x25519_public, mlkem_public_key=mlkem_public)
        serialized = valid_key.serialize()

        # Test exactly 36 bytes (just enough for header, no ML-KEM key)
        with pytest.raises(ValueError, match="Insufficient data for ML-KEM public key"):
            HybridPublicKey.deserialize(serialized[:36])

        # Test oversized ML-KEM length (more data than provided)
        bad_len = struct.pack('>I', 10000)  # 10000 bytes but we don't have that much
        bad_data = serialized[:32] + bad_len + serialized[36:60]
        with pytest.raises(ValueError, match="Insufficient data for ML-KEM public key"):
            HybridPublicKey.deserialize(bad_data)

    def test_private_key_deserialize_edge_cases(self):
        """Test edge cases in HybridPrivateKey.deserialize for coverage."""
        from pqblocks_wire.hybrid import HybridPrivateKey
        from cryptography.hazmat.primitives.asymmetric import x25519
        from pqblocks_wire import generate_mlkem_keypair

        # Valid key for reference
        x25519_private = x25519.X25519PrivateKey.generate()
        _, mlkem_private = generate_mlkem_keypair("ML-KEM-768")
        valid_key = HybridPrivateKey(x25519_private_key=x25519_private, mlkem_private_key=mlkem_private)
        serialized = valid_key.serialize()

        # Test exactly 36 bytes (just enough for header, no ML-KEM key)
        with pytest.raises(ValueError, match="Insufficient data for ML-KEM private key"):
            HybridPrivateKey.deserialize(serialized[:36])

        # Test oversized ML-KEM length
        bad_len = struct.pack('>I', 10000)
        bad_data = serialized[:32] + bad_len + serialized[36:60]
        with pytest.raises(ValueError, match="Insufficient data for ML-KEM private key"):
            HybridPrivateKey.deserialize(bad_data)

    def test_legacy_hybrid_key_exchange_path(self):
        """Test the legacy hybrid_key_exchange function for coverage of ML-KEM mismatch path."""
        from pqblocks_wire.hybrid import hybrid_key_exchange
        from cryptography.hazmat.primitives.asymmetric import x25519
        from pqblocks_wire import generate_mlkem_keypair

        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        mlkem_public, mlkem_private = generate_mlkem_keypair("ML-KEM-768")

        # This exercises the path where encapsulate_mlkem succeeds but we verify the decapsulation
        # The mismatch check on line 354-355 is hard to trigger without mocking
        # But we can at least exercise the basic path
        secret = hybrid_key_exchange(
            x25519_private_key=x25519_private,
            x25519_public_key=x25519_public,
            mlkem_public_key=mlkem_public,
            mlkem_private_key=mlkem_private
        )
        assert isinstance(secret, bytes)
        assert len(secret) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])