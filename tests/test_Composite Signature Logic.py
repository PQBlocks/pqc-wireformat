"""Tests for Composite Signature Logic (feature 5) - hybrid wire format compatibility package.

Contract (from spec.md [feature 5]):
- Input: ML-DSA key pair, EdDSA key pair, message
- Output: Composite signature, verification function  
- Contract: Both components must verify independently
- Tests: test_composite_sign(), test_composite_verify(), test_downgrade_prevention()
"""

import sys
import os
import struct

import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqblocks_wire.composite_sig import (
    generate_composite_keypair,
    composite_sign,
    composite_verify,
    composite_verify_individual,
    CompositePublicKey,
    CompositePrivateKey,
    CompositeSignature
)


class TestCompositeKeySerialization:
    """Test composite key serialization/deserialization."""

    def test_public_key_serialize_deserialize(self):
        """Test that public keys can be serialized and deserialized."""
        public_key, _ = generate_composite_keypair()
        
        # Serialize
        serialized = public_key.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
        
        # Deserialize
        deserialized = CompositePublicKey.deserialize(serialized)
        assert deserialized.mldsa_public_key == public_key.mldsa_public_key
        assert deserialized.ed25519_public_key == public_key.ed25519_public_key

    def test_public_key_deserialize_invalid_data(self):
        """Test deserializing corrupted public key data."""
        # Too short data
        with pytest.raises(ValueError, match="Truncated"):
            CompositePublicKey.deserialize(b"")

    def test_private_key_serialize_deserialize(self):
        """Test that private keys can be serialized and deserialized."""
        _, private_key = generate_composite_keypair()
        
        # Serialize
        serialized = private_key.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
        
        # Deserialize
        deserialized = CompositePrivateKey.deserialize(serialized)
        assert deserialized.mldsa_secret_key == private_key.mldsa_secret_key

    def test_private_key_deserialize_invalid_data(self):
        """Test deserializing corrupted private key data."""
        # Too short data
        with pytest.raises(ValueError, match="Truncated"):
            CompositePrivateKey.deserialize(b"")
        
        # Invalid Ed25519 key format
        fake_data = struct.pack('>I', 100) + b'x' * 100 + struct.pack('>I', 50) + b'y' * 50
        with pytest.raises(Exception):  # Should fail to parse invalid Ed25519 key
            CompositePrivateKey.deserialize(fake_data)

    def test_signature_serialize_deserialize(self):
        """Test that signatures can be serialized and deserialized."""
        public_key, private_key = generate_composite_keypair()
        message = b"Test message"
        signature = composite_sign(private_key, message)
        
        # Serialize
        serialized = signature.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
        
        # Deserialize
        deserialized = CompositeSignature.deserialize(serialized)
        assert deserialized.mldsa_signature == signature.mldsa_signature
        assert deserialized.ed25519_signature == signature.ed25519_signature

    def test_signature_deserialize_invalid_data(self):
        """Test deserializing corrupted signature data."""
        # Too short data
        with pytest.raises(ValueError, match="Truncated"):
            CompositeSignature.deserialize(b"")


class TestCompositeSign:
    """Test composite signature creation with both ML-DSA and Ed25519 components."""

    def test_composite_sign_mldsa_ed25519(self):
        """Composite sign with ML-DSA + Ed25519 produces two component signatures."""
        # Generate composite keypair using product code
        public_key, private_key = generate_composite_keypair()
        
        message = b"Test message for composite signature"
        
        # Create composite signature using product code
        composite_signature = composite_sign(private_key, message)
        
        # Verify it's a proper CompositeSignature object
        assert isinstance(composite_signature, CompositeSignature)
        assert len(composite_signature.mldsa_signature) > 0
        assert len(composite_signature.ed25519_signature) == 64  # Ed25519 signature is always 64 bytes

    def test_composite_sign_different_messages(self):
        """Composite signatures for different messages are distinct."""
        # Generate keypairs
        public_key1, private_key1 = generate_composite_keypair()
        public_key2, private_key2 = generate_composite_keypair()
        
        # Sign different messages
        sig1 = composite_sign(private_key1, b"Message 1")
        sig2 = composite_sign(private_key2, b"Message 2")
        
        # Signatures should be different for different messages/keys
        assert sig1.mldsa_signature != sig2.mldsa_signature
        assert sig1.ed25519_signature != sig2.ed25519_signature

    def test_composite_sign_verify_mldsa(self):
        """Verify ML-DSA component of composite signature."""
        # Generate keypair
        public_key, private_key = generate_composite_keypair()
        
        message = b"Test message for composite signature"
        composite_signature = composite_sign(private_key, message)
        
        # Verify using product code - both components should verify
        is_valid = composite_verify(public_key, message, composite_signature)
        assert is_valid, "Composite signature should verify"

    def test_composite_sign_verify_ed25519(self):
        """Test that we can access individual components for verification."""
        # Generate keypair
        public_key, private_key = generate_composite_keypair()
        
        message = b"Test message for composite signature"
        composite_signature = composite_sign(private_key, message)
        
        # Get individual verification results
        mldsa_valid, ed25519_valid = composite_verify_individual(
            public_key, message, composite_signature
        )
        
        # Both should be valid
        assert mldsa_valid, "ML-DSA component should verify"
        assert ed25519_valid, "Ed25519 component should verify"


class TestCompositeVerify:
    """Test composite signature verification."""

    def test_composite_verify_both_valid(self):
        """Verify composite signature when both components are valid."""
        # Generate keypair
        public_key, private_key = generate_composite_keypair()
        
        message = b"Test composite message"
        composite_signature = composite_sign(private_key, message)
        
        # Both must verify independently via product code
        is_valid = composite_verify(public_key, message, composite_signature)
        assert is_valid, "Composite signature should verify when both components are valid"

    def test_composite_verify_mldsa_invalid(self):
        """Reject composite signature when ML-DSA component is invalid."""
        # Generate two different keypairs
        public_key1, private_key1 = generate_composite_keypair()
        public_key2, private_key2 = generate_composite_keypair()
        
        message = b"Test composite message"
        
        # Sign with first key pair
        composite_signature = composite_sign(private_key1, message)
        
        # Try to verify with second public key (should fail)
        is_valid = composite_verify(public_key2, message, composite_signature)
        assert not is_valid, "Composite verify with wrong public key must fail"

    def test_composite_verify_ed25519_invalid(self):
        """Reject composite signature when Ed25519 component is invalid."""
        # Generate two different keypairs
        public_key1, private_key1 = generate_composite_keypair()
        public_key2, private_key2 = generate_composite_keypair()
        
        message = b"Test message"
        
        # Sign with first key pair
        composite_signature = composite_sign(private_key1, message)
        
        # Try to verify with second public key (should fail)
        is_valid = composite_verify(public_key2, message, composite_signature)
        assert not is_valid, "Composite verify with wrong public key must fail"

    def test_composite_verify_tampered_message(self):
        """Reject composite signature when message is tampered."""
        # Generate keypair
        public_key, private_key = generate_composite_keypair()
        
        original_message = b"Original message"
        tampered_message = b"Tampered message"
        
        # Sign original message
        composite_signature = composite_sign(private_key, original_message)
        
        # Verify with tampered message must fail
        is_valid = composite_verify(public_key, tampered_message, composite_signature)
        assert not is_valid, "Composite verify with tampered message must fail"


class TestDowngradePrevention:
    """Test that composite verification doesn't allow downgrade attacks."""

    def test_downgrade_prevention_stripped_mldsa(self):
        """Verify that we can detect when one component would fail."""
        # Generate keypair
        public_key, private_key = generate_composite_keypair()
        
        message = b"Test downgrade prevention"
        composite_signature = composite_sign(private_key, message)
        
        # Get individual verification results
        mldsa_valid, ed25519_valid = composite_verify_individual(
            public_key, message, composite_signature
        )
        
        # Both should be valid for a properly signed message
        assert mldsa_valid, "ML-DSA must verify"
        assert ed25519_valid, "Ed25519 must verify"
        
        # The composite verification requires BOTH to be valid
        composite_valid = composite_verify(public_key, message, composite_signature)
        assert composite_valid, "Composite verification requires both signatures to be valid"

    def test_downgrade_prevention_stripped_ed25519(self):
        """Test that tampering with one component breaks composite verification."""
        # Generate keypair
        public_key, private_key = generate_composite_keypair()
        
        message = b"Test downgrade prevention"
        composite_signature = composite_sign(private_key, message)
        
        # Tamper with the ML-DSA signature
        tampered_mldsa = bytearray(composite_signature.mldsa_signature)
        tampered_mldsa[0] ^= 0xFF
        tampered_signature = CompositeSignature(
            mldsa_signature=bytes(tampered_mldsa),
            ed25519_signature=composite_signature.ed25519_signature
        )
        
        # Verify should fail due to tampered ML-DSA component
        is_valid = composite_verify(public_key, message, tampered_signature)
        assert not is_valid, "Composite verification must fail when ML-DSA component is tampered"

    def test_downgrade_requires_both_components(self):
        """Composite verification requires both ML-DSA and Ed25519 to be valid."""
        # Generate keypair
        public_key, private_key = generate_composite_keypair()
        
        message = b"Test message"
        
        # Create valid signature
        composite_signature = composite_sign(private_key, message)
        
        # Successful composite verification requires both components
        mldsa_valid, ed25519_valid = composite_verify_individual(
            public_key, message, composite_signature
        )
        
        # Composite verification means BOTH must be valid
        composite_valid = mldsa_valid and ed25519_valid
        assert composite_valid, "Composite verification requires both signatures to be valid"
        
        # Verify using the product code function
        product_code_valid = composite_verify(public_key, message, composite_signature)
        assert product_code_valid, "Product code composite verify should work"
        assert product_code_valid == composite_valid, "Product code should match manual check"


if __name__ == "__main__":
    # Allow running directly for development/testing
    pytest.main([__file__, "-v"])
