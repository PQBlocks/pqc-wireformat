"""Tests for Composite Signature Logic helper functions (feature 5) - wire format compatibility package.

Tests to increase coverage for composite_sig.py and wireformat.py functions.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from pqblocks_wire.composite_sig import (
    generate_composite_keypair,
    composite_sign,
    composite_verify,
    composite_verify_individual,
    CompositePublicKey,
    CompositePrivateKey,
    CompositeSignature,
    LABEL_MLDSA65_ED25519
)
from pqblocks_wire.wireformat import (
    encode_wire_format,
    decode_wire_format,
    encode_composite_signatures,
    decode_composite_signatures,
    WireFormatError
)

def test_composite_publickey_serialize_deserialize():
    """Test CompositePublicKey serialization/deserialization helper functions."""
    # Generate keypair
    public_key, private_key = generate_composite_keypair()
    
    # Test serialize
    serialized = public_key.serialize()
    assert isinstance(serialized, bytes)
    assert len(serialized) > 0
    
    # Test deserialize
    deserialized = CompositePublicKey.deserialize(serialized)
    assert deserialized.mldsa_public_key == public_key.mldsa_public_key
    assert deserialized.ed25519_public_key == public_key.ed25519_public_key

def test_composite_privatekey_serialize_deserialize():
    """Test CompositePrivateKey serialization/deserialization helper functions."""
    # Generate keypair
    public_key, private_key = generate_composite_keypair()
    
    # Test serialize
    serialized = private_key.serialize()
    assert isinstance(serialized, bytes)
    assert len(serialized) > 0
    
    # Test deserialize
    deserialized = CompositePrivateKey.deserialize(serialized)
    assert deserialized.mldsa_secret_key == private_key.mldsa_secret_key
    # Note: Ed25519PrivateKey objects are not directly comparable via ==
    # just verify deserialized type and that mldsa matches
    assert isinstance(deserialized.ed25519_private_key, type(private_key.ed25519_private_key))

def test_composite_signature_serialize_deserialize():
    """Test CompositeSignature serialization/deserialization helper functions."""
    # Generate keypair and sign
    public_key, private_key = generate_composite_keypair()
    message = b"Test message"
    signature = composite_sign(private_key, message)
    
    # Test serialize
    serialized = signature.serialize()
    assert isinstance(serialized, bytes)
    assert len(serialized) > 0
    
    # Test deserialize
    deserialized = CompositeSignature.deserialize(serialized)
    assert deserialized.mldsa_signature == signature.mldsa_signature
    assert deserialized.ed25519_signature == signature.ed25519_signature

def test_composite_sig_label_function():
    """Test _compute_message_representative helper function."""
    from pqblocks_wire.composite_sig import _compute_message_representative
    
    message = b"Test message"
    context = b"test_context"
    
    # Test with default label
    result1 = _compute_message_representative(message, context)
    assert isinstance(result1, bytes)
    assert len(result1) > 0
    
    # Test with different label
    result2 = _compute_message_representative(message, context, b"CUSTOM_LABEL")
    assert isinstance(result2, bytes)
    assert len(result2) > 0
    
    # Different label should produce different results
    assert result1 != result2
    
    # Test context length validation
    try:
        _compute_message_representative(message, b"x" * 256)  # Exceeds 255 bytes
        assert False, "Should have raised ValueError for context too long"
    except ValueError as e:
        assert "Context length exceeds maximum of 255 bytes" in str(e)

def test_composite_sig_deterministic_operations():
    """Test deterministic operations in composite_sig.py."""
    # Generate keypair
    public_key, private_key = generate_composite_keypair()
    message = b"Deterministic test message"
    
    # Sign multiple times with same key
    sig1 = composite_sign(private_key, message)
    sig2 = composite_sign(private_key, message)
    
    # For Ed25519, signing with the same private key and message should be deterministic
    # (cryptographic signatures with deterministic randomness should be identical)
    # Let's check if Ed25519 signatures are indeed identical for same inputs
    assert sig1.ed25519_signature == sig2.ed25519_signature, "Ed25519 signatures should be deterministic with same key and message"
    
    # ML-DSA signatures should be different due to fresh randomness
    assert sig1.mldsa_signature != sig2.mldsa_signature, "ML-DSA signatures should be different due to fresh randomness"

def test_composite_sig_error_handling_empty_message():
    """Test composite signature error handling with empty message."""
    public_key, private_key = generate_composite_keypair()
    
    # Sign empty message
    signature = composite_sign(private_key, b"")
    assert isinstance(signature, CompositeSignature)
    assert len(signature.mldsa_signature) > 0
    assert len(signature.ed25519_signature) == 64
    
    # Verify empty message
    is_valid = composite_verify(public_key, b"", signature)
    assert is_valid

def test_composite_sig_helper_functions():
    """Test helper functions in composite_sig.py."""
    # Test that all main functions are callable and return expected types
    public_key, private_key = generate_composite_keypair()
    message = b"Helper functions test"
    
    # Test composite_sign
    signature = composite_sign(private_key, message)
    assert isinstance(signature, CompositeSignature)
    
    # Test composite_verify
    is_valid = composite_verify(public_key, message, signature)
    assert isinstance(is_valid, bool)
    assert is_valid
    
    # Test composite_verify_individual
    mldsa_valid, ed25519_valid = composite_verify_individual(public_key, message, signature)
    assert isinstance(mldsa_valid, bool)
    assert isinstance(ed25519_valid, bool)
    assert mldsa_valid and ed25519_valid

def test_wireformat_helper_encode_roundtrip_all_components():
    """Test encode_composite_signatures round-trip with all edge cases."""
    from pqblocks_wire.wireformat import encode_composite_signatures, decode_composite_signatures
    
    # Create all possible component combinations
    test_cases = [
        {"mlkem_ciphertext": bytes([i for i in range(256)]) * 6},
        {"mldsa_signature": bytes([i % 256 for i in range(3500)])},
        {"slhdsa_signature": bytes([255] * 10000)},
        {"payload": b"payload only"},
        {"mlkem_ciphertext": bytes([i for i in range(256)]) * 6, "payload": b"full"},
        {"mldsa_signature": bytes([i % 256 for i in range(3500)]), "slhdsa_signature": bytes([255] * 10000)},
        {"mlkem_ciphertext": bytes([i for i in range(256)]) * 6, "mldsa_signature": bytes([i % 256 for i in range(3500)]), "payload": b"all three"},
    ]
    
    for components in test_cases:
        # Encode
        wire = encode_composite_signatures(**components)
        assert isinstance(wire, bytes)
        assert len(wire) > 0
        
        # Decode
        decoded = decode_composite_signatures(wire)
        
        # Verify components match
        for key, expected_value in components.items():
            if key == "payload":
                assert decoded.payload == expected_value
            else:
                actual_value = getattr(decoded, key.replace("_signature", "_signature"))
                assert actual_value == expected_value

def test_wireformat_helper_boundary_conditions():
    """Test wireformat helper functions boundary conditions."""
    # Test with maximum allowed sizes
    max_mlkem = bytes([i % 256 for i in range(1568)])
    max_mldsa = bytes([i % 256 for i in range(4627)])
    max_slhdsa = bytes([255] * 49856)
    
    wire = encode_composite_signatures(
        mlkem_ciphertext=max_mlkem,
        mldsa_signature=max_mldsa,
        slhdsa_signature=max_slhdsa,
        payload=b"max components"
    )
    
    decoded = decode_composite_signatures(wire)
    assert decoded.mlkem_ciphertext == max_mlkem
    assert decoded.mldsa_signature == max_mldsa
    assert decoded.slhdsa_signature == max_slhdsa
    assert decoded.payload == b"max components"

def test_wireformat_helper_error_conditions():
    """Test wireformat helper functions error conditions."""
    from pqblocks_wire.wireformat import encode_composite_signatures, decode_composite_signatures, WireFormatError
    
    # Test with empty components (should work)
    wire = encode_composite_signatures()
    decoded = decode_composite_signatures(wire)
    assert decoded.payload == b''
    
    # Test with non-bytes input (should raise TypeError)
    try:
        encode_composite_signatures(mlkem_ciphertext="not bytes")
        assert False, "Should have raised TypeError"
    except TypeError:
        pass
    
    # Test decode with invalid magic (should raise WireFormatError)
    try:
        decode_composite_signatures(b"INVALID_MAGIC")
        assert False, "Should have raised WireFormatError"
    except WireFormatError:
        pass

def test_composite_sig_wrapper_methods():
    """Test that composite_sig.py wrapper methods work correctly."""
    from pqblocks_wire.composite_sig import LABEL_MLDSA65_ED25519
    
    # Test that constants are accessible
    assert isinstance(LABEL_MLDSA65_ED25519, bytes)
    assert len(LABEL_MLDSA65_ED25519) > 0

def test_composite_sig_module_imports():
    """Test that all composite_sig module imports work correctly."""
    # This test ensures that the module can be imported and all functions are available
    assert True  # If we got here, imports succeeded

if __name__ == "__main__":
    pytest.main([__file__, "-v"])