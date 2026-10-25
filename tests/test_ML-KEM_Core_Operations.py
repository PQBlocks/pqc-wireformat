#!/usr/bin/env python3
"""
Additional tests for ML-KEM Core Operations to improve coverage.
Focuses on KAT operations, error handling, and type validation.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from pqblocks_wire.mlkem import (
    MLKEMWrapper,
    KYBER_PY_AVAILABLE,
    generate_mlkem_keypair,
    encapsulate_mlkem,
    decapsulate_mlkem,
)
# encapsulate_kat_mlkem is only exposed at package level, use MLKEMWrapper.encapsulate_kat
from pqblocks_wire import encapsulate_kat_mlkem

# Test KAT operations when kyber-py is available
if KYBER_PY_AVAILABLE:
    def test_mlkem_kat_encapsulate_kat_512():
        """Test MLKEMWrapper.encapsulate_kat for ML-KEM-512."""
        # Skip if kyber-py not available
        if not KYBER_PY_AVAILABLE:
            pytest.skip("kyber-py not available")

        # Generate a keypair
        pk, sk = generate_mlkem_keypair("ML-KEM-512")
        
        # Create a deterministic mask
        m = bytes([i % 256 for i in range(32)])
        
        # Test encapsulate_kat
        ct, ss = MLKEMWrapper.encapsulate_kat(pk, "ML-KEM-512", m)
        assert isinstance(ct, bytes)
        assert len(ct) > 0
        assert isinstance(ss, bytes)
        assert len(ss) == 32
        
        # Verify by decapsulating
        ss_decapped = decapsulate_mlkem(sk, ct, "ML-KEM-512")
        assert ss == ss_decapped

    def test_mlkem_kat_encapsulate_kat_768():
        """Test MLKEMWrapper.encapsulate_kat for ML-KEM-768."""
        if not KYBER_PY_AVAILABLE:
            pytest.skip("kyber-py not available")

        pk, sk = generate_mlkem_keypair("ML-KEM-768")
        m = bytes([i % 256 for i in range(32)])
        
        ct, ss = MLKEMWrapper.encapsulate_kat(pk, "ML-KEM-768", m)
        assert isinstance(ct, bytes)
        assert len(ct) > 0
        assert isinstance(ss, bytes)
        assert len(ss) == 32
        
        ss_decapped = decapsulate_mlkem(sk, ct, "ML-KEM-768")
        assert ss == ss_decapped

    def test_mlkem_kat_encapsulate_kat_1024():
        """Test MLKEMWrapper.encapsulate_kat for ML-KEM-1024."""
        if not KYBER_PY_AVAILABLE:
            pytest.skip("kyber-py not available")

        pk, sk = generate_mlkem_keypair("ML-KEM-1024")
        m = bytes([i % 256 for i in range(32)])
        
        ct, ss = MLKEMWrapper.encapsulate_kat(pk, "ML-KEM-1024", m)
        assert isinstance(ct, bytes)
        assert len(ct) > 0
        assert isinstance(ss, bytes)
        assert len(ss) == 32
        
        ss_decapped = decapsulate_mlkem(sk, ct, "ML-KEM-1024")
        assert ss == ss_decapped

else:
    # Skip tests when kyber-py is not available
    def test_mlkem_kat_encapsulate_kat_512():
        pytest.skip("kyber-py not available")

    def test_mlkem_kat_encapsulate_kat_768():
        pytest.skip("kyber-py not available")

    def test_mlkem_kat_encapsulate_kat_1024():
        pytest.skip("kyber-py not available")

# Test error handling in MLKEMWrapper class methods
def test_mlkem_wrapper_keygen_type_error():
    """Test MLKEMWrapper.keygen raises TypeError for non-string parameter_set."""
    with pytest.raises(TypeError, match="parameter_set must be str"):
        MLKEMWrapper.keygen(123)

    with pytest.raises(TypeError, match="parameter_set must be str"):
        MLKEMWrapper.keygen(None)

def test_mlkem_wrapper_keygen_value_error():
    """Test MLKEMWrapper.keygen raises ValueError for unsupported parameter_set."""
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.keygen("INVALID-PARAM-SET")

    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.keygen("ML-KEM-512-INVALID")

def test_mlkem_wrapper_encapsulate_type_error():
    """Test MLKEMWrapper.encapsulate raises TypeError for invalid inputs."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    
    # Test non-bytes public_key
    with pytest.raises(TypeError, match="public_key must be bytes"):
        MLKEMWrapper.encapsulate("not bytes", "ML-KEM-512")
        
    # Test non-string parameter_set
    with pytest.raises(TypeError, match="parameter_set must be str"):
        MLKEMWrapper.encapsulate(pk, 123)

def test_mlkem_wrapper_encapsulate_value_error():
    """Test MLKEMWrapper.encapsulate raises ValueError for unsupported parameter_set."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.encapsulate(pk, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.encapsulate(pk, "")

def test_mlkem_wrapper_decapsulate_type_error():
    """Test MLKEMWrapper.decapsulate raises TypeError for invalid inputs."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    ct, _ = encapsulate_mlkem(pk, "ML-KEM-512")
    
    # Test non-bytes private_key
    with pytest.raises(TypeError, match="private_key must be bytes"):
        MLKEMWrapper.decapsulate("not bytes", ct, "ML-KEM-512")
        
    # Test non-bytes ciphertext
    with pytest.raises(TypeError, match="ciphertext must be bytes"):
        MLKEMWrapper.decapsulate(sk, "not bytes", "ML-KEM-512")
        
    # Test non-string parameter_set
    with pytest.raises(TypeError, match="parameter_set must be str"):
        MLKEMWrapper.decapsulate(sk, ct, 123)

def test_mlkem_wrapper_decapsulate_value_error():
    """Test MLKEMWrapper.decapsulate raises ValueError for unsupported parameter_set."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    ct, _ = encapsulate_mlkem(pk, "ML-KEM-512")
    
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.decapsulate(sk, ct, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.decapsulate(sk, ct, "")

# Test KAT-specific error handling
def test_mlkem_wrapper_encapsulate_kat_type_error():
    """Test MLKEMWrapper.encapsulate_kat raises TypeError for invalid inputs."""
    if not KYBER_PY_AVAILABLE:
        pytest.skip("kyber-py not available")

    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    m = bytes([1] * 32)
    
    # Test non-bytes public_key
    with pytest.raises(TypeError, match="public_key must be bytes"):
        MLKEMWrapper.encapsulate_kat("not bytes", "ML-KEM-512", m)
        
    # Test non-string parameter_set
    with pytest.raises(TypeError, match="parameter_set must be str"):
        MLKEMWrapper.encapsulate_kat(pk, 123, m)
        
    # Test non-bytes mask
    with pytest.raises(TypeError, match="m must be bytes"):
        MLKEMWrapper.encapsulate_kat(pk, "ML-KEM-512", "not bytes")

def test_mlkem_wrapper_encapsulate_kat_value_error():
    """Test MLKEMWrapper.encapsulate_kat raises ValueError for unsupported parameter_set."""
    if not KYBER_PY_AVAILABLE:
        pytest.skip("kyber-py not available")

    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    m = bytes([1] * 32)
    
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.encapsulate_kat(pk, "INVALID-PARAM-SET", m)
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        MLKEMWrapper.encapsulate_kat(pk, "", m)

# Test the module-level functions
def test_generate_mlkem_keypair_type_error():
    """Test generate_mlkem_keypair raises TypeError for non-string parameter_set."""
    with pytest.raises(TypeError, match="parameter_set must be str"):
        generate_mlkem_keypair(123)
        
    with pytest.raises(TypeError, match="parameter_set must be str"):
        generate_mlkem_keypair(None)

def test_generate_mlkem_keypair_value_error():
    """Test generate_mlkem_keypair raises TypeError for unsupported parameter_set."""
    with pytest.raises(TypeError, match="Unsupported parameter set"):
        generate_mlkem_keypair("INVALID-PARAM-SET")

def test_encapsulate_mlkem_type_error():
    """Test encapsulate_mlkem raises TypeError for invalid inputs."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    
    # Test non-bytes public_key
    with pytest.raises(TypeError, match="public_key must be bytes"):
        encapsulate_mlkem("not bytes", "ML-KEM-512")
        
    # Test non-string parameter_set
    with pytest.raises(TypeError, match="parameter_set must be str"):
        encapsulate_mlkem(pk, 123)

def test_encapsulate_mlkem_value_error():
    """Test encapsulate_mlkem raises ValueError for unsupported parameter_set."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        encapsulate_mlkem(pk, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        encapsulate_mlkem(pk, "")

def test_decapsulate_mlkem_type_error():
    """Test decapsulate_mlkem raises TypeError for invalid inputs."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    ct, _ = encapsulate_mlkem(pk, "ML-KEM-512")
    
    # Test non-bytes private_key
    with pytest.raises(TypeError, match="private_key must be bytes"):
        decapsulate_mlkem("not bytes", ct, "ML-KEM-512")
        
    # Test non-bytes ciphertext
    with pytest.raises(TypeError, match="ciphertext must be bytes"):
        decapsulate_mlkem(sk, "not bytes", "ML-KEM-512")
        
    # Test non-string parameter_set
    with pytest.raises(TypeError, match="parameter_set must be str"):
        decapsulate_mlkem(sk, ct, 123)

def test_decapsulate_mlkem_value_error():
    """Test decapsulate_mlkem raises ValueError for unsupported parameter_set."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    ct, _ = encapsulate_mlkem(pk, "ML-KEM-512")
    
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        decapsulate_mlkem(sk, ct, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        decapsulate_mlkem(sk, ct, "")

# Test determinism of KAT operations
def test_mlkem_kat_deterministic():
    """Test that KAT operations are deterministic with fixed inputs."""
    if not KYBER_PY_AVAILABLE:
        pytest.skip("kyber-py not available")\

    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    mask = bytes([1] * 32)  # Fixed mask

    # Perform KAT operation twice with same inputs
    ct1, ss1 = MLKEMWrapper.encapsulate_kat(pk, "ML-KEM-512", mask)
    ct2, ss2 = MLKEMWrapper.encapsulate_kat(pk, "ML-KEM-512", mask)

    # Should be identical (deterministic)
    assert ct1 == ct2
    assert ss1 == ss2

# Test that mlkem_test_all_operations runs without error
def test_mlkem_test_all_operations_runs():
    """Test that mlkem_test_all_operations executes without raising exception."""
    MLKEMWrapper.mlkem_test_all_operations()
    # Also test the module-level function
    from pqblocks_wire.mlkem import mlkem_test_all_operations
    mlkem_test_all_operations()

# NEW TESTS FOR COVERAGE GAPS - Error handling for module-level functions
# Note: MLKEMWrapper in pqblocks_wire.mlkem doesn't have length_* helpers.
# These tests cover error handling paths in module-level functions instead.

def test_generate_mlkem_keypair_type_error():
    """Test generate_mlkem_keypair raises TypeError for non-string parameter_set."""
    with pytest.raises(TypeError, match="parameter_set must be str"):
        generate_mlkem_keypair(123)

        
    with pytest.raises(TypeError, match="parameter_set must be str"):
        generate_mlkem_keypair(None)


def test_generate_mlkem_keypair_value_error():
    """Test generate_mlkem_keypair raises ValueError for unsupported parameter_set."""
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        generate_mlkem_keypair("INVALID-PARAM-SET")

        
def test_encapsulate_mlkem_type_error():
    """Test encapsulate_mlkem raises TypeError for invalid inputs."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    
    # Test non-bytes public_key
    with pytest.raises(TypeError, match="public_key must be bytes"):
        encapsulate_mlkem("not bytes", "ML-KEM-512")

        
    # Test non-string parameter_set
    with pytest.raises(TypeError, match="parameter_set must be str"):
        encapsulate_mlkem(pk, 123)


def test_encapsulate_mlkem_value_error():
    """Test encapsulate_mlkem raises ValueError for unsupported parameter_set."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        encapsulate_mlkem(pk, "INVALID-PARAM-SET")

        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        encapsulate_mlkem(pk, "")


def test_decapsulate_mlkem_type_error():
    """Test decapsulate_mlkem raises TypeError for invalid inputs."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    ct, _ = encapsulate_mlkem(pk, "ML-KEM-512")
    
    # Test non-bytes private_key
    with pytest.raises(TypeError, match="private_key must be bytes"):
        decapsulate_mlkem("not bytes", ct, "ML-KEM-512")

        
    # Test non-bytes ciphertext
    with pytest.raises(TypeError, match="ciphertext must be bytes"):
        decapsulate_mlkem(sk, "not bytes", "ML-KEM-512")

        
    # Test non-string parameter_set
    with pytest.raises(TypeError, match="parameter_set must be str"):
        decapsulate_mlkem(sk, ct, 123)


def test_decapsulate_mlkem_value_error():
    """Test decapsulate_mlkem raises ValueError for unsupported parameter_set."""
    pk, sk = generate_mlkem_keypair("ML-KEM-512")
    ct, _ = encapsulate_mlkem(pk, "ML-KEM-512")
    
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        decapsulate_mlkem(sk, ct, "INVALID-PARAM-SET")

        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        decapsulate_mlkem(sk, ct, "")


# Tests for missing lines in repository root src/mlkem.py - lines 9-11, 20,30,40,50,59,68,77,87,97,133,148,153-200,212,227,231

def test_lane_root_mlkem_import():
    """Test that repository root mlkem.py can be imported."""
    try:
        from pqblocks_wire import lane_root_mlkem as mlkem
        assert mlkem is not None
        assert hasattr(mlkem, 'generate_mlkem_keypair')
        assert hasattr(mlkem, 'encapsulate_mlkem')
        assert hasattr(mlkem, 'decapsulate_mlkem')
        print("✅ Lane root mlkem.py imported successfully")
    except ImportError as e:
        raise AssertionError(f"Failed to import the duplicate mlkem module: {e}")

def test_lane_root_mlkem_512_operations():
    """Test ML-KEM-512 operations using repository root implementation."""
    from pqblocks_wire import lane_root_mlkem as mlkem
    
    # Test key generation
    pk, sk = mlkem.generate_mlkem_keypair("ML-KEM-512")
    assert isinstance(pk, bytes) and len(pk) > 0
    assert isinstance(sk, bytes) and len(sk) > 0
    
    # Test encapsulation
    ct, ss = mlkem.encapsulate_mlkem(pk, "ML-KEM-512")
    assert isinstance(ct, bytes) and len(ct) > 0
    assert isinstance(ss, bytes) and len(ss) > 0
    
    # Test decapsulation
    ss_decapped = mlkem.decapsulate_mlkem(sk, ct, "ML-KEM-512")
    assert ss == ss_decapped, "Shared secrets should match"
    
    print("✅ Lane root ML-KEM-512 operations successful")

def test_lane_root_mlkem_768_operations():
    """Test ML-KEM-768 operations using repository root implementation."""
    from pqblocks_wire import lane_root_mlkem as mlkem
    
    # Test key generation
    pk, sk = mlkem.generate_mlkem_keypair("ML-KEM-768")
    assert isinstance(pk, bytes) and len(pk) > 0
    assert isinstance(sk, bytes) and len(sk) > 0
    
    # Test encapsulation
    ct, ss = mlkem.encapsulate_mlkem(pk, "ML-KEM-768")
    assert isinstance(ct, bytes) and len(ct) > 0
    assert isinstance(ss, bytes) and len(ss) > 0
    
    # Test decapsulation
    ss_decapped = mlkem.decapsulate_mlkem(sk, ct, "ML-KEM-768")
    assert ss == ss_decapped, "Shared secrets should match"
    
    print("✅ Lane root ML-KEM-768 operations successful")

def test_lane_root_mlkem_1024_operations():
    """Test ML-KEM-1024 operations using repository root implementation."""
    from pqblocks_wire import lane_root_mlkem as mlkem
    
    # Test key generation
    pk, sk = mlkem.generate_mlkem_keypair("ML-KEM-1024")
    assert isinstance(pk, bytes) and len(pk) > 0
    assert isinstance(sk, bytes) and len(sk) > 0
    
    # Test encapsulation
    ct, ss = mlkem.encapsulate_mlkem(pk, "ML-KEM-1024")
    assert isinstance(ct, bytes) and len(ct) > 0
    assert isinstance(ss, bytes) and len(ss) > 0
    
    # Test decapsulation
    ss_decapped = mlkem.decapsulate_mlkem(sk, ct, "ML-KEM-1024")
    assert ss == ss_decapped, "Shared secrets should match"
    
    print("✅ Lane root ML-KEM-1024 operations successful")

def test_lane_root_mlkem_liboqs_unavailable():
    """Test repository root mlkem when LIBOQS is unavailable - covers lines 9-11, 20,30,40,50,59,68,77,87,97."""
    from pqblocks_wire import lane_root_mlkem as mlkem
    
    # Mock LIBOQS_AVAILABLE to False
    from unittest.mock import patch
    with patch('pqblocks_wire.lane_root_mlkem.LIBOQS_AVAILABLE', False):
        # Test that import error path is covered (lines 9-11)
        # The warning print should happen on import, but we test the functions
        
        # Test keygen functions raise ImportError when LIBOQS unavailable (lines 20,30,40,50,59,68,77,87,97)
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
            mlkem.generate_mlkem_keypair("ML-KEM-512")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
            mlkem.generate_mlkem_keypair("ML-KEM-768")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
            mlkem.generate_mlkem_keypair("ML-KEM-1024")
            
        # Test encapsulate functions raise ImportError when LIBOQS unavailable
        pk, sk = b"dummy_public_key", b"dummy_private_key"  # Dummy values won't be used due to early ImportError
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
            mlkem.encapsulate_mlkem(pk, "ML-KEM-512")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
            mlkem.encapsulate_mlkem(pk, "ML-KEM-768")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
            mlkem.encapsulate_mlkem(pk, "ML-KEM-1024")
            
        # Test decapsulate functions raise ImportError when LIBOQS unavailable
        ct = b"dummy_ciphertext"
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
            mlkem.decapsulate_mlkem(sk, ct, "ML-KEM-512")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
            mlkem.decapsulate_mlkem(sk, ct, "ML-KEM-768")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
            mlkem.decapsulate_mlkem(sk, ct, "ML-KEM-1024")
        
        print("✅ Lane root ML-KEM LIBOQS unavailable error paths tested")

def test_lane_root_mlkem_value_error_unsupported_params():
    """Test repository root mlkem ValueError for unsupported parameter sets - covers lines 133,148,212,227,231."""
    from pqblocks_wire import lane_root_mlkem as mlkem
    
    # Test encapsulate_mlkem with invalid parameter set (lines 133, 212)
    pk, sk = mlkem.generate_mlkem_keypair("ML-KEM-512")  # Valid keypair for testing
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem.encapsulate_mlkem(pk, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem.encapsulate_mlkem(pk, "")
        
    # Test decapsulate_mlkem with invalid parameter set (lines 148, 227)
    ct, ss = mlkem.encapsulate_mlkem(pk, "ML-KEM-512")
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem.decapsulate_mlkem(sk, ct, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem.decapsulate_mlkem(sk, ct, "")
        
    # Test generate_mlkem_keypair with invalid parameter set (line 231)
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem.generate_mlkem_keypair("INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem.generate_mlkem_keypair("")
        
    print("✅ Lane root ML-KEM unsupported parameter ValueError paths tested")

def test_lane_root_mlkem_test_all_operations():
    """Test repository root mlkem_test_all_operations when LIBOQS available - covers lines 153-200."""
    from pqblocks_wire import lane_root_mlkem as mlkem
    
    # Test that mlkem_test_all_operations runs when LIBOQS is available (lines 153-200)
    # This should execute the happy path for all three parameter sets
    mlkem.mlkem_test_all_operations()
    
    print("✅ Lane root ML-KEM test_all_operations executed successfully")

if __name__ == "__main__":
    # Allow running directly for development/testing
    pytest.main([__file__, "-v"])