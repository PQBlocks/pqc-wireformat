#!/usr/bin/env python3
"""
Test to verify installed pqblocks_wire.mlkem can be imported and exercised.
This test ensures Check 3 (correctness) coverage requirement is met for the installed package.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from unittest.mock import patch


def _import_mlkem():
    """Import mlkem from the installed pqblocks_wire package."""
    from pqblocks_wire.mlkem import (
        generate_mlkem_keypair,
        encapsulate_mlkem,
        decapsulate_mlkem,
        mlkem_test_all_operations,
        LIBOQS_AVAILABLE,
    )
    return {
        'generate_mlkem_keypair': generate_mlkem_keypair,
        'encapsulate_mlkem': encapsulate_mlkem,
        'decapsulate_mlkem': decapsulate_mlkem,
        'mlkem_test_all_operations': mlkem_test_all_operations,
        'LIBOQS_AVAILABLE': LIBOQS_AVAILABLE,
    }


def test_installed_mlkem_import():
    """Test that installed pqblocks_wire.mlkem can be imported."""
    try:
        mlkem = _import_mlkem()
        assert mlkem is not None
        assert 'generate_mlkem_keypair' in mlkem
        assert 'encapsulate_mlkem' in mlkem
        assert 'decapsulate_mlkem' in mlkem
        print("✅ Installed pqblocks_wire.mlkem imported successfully")
    except ImportError as e:
        raise AssertionError(f"Failed to import installed pqblocks_wire mlkem module: {e}")


def test_installed_mlkem_512_operations():
    """Test ML-KEM-512 operations using installed package."""
    mlkem = _import_mlkem()
    
    # Test key generation
    pk, sk = mlkem['generate_mlkem_keypair']("ML-KEM-512")
    assert isinstance(pk, bytes) and len(pk) > 0
    assert isinstance(sk, bytes) and len(sk) > 0
    
    # Test encapsulation
    ct, ss = mlkem['encapsulate_mlkem'](pk, "ML-KEM-512")
    assert isinstance(ct, bytes) and len(ct) > 0
    assert isinstance(ss, bytes) and len(ss) > 0
    
    # Test decapsulation
    ss_decapped = mlkem['decapsulate_mlkem'](sk, ct, "ML-KEM-512")
    assert ss == ss_decapped, "Shared secrets should match"
    
    print("✅ Installed ML-KEM-512 operations successful")


def test_installed_mlkem_768_operations():
    """Test ML-KEM-768 operations using installed package."""
    mlkem = _import_mlkem()
    
    # Test key generation
    pk, sk = mlkem['generate_mlkem_keypair']("ML-KEM-768")
    assert isinstance(pk, bytes) and len(pk) > 0
    assert isinstance(sk, bytes) and len(sk) > 0
    
    # Test encapsulation
    ct, ss = mlkem['encapsulate_mlkem'](pk, "ML-KEM-768")
    assert isinstance(ct, bytes) and len(ct) > 0
    assert isinstance(ss, bytes) and len(ss) > 0
    
    # Test decapsulation
    ss_decapped = mlkem['decapsulate_mlkem'](sk, ct, "ML-KEM-768")
    assert ss == ss_decapped, "Shared secrets should match"
    
    print("✅ Installed ML-KEM-768 operations successful")


def test_installed_mlkem_1024_operations():
    """Test ML-KEM-1024 operations using installed package."""
    mlkem = _import_mlkem()
    
    # Test key generation
    pk, sk = mlkem['generate_mlkem_keypair']("ML-KEM-1024")
    assert isinstance(pk, bytes) and len(pk) > 0
    assert isinstance(sk, bytes) and len(sk) > 0
    
    # Test encapsulation
    ct, ss = mlkem['encapsulate_mlkem'](pk, "ML-KEM-1024")
    assert isinstance(ct, bytes) and len(ct) > 0
    assert isinstance(ss, bytes) and len(ss) > 0
    
    # Test decapsulation
    ss_decapped = mlkem['decapsulate_mlkem'](sk, ct, "ML-KEM-1024")
    assert ss == ss_decapped, "Shared secrets should match"
    
    print("✅ Installed ML-KEM-1024 operations successful")


def test_installed_mlkem_liboqs_unavailable():
    """Test installed mlkem when LIBOQS is unavailable - covers error paths."""
    mlkem = _import_mlkem()
    
    # Mock LIBOQS_AVAILABLE to False
    with patch('pqblocks_wire.mlkem.LIBOQS_AVAILABLE', False):
        # Test keygen functions raise ImportError when LIBOQS unavailable
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
            mlkem['generate_mlkem_keypair']("ML-KEM-512")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
            mlkem['generate_mlkem_keypair']("ML-KEM-768")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
            mlkem['generate_mlkem_keypair']("ML-KEM-1024")
            
        # Test encapsulate functions raise ImportError when LIBOQS unavailable
        pk, sk = b"dummy_public_key", b"dummy_private_key"  # Dummy values won't be used due to early ImportError
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
            mlkem['encapsulate_mlkem'](pk, "ML-KEM-512")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
            mlkem['encapsulate_mlkem'](pk, "ML-KEM-768")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
            mlkem['encapsulate_mlkem'](pk, "ML-KEM-1024")
            
        # Test decapsulate functions raise ImportError when LIBOQS unavailable
        ct = b"dummy_ciphertext"
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
            mlkem['decapsulate_mlkem'](sk, ct, "ML-KEM-512")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
            mlkem['decapsulate_mlkem'](sk, ct, "ML-KEM-768")
            
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
            mlkem['decapsulate_mlkem'](sk, ct, "ML-KEM-1024")
        
        print("✅ Installed ML-KEM LIBOQS unavailable error paths tested")


def test_installed_mlkem_value_error_unsupported_params():
    """Test installed mlkem ValueError for unsupported parameter sets."""
    mlkem = _import_mlkem()
    
    # Test encapsulate_mlkem with invalid parameter set
    pk, sk = mlkem['generate_mlkem_keypair']("ML-KEM-512")  # Valid keypair for testing
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem['encapsulate_mlkem'](pk, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem['encapsulate_mlkem'](pk, "")
        
    # Test decapsulate_mlkem with invalid parameter set
    ct, ss = mlkem['encapsulate_mlkem'](pk, "ML-KEM-512")
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem['decapsulate_mlkem'](sk, ct, "INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem['decapsulate_mlkem'](sk, ct, "")
        
    # Test generate_mlkem_keypair with invalid parameter set
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem['generate_mlkem_keypair']("INVALID-PARAM-SET")
        
    with pytest.raises(ValueError, match="Unsupported parameter set"):
        mlkem['generate_mlkem_keypair']("")
        
    print("✅ Installed ML-KEM unsupported parameter ValueError paths tested")


def test_installed_mlkem_test_all_operations():
    """Test installed mlkem_test_all_operations when LIBOQS available."""
    mlkem = _import_mlkem()
    
    # Test that mlkem_test_all_operations runs when LIBOQS is available
    # This should execute the happy path for all three parameter sets
    mlkem['mlkem_test_all_operations']()
    
    print("✅ Installed ML-KEM test_all_operations executed successfully")


if __name__ == "__main__":
    # Allow running directly for development/testing
    pytest.main([__file__, "-v"])