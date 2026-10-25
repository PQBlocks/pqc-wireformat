#!/usr/bin/env python3
"""
Additional tests for pqblocks_wire.mlkem to improve coverage.
Focuses on backend availability paths, error handling, and type validation.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from unittest.mock import patch


class TestMLKEMWrapperTypeErrors:
    """Test MLKEMWrapper TypeError paths."""

    def test_encapsulate_kat_non_bytes_public_key(self):
        """Test encapsulate_kat with non-bytes public_key (line 160)."""
        with pytest.raises(TypeError, match="public_key must be bytes"):
            from pqblocks_wire.mlkem import MLKEMWrapper
            MLKEMWrapper.encapsulate_kat("not bytes", "ML-KEM-512", b"mask")

        print("✅ MLKEMWrapper encapsulate_kat non-bytes public_key tested")

    def test_encapsulate_kat_non_string_parameter_set(self):
        """Test encapsulate_kat with non-string parameter_set (line 162)."""
        with pytest.raises(TypeError, match="parameter_set must be str"):
            from pqblocks_wire.mlkem import MLKEMWrapper
            MLKEMWrapper.encapsulate_kat(b"pk", 123, b"mask")

        print("✅ MLKEMWrapper encapsulate_kat non-string parameter_set tested")

    def test_encapsulate_kat_non_bytes_mask(self):
        """Test encapsulate_kat with non-bytes mask (line 164)."""
        with pytest.raises(TypeError, match="m must be bytes"):
            from pqblocks_wire.mlkem import MLKEMWrapper
            MLKEMWrapper.encapsulate_kat(b"pk", "ML-KEM-512", "not bytes")

        print("✅ MLKEMWrapper encapsulate_kat non-bytes mask tested")

    def test_encapsulate_mlkem_non_bytes_public_key(self):
        """Test encapsulate_mlkem with non-bytes public_key (line 349)."""
        with pytest.raises(TypeError, match="public_key must be bytes"):
            from pqblocks_wire.mlkem import encapsulate_mlkem
            encapsulate_mlkem("not bytes", "ML-KEM-512")

        print("✅ encapsulate_mlkem non-bytes public_key tested")

    def test_decapsulate_mlkem_non_bytes_private_key(self):
        """Test decapsulate_mlkem with non-bytes private_key (line 358)."""
        with pytest.raises(TypeError, match="private_key must be bytes"):
            from pqblocks_wire.mlkem import decapsulate_mlkem
            decapsulate_mlkem("not bytes", b"ct", "ML-KEM-512")

        print("✅ decapsulate_mlkem non-bytes private_key tested")

    def test_decapsulate_mlkem_non_bytes_ciphertext(self):
        """Test decapsulate_mlkem with non-bytes ciphertext (line 360)."""
        with pytest.raises(TypeError, match="ciphertext must be bytes"):
            from pqblocks_wire.mlkem import decapsulate_mlkem
            decapsulate_mlkem(b"sk", "not bytes", "ML-KEM-512")

        print("✅ decapsulate_mlkem non-bytes ciphertext tested")

    def test_decapsulate_mlkem_non_string_parameter_set(self):
        """Test decapsulate_mlkem with non-string parameter_set (line 362)."""
        with pytest.raises(TypeError, match="parameter_set must be str"):
            from pqblocks_wire.mlkem import decapsulate_mlkem
            decapsulate_mlkem(b"sk", b"ct", 123)

        print("✅ decapsulate_mlkem non-string parameter_set tested")

    def test_generate_mlkem_keypair_non_string_param(self):
        """Test generate_mlkem_keypair with non-string parameter_set (line 335/212)."""
        # Check the code path for non-string input
        with pytest.raises(TypeError):
            from pqblocks_wire.mlkem import generate_mlkem_keypair
            generate_mlkem_keypair(123)

        with pytest.raises(TypeError):
            from pqblocks_wire.mlkem import generate_mlkem_keypair
            generate_mlkem_keypair(None)

        print("✅ generate_mlkem_keypair non-string param tested")


class TestMLKEMWrapperValueErrors:
    """Test MLKEMWrapper ValueError paths."""

    def test_encapsulate_mlkem_value_error_invalid_param(self):
        """Test encapsulate_mlkem ValueError for unsupported parameter_set."""
        from pqblocks_wire.mlkem import MLKEMWrapper
        from pqblocks_wire.mlkem import generate_mlkem_keypair
        pk, sk = generate_mlkem_keypair("ML-KEM-512")
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLKEMWrapper.encapsulate(pk, "INVALID-PARAM-SET")

        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLKEMWrapper.encapsulate(pk, "")

        print("✅ encapsulate_mlkem ValueError invalid param tested")

    def test_decapsulate_mlkem_value_error_invalid_param(self):
        """Test decapsulate_mlkem ValueError for unsupported parameter_set."""
        from pqblocks_wire.mlkem import MLKEMWrapper
        from pqblocks_wire.mlkem import generate_mlkem_keypair, encapsulate_mlkem
        pk, sk = generate_mlkem_keypair("ML-KEM-512")
        ct, ss = encapsulate_mlkem(pk, "ML-KEM-512")
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLKEMWrapper.decapsulate(sk, ct, "INVALID-PARAM-SET")

        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLKEMWrapper.decapsulate(sk, ct, "")

        print("✅ decapsulate_mlkem ValueError invalid param tested")


class TestModuleLevelBackendPaths:
    """Test module-level function backend availability paths."""

    @patch('pqblocks_wire.mlkem.LIBOQS_AVAILABLE', False)
    def test_encapsulate_mlkem_liboqs_unavailable_512(self):
        """Test encapsulate_mlkem with LIBOQS_AVAILABLE=False for ML-KEM-512."""
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
            from pqblocks_wire.mlkem import encapsulate_mlkem
            encapsulate_mlkem(b"pk", "ML-KEM-512")

        print("✅ encapsulate_mlkem LIBOQS unavailable 512 tested")

    @patch('pqblocks_wire.mlkem.LIBOQS_AVAILABLE', False)
    def test_encapsulate_mlkem_liboqs_unavailable_768(self):
        """Test encapsulate_mlkem with LIBOQS_AVAILABLE=False for ML-KEM-768."""
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
            from pqblocks_wire.mlkem import encapsulate_mlkem
            from pqblocks_wire.mlkem import MLKEMWrapper
            MLKEMWrapper.encapsulate(b"pk", "ML-KEM-768")

        print("✅ encapsulate_mlkem LIBOQS unavailable 768 tested")

    @patch('pqblocks_wire.mlkem.LIBOQS_AVAILABLE', False)
    def test_encapsulate_mlkem_liboqs_unavailable_1024(self):
        """Test encapsulate_mlkem with LIBOQS_AVAILABLE=False for ML-KEM-1024."""
        with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
            from pqblocks_wire.mlkem import encapsulate_mlkem
            from pqblocks_wire.mlkem import MLKEMWrapper
            MLKEMWrapper.encapsulate(b"pk", "ML-KEM-1024")

        print("✅ encapsulate_mlkem LIBOQS unavailable 1024 tested")


class TestLaneRootMLKEMCoverage:
    """Test installed pqblocks_wire.mlkem coverage paths."""

    def _import_mlkem(self):
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

    def test_lane_root_mlkem_liboqs_unavailable_error_paths(self):
        """Test installed mlkem error paths when LIBOQS unavailable."""
        from unittest.mock import patch

        mlkem = self._import_mlkem()
        with patch('pqblocks_wire.mlkem.LIBOQS_AVAILABLE', False):
            # Test keygen functions raise ImportError when LIBOQS unavailable
            with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-512"):
                mlkem['generate_mlkem_keypair']("ML-KEM-512")

            with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-768"):
                mlkem['generate_mlkem_keypair']("ML-KEM-768")

            with pytest.raises(ImportError, match="liboqs-python is required for ML-KEM-1024"):
                mlkem['generate_mlkem_keypair']("ML-KEM-1024")

            # Test encapsulate functions raise ImportError when LIBOQS unavailable
            pk, sk = b"dummy_public_key", b"dummy_private_key"
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

    def test_lane_root_mlkem_value_error_unsupported_params(self):
        """Test installed mlkem ValueError for unsupported parameter sets."""
        mlkem = self._import_mlkem()

        pk, sk = mlkem['generate_mlkem_keypair']("ML-KEM-512")

        # Test encapsulate_mlkem with invalid parameter set
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

    def test_lane_root_mlkem_test_all_operations_happy_path(self):
        """Test installed mlkem_test_all_operations when LIBOQS available."""
        mlkem = self._import_mlkem()
        mlkem['mlkem_test_all_operations']()
        print("✅ Installed ML-KEM test_all_operations executed successfully")


class TestMLKEMWrapperInternals:
    """Test MLKEMWrapper internal helper methods."""

    def test_mlkem_wrapper_internals(self):
        """Test MLKEMWrapper internal methods."""
        from pqblocks_wire.mlkem import MLKEMWrapper

        # Get a valid keypair to trigger the encapsulate methods
        from pqblocks_wire.mlkem import encapsulate_mlkem
        pk, sk = MLKEMWrapper.keygen_mlkem512()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)
        print("✅ MLKEMWrapper keygen_mlkem512 works")

        pk768, sk768 = MLKEMWrapper.keygen_mlkem768()
        assert isinstance(pk768, bytes)
        assert isinstance(sk768, bytes)
        print("✅ MLKEMWrapper keygen_mlkem768 works")

        pk1024, sk1024 = MLKEMWrapper.keygen_mlkem1024()
        assert isinstance(pk1024, bytes)
        assert isinstance(sk1024, bytes)
        print("✅ MLKEMWrapper keygen_mlkem1024 works")


class TestMLKEMWrapperTestAllOperations:
    """Test MLKEMWrapper.test_all_operations entrypoint."""

    def test_mlkem_test_all_operations(self):
        """Test mlkem_test_all_operations runs successfully (covers lines 153-200)."""
        from pqblocks_wire.mlkem import mlkem_test_all_operations

        # This exercises all the ML-KEM operations - 512, 768, 1024
        mlkem_test_all_operations()

        print("✅ ML-KEM test_all_operations completed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])