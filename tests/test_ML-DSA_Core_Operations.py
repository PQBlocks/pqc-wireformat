"""Tests for ML-DSA Core Operations (feature 2) - wire format compatibility package.

Tests must exercise product code (src/pqblocks_wire/mldsa.py) not just
oqs directly. The oqs library is used internally by the product code,
but tests must call the product code functions.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from .conftest import load_official_vectors
from pqblocks_wire.mldsa import (
    generate_mldsa_keypair,
    sign_mldsa,
    verify_mldsa
)


def test_mldsa_load_vectors():
    """Load official ML-DSA test vectors."""
    # Verify Wycheproof vectors are available
    mldsa_verify_groups = load_official_vectors('mldsa_65_verify_test')
    assert len(mldsa_verify_groups) > 0, "No ML-DSA verify test vectors loaded"

    total_verify = sum(len(group.get('tests', [])) for group in mldsa_verify_groups)
    assert total_verify >= 210, f"Expected 210+ ML-DSA verify test cases, got {total_verify}"

    # Check for sign vectors - some may be under different names
    try:
        mldsa_sign_groups = load_official_vectors('mldsa_65_sign_test')
    except FileNotFoundError:
        # Try alternative names
        try:
            mldsa_sign_groups = load_official_vectors('mldsa_65_sign_seed_test')
        except FileNotFoundError:
            mldsa_sign_groups = load_official_vectors('mldsa_65_sign_noseed_test')
    assert len(mldsa_sign_groups) > 0, "No ML-DSA sign test vectors loaded"
    total_sign = sum(len(group.get('tests', [])) for group in mldsa_sign_groups)
    assert total_sign >= 105, f"Expected 105+ ML-DSA sign test cases, got {total_sign}"


def test_mldsa_65_keygen():
    """Test ML-DSA-65 key generation with product code."""
    # Generate keypair using product code
    pk, sk = generate_mldsa_keypair('ML-DSA-65')

    # Verify key lengths
    from pqblocks_wire.mldsa import MLDSAWrapper
    assert len(pk) == MLDSAWrapper.length_public_key('ML-DSA-65'), \
        f"PK length mismatch: {len(pk)} vs {MLDSAWrapper.length_public_key('ML-DSA-65')}"
    assert len(sk) == MLDSAWrapper.length_secret_key('ML-DSA-65'), \
        f"SK length mismatch: {len(sk)} vs {MLDSAWrapper.length_secret_key('ML-DSA-65')}"


def test_mldsa_65_sign_verify():
    """Test ML-DSA-65 sign and verify with product code."""
    # Generate keypair using product code
    pk, sk = generate_mldsa_keypair('ML-DSA-65')

    # Sign a message
    message = b"Test message for ML-DSA-65 signing"
    signature = sign_mldsa(message, sk, 'ML-DSA-65')

    # Verify signature using product code
    result = verify_mldsa(message, signature, pk, 'ML-DSA-65')
    assert result, "Signature verification failed"

    # Verify signature length
    from pqblocks_wire.mldsa import MLDSAWrapper
    assert len(signature) == MLDSAWrapper.length_signature('ML-DSA-65'), \
        f"Signature length mismatch: {len(signature)} vs {MLDSAWrapper.length_signature('ML-DSA-65')}"


def test_mldsa_65_verify_tampered():
    """Test ML-DSA-65 rejects tampered signatures."""
    # Generate keypair using product code
    pk, sk = generate_mldsa_keypair('ML-DSA-65')

    # Sign a message
    message = b"Test message for ML-DSA-65 signing"
    signature = sign_mldsa(message, sk, 'ML-DSA-65')

    # Tamper with signature
    tampered = bytearray(signature)
    tampered[0] ^= 0xFF
    tampered_sig = bytes(tampered)

    # Verify should fail using product code
    result = verify_mldsa(message, tampered_sig, pk, 'ML-DSA-65')
    assert not result, "Tampered signature should be rejected"


def test_mldsa_87_keygen():
    """Test ML-DSA-87 key generation with product code."""
    # Generate keypair using product code
    pk, sk = generate_mldsa_keypair('ML-DSA-87')

    # Verify key lengths match specification
    from pqblocks_wire.mldsa import MLDSAWrapper
    assert len(pk) == MLDSAWrapper.length_public_key('ML-DSA-87')
    assert len(sk) == MLDSAWrapper.length_secret_key('ML-DSA-87')


def test_mldsa_44_keygen():
    """Test ML-DSA-44 key generation with product code."""
    # Generate keypair using product code
    pk, sk = generate_mldsa_keypair('ML-DSA-44')

    # Verify key lengths match specification
    from pqblocks_wire.mldsa import MLDSAWrapper
    assert len(pk) == MLDSAWrapper.length_public_key('ML-DSA-44')
    assert len(sk) == MLDSAWrapper.length_secret_key('ML-DSA-44')


def test_mldsa_multiple_signatures():
    """Test ML-DSA multiple signatures on same message use fresh randomness."""
    message = b"Test message for multiple signatures"

    # Generate multiple signatures on same message using product code
    signatures = []
    for _ in range(10):
        pk, sk = generate_mldsa_keypair('ML-DSA-65')
        sig_inner = sign_mldsa(message, sk, 'ML-DSA-65')
        signatures.append(sig_inner)

    # All signatures should be unique (due to fresh randomness)
    unique_sigs = set(s.hex() for s in signatures)
    assert len(unique_sigs) == 10, "All signatures should be unique"


def test_mldsa_invalid_signature_rejection():
    """Test ML-DSA rejects signatures with wrong public key."""
    # Generate keypair using product code
    pk, sk = generate_mldsa_keypair('ML-DSA-65')
    message = b"Test message for ML-DSA-65 signing"
    signature = sign_mldsa(message, sk, 'ML-DSA-65')

    # Generate a different keypair using product code
    pk_wrong, sk_wrong = generate_mldsa_keypair('ML-DSA-65')

    # Verify should fail with wrong key using product code
    result = verify_mldsa(message, signature, pk_wrong, 'ML-DSA-65')
    assert not result, "Signature should be rejected with wrong public key"


class TestMLDSAParameterValidation:
    """Test ML-DSA parameter set validation and metadata."""

    def test_keygen_unsupported_parameter_set(self):
        """keygen must reject unsupported parameter sets loudly."""
        from pqblocks_wire.mldsa import MLDSAWrapper
        import pytest
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper.keygen('NOT-A-REAL-PARAM-SET')

    def test_sign_unsupported_parameter_set(self):
        """sign must reject unsupported parameter sets loudly."""
        from pqblocks_wire.mldsa import MLDSAWrapper
        import pytest
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper.sign(b"msg", b"sk", 'NOT-A-REAL-PARAM-SET')

    def test_verify_unsupported_parameter_set(self):
        """verify must reject unsupported parameter sets loudly."""
        from pqblocks_wire.mldsa import MLDSAWrapper
        import pytest
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper.verify(b"msg", b"sig", b"pk", 'NOT-A-REAL-PARAM-SET')

    def test_length_helpers_unsupported_parameter_set(self):
        """All length_* helpers must reject unsupported parameter sets loudly."""
        from pqblocks_wire.mldsa import MLDSAWrapper
        import pytest
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper.length_public_key('NOT-A-REAL-PARAM-SET')
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper.length_secret_key('NOT-A-REAL-PARAM-SET')
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper.length_signature('NOT-A-REAL-PARAM-SET')

    def test_keygen_from_seed_unsupported_parameter_set(self):
        """Deterministic keygen must reject unsupported parameter sets loudly."""
        from pqblocks_wire.mldsa import MLDSAWrapper
        import pytest
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper._keygen_from_seed('NOT-A-REAL-PARAM-SET', b"\x00" * 32)

    def test_sign_from_seed_unsupported_parameter_set(self):
        """Deterministic sign must reject unsupported parameter sets loudly."""
        from pqblocks_wire.mldsa import MLDSAWrapper
        import pytest
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper._sign_from_seed('NOT-A-REAL-PARAM-SET', b"msg", b"\x00" * 32)

    def test_verify_from_seed_unsupported_parameter_set(self):
        """Deterministic verify must reject unsupported parameter sets loudly."""
        from pqblocks_wire.mldsa import MLDSAWrapper
        import pytest
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            MLDSAWrapper._verify_from_seed('NOT-A-REAL-PARAM-SET', b"msg", b"sig", b"\x00" * 32, b"pk")

    def test_test_all_operations_entrypoint(self):
        """The *_test_all_operations entrypoint must run cleanly."""
        from pqblocks_wire.mldsa import mldsa_test_all_operations
        mldsa_test_all_operations()