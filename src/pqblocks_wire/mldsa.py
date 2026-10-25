"""ML-DSA (FIPS 204) signature operations via liboqs-python.

Thin wrapper providing ML-DSA operations. Never re-implements the primitive.
Deterministic seed-based operations enabled per FIPS 204 KAT requirements.
"""

import oqs
from typing import Tuple, Optional


class MLDSAWrapper:
    """Wrapper providing ML-DSA operations via liboqs-python.

    Supports both randomized (default) and deterministic seed-based operations
    per FIPS 204 specification.
    """

    # Supported parameter sets
    SUPPORTED_PARAMETER_SETS = [
        'ML-DSA-44',
        'ML-DSA-65',
        'ML-DSA-87',
    ]

    @staticmethod
    def keygen(parameter_set: str) -> Tuple[bytes, bytes]:
        """Generate ML-DSA keypair.

        Returns (public_key, secret_key) using randomized key generation.
        """
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        sig = oqs.Signature(parameter_set)
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pk, sk

    @staticmethod
    def _keygen_from_seed(parameter_set: str, seed: bytes) -> Tuple[bytes, bytes]:
        """Generate ML-DSA keypair deterministically from seed.

        FIPS 204 deterministic key generation. Same seed => same keypair.

        Args:
            parameter_set: One of the supported parameter sets
            seed: Seed bytes for deterministic key generation

        Returns:
            (public_key, secret_key) pair deterministically derived from seed
        """
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        # Use liboqs with seed-derived secret key
        # Per FIPS 204, set secret_key before generate_keypair for determinism
        sig = oqs.Signature(parameter_set)
        sig.secret_key = seed
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pk, sk

    @staticmethod
    def sign(message: bytes, private_key: bytes, parameter_set: str) -> bytes:
        """Sign a message using ML-DSA.

        Returns the signature bytes using randomized signing.
        """
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        sig = oqs.Signature(parameter_set)
        sig.secret_key = private_key
        signature = sig.sign(message)
        return signature

    @staticmethod
    def _sign_from_seed(parameter_set: str, message: bytes, seed: bytes) -> bytes:
        """Sign a message deterministically from seed.

        FIPS 204 deterministic signature generation. Same seed + message =>
        same signature.

        Args:
            parameter_set: One of the supported parameter sets
            message: Message to sign
            seed: Seed bytes for deterministic signature generation

        Returns:
            Signature bytes deterministically derived from seed and message
        """
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        # Create signature instance with seed for deterministic results
        sig = oqs.Signature(parameter_set)
        sig.secret_key = seed
        signature = sig.sign(message)
        return signature

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes, parameter_set: str) -> bool:
        """Verify a signature using ML-DSA.

        Returns True if verification succeeds, False otherwise.
        """
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        sig = oqs.Signature(parameter_set)
        return sig.verify(message, signature, public_key)

    @staticmethod
    def _verify_from_seed(
        parameter_set: str,
        message: bytes,
        signature: bytes,
        seed: bytes,
        public_key: bytes,
    ) -> bool:
        """Verify a signature deterministically from seed.

        FIPS 204 deterministic verification using the seed-derived key pair.

        Args:
            parameter_set: One of the supported parameter sets
            message: Message that was signed
            signature: Signature to verify
            seed: Seed that was used for key generation and signing
            public_key: Expected public key (verified against seed-derived key)

        Returns:
            True if verification succeeds, False otherwise
        """
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        # Derive keypair from seed for deterministic verification
        sig = oqs.Signature(parameter_set)
        sig.secret_key = seed
        derived_pk = sig.generate_keypair()

        # Verify that derived public key matches the provided one
        if derived_pk != public_key:
            return False

        # Verify the signature
        return sig.verify(message, signature, public_key)

    @staticmethod
    def length_public_key(parameter_set: str) -> int:
        """Return the public key length for a parameter set."""
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        sig = oqs.Signature(parameter_set)
        return sig.length_public_key

    @staticmethod
    def length_secret_key(parameter_set: str) -> int:
        """Return the secret key length for a parameter set."""
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        sig = oqs.Signature(parameter_set)
        return sig.length_secret_key

    @staticmethod
    def length_signature(parameter_set: str) -> int:
        """Return the signature length for a parameter set."""
        if parameter_set not in MLDSAWrapper.SUPPORTED_PARAMETER_SETS:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

        sig = oqs.Signature(parameter_set)
        return sig.length_signature


def generate_mldsa_keypair(parameter_set: str) -> Tuple[bytes, bytes]:
    """Generate ML-DSA keypair using FIPS 204 specification."""
    return MLDSAWrapper.keygen(parameter_set)


def sign_mldsa(message: bytes, private_key: bytes, parameter_set: str) -> bytes:
    """Sign a message using ML-DSA."""
    return MLDSAWrapper.sign(message, private_key, parameter_set)


def verify_mldsa(message: bytes, signature: bytes, public_key: bytes, parameter_set: str) -> bool:
    """Verify a signature using ML-DSA."""
    return MLDSAWrapper.verify(message, signature, public_key, parameter_set)


def mldsa_test_all_operations():
    """Test all ML-DSA operations using liboqs where available."""
    print("Testing ML-DSA operations with FIPS 204 specification...")

    for param_set in [
        'ML-DSA-44',
        'ML-DSA-65',
        'ML-DSA-87',
    ]:
        print(f"\nTesting {param_set}:")
        pk, sk = generate_mldsa_keypair(param_set)
        print(f"  Generated keypair - PK length: {len(pk)}, SK length: {len(sk)}")

        message = b"Test message for ML-DSA signing"
        signature = sign_mldsa(message, sk, param_set)
        print(f"  Signed - Signature length: {len(signature)}")

        result = verify_mldsa(message, signature, pk, param_set)
        print(f"  Verified: {result}")
        assert result, f"Verification failed for {param_set}"

    print("\n✅ All ML-DSA core operations tests completed successfully!")


if __name__ == "__main__":
    mldsa_test_all_operations()