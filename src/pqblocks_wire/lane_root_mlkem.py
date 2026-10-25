from typing import Tuple, Optional
import sys
import os

# Try to import oqs (liboqs-python) which provides all ML-KEM parameter sets
try:
    import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    print("WARNING: liboqs-python is required for ML-KEM operations")

class MLKEMWrapper:
    """Wrapper providing ML-KEM operations via liboqs backend."""

    @staticmethod
    def _keygen_mlkem512() -> Tuple[bytes, bytes]:
        """Generate ML-KEM-512 keypair using liboqs."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-512")
        kem = oqs.KeyEncapsulation('ML-KEM-512')
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        return pk, sk

    @staticmethod
    def _keygen_mlkem768() -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 keypair using liboqs."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-768")
        kem = oqs.KeyEncapsulation('ML-KEM-768')
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        return pk, sk

    @staticmethod
    def _keygen_mlkem1024() -> Tuple[bytes, bytes]:
        """Generate ML-KEM-1024 keypair using liboqs."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-1024")
        kem = oqs.KeyEncapsulation('ML-KEM-1024')
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        return pk, sk

    @staticmethod
    def _encapsulate_mlkem512(public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate using ML-KEM-512 via liboqs (production use - random)."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-512")
        kem = oqs.KeyEncapsulation('ML-KEM-512')
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    @staticmethod
    def _encapsulate_mlkem768(public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate using ML-KEM-768 via liboqs (production use - random)."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-768")
        kem = oqs.KeyEncapsulation('ML-KEM-768')
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    @staticmethod
    def _encapsulate_mlkem1024(public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate using ML-KEM-1024 via liboqs (production use - random)."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-1024")
        kem = oqs.KeyEncapsulation('ML-KEM-1024')
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    @staticmethod
    def _decapsulate_mlkem512(private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using ML-KEM-512 via liboqs."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-512")
        kem = oqs.KeyEncapsulation('ML-KEM-512')
        kem.secret_key = private_key
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    @staticmethod
    def _decapsulate_mlkem768(private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using ML-KEM-768 via liboqs."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-768")
        kem = oqs.KeyEncapsulation('ML-KEM-768')
        kem.secret_key = private_key
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    @staticmethod
    def _decapsulate_mlkem1024(private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using ML-KEM-1024 via liboqs."""
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for ML-KEM-1024")
        kem = oqs.KeyEncapsulation('ML-KEM-1024')
        kem.secret_key = private_key
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    # Production public methods
    @staticmethod
    def keygen_mlkem512() -> Tuple[bytes, bytes]:
        """Public method for ML-KEM-512 key generation."""
        return MLKEMWrapper._keygen_mlkem512()

    @staticmethod
    def keygen_mlkem768() -> Tuple[bytes, bytes]:
        """Public method for ML-KEM-768 key generation."""
        return MLKEMWrapper._keygen_mlkem768()

    @staticmethod
    def keygen_mlkem1024() -> Tuple[bytes, bytes]:
        """Public method for ML-KEM-1024 key generation."""
        return MLKEMWrapper._keygen_mlkem1024()

    @staticmethod
    def encapsulate(public_key: bytes, parameter_set: str) -> Tuple[bytes, bytes]:
        """Encapsulate using ML-KEM as per FIPS 203 Algorithm 20 (production use - random).

        Returns (ciphertext, shared_secret).
        Uses encap_secret() from liboqs for production operation.
        """
        if parameter_set == "ML-KEM-512":
            return MLKEMWrapper._encapsulate_mlkem512(public_key)
        elif parameter_set == "ML-KEM-768":
            return MLKEMWrapper._encapsulate_mlkem768(public_key)
        elif parameter_set == "ML-KEM-1024":
            return MLKEMWrapper._encapsulate_mlkem1024(public_key)
        else:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

    @staticmethod
    def decapsulate(private_key: bytes, ciphertext: bytes, parameter_set: str) -> bytes:
        """Decapsulate using ML-KEM as per FIPS 203 Algorithm 21.

        Returns shared_secret.
        """
        if parameter_set == "ML-KEM-512":
            return MLKEMWrapper._decapsulate_mlkem512(private_key, ciphertext)
        elif parameter_set == "ML-KEM-768":
            return MLKEMWrapper._decapsulate_mlkem768(private_key, ciphertext)
        elif parameter_set == "ML-KEM-1024":
            return MLKEMWrapper._decapsulate_mlkem1024(private_key, ciphertext)
        else:
            raise ValueError(f"Unsupported parameter set: {parameter_set}")

    @staticmethod
    def mlkem_test_all_operations():
        """Test all ML-KEM operations using available backends."""
        print("Testing ML-KEM operations with FIPS 203 specification...")

        # Test ML-KEM-512 (using liboqs)
        if LIBOQS_AVAILABLE:
            print("\nTesting ML-KEM-512 (liboqs):")
            pk, sk = generate_mlkem_keypair("ML-KEM-512")
            print(f"  Generated keypair - PK length: {len(pk)}, SK length: {len(sk)}")

            ct, ss = encapsulate_mlkem(pk, "ML-KEM-512")
            print(f"  Encapsulated - CT length: {len(ct)}, SS length: {len(ss)}")

            ss_decapped = decapsulate_mlkem(sk, ct, "ML-KEM-512")
            print(f"  Decapsulated - SS length: {len(ss_decapped)}")

            assert ss == ss_decapped, "Shared secrets should match"
            print("  ✅ ML-KEM-512 operations successful")

        # Test ML-KEM-768 (using available backend)
        if LIBOQS_AVAILABLE:
            print("\nTesting ML-KEM-768:")
            pk, sk = generate_mlkem_keypair("ML-KEM-768")
            print(f"  Generated keypair - PK length: {len(pk)}, SK length: {len(sk)}")

            ct, ss = encapsulate_mlkem(pk, "ML-KEM-768")
            print(f"  Encapsulated - CT length: {len(ct)}, SS length: {len(ss)}")

            ss_decapped = decapsulate_mlkem(sk, ct, "ML-KEM-768")
            print(f"  Decapsulated - SS length: {len(ss_decapped)}")

            assert ss == ss_decapped, "Shared secrets should match"
            print("  ✅ ML-KEM-768 operations successful")

        # Test ML-KEM-1024 (using available backend)
        if LIBOQS_AVAILABLE:
            print("\nTesting ML-KEM-1024:")
            pk, sk = generate_mlkem_keypair("ML-KEM-1024")
            print(f"  Generated keypair - PK length: {len(pk)}, SK length: {len(sk)}")

            ct, ss = encapsulate_mlkem(pk, "ML-KEM-1024")
            print(f"  Encapsulated - CT length: {len(ct)}, SS length: {len(ss)}")

            ss_decapped = decapsulate_mlkem(sk, ct, "ML-KEM-1024")
            print(f"  Decapsulated - SS length: {len(ss_decapped)}")

            assert ss == ss_decapped, "Shared secrets should match"
            print("  ✅ ML-KEM-1024 operations successful")

        print("\n✅ All ML-KEM core operations tests completed successfully!")


def generate_mlkem_keypair(parameter_set: str) -> Tuple[bytes, bytes]:
    """Generate ML-KEM keypair using FIPS 203 specification."""
    if parameter_set == "ML-KEM-512":
        return MLKEMWrapper.keygen_mlkem512()
    elif parameter_set == "ML-KEM-768":
        return MLKEMWrapper.keygen_mlkem768()
    elif parameter_set == "ML-KEM-1024":
        return MLKEMWrapper.keygen_mlkem1024()
    else:
        raise ValueError(f"Unsupported parameter set: {parameter_set}")


def encapsulate_mlkem(public_key: bytes, parameter_set: str) -> Tuple[bytes, bytes]:
    """Encapsulate using ML-KEM as per FIPS 203 Algorithm 20."""
    return MLKEMWrapper.encapsulate(public_key, parameter_set)


def decapsulate_mlkem(private_key: bytes, ciphertext: bytes, parameter_set: str) -> bytes:
    """Decapsulate using ML-KEM as per FIPS 203 Algorithm 21."""
    return MLKEMWrapper.decapsulate(private_key, ciphertext, parameter_set)


def mlkem_test_all_operations():
    """Test all ML-KEM operations."""
    MLKEMWrapper.mlkem_test_all_operations()


if __name__ == "__main__":
    mlkem_test_all_operations()