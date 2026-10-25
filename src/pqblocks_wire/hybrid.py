"""Hybrid Key Exchange for PQC Hybrid Operations (feature 6).

This module implements hybrid key exchange combining X25519 (classical) 
and ML-KEM (post-quantum) as specified in draft-ietf-tls-hybrid-design.

The hybrid key exchange produces a combined shared secret that can be used
for key derivation in hybrid TLS 1.3 and other protocols.
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519


@dataclass
class HybridPublicKey:
    """Hybrid public key containing both X25519 and ML-KEM public keys."""
    x25519_public_key: x25519.X25519PublicKey
    mlkem_public_key: bytes
    
    def serialize(self) -> bytes:
        """Serialize hybrid public key for transmission."""
        # X25519 public key is always 32 bytes
        x25519_bytes = self.x25519_public_key.public_bytes_raw()
        # ML-KEM public key varies by parameter set
        mlkem_len = len(self.mlkem_public_key)
        parts = [
            x25519_bytes,
            struct.pack('>I', mlkem_len),
            self.mlkem_public_key
        ]
        return b''.join(parts)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'HybridPublicKey':
        """Deserialize hybrid public key from bytes."""
        if len(data) < 36:  # 32 bytes X25519 + 4 bytes length
            raise ValueError("Insufficient data for hybrid public key")
        
        # Extract X25519 public key (first 32 bytes)
        x25519_bytes = data[:32]
        x25519_public_key = x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
        
        # Extract ML-KEM public key length
        mlkem_len = struct.unpack('>I', data[32:36])[0]
        
        if len(data) < 36 + mlkem_len:
            raise ValueError("Insufficient data for ML-KEM public key")
        
        # Extract ML-KEM public key
        mlkem_public_key = data[36:36 + mlkem_len]
        
        return cls(
            x25519_public_key=x25519_public_key,
            mlkem_public_key=mlkem_public_key
        )


@dataclass
class HybridPrivateKey:
    """Hybrid private key containing both X25519 and ML-KEM private keys."""
    x25519_private_key: x25519.X25519PrivateKey
    mlkem_private_key: bytes
    
    def serialize(self) -> bytes:
        """Serialize hybrid private key for storage."""
        # X25519 private key in raw format
        x25519_bytes = self.x25519_private_key.private_bytes_raw()
        # ML-KEM private key varies by parameter set
        mlkem_len = len(self.mlkem_private_key)
        parts = [
            x25519_bytes,
            struct.pack('>I', mlkem_len),
            self.mlkem_private_key
        ]
        return b''.join(parts)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'HybridPrivateKey':
        """Deserialize hybrid private key from bytes."""
        if len(data) < 36:  # 32 bytes X25519 + 4 bytes length
            raise ValueError("Insufficient data for hybrid private key")
        
        # Extract X25519 private key (first 32 bytes)
        x25519_bytes = data[:32]
        x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(x25519_bytes)
        
        # Extract ML-KEM private key length
        mlkem_len = struct.unpack('>I', data[32:36])[0]
        
        if len(data) < 36 + mlkem_len:
            raise ValueError("Insufficient data for ML-KEM private key")
        
        # Extract ML-KEM private key
        mlkem_private_key = data[36:36 + mlkem_len]
        
        return cls(
            x25519_private_key=x25519_private_key,
            mlkem_private_key=mlkem_private_key
        )


def hybrid_key_exchange_initiator(
    x25519_private_key: x25519.X25519PrivateKey,
    x25519_public_key: x25519.X25519PublicKey,
    mlkem_public_key: bytes
) -> Tuple[bytes, bytes]:
    """Perform hybrid key exchange as INITIATOR (generates ML-KEM ciphertext).
    
    Args:
        x25519_private_key: Our X25519 private key
        x25519_public_key: Peer's X25519 public key
        mlkem_public_key: Peer's ML-KEM public key
        
    Returns:
        Tuple of (mlkem_ciphertext, combined_shared_secret)
        where combined_shared_secret is 32 bytes derived from both X25519 and ML-KEM
        
    Raises:
        ValueError: If key sizes are invalid
        TypeError: If inputs are not of expected types
    """
    # Validate inputs
    if not isinstance(x25519_private_key, x25519.X25519PrivateKey):
        raise TypeError("x25519_private_key must be X25519PrivateKey")
    if not isinstance(x25519_public_key, x25519.X25519PublicKey):
        raise TypeError("x25519_public_key must be X25519PublicKey")
    if not isinstance(mlkem_public_key, bytes):
        raise TypeError("mlkem_public_key must be bytes")
    
    # Perform X25519 key exchange
    x25519_shared_secret = x25519_private_key.exchange(x25519_public_key)
    if len(x25519_shared_secret) != 32:
        raise ValueError(f"X25519 shared secret must be 32 bytes, got {len(x25519_shared_secret)}")
    
    # Perform ML-KEM encapsulation (initiator side)
    from pqblocks_wire import encapsulate_mlkem
    try:
        mlkem_ciphertext, mlkem_shared_secret = encapsulate_mlkem(mlkem_public_key, "ML-KEM-768")
    except Exception as e:
        raise ValueError(f"ML-KEM encapsulation failed: {e}") from e
    
    if len(mlkem_shared_secret) != 32:
        raise ValueError(f"ML-KEM shared secret must be 32 bytes, got {len(mlkem_shared_secret)}")
    if len(mlkem_ciphertext) != 1088:  # ML-KEM-768 ciphertext size
        raise ValueError(f"ML-KEM ciphertext must be 1088 bytes, got {len(mlkem_ciphertext)}")
    
    # Combine shared secrets using KDF-like construction
    combined_input = x25519_shared_secret + mlkem_shared_secret
    combined_secret = hashlib.sha256(combined_input).digest()
    
    return mlkem_ciphertext, combined_secret


def hybrid_key_exchange_responder(
    x25519_private_key: x25519.X25519PrivateKey,
    x25519_public_key: x25519.X25519PublicKey,
    mlkem_private_key: bytes,
    mlkem_ciphertext: bytes
) -> bytes:
    """Perform hybrid key exchange as RESPONDER (decapsulates ML-KEM ciphertext).
    
    Args:
        x25519_private_key: Our X25519 private key
        x25519_public_key: Peer's X25519 public key
        mlkem_private_key: Our ML-KEM private key
        mlkem_ciphertext: ML-KEM ciphertext received from initiator
        
    Returns:
        Combined shared secret (32 bytes) derived from both X25519 and ML-KEM shared secrets
        
    Raises:
        ValueError: If key sizes are invalid
        TypeError: If inputs are not of expected types
    """
    # Validate inputs
    if not isinstance(x25519_private_key, x25519.X25519PrivateKey):
        raise TypeError("x25519_private_key must be X25519PrivateKey")
    if not isinstance(x25519_public_key, x25519.X25519PublicKey):
        raise TypeError("x25519_public_key must be X25519PublicKey")
    if not isinstance(mlkem_private_key, bytes):
        raise TypeError("mlkem_private_key must be bytes")
    if not isinstance(mlkem_ciphertext, bytes):
        raise TypeError("mlkem_ciphertext must be bytes")
    
    # Perform X25519 key exchange
    x25519_shared_secret = x25519_private_key.exchange(x25519_public_key)
    if len(x25519_shared_secret) != 32:
        raise ValueError(f"X25519 shared secret must be 32 bytes, got {len(x25519_shared_secret)}")
    
    # Perform ML-KEM decapsulation (responder side)
    from pqblocks_wire import decapsulate_mlkem
    try:
        mlkem_shared_secret = decapsulate_mlkem(mlkem_private_key, mlkem_ciphertext, "ML-KEM-768")
    except Exception as e:
        raise ValueError(f"ML-KEM decapsulation failed: {e}") from e
    
    if len(mlkem_shared_secret) != 32:
        raise ValueError(f"ML-KEM shared secret must be 32 bytes, got {len(mlkem_shared_secret)}")
    
    # Combine shared secrets using KDF-like construction
    combined_input = x25519_shared_secret + mlkem_shared_secret
    combined_secret = hashlib.sha256(combined_input).digest()
    
    return combined_secret


def classical_fallback(
    x25519_private_key: x25519.X25519PrivateKey,
    x25519_public_key: x25519.X25519PublicKey
) -> bytes:
    """Perform classical X25519 key exchange as fallback.
    
    Args:
        x25519_private_key: X25519 private key
        x25519_public_key: X25519 public key (of the peer)
        
    Returns:
        X25519 shared secret (32 bytes)
        
    Raises:
        TypeError: If inputs are not of expected types
        ValueError: If shared secret is not 32 bytes
    """
    # Validate inputs
    if not isinstance(x25519_private_key, x25519.X25519PrivateKey):
        raise TypeError("x25519_private_key must be X25519PrivateKey")
    if not isinstance(x25519_public_key, x25519.X25519PublicKey):
        raise TypeError("x25519_public_key must be X25519PublicKey")
    
    # Perform X25519 key exchange
    shared_secret = x25519_private_key.exchange(x25519_public_key)
    
    if len(shared_secret) != 32:
        raise ValueError(f"X25519 shared secret must be 32 bytes, got {len(shared_secret)}")
    
    return shared_secret


def generate_hybrid_keypair() -> Tuple[HybridPublicKey, HybridPrivateKey]:
    """Generate a hybrid key pair (X25519 + ML-KEM-768).
    
    Returns:
        Tuple of (HybridPublicKey, HybridPrivateKey)
    """
    # Generate X25519 key pair
    x25519_private = x25519.X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key()
    
    # Generate ML-KEM-768 key pair
    from pqblocks_wire import generate_mlkem_keypair
    mlkem_public, mlkem_private = generate_mlkem_keypair("ML-KEM-768")
    
    # Create hybrid keys
    hybrid_public = HybridPublicKey(
        x25519_public_key=x25519_public,
        mlkem_public_key=mlkem_public
    )
    hybrid_private = HybridPrivateKey(
        x25519_private_key=x25519_private,
        mlkem_private_key=mlkem_private
    )
    
    return hybrid_public, hybrid_private


def hybrid_test_basic_operations() -> None:
    """Test basic hybrid key exchange operations."""
    # Generate hybrid key pair for us
    hybrid_public, hybrid_private = generate_hybrid_keypair()
    
    # Generate peer's hybrid key pair
    peer_public, peer_private = generate_hybrid_keypair()
    
    # Perform hybrid key exchange (we initiate, peer responds)
    mlkem_ct, shared_secret_initiator = hybrid_key_exchange_initiator(
        x25519_private_key=hybrid_private.x25519_private_key,
        x25519_public_key=peer_public.x25519_public_key,
        mlkem_public_key=peer_public.mlkem_public_key
    )
    
    # Peer performs hybrid key exchange (responds)
    shared_secret_responder = hybrid_key_exchange_responder(
        x25519_private_key=peer_private.x25519_private_key,
        x25519_public_key=hybrid_public.x25519_public_key,
        mlkem_private_key=peer_private.mlkem_private_key,
        mlkem_ciphertext=mlkem_ct
    )
    
    # Both should derive the same shared secret
    assert shared_secret_initiator == shared_secret_responder, f"Mismatch: {shared_secret_initiator.hex()} != {shared_secret_responder.hex()}"
    assert len(shared_secret_initiator) == 32
    
    # Test classical fallback
    classical_secret = classical_fallback(
        x25519_private_key=hybrid_private.x25519_private_key,
        x25519_public_key=peer_public.x25519_public_key
    )
    
    assert len(classical_secret) == 32
    # Classical secret should be different from hybrid secret
    assert classical_secret != shared_secret_initiator
    
    print("✅ Hybrid key exchange basic operations test passed!")


# Backward compatibility: provide the old interface name
def hybrid_key_exchange(
    x25519_private_key: x25519.X25519PrivateKey,
    x25519_public_key: x25519.X25519PublicKey,
    mlkem_public_key: bytes,
    mlkem_private_key: bytes
) -> bytes:
    """Legacy interface for hybrid key exchange (combined secret only).
    
    This function performs both encapsulation and decapsulation using the same
    party's keys - useful for testing but NOT for real key exchange.
    For real key exchange, use hybrid_key_exchange_initiator and hybrid_key_exchange_responder.
    
    Args:
        x25519_private_key: Our X25519 private key
        x25519_public_key: Peer's X25519 public key
        mlkem_public_key: Peer's ML-KEM public key
        mlkem_private_key: Our ML-KEM private key
        
    Returns:
        Combined shared secret (32 bytes)
    """
    # Validate inputs
    if not isinstance(x25519_private_key, x25519.X25519PrivateKey):
        raise TypeError("x25519_private_key must be X25519PrivateKey")
    if not isinstance(x25519_public_key, x25519.X25519PublicKey):
        raise TypeError("x25519_public_key must be X25519PublicKey")
    if not isinstance(mlkem_public_key, bytes):
        raise TypeError("mlkem_public_key must be bytes")
    if not isinstance(mlkem_private_key, bytes):
        raise TypeError("mlkem_private_key must be bytes")
    
    # Perform X25519 key exchange
    x25519_shared_secret = x25519_private_key.exchange(x25519_public_key)
    if len(x25519_shared_secret) != 32:
        raise ValueError(f"X25519 shared secret must be 32 bytes, got {len(x25519_shared_secret)}")
    
    # For ML-KEM: encapsulate to peer's public key, then decapsulate with our private key
    # This simulates both sides of the exchange using the same keys (for testing)
    from pqblocks_wire import encapsulate_mlkem, decapsulate_mlkem
    try:
        mlkem_ciphertext, mlkem_shared_secret = encapsulate_mlkem(mlkem_public_key, "ML-KEM-768")
        # Verify by decapsulating
        mlkem_shared_secret2 = decapsulate_mlkem(mlkem_private_key, mlkem_ciphertext, "ML-KEM-768")
        if mlkem_shared_secret != mlkem_shared_secret2:
            raise ValueError("ML-KEM encapsulation/decapsulation mismatch")
    except Exception as e:
        raise ValueError(f"ML-KEM operation failed: {e}") from e
    
    if len(mlkem_shared_secret) != 32:
        raise ValueError(f"ML-KEM shared secret must be 32 bytes, got {len(mlkem_shared_secret)}")
    
    # Combine shared secrets using KDF-like construction
    combined_input = x25519_shared_secret + mlkem_shared_secret
    combined_secret = hashlib.sha256(combined_input).digest()
    
    return combined_secret


if __name__ == "__main__":
    hybrid_test_basic_operations()