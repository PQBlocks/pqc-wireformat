"""Composite Signature Logic for PQC Hybrid Operations (feature 5).

This module implements composite signatures combining ML-DSA (FIPS 204) 
with traditional algorithms (Ed25519 per RFC 8410) as specified in 
draft-ietf-lamps-pq-composite-sigs.

The composite algorithm presents a single public key and signature value
such that it can be treated as a single atomic algorithm at the protocol level.
"""

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

import oqs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# Composite algorithm identifier prefix
COMPOSITE_PREFIX = b"CompositeAlgorithmSignatures2025"

# Label values for composite algorithms (per draft-ietf-lamps-pq-composite-sigs-19 Section 6)
# These bind the signature to the specific composite algorithm
LABEL_MLDSA65_ED25519 = b"ML-DSA-65+Ed25519"


@dataclass
class CompositePublicKey:
    """Composite public key containing both ML-DSA and Ed25519 public keys."""
    mldsa_public_key: bytes
    ed25519_public_key: bytes
    
    def serialize(self) -> bytes:
        """Serialize composite public key using length-prefixed format."""
        parts = [
            struct.pack('>I', len(self.mldsa_public_key)),
            self.mldsa_public_key,
            struct.pack('>I', len(self.ed25519_public_key)),
            self.ed25519_public_key,
        ]
        return b''.join(parts)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'CompositePublicKey':
        """Deserialize composite public key from length-prefixed format."""
        offset = 0
        
        # Read ML-DSA public key
        if offset + 4 > len(data):
            raise ValueError("Truncated: expected ML-DSA public key length")
        mldsa_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        if offset + mldsa_len > len(data):
            raise ValueError("Truncated: expected ML-DSA public key data")
        mldsa_pk = data[offset:offset + mldsa_len]
        offset += mldsa_len
        
        # Read Ed25519 public key
        if offset + 4 > len(data):
            raise ValueError("Truncated: expected Ed25519 public key length")
        ed25519_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        if offset + ed25519_len > len(data):
            raise ValueError("Truncated: expected Ed25519 public key data")
        ed25519_pk = data[offset:offset + ed25519_len]
        
        return cls(mldsa_public_key=mldsa_pk, ed25519_public_key=ed25519_pk)


@dataclass
class CompositePrivateKey:
    """Composite private key containing ML-DSA secret key and Ed25519 private key.
    
    Note: We store the full ML-DSA secret key (not just the seed) because 
    liboqs's generate_keypair() is not deterministic when called multiple times
    with the same seed. Storing the full secret key ensures we can reproduce
    the exact same keypair for signing.
    """
    mldsa_secret_key: bytes  # Full ML-DSA secret key for consistent signing
    ed25519_private_key: ed25519.Ed25519PrivateKey
    
    def serialize(self) -> bytes:
        """Serialize composite private key using length-prefixed format."""
        # Serialize Ed25519 private key to PKCS8 format
        ed25519_sk_bytes = self.ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        parts = [
            struct.pack('>I', len(self.mldsa_secret_key)),
            self.mldsa_secret_key,
            struct.pack('>I', len(ed25519_sk_bytes)),
            ed25519_sk_bytes,
        ]
        return b''.join(parts)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'CompositePrivateKey':
        """Deserialize composite private key from length-prefixed format."""
        from cryptography.hazmat.primitives import serialization
        
        offset = 0
        
        # Read ML-DSA secret key
        if offset + 4 > len(data):
            raise ValueError("Truncated: expected ML-DSA secret key length")
        mldsa_sk_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        if offset + mldsa_sk_len > len(data):
            raise ValueError("Truncated: expected ML-DSA secret key data")
        mldsa_sk = data[offset:offset + mldsa_sk_len]
        offset += mldsa_sk_len
        
        # Read Ed25519 private key
        if offset + 4 > len(data):
            raise ValueError("Truncated: expected Ed25519 private key length")
        ed25519_sk_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        if offset + ed25519_sk_len > len(data):
            raise ValueError("Truncated: expected Ed25519 private key data")
        ed25519_sk_bytes = data[offset:offset + ed25519_sk_len]
        
        # Load Ed25519 private key from PKCS8 PEM format
        # The data is already in PEM format, we need to parse it
        ed25519_priv = serialization.load_pem_private_key(
            ed25519_sk_bytes,
            password=None
        )
        if not isinstance(ed25519_priv, ed25519.Ed25519PrivateKey):
            raise ValueError("Deserialized key is not Ed25519")
        
        return cls(mldsa_secret_key=mldsa_sk, ed25519_private_key=ed25519_priv)


@dataclass
class CompositeSignature:
    """Composite signature containing both ML-DSA and Ed25519 signatures."""
    mldsa_signature: bytes
    ed25519_signature: bytes
    
    def serialize(self) -> bytes:
        """Serialize composite signature using length-prefixed format."""
        parts = [
            struct.pack('>I', len(self.mldsa_signature)),
            self.mldsa_signature,
            struct.pack('>I', len(self.ed25519_signature)),
            self.ed25519_signature,
        ]
        return b''.join(parts)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'CompositeSignature':
        """Deserialize composite signature from length-prefixed format."""
        offset = 0
        
        # Read ML-DSA signature
        if offset + 4 > len(data):
            raise ValueError("Truncated: expected ML-DSA signature length")
        mldsa_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        if offset + mldsa_len > len(data):
            raise ValueError("Truncated: expected ML-DSA signature data")
        mldsa_sig = data[offset:offset + mldsa_len]
        offset += mldsa_len
        
        # Read Ed25519 signature
        if offset + 4 > len(data):
            raise ValueError("Truncated: expected Ed25519 signature length")
        ed25519_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        if offset + ed25519_len > len(data):
            raise ValueError("Truncated: expected Ed25519 signature data")
        ed25519_sig = data[offset:offset + ed25519_len]
        
        return cls(mldsa_signature=mldsa_sig, ed25519_signature=ed25519_sig)


def _compute_message_representative(
    message: bytes,
    context: bytes = b"",
    label: bytes = LABEL_MLDSA65_ED25519
) -> bytes:
    """Compute the pre-hashed message representative M' per draft specification.
    
    M' := Prefix || Label || len(ctx) || ctx || PH(M)
    
    Args:
        message: The message to be signed
        context: Optional context string (max 255 bytes)
        label: Signature label specific to the composite algorithm
        
    Returns:
        The message representative M' ready for signing
    """
    if len(context) > 255:
        raise ValueError("Context length exceeds maximum of 255 bytes")
    
    # PH(M) = SHA2-512(message) - per FIPS 204, ML-DSA uses SHAKE256 but
    # for composite we use SHA2-512 for pre-hashing
    ph = hashlib.sha512(message).digest()
    
    # M' = Prefix || Label || len(ctx) || ctx || PH(M)
    parts = [
        COMPOSITE_PREFIX,
        label,
        bytes([len(context)]),
        context,
        ph,
    ]
    return b''.join(parts)


def generate_composite_keypair() -> Tuple[CompositePublicKey, CompositePrivateKey]:
    """Generate a composite ML-DSA-65 + Ed25519 key pair.
    
    Per draft-ietf-lamps-pq-composite-sigs Section 3.1:
    1. Generate ML-DSA keypair (randomized)
    2. Generate Ed25519 keypair
    3. Serialize both public keys into composite public key
    4. Serialize both private keys into composite private key
    
    Returns:
        (CompositePublicKey, CompositePrivateKey) tuple
    """
    # Generate ML-DSA keypair using liboqs
    mldsa_sig = oqs.Signature('ML-DSA-65')
    mldsa_pk = mldsa_sig.generate_keypair()
    mldsa_sk = mldsa_sig.export_secret_key()
    
    # Generate Ed25519 keypair
    ed25519_priv = ed25519.Ed25519PrivateKey.generate()
    ed25519_pub = ed25519_priv.public_key()
    ed25519_pk_bytes = ed25519_pub.public_bytes_raw()
    
    # Create composite keys
    comp_pk = CompositePublicKey(
        mldsa_public_key=mldsa_pk,
        ed25519_public_key=ed25519_pk_bytes
    )
    comp_sk = CompositePrivateKey(
        mldsa_secret_key=mldsa_sk,
        ed25519_private_key=ed25519_priv
    )
    
    return comp_pk, comp_sk


def composite_sign(
    composite_private_key: CompositePrivateKey,
    message: bytes,
    context: bytes = b""
) -> CompositeSignature:
    """Create a composite signature using both ML-DSA and Ed25519.
    
    Per draft-ietf-lamps-pq-composite-sigs Section 3.2:
    1. Compute message representative M' = Prefix || Label || len(ctx) || ctx || PH(M)
    2. Sign M' with ML-DSA (using the saved secret key)
    3. Sign M' with Ed25519
    4. Combine both signatures into composite signature
    
    Args:
        composite_private_key: Composite private key containing both component keys
        message: Message to sign
        context: Optional context string (max 255 bytes)
        
    Returns:
        CompositeSignature containing both component signatures
    """
    # Compute message representative
    m_prime = _compute_message_representative(message, context)
    
    # Sign with ML-DSA (using the saved secret key)
    mldsa_sig = oqs.Signature('ML-DSA-65')
    mldsa_sig.secret_key = composite_private_key.mldsa_secret_key
    mldsa_signature = mldsa_sig.sign(m_prime)
    
    # Sign with Ed25519 (using the same message representative)
    ed25519_signature = composite_private_key.ed25519_private_key.sign(m_prime)
    
    return CompositeSignature(
        mldsa_signature=mldsa_signature,
        ed25519_signature=ed25519_signature
    )


def composite_verify(
    composite_public_key: CompositePublicKey,
    message: bytes,
    composite_signature: CompositeSignature,
    context: bytes = b""
) -> bool:
    """Verify a composite signature - BOTH components must verify independently.
    
    Per draft-ietf-lamps-pq-composite-sigs Section 3.3:
    1. Compute message representative M' = Prefix || Label || len(ctx) || ctx || PH(M)
    2. Verify ML-DSA signature on M'
    3. Verify Ed25519 signature on M'
    4. Return True ONLY if BOTH verify successfully
    
    This prevents downgrade attacks where an attacker strips one component.
    
    Args:
        composite_public_key: Composite public key containing both component keys
        message: Original message that was signed
        composite_signature: Composite signature to verify
        context: Optional context string (must match signing context)
        
    Returns:
        True if BOTH component signatures verify, False otherwise
    """
    # Compute message representative
    m_prime = _compute_message_representative(message, context)
    
    # Verify ML-DSA component
    mldsa_sig = oqs.Signature('ML-DSA-65')
    mldsa_valid = mldsa_sig.verify(
        m_prime,
        composite_signature.mldsa_signature,
        composite_public_key.mldsa_public_key
    )
    
    # Verify Ed25519 component
    try:
        ed25519_pub = ed25519.Ed25519PublicKey.from_public_bytes(
            composite_public_key.ed25519_public_key
        )
        ed25519_pub.verify(
            composite_signature.ed25519_signature,
            m_prime
        )
        ed25519_valid = True
    except InvalidSignature:
        ed25519_valid = False
    except Exception:
        ed25519_valid = False
    
    # BOTH must verify - no downgrade allowed
    return mldsa_valid and ed25519_valid


def composite_verify_individual(
    composite_public_key: CompositePublicKey,
    message: bytes,
    composite_signature: CompositeSignature,
    context: bytes = b""
) -> Tuple[bool, bool]:
    """Verify composite signature components individually.
    
    Returns:
        Tuple of (mldsa_valid, ed25519_valid) - useful for diagnostics
    """
    m_prime = _compute_message_representative(message, context)
    
    # Verify ML-DSA component
    mldsa_sig = oqs.Signature('ML-DSA-65')
    mldsa_valid = mldsa_sig.verify(
        m_prime,
        composite_signature.mldsa_signature,
        composite_public_key.mldsa_public_key
    )
    
    # Verify Ed25519 component
    try:
        ed25519_pub = ed25519.Ed25519PublicKey.from_public_bytes(
            composite_public_key.ed25519_public_key
        )
        ed25519_pub.verify(
            composite_signature.ed25519_signature,
            m_prime
        )
        ed25519_valid = True
    except InvalidSignature:
        ed25519_valid = False
    except Exception:
        ed25519_valid = False
    
    return mldsa_valid, ed25519_valid