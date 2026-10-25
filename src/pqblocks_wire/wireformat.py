"""Wire Format Assembler for PQC Hybrid Operations.

This module provides encoding and decoding of hybrid PQC wire formats
containing ML-KEM ciphertexts, ML-DSA signatures, SLH-DSA signatures,
and arbitrary payloads.

The format is a self-describing, length-prefixed binary format:
- Magic: b'PQCWF1' (6 bytes)
- Version: 1 byte (currently 1)
- Flags: 1 byte (bitmask indicating which components present)
- For each present component: length (4 bytes big-endian) + data
- Payload: length (4 bytes big-endian) + data (optional, may be empty)
"""

from dataclasses import dataclass
from typing import Optional
import struct


# Wire format constants
MAGIC = b'PQCWF1'
VERSION = 1
MAX_MLKEM_CIPHERTEXT = 1568    # FIPS 203 ML-KEM-1024 max
MAX_MLDSA_SIGNATURE = 4627     # FIPS 204 ML-DSA-87 max
MAX_SLHDSA_SIGNATURE = 49856   # FIPS 205 SLH-DSA max

# Flag bits
FLAG_MLKEM = 0x01
FLAG_MLDSA = 0x02
FLAG_SLHDSA = 0x04
FLAG_PAYLOAD = 0x08


class WireFormatError(Exception):
    """Raised when wire format encoding/decoding fails."""
    pass


@dataclass
class DecodedWireFormat:
    """Decoded wire format components."""
    mlkem_ciphertext: Optional[bytes] = None
    mldsa_signature: Optional[bytes] = None
    slhdsa_signature: Optional[bytes] = None
    payload: Optional[bytes] = None
    version: int = VERSION


def encode_wire_format(
    mlkem_ciphertext: Optional[bytes] = None,
    mldsa_signature: Optional[bytes] = None,
    slhdsa_signature: Optional[bytes] = None,
    payload: Optional[bytes] = None,
) -> bytes:
    """Encode PQC components into hybrid wire format bytes.

    Args:
        mlkem_ciphertext: ML-KEM ciphertext (max 1568 bytes per FIPS 203)
        mldsa_signature: ML-DSA signature (max 4627 bytes per FIPS 204)
        slhdsa_signature: SLH-DSA signature (max 49856 bytes per FIPS 205)
        payload: Arbitrary payload data

    Returns:
        Encoded wire format bytes

    Raises:
        WireFormatError: If component sizes exceed FIPS maximums
        TypeError: If inputs are not bytes
    """
    # Validate input types
    for name, value in [
        ("mlkem_ciphertext", mlkem_ciphertext),
        ("mldsa_signature", mldsa_signature),
        ("slhdsa_signature", slhdsa_signature),
        ("payload", payload),
    ]:
        if value is not None and not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes, got {type(value).__name__}")

    # Validate size limits per FIPS specs
    if mlkem_ciphertext is not None and len(mlkem_ciphertext) > MAX_MLKEM_CIPHERTEXT:
        raise WireFormatError(
            f"ML-KEM ciphertext exceeds FIPS 203 maximum of {MAX_MLKEM_CIPHERTEXT} bytes: "
            f"got {len(mlkem_ciphertext)} bytes"
        )
    if mldsa_signature is not None and len(mldsa_signature) > MAX_MLDSA_SIGNATURE:
        raise WireFormatError(
            f"ML-DSA signature exceeds FIPS 204 maximum of {MAX_MLDSA_SIGNATURE} bytes: "
            f"got {len(mldsa_signature)} bytes"
        )
    if slhdsa_signature is not None and len(slhdsa_signature) > MAX_SLHDSA_SIGNATURE:
        raise WireFormatError(
            f"SLH-DSA signature exceeds FIPS 205 maximum of {MAX_SLHDSA_SIGNATURE} bytes: "
            f"got {len(slhdsa_signature)} bytes"
        )

    # Build flag byte
    flags = 0
    if mlkem_ciphertext is not None:
        flags |= FLAG_MLKEM
    if mldsa_signature is not None:
        flags |= FLAG_MLDSA
    if slhdsa_signature is not None:
        flags |= FLAG_SLHDSA
    if payload is not None and len(payload) > 0:
        flags |= FLAG_PAYLOAD

    # Build the wire format
    parts = [MAGIC, bytes([VERSION]), bytes([flags])]

    def add_component(data: bytes):
        parts.append(struct.pack('>I', len(data)))
        parts.append(data)

    if mlkem_ciphertext is not None:
        add_component(mlkem_ciphertext)
    if mldsa_signature is not None:
        add_component(mldsa_signature)
    if slhdsa_signature is not None:
        add_component(slhdsa_signature)
    if payload is not None and len(payload) > 0:
        add_component(payload)

    return b''.join(parts)


def decode_wire_format(wire: bytes) -> DecodedWireFormat:
    """Decode hybrid wire format bytes back into components.

    Args:
        wire: Wire format bytes to decode

    Returns:
        DecodedWireFormat with extracted components

    Raises:
        WireFormatError: If wire format is malformed, truncated, or invalid
    """
    if not isinstance(wire, (bytes, bytearray)):
        raise TypeError(f"wire must be bytes, got {type(wire).__name__}")

    if len(wire) < 8:  # MAGIC (6) + VERSION (1) + FLAGS (1)
        raise WireFormatError(
            f"Wire format too short: {len(wire)} bytes, minimum 8"
        )

    # Check magic
    if wire[:6] != MAGIC:
        raise WireFormatError(
            f"Invalid magic bytes: expected {MAGIC!r}, got {wire[:6]!r}"
        )

    version = wire[6]
    if version != VERSION:
        raise WireFormatError(
            f"Unsupported wire format version: {version} (expected {VERSION})"
        )

    flags = wire[7]
    offset = 8

    def read_component() -> bytes:
        nonlocal offset
        if offset + 4 > len(wire):
            raise WireFormatError("Truncated: expected component length")
        length = struct.unpack('>I', wire[offset:offset + 4])[0]
        offset += 4
        if offset + length > len(wire):
            raise WireFormatError(
                f"Truncated: expected {length} bytes of component data"
            )
        data = wire[offset:offset + length]
        offset += length
        return data

    result = DecodedWireFormat(version=version)

    if flags & FLAG_MLKEM:
        result.mlkem_ciphertext = read_component()
        if len(result.mlkem_ciphertext) > MAX_MLKEM_CIPHERTEXT:
            raise WireFormatError(
                f"ML-KEM ciphertext exceeds maximum: "
                f"{len(result.mlkem_ciphertext)} > {MAX_MLKEM_CIPHERTEXT}"
            )

    if flags & FLAG_MLDSA:
        result.mldsa_signature = read_component()
        if len(result.mldsa_signature) > MAX_MLDSA_SIGNATURE:
            raise WireFormatError(
                f"ML-DSA signature exceeds maximum: "
                f"{len(result.mldsa_signature)} > {MAX_MLDSA_SIGNATURE}"
            )

    if flags & FLAG_SLHDSA:
        result.slhdsa_signature = read_component()
        if len(result.slhdsa_signature) > MAX_SLHDSA_SIGNATURE:
            raise WireFormatError(
                f"SLH-DSA signature exceeds maximum: "
                f"{len(result.slhdsa_signature)} > {MAX_SLHDSA_SIGNATURE}"
            )

    if flags & FLAG_PAYLOAD:
        result.payload = read_component()
    else:
        result.payload = b''

    # Ensure no trailing garbage
    if offset != len(wire):
        raise WireFormatError(
            f"Trailing data after decode: {len(wire) - offset} bytes remaining"
        )

    return result


def wireformat_test_roundtrip() -> None:
    """Test round-trip encoding/decoding."""
    # Test ML-KEM only
    ct = bytes(range(256)) * 6
    wire = encode_wire_format(mlkem_ciphertext=ct)
    decoded = decode_wire_format(wire)
    assert decoded.mlkem_ciphertext == ct

    # Test with all components
    mlkem_ct = bytes([1, 2, 3, 4]) * 272
    mldsa_sig = bytes(range(256)) * 18
    slhdsa_sig = bytes([7] * 7856)
    payload = b"test payload"

    wire = encode_wire_format(
        mlkem_ciphertext=mlkem_ct,
        mldsa_signature=mldsa_sig,
        slhdsa_signature=slhdsa_sig,
        payload=payload,
    )
    decoded = decode_wire_format(wire)
    assert decoded.mlkem_ciphertext == mlkem_ct
    assert decoded.mldsa_signature == mldsa_sig
    assert decoded.slhdsa_signature == slhdsa_sig
    assert decoded.payload == payload

    print("✅ Wire format round-trip tests passed!")


def encode_composite_signatures(
    mlkem_ciphertext: Optional[bytes] = None,
    mldsa_signature: Optional[bytes] = None,
    slhdsa_signature: Optional[bytes] = None,
    payload: Optional[bytes] = None,
) -> bytes:
    """Encode multiple PQC signatures into a composite wire format.
    
    This implements feature 5 Composite Signature Logic, allowing multiple
    signature algorithms (ML-KEM, ML-DSA, SLH-DSA) to be encoded together
    into a single wire format packet.
    
    Args:
        mlkem_ciphertext: ML-KEM ciphertext (max 1568 bytes per FIPS 203)
        mldsa_signature: ML-DSA signature (max 4627 bytes per FIPS 204)
        slhdsa_signature: SLH-DSA signature (max 49856 bytes per FIPS 205)
        payload: Arbitrary payload data
        
    Returns:
        Encoded wire format bytes containing all components
        
    Raises:
        WireFormatError: If component sizes exceed FIPS maximums
    """
    # Validate input types
    for name, value in [
        ("mlkem_ciphertext", mlkem_ciphertext),
        ("mldsa_signature", mldsa_signature),
        ("slhdsa_signature", slhdsa_signature),
        ("payload", payload),
    ]:
        if value is not None and not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes, got {type(value).__name__}")

    # Validate size limits per FIPS specs
    if mlkem_ciphertext is not None and len(mlkem_ciphertext) > MAX_MLKEM_CIPHERTEXT:
        raise WireFormatError(
            f"ML-KEM ciphertext exceeds FIPS 203 maximum of {MAX_MLKEM_CIPHERTEXT} bytes: "
            f"got {len(mlkem_ciphertext)} bytes"
        )
    if mldsa_signature is not None and len(mldsa_signature) > MAX_MLDSA_SIGNATURE:
        raise WireFormatError(
            f"ML-DSA signature exceeds FIPS 204 maximum of {MAX_MLDSA_SIGNATURE} bytes: "
            f"got {len(mldsa_signature)} bytes"
        )
    if slhdsa_signature is not None and len(slhdsa_signature) > MAX_SLHDSA_SIGNATURE:
        raise WireFormatError(
            f"SLH-DSA signature exceeds FIPS 205 maximum of {MAX_SLHDSA_SIGNATURE} bytes: "
            f"got {len(slhdsa_signature)} bytes"
        )

    # Build flag byte with all present components
    flags = 0
    if mlkem_ciphertext is not None:
        flags |= FLAG_MLKEM
    if mldsa_signature is not None:
        flags |= FLAG_MLDSA
    if slhdsa_signature is not None:
        flags |= FLAG_SLHDSA
    if payload is not None and len(payload) > 0:
        flags |= FLAG_PAYLOAD

    # Build the wire format
    parts = [MAGIC, bytes([VERSION]), bytes([flags])]

    def add_component(data: bytes):
        parts.append(struct.pack('>I', len(data)))
        parts.append(data)

    if mlkem_ciphertext is not None:
        add_component(mlkem_ciphertext)
    if mldsa_signature is not None:
        add_component(mldsa_signature)
    if slhdsa_signature is not None:
        add_component(slhdsa_signature)
    if payload is not None and len(payload) > 0:
        add_component(payload)

    return b''.join(parts)


def decode_composite_signatures(wire: bytes) -> DecodedWireFormat:
    """Decode composite wire format back into components.
    
    Args:
        wire: Wire format bytes containing multiple signatures
        
    Returns:
        DecodedWireFormat with extracted components
        
    Raises:
        WireFormatError: If wire format is malformed or component sizes exceed limits
    """
    if not isinstance(wire, (bytes, bytearray)):
        raise TypeError(f"wire must be bytes, got {type(wire).__name__}")

    if len(wire) < 8:  # MAGIC (6) + VERSION (1) + FLAGS (1)
        raise WireFormatError(
            f"Wire format too short: {len(wire)} bytes, minimum 8"
        )

    # Check magic
    if wire[:6] != MAGIC:
        raise WireFormatError(
            f"Invalid magic bytes: expected {MAGIC!r}, got {wire[:6]!r}"
        )

    version = wire[6]
    if version != VERSION:
        raise WireFormatError(
            f"Unsupported wire format version: {version} (expected {VERSION})"
        )

    flags = wire[7]
    offset = 8

    def read_component() -> bytes:
        nonlocal offset
        if offset + 4 > len(wire):
            raise WireFormatError("Truncated: expected component length")
        length = struct.unpack('>I', wire[offset:offset + 4])[0]
        offset += 4
        if offset + length > len(wire):
            raise WireFormatError(
                f"Truncated: expected {length} bytes of component data"
            )
        data = wire[offset:offset + length]
        offset += length
        return data

    result = DecodedWireFormat(version=version)

    if flags & FLAG_MLKEM:
        result.mlkem_ciphertext = read_component()
        if len(result.mlkem_ciphertext) > MAX_MLKEM_CIPHERTEXT:
            raise WireFormatError(
                f"ML-KEM ciphertext exceeds maximum: "
                f"{len(result.mlkem_ciphertext)} > {MAX_MLKEM_CIPHERTEXT}"
            )

    if flags & FLAG_MLDSA:
        result.mldsa_signature = read_component()
        if len(result.mldsa_signature) > MAX_MLDSA_SIGNATURE:
            raise WireFormatError(
                f"ML-DSA signature exceeds maximum: "
                f"{len(result.mldsa_signature)} > {MAX_MLDSA_SIGNATURE}"
            )

    if flags & FLAG_SLHDSA:
        result.slhdsa_signature = read_component()
        if len(result.slhdsa_signature) > MAX_SLHDSA_SIGNATURE:
            raise WireFormatError(
                f"SLH-DSA signature exceeds maximum: "
                f"{len(result.slhdsa_signature)} > {MAX_SLHDSA_SIGNATURE}"
            )

    if flags & FLAG_PAYLOAD:
        result.payload = read_component()
    else:
        result.payload = b''

    # Ensure no trailing garbage
    if offset != len(wire):
        raise WireFormatError(
            f"Trailing data after decode: {len(wire) - offset} bytes remaining"
        )

    return result


if __name__ == "__main__":
    wireformat_test_roundtrip()