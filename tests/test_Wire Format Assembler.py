"""Tests for Wire Format Assembler (feature 4) - hybrid wire format encode/decode.

Contract (from spec.md [feature 4]):
- Input: PQC components (ML-KEM ciphertext, ML-DSA signature, etc.)
- Output: Compliant hybrid wire format bytes
- Contract: Round-trip encode/decode preserves all fields exactly
- Tests: test_wire_format_roundtrip(), test_wire_format_malformed()
"""

import pytest

pytest.importorskip("pqblocks_wire")


class TestWireFormatRoundtrip:
    """Round-trip encode/decode must preserve all fields exactly."""

    def test_wire_format_roundtrip_mlkem_only(self):
        """Round-trip with only ML-KEM ciphertext preserves bytes exactly."""
        from pqblocks_wire.wireformat import encode_wire_format, decode_wire_format

        mlkem_ct = bytes(range(256)) * 6  # 1536 bytes ML-KEM-1024 ciphertext size
        wire = encode_wire_format(mlkem_ciphertext=mlkem_ct)

        decoded = decode_wire_format(wire)
        assert decoded.mlkem_ciphertext == mlkem_ct

    def test_wire_format_roundtrip_with_signature(self):
        """Round-trip with ML-DSA signature preserves signature bytes exactly."""
        from pqblocks_wire.wireformat import encode_wire_format, decode_wire_format

        mlkem_ct = b"kem_ciphertext_bytes_1088" * 50  # 1300 bytes
        mldsa_sig = b"mldsa_signature_3309_bytes" * 130

        wire = encode_wire_format(
            mlkem_ciphertext=mlkem_ct,
            mldsa_signature=mldsa_sig,
        )
        decoded = decode_wire_format(wire)
        assert decoded.mldsa_signature == mldsa_sig

    def test_wire_format_roundtrip_all_components(self):
        """Full payload: ML-KEM ct + ML-DSA sig + SLH-DSA sig + payload."""
        from pqblocks_wire.wireformat import encode_wire_format, decode_wire_format

        mlkem_ct = bytes([1, 2, 3, 4]) * 272  # 1088 bytes ML-KEM-768 CT
        mldsa_sig = bytes(range(256)) * 14   # 3584 bytes (ML-DSA-65 sig)
        slhdsa_sig = bytes([7] * 7856)       # SLH-DSA small sig
        payload = b"hello world, pqc wire format"

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

    def test_wire_format_roundtrip_empty_payload_only(self):
        """Encoding with only an empty payload works, decodes to empty."""
        from pqblocks_wire.wireformat import encode_wire_format, decode_wire_format

        wire = encode_wire_format(payload=b"")
        decoded = decode_wire_format(wire)
        assert decoded.payload == b""
        assert decoded.mlkem_ciphertext is None
        assert decoded.mldsa_signature is None
        assert decoded.slhdsa_signature is None

    def test_wire_format_deterministic_encoding(self):
        """Same inputs produce byte-identical wire encodings (canonical form)."""
        from pqblocks_wire.wireformat import encode_wire_format

        mlkem_ct = b"kembytes" * 136  # 1088 bytes
        mldsa_sig = b"sig" * 1103

        w1 = encode_wire_format(mlkem_ciphertext=mlkem_ct, mldsa_signature=mldsa_sig)
        w2 = encode_wire_format(mlkem_ciphertext=mlkem_ct, mldsa_signature=mldsa_sig)
        assert w1 == w2, "Encoding must be canonical/deterministic"

    def test_wire_format_output_is_bytes(self):
        """encode_wire_format returns bytes suitable for network/disk."""
        from pqblocks_wire.wireformat import encode_wire_format

        wire = encode_wire_format(payload=b"data")
        assert isinstance(wire, (bytes, bytearray))


class TestWireFormatMalformed:
    """Malformed/truncated/oversized inputs must raise catchable errors, not crash."""

    def test_wire_format_malformed_truncated(self):
        """Truncated wire format raises a specific decode error."""
        from pqblocks_wire.wireformat import (
            encode_wire_format, decode_wire_format, WireFormatError,
        )

        wire = encode_wire_format(mlkem_ciphertext=b"cut" * 300, payload=b"x" * 100)
        truncated = wire[: len(wire) // 2]
        with pytest.raises(WireFormatError):
            decode_wire_format(truncated)

    def test_wire_format_malformed_bad_magic(self):
        """Bytes without correct magic/header raise WireFormatError."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError

        with pytest.raises(WireFormatError):
            decode_wire_format(b"THIS_IS_NOT_A_WIRE_FORMAT_PACKET")

    def test_wire_format_malformed_oversized_component(self):
        """Oversized ML-KEM ciphertext (per FIPS 203 max 1568 bytes) rejected."""
        from pqblocks_wire.wireformat import encode_wire_format, WireFormatError

        oversized = b"x" * 100_000
        with pytest.raises(WireFormatError):
            encode_wire_format(mlkem_ciphertext=oversized)

    def test_wire_format_malformed_non_bytes_input(self):
        """Non-bytes input fields raise TypeError (defensive parse)."""
        from pqblocks_wire.wireformat import encode_wire_format

        with pytest.raises(TypeError):
            encode_wire_format(mlkem_ciphertext="not bytes")

    def test_wire_format_malformed_empty_bytes(self):
        """Decoding empty input raises WireFormatError, not crash."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError

        with pytest.raises(WireFormatError):
            decode_wire_format(b"")

    def test_wire_format_truncated_at_every_prefix(self):
        """Decode at every truncation boundary never raises a bare Exception."""
        from pqblocks_wire.wireformat import (
            encode_wire_format, decode_wire_format, WireFormatError,
        )

        wire = encode_wire_format(
            mlkem_ciphertext=b"K" * 1088,
            payload=b"payload with some length to make truncation interesting",
        )
        # Walk every byte boundary; successful decodes at any prefix are
        # violations of the length-prefix protocol.
        for i in range(1, len(wire)):
            try:
                decode_wire_format(wire[:i])
            except WireFormatError:
                continue
            # If decode succeeded on a strict prefix, the framing is broken
            pytest.fail(
                f"decode_wire_format succeeded on truncated prefix of {i} bytes"
            )


class TestWireFormatSizeLimits:
    """Wire format size limits per FIPS 203/204/205 maximum sizes."""

    def test_wire_format_max_mlkem_ciphertext(self):
        """ML-KEM-1024 max ciphertext (1568 bytes) is accepted."""
        from pqblocks_wire.wireformat import encode_wire_format, decode_wire_format

        ct = bytes(range(256)) * 6 + bytes(range(32))  # 1568 bytes
        wire = encode_wire_format(mlkem_ciphertext=ct)
        decoded = decode_wire_format(wire)
        assert decoded.mlkem_ciphertext == ct

    def test_wire_format_oversized_mldsa_signature(self):
        """ML-DSA signature beyond 4627 bytes (FIPS 204 max) is rejected."""
        from pqblocks_wire.wireformat import encode_wire_format, WireFormatError

        oversized_sig = b"s" * 5000
        with pytest.raises(WireFormatError):
            encode_wire_format(mldsa_signature=oversized_sig)

    def test_wire_format_oversized_slhdsa_signature(self):
        """SLH-DSA signature beyond 49856 bytes (FIPS 205 max) is rejected."""
        from pqblocks_wire.wireformat import encode_wire_format, WireFormatError

        oversized_sig = b"s" * 50000
        with pytest.raises(WireFormatError):
            encode_wire_format(slhdsa_signature=oversized_sig)


class TestWireFormatComposite:
    """Tests for encode_composite_signatures and decode_composite_signatures."""

    def test_composite_signatures_encode_decode_mlkem_only(self):
        """Composite signatures round-trip with ML-KEM only."""
        from pqblocks_wire.wireformat import (
            encode_composite_signatures, decode_composite_signatures,
        )
        
        mlkem_ct = bytes(range(256)) * 6
        wire = encode_composite_signatures(mlkem_ciphertext=mlkem_ct)
        decoded = decode_composite_signatures(wire)
        assert decoded.mlkem_ciphertext == mlkem_ct
        assert decoded.mldsa_signature is None
        assert decoded.slhdsa_signature is None
        assert decoded.payload == b''

    def test_composite_signatures_encode_decode_all(self):
        """Composite signatures round-trip with all components."""
        from pqblocks_wire.wireformat import (
            encode_composite_signatures, decode_composite_signatures,
        )
        
        mlkem_ct = bytes([1, 2, 3, 4]) * 272
        mldsa_sig = bytes(range(256)) * 14
        slhdsa_sig = bytes([7] * 7856)
        payload = b"composite test payload"
        
        wire = encode_composite_signatures(
            mlkem_ciphertext=mlkem_ct,
            mldsa_signature=mldsa_sig,
            slhdsa_signature=slhdsa_sig,
            payload=payload,
        )
        decoded = decode_composite_signatures(wire)
        assert decoded.mlkem_ciphertext == mlkem_ct
        assert decoded.mldsa_signature == mldsa_sig
        assert decoded.slhdsa_signature == slhdsa_sig
        assert decoded.payload == payload

    def test_composite_signatures_deterministic(self):
        """Composite signatures encoding is deterministic."""
        from pqblocks_wire.wireformat import encode_composite_signatures
        
        mlkem_ct = b"kembytes" * 136
        mldsa_sig = b"sig" * 1103
        
        w1 = encode_composite_signatures(mlkem_ciphertext=mlkem_ct, mldsa_signature=mldsa_sig)
        w2 = encode_composite_signatures(mlkem_ciphertext=mlkem_ct, mldsa_signature=mldsa_sig)
        assert w1 == w2

    def test_composite_signatures_malformed_truncated(self):
        """Truncated composite signatures raises WireFormatError."""
        from pqblocks_wire.wireformat import (
            encode_composite_signatures, decode_composite_signatures, WireFormatError,
        )
        
        wire = encode_composite_signatures(mlkem_ciphertext=b"K" * 1088, payload=b"payload")
        truncated = wire[: len(wire) // 2]
        with pytest.raises(WireFormatError):
            decode_composite_signatures(truncated)

    def test_composite_signatures_bad_magic(self):
        """Bad magic in composite signatures raises WireFormatError."""
        from pqblocks_wire.wireformat import decode_composite_signatures, WireFormatError
        
        with pytest.raises(WireFormatError):
            decode_composite_signatures(b"BAD_MAGIC")

    def test_composite_signatures_oversized_mlkem(self):
        """Oversized ML-KEM in composite signatures rejected."""
        from pqblocks_wire.wireformat import encode_composite_signatures, WireFormatError
        
        oversized = b"x" * 100_000
        with pytest.raises(WireFormatError):
            encode_composite_signatures(mlkem_ciphertext=oversized)

    def test_composite_signatures_oversized_mldsa(self):
        """Oversized ML-DSA in composite signatures rejected."""
        from pqblocks_wire.wireformat import encode_composite_signatures, WireFormatError
        
        oversized = b"s" * 5000
        with pytest.raises(WireFormatError):
            encode_composite_signatures(mldsa_signature=oversized)

    def test_composite_signatures_oversized_slhdsa(self):
        """Oversized SLH-DSA in composite signatures rejected."""
        from pqblocks_wire.wireformat import encode_composite_signatures, WireFormatError
        
        oversized = b"s" * 50000
        with pytest.raises(WireFormatError):
            encode_composite_signatures(slhdsa_signature=oversized)

    def test_composite_signatures_non_bytes(self):
        """Non-bytes input to composite signatures raises TypeError."""
        from pqblocks_wire.wireformat import encode_composite_signatures
        
        with pytest.raises(TypeError):
            encode_composite_signatures(mlkem_ciphertext="not bytes")

    def test_composite_signatures_empty_decode(self):
        """Empty input to decode_composite_signatures raises WireFormatError."""
        from pqblocks_wire.wireformat import decode_composite_signatures, WireFormatError
        
        with pytest.raises(WireFormatError):
            decode_composite_signatures(b"")


class TestWireFormatDecodeErrors:
    """Additional decode error path tests for wireformat."""

    def test_decode_wrong_version(self):
        """Decode with unsupported version raises WireFormatError."""
        from pqblocks_wire.wireformat import (
            encode_wire_format, decode_wire_format, WireFormatError, MAGIC, VERSION, FLAG_PAYLOAD
        )
        import struct
        
        # Create wire with wrong version
        payload = b"test"
        parts = [MAGIC, bytes([99]), bytes([FLAG_PAYLOAD])]  # version 99
        parts.append(struct.pack('>I', len(payload)))
        parts.append(payload)
        bad_wire = b''.join(parts)
        
        with pytest.raises(WireFormatError):
            decode_wire_format(bad_wire)

    def test_decode_trailing_garbage(self):
        """Trailing data after decode raises WireFormatError."""
        from pqblocks_wire.wireformat import (
            encode_wire_format, decode_wire_format, WireFormatError,
        )
        
        wire = encode_wire_format(payload=b"test")
        with pytest.raises(WireFormatError):
            decode_wire_format(wire + b"garbage")

    def test_decode_truncated_length(self):
        """Truncated length field raises WireFormatError."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError
        
        # Just magic + version + flags + partial length
        truncated = b'PQCWF1\x01\x01\x00\x00'  # 9 bytes, need 10 for length
        with pytest.raises(WireFormatError):
            decode_wire_format(truncated)

    def test_decode_truncated_data(self):
        """Truncated component data raises WireFormatError."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError
        import struct
        
        # Magic + version + flags + length=100 but only 50 bytes data
        parts = [b'PQCWF1', b'\x01', b'\x01']  # FLAG_MLKEM
        parts.append(struct.pack('>I', 100))
        parts.append(b'x' * 50)  # Only 50 bytes, need 100
        truncated = b''.join(parts)
        with pytest.raises(WireFormatError):
            decode_wire_format(truncated)

    def test_decode_mlkem_exceeds_max(self):
        """ML-KEM ciphertext exceeding max raises WireFormatError on decode."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError, MAGIC, VERSION, FLAG_MLKEM
        import struct
        
        # Create wire with oversized ML-KEM (2000 bytes > 1568 max)
        parts = [MAGIC, bytes([VERSION]), bytes([FLAG_MLKEM])]
        parts.append(struct.pack('>I', 2000))
        parts.append(b'x' * 2000)
        wire = b''.join(parts)
        with pytest.raises(WireFormatError):
            decode_wire_format(wire)

    def test_decode_mldsa_exceeds_max(self):
        """ML-DSA signature exceeding max raises WireFormatError on decode."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError, MAGIC, VERSION, FLAG_MLDSA
        import struct
        
        # Create wire with oversized ML-DSA (5000 bytes > 4627 max)
        parts = [MAGIC, bytes([VERSION]), bytes([FLAG_MLDSA])]
        parts.append(struct.pack('>I', 5000))
        parts.append(b'x' * 5000)
        wire = b''.join(parts)
        with pytest.raises(WireFormatError):
            decode_wire_format(wire)

    def test_decode_slhdsa_exceeds_max(self):
        """SLH-DSA signature exceeding max raises WireFormatError on decode."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError, MAGIC, VERSION, FLAG_SLHDSA
        import struct
        
        # Create wire with oversized SLH-DSA (50000 bytes > 49856 max)
        parts = [MAGIC, bytes([VERSION]), bytes([FLAG_SLHDSA])]
        parts.append(struct.pack('>I', 50000))
        parts.append(b'x' * 50000)
        wire = b''.join(parts)
        with pytest.raises(WireFormatError):
            decode_wire_format(wire)

    def test_decode_non_bytes_input(self):
        """Non-bytes input to decode_wire_format raises TypeError."""
        from pqblocks_wire.wireformat import decode_wire_format
        
        with pytest.raises(TypeError):
            decode_wire_format("not bytes")

    def test_decode_empty_input(self):
        """Empty input to decode_wire_format raises WireFormatError."""
        from pqblocks_wire.wireformat import decode_wire_format, WireFormatError
        
        with pytest.raises(WireFormatError):
            decode_wire_format(b"")
