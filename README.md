# pqblocks-wire

A small, length-prefixed binary frame (`PQCWF1`) that carries an ML-KEM ciphertext, an ML-DSA signature, an SLH-DSA signature and a payload, with a strict parser. It also has thin wrappers for ML-KEM / ML-DSA / SLH-DSA key generation, encapsulation and signing, a composite ML-DSA-65 + Ed25519 signature, and an X25519 + ML-KEM-768 hybrid secret.

**When to use it:** you need to move post-quantum ciphertexts and signatures between Python services in one self-describing blob, and you control both ends.

**Standards involved:** the primitives are FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA). This package does not implement them: it calls **liboqs** through **liboqs-python**. X25519 and Ed25519 come from **pyca/cryptography**. The frame format is this package's own and is not an IETF or NIST format.

```bash
pip install git+https://github.com/PQBlocks/pqc-wireformat        # needs the liboqs shared library, see "Requirements"
```

```python
from pqblocks_wire import (generate_mlkem_keypair, encapsulate_mlkem, decapsulate_mlkem,
                           encode_wire_format, decode_wire_format)

pk, sk = generate_mlkem_keypair("ML-KEM-768")
ct, ss_sender = encapsulate_mlkem(pk, "ML-KEM-768")
frame = encode_wire_format(mlkem_ciphertext=ct, payload=b"hello")      # 1109 bytes
received = decode_wire_format(frame)
ss_receiver = decapsulate_mlkem(sk, received.mlkem_ciphertext, "ML-KEM-768")
print(ss_sender == ss_receiver, received.payload)                    # True b'hello'
```

## Requirements

- **Python:** 3.11 to 3.14.
- **Runtime dependencies:**
  - `liboqs-python`, for ML-KEM, ML-DSA and SLH-DSA.
  - `cryptography` (pyca), for X25519 and Ed25519.
- **System library: liboqs.** liboqs-python needs the liboqs shared library. This release was tested with liboqs **0.16.0** and liboqs-python 0.16.0.1.
  - Install liboqs, then point to it: `export OQS_LIB_PATH=/path/to/liboqs.so` (or put it on the system loader path, e.g. `/usr/local/lib` plus `ldconfig`).
  - If liboqs-python cannot find the library, it tries to download and build liboqs itself on first import. That needs git, cmake and a compiler.
- **Optional:** `kyber-py`. It is only needed for `encapsulate_kat_mlkem` and the tests that use it.

## Why

- **One frame, strict parsing.** The decoder rejects:
  - bad magic or an unknown version;
  - truncation at any byte;
  - components above the largest FIPS sizes;
  - trailing bytes.
- **Maintained primitives only.** Every primitive is delegated to liboqs or pyca. No cryptographic algorithm is re-implemented here.
- **Honest test record:** 219 tests (209 pass, 10 skipped), with 98 % statement coverage. With the official vector corpus configured (`PQBLOCKS_VECTORS`), 218 pass and 1 is skipped: the ML-KEM and SLH-DSA tests then compare this package's outputs with the NIST ACVP vectors. [TESTING.md](TESTING.md) says plainly what the tests do **not** check; in particular, no ML-DSA output is compared with a vector.

## Usage

### The frame

```
"PQCWF1" (6 bytes) | version = 0x01 (1 byte) | flags (1 byte)
then, for each flag set, in this fixed order:  u32 big-endian length | bytes
    0x01 ML-KEM ciphertext   (at most 1568 bytes, the ML-KEM-1024 size)
    0x02 ML-DSA signature    (at most 4627 bytes, the ML-DSA-87 size)
    0x04 SLH-DSA signature   (at most 49856 bytes, the largest SLH-DSA size)
    0x08 payload             (any length; an empty payload is not written)
```

- **What the frame does not say:** it carries no algorithm or parameter-set identifier. The receiver must know which parameter set was used.
- **No integrity:** the frame adds no integrity protection. Sign the payload (see `examples/signed_frame.py`), and verify before trusting it.
- **Decoding:** the decoder returns `DecodedWireFormat`. Absent components are `None`, and an absent payload is `b""`.

### Primitives

- **ML-KEM:** `"ML-KEM-512"`, `"ML-KEM-768"`, `"ML-KEM-1024"`.
- **ML-DSA:** `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"`.
- **SLH-DSA:** liboqs names, e.g. `"SLH_DSA_PURE_SHA2_128F"`. There are 12 in total: SHA2 / SHAKE × 128 / 192 / 256 × s / f.
- **Randomness:** all key generation and signing is randomised by liboqs.

### Composite signature and hybrid secret

- **Composite signature:** `composite_sign` signs `M' = "CompositeAlgorithmSignatures2025" || label || len(ctx) || ctx || SHA-512(M)` with both ML-DSA-65 and Ed25519. `composite_verify` is True only if **both** verify.
- **Hybrid secret:** `hybrid_key_exchange_initiator` / `_responder` give both sides `SHA-256(X25519 secret || ML-KEM-768 secret)`.
- See [Limitations](#limitations) before using either.

## API reference

Real signatures from the code. Everything is importable from `pqblocks_wire`.

| Call | Returns / raises |
|---|---|
| `encode_wire_format(mlkem_ciphertext=None, mldsa_signature=None, slhdsa_signature=None, payload=None)` | `bytes`. Raises `TypeError` (non-bytes) and `WireFormatError` (oversize). |
| `decode_wire_format(wire)` | `DecodedWireFormat(mlkem_ciphertext, mldsa_signature, slhdsa_signature, payload, version)`. Raises `WireFormatError` (too short, bad magic, wrong version, truncated, oversize, trailing data) and `TypeError`. |
| `encode_composite_signatures(...)` / `decode_composite_signatures(wire)` | The same format and behaviour as the two calls above, under a second name. |
| `generate_mlkem_keypair(parameter_set)` | `(public_key, secret_key)` |
| `encapsulate_mlkem(public_key, parameter_set)` | `(ciphertext, shared_secret)`, with a 32-byte secret |
| `decapsulate_mlkem(private_key, ciphertext, parameter_set)` | `shared_secret`. Liboqs applies implicit rejection to a bad ciphertext and returns a pseudorandom secret. |
| `generate_mldsa_keypair(ps)`, `sign_mldsa(message, private_key, ps)`, `verify_mldsa(message, signature, public_key, ps)` | `(pk, sk)`, `bytes` and `bool` respectively. Raises `ValueError` for an unknown `ps`. |
| `generate_slhdsa_keypair(ps)`, `sign_slhdsa(message, private_key, ps)`, `verify_slhdsa(message, signature, public_key, ps)` | As for ML-DSA. |
| `MLDSAWrapper` / `SLHDSASignatureWrapper` `.length_public_key(ps)`, `.length_secret_key(ps)`, `.length_signature(ps)` | `int` |
| `generate_composite_keypair()` | `(CompositePublicKey, CompositePrivateKey)` for ML-DSA-65 + Ed25519 |
| `composite_sign(composite_private_key, message, context=b"")` | `CompositeSignature`. `context` is at most 255 bytes. |
| `composite_verify(composite_public_key, message, composite_signature, context=b"")` | `bool`, True only when both parts verify |
| `composite_verify_individual(...)` | `(mldsa_valid, ed25519_valid)` |
| `generate_hybrid_keypair()` | `(HybridPublicKey, HybridPrivateKey)` for X25519 + ML-KEM-768 |
| `hybrid_key_exchange_initiator(x25519_private_key, x25519_public_key, mlkem_public_key)` | `(mlkem_ciphertext, secret)`, with a 32-byte secret |
| `hybrid_key_exchange_responder(x25519_private_key, x25519_public_key, mlkem_private_key, mlkem_ciphertext)` | `secret` (32 bytes) |
| `classical_fallback(x25519_private_key, x25519_public_key)` | 32-byte X25519 secret |
| `HybridPublicKey` / `HybridPrivateKey` / `CompositePublicKey` / `CompositePrivateKey` / `CompositeSignature` | `.serialize()` → `bytes`; `.deserialize(data)` (classmethod). Length-prefixed. |
| `encapsulate_kat_mlkem(public_key, parameter_set, m)` | **Test helper.** Deterministic encapsulation with a caller-chosen `m`. Needs kyber-py. Never use it in production. |
| `hybrid_key_exchange(...)` | **Test helper.** It runs both sides with one party's keys. |
| `mlkem_test_all_operations()`, `mldsa_test_all_operations()`, `slhdsa_test_all_operations()`, `hybrid_test_basic_operations()` | Printing self-tests |

`pqblocks_wire.lane_root_mlkem` is an older, smaller copy of `pqblocks_wire.mlkem` (230 vs 351 lines), kept because the test suite imports it. Do not use it.

## Limitations

- **Partial official-vector testing, off by default.** The vector corpora are not shipped. With `PQBLOCKS_VECTORS` set, ML-KEM key generation, encapsulation and decapsulation are compared byte for byte with the ACVP FIPS 203 vectors, and the SLH-DSA wrapper is run on the ACVP FIPS 205 external/pure vectors with an empty context (36 of the signing and verification vectors, plus all 120 key-generation vectors). SLH-DSA signatures are not compared byte for byte (liboqs signs with fresh randomness), and no ML-DSA output is compared with any vector. Details are in [TESTING.md](TESTING.md).
- **Hybrid secret is a plain hash combiner:**
  - it has no domain-separation label;
  - it does not bind the ciphertext or the public keys;
  - its X25519 half is static-static, so that half has no forward secrecy;
  - it is fixed to ML-KEM-768;
  - it is not X-Wing and not the TLS 1.3 hybrid key schedule.

  Feed it into your own transcript-bound KDF, or use X-Wing.
- **The composite signature does not interoperate with draft-ietf-lamps-pq-composite-sigs.** The label, the ML-DSA context handling and the serialization differ from the draft.
- **No ML-DSA / SLH-DSA context strings:** `sign_mldsa` and `sign_slhdsa` have no `ctx` argument.
- **Secret-key lengths are not checked.** A wrong-length secret key leads to an out-of-bounds read inside liboqs. Pass only keys produced by this package or by liboqs.
- **Not deterministic despite their docstrings:** the private `_keygen_from_seed` / `_sign_from_seed` / `_verify_from_seed` helpers are not seed-deterministic. Do not use them.
- **Import-time output:** importing the package prints `WARNING:` lines to stdout when kyber-py is not installed. liboqs-python itself prints `liboqs-python faulthandler is disabled`.
- **No algorithm id in the frame:** the receiver must already know the parameter sets.

## Security notes

The package handles key material but has had no external audit. It is **not FIPS 140 / CMVP validated**. Read [SECURITY_NOTES.md](SECURITY_NOTES.md) for the review findings: 7 medium and 6 low, none critical or high.

## Verification

[TESTING.md](TESTING.md) · [BENCHMARKS.md](BENCHMARKS.md) · [EVIDENCE.md](EVIDENCE.md) · [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) · [USE_CASES.md](USE_CASES.md) · [SECURITY_NOTES.md](SECURITY_NOTES.md)

## Part of PQBlocks

[PQBlocks](https://github.com/PQBlocks) builds open, tested building blocks for the post-quantum transition. This package is its wire-format and integration layer over maintained post-quantum libraries.
