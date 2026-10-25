# Security notes: pqblocks-wire

## What this package protects, and what it does not

- **The frame is a container, not a security mechanism.** `encode_wire_format` / `decode_wire_format` give no confidentiality, integrity, authenticity or replay protection. The receiver must verify the signatures in the frame over the payload, and must use the ML-KEM shared secret with an AEAD, before trusting anything.
- **No algorithm identifier.** The frame carries no algorithm or parameter-set identifier. The receiver must fix the expected parameter sets out of band; otherwise algorithm confusion is the caller's problem.
- **Parsing hostile frames.** The decoder is strict about structure: magic, version, truncation, size caps, trailing bytes. It does not reject unknown flag bits, though, and it accepts a flagged empty payload, so two byte strings can decode to equal values. Do not use the raw frame bytes as a unique identifier.
- **Security comes from the libraries.** The security of ML-KEM, ML-DSA, SLH-DSA, X25519 and Ed25519 is that of liboqs and pyca/cryptography. This package adds no cryptographic strength.

## Backend

| Primitive | Backend |
|---|---|
| ML-KEM, ML-DSA, SLH-DSA | **liboqs** (C) through **liboqs-python**. Tested with liboqs 0.16.0 and liboqs-python 0.16.0.1. |
| X25519, Ed25519 | **pyca/cryptography** (OpenSSL / Rust). Tested with 50.0.2. |
| SHA-256, SHA-512 | Python `hashlib` |
| Deterministic ML-KEM encapsulation (test helper only) | kyber-py, pure Python, optional |

The package needs the liboqs shared library at runtime. Set `OQS_LIB_PATH`, or install liboqs on the loader path. Without it, liboqs-python tries to download and build liboqs on first import.

## Constant-time status

- **Not claimed for this package's own code.** It only handles public-length framing and calls into the libraries.
- **Library code:** constant-time properties are those of liboqs and pyca.
- **Comparisons:** `composite_verify` / `verify_*` return library results; there are no secret-dependent comparisons in Python.
- **kyber-py:** the kyber-py test helper is not constant-time.

## Zeroization

**None.**
- Secret keys are returned and stored as immutable Python `bytes`, which cannot be wiped.
- The `oqs` objects created per call are never `free()`d, so liboqs' `OQS_MEM_cleanse` is not called on their buffers.
- Treat process memory as holding key material.

## Randomness

- **Key generation, encapsulation and signing:** liboqs (OS RNG) and pyca.
- **No seedable RNG:** the package does not expose a seedable RNG.
- **The one exception: `encapsulate_kat_mlkem(public_key, parameter_set, m)`.** It is exported at package level and uses a **caller-chosen** `m`, so a fixed `m` gives a predictable shared secret. It exists for tests; never call it in production.

## Review findings (internal crypto-integration review, 2026-10-25)

There are no critical and no high findings. The open items are below; none was fixed in 0.1.0.

**Medium**
1. **Secret-key length is not validated.**
   - *Affected calls:* `decapsulate_mlkem`, `sign_mldsa`, `sign_slhdsa`, `composite_sign`, `hybrid_key_exchange_responder`.
   - *Effect:* the raw key bytes go straight to liboqs, which reads the full secret-key length. A too-short key causes an **out-of-bounds read** of process memory, and the call may still "succeed". For example, `sign_mldsa` with a 10-byte key returns a signature.
   - *Who can trigger it:* public keys, ciphertexts and signatures from a peer are copied into fixed-size buffers and are not affected. Only your own secret-key input can trigger this.
   - *What to do:* pass only keys produced by this package or liboqs, and check `len(sk) == MLDSAWrapper.length_secret_key(ps)` (and the equivalents) yourself.
2. **The `_from_seed` helpers are not deterministic.** `MLDSAWrapper` / `SLHDSASignatureWrapper` `._keygen_from_seed`, `._sign_from_seed` and `._verify_from_seed` are documented as seed-deterministic but are not. `_sign_from_seed` also uses the seed as a secret key, which is out-of-bounds (see item 1). These are private helpers; do not call them.
3. **The hybrid combiner is a plain hash.** It computes `SHA-256(ss_X25519 || ss_ML-KEM-768)`:
   - it has no domain-separation label;
   - it does not bind the ciphertext or the public keys;
   - its X25519 half is static-static (no forward secrecy for the classical half);
   - it is fixed to ML-KEM-768.

   Feed the result into a transcript-bound KDF, or use X-Wing.
4. **`hybrid_key_exchange()` is a testing function that is easy to misuse.** It runs both sides with one party's ML-KEM keys, so a peer cannot derive the same secret. Use the `_initiator` / `_responder` pair.
5. **`encapsulate_kat_mlkem` is a deterministic, caller-seeded encapsulation** in the public namespace (see Randomness).
6. **Secret keys appear in `repr`.** `repr()` of `HybridPrivateKey` and `CompositePrivateKey` prints the ML-KEM / ML-DSA secret-key bytes. Do not log these objects.
7. **No zeroization** (see above).

**Low**
1. **Frames are not canonical.** Unknown flag bits are ignored, a flagged empty payload is accepted, and the frame has no algorithm id.
2. **Containers accept trailing bytes.** `HybridPublicKey` / `HybridPrivateKey` / `CompositePublicKey` / `CompositePrivateKey` / `CompositeSignature` `.deserialize` accept trailing bytes and do not check component lengths.
3. **An oversize ML-DSA public key raises.** `composite_verify` raises `ValueError` on an oversize ML-DSA public key instead of returning `False`. This fails closed and is not a bypass.
4. **The composite signature does not interoperate** with draft-ietf-lamps-pq-composite-sigs: the label, the ML-DSA context and the serialization all differ. Downgrade protection is correct: both parts must verify.
5. **Import-time warnings.** Missing optional backends print `WARNING:` lines to stdout at import time.
6. **No context strings.** ML-DSA / SLH-DSA context strings (`ctx`) are not supported.

## Dependencies

- **Runtime:** `cryptography` and `liboqs-python`, plus the liboqs C library.
- **Tests:** `pytest`, and optionally `kyber-py`.
- **Audit:** `pip-audit` at build time reported no known vulnerabilities in cryptography 50.0.2 and liboqs-python 0.16.0.1.

## Audit status and validation

- **Audit:** self-verified only, through the test suite, an internal adversarial review and the crypto-integration review above. There has been no external third-party audit.
- **Validation:** not FIPS 140-3 / CMVP validated, and liboqs is not a validated module.
