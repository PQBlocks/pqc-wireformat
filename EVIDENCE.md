# Evidence: pqblocks-wire

This file lists where each part of the package comes from and how the code maps to it. The package implements **no cryptographic primitive**. It assembles and parses bytes, and calls maintained libraries for everything else.

## Primary sources

1. NIST. *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard.* 13 August 2024. doi:[10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203). Source of the ML-KEM parameter sets and the ciphertext sizes (768 / 1088 / 1568 bytes).
2. NIST. *FIPS 204: Module-Lattice-Based Digital Signature Standard.* 13 August 2024. doi:[10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204). Source of the ML-DSA parameter sets and the signature sizes (2420 / 3309 / 4627 bytes).
3. NIST. *FIPS 205: Stateless Hash-Based Digital Signature Standard.* 13 August 2024. doi:[10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205). Source of the SLH-DSA parameter sets, the largest signature (49,856 bytes, SLH-DSA-*-256f) and the 17,088-byte SHA2-128f signature.
4. M. Ounsworth, J. Gray, M. Pala, J. Klaussner, S. Fluhrer. *Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for use in X.509 Public Key Infrastructure*, draft-ietf-lamps-pq-composite-sigs-19 (21 April 2026). https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/. Source of the message representative `M' = Prefix || Label || len(ctx) || ctx || PH(M)` and the prefix string. This package follows its shape but is **not wire-compatible** with it (see the map below).
5. RFC 9881. J. Massimo, P. Kampanakis, S. Turner, B. E. Westerbaan. *Internet X.509 Public Key Infrastructure -- Algorithm Identifiers for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA)*, October 2025. https://www.rfc-editor.org/rfc/rfc9881. Background only: this package produces no X.509 certificate structures, OIDs or ASN.1.
6. D. Connolly, P. Schwabe, B. E. Westerbaan. *X-Wing: general-purpose hybrid post-quantum KEM*, draft-connolly-cfrg-xwing-kem-11 (23 September 2026). https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/11/. Cited as the reference hybrid combiner that this package's simpler combiner does **not** follow.
7. *Hybrid key exchange in TLS 1.3*, draft-ietf-tls-hybrid-design (IETF TLS working group). https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/. Concatenation of the shared secrets inside the TLS key schedule. Here the concatenation is hashed directly, with no transcript.
8. RFC 7748 (X25519), https://www.rfc-editor.org/rfc/rfc7748, and RFC 8032 (Ed25519), https://www.rfc-editor.org/rfc/rfc8032. Both are provided by pyca/cryptography.

DOIs 1 to 3 were confirmed through `api.crossref.org/works/<doi>` on 2026-10-25. URLs 4 to 8 returned HTTP 200 on the same day.

## Libraries that do the cryptography

| Function | Library | Calls made |
|---|---|---|
| ML-KEM-512/768/1024 keygen, encaps, decaps | liboqs via liboqs-python (`oqs.KeyEncapsulation`) | `generate_keypair`, `export_secret_key`, `encap_secret`, `decap_secret` |
| ML-DSA-44/65/87, SLH-DSA (12 sets) keygen, sign, verify | liboqs via liboqs-python (`oqs.Signature`) | `generate_keypair`, `sign`, `verify` |
| X25519, Ed25519, PKCS#8 PEM for the Ed25519 key | pyca/cryptography | `X25519PrivateKey.generate/exchange`, `Ed25519PrivateKey.generate/sign`, `Ed25519PublicKey.verify` |
| SHA-256 (hybrid combiner), SHA-512 (composite pre-hash) | Python `hashlib` | |
| Deterministic ML-KEM encapsulation (test helper only) | kyber-py, optional | `ML_KEM_*._encaps_internal` |

`mlkem.py` also tries to import `cryptography.hazmat.primitives.asymmetric.mlkem` and sets a flag. **No code path uses it:** every ML-KEM operation goes through liboqs. Older project documents described a pyca ML-KEM path; the code is authoritative.

## Method to code

| Element | Source | Implementation |
|---|---|---|
| Frame header | own design | `wireformat.py`: `MAGIC = b"PQCWF1"`, `VERSION = 1`, flag bits 0x01 / 0x02 / 0x04 / 0x08 |
| Component framing | own design | u32 big-endian length + bytes, in fixed order: ML-KEM, ML-DSA, SLH-DSA, payload |
| Size caps | FIPS 203/204/205 maximum sizes | `MAX_MLKEM_CIPHERTEXT = 1568`, `MAX_MLDSA_SIGNATURE = 4627`, `MAX_SLHDSA_SIGNATURE = 49856`, enforced on encode and decode |
| Strict decode | own design | rejects short input, bad magic, other versions, truncated length or data, oversize components and trailing bytes. Does **not** reject unknown flag bits. |
| Composite message representative | draft-19 §2.2 and §3.2 | `_compute_message_representative`: `"CompositeAlgorithmSignatures2025" || b"ML-DSA-65+Ed25519" || len(ctx) || ctx || SHA-512(M)` |
| Composite differences from draft-19 | | label is `ML-DSA-65+Ed25519`, not `COMPSIG-MLDSA65-Ed25519-SHA512`; ML-DSA signs with an empty context, not `ctx = Label`; the signature value is length-prefixed, not `mldsaSig || tradSig` |
| Composite verify | draft-19 §3.3 (both must verify) | `composite_verify` returns `mldsa_valid and ed25519_valid` |
| Hybrid secret | own construction | `SHA-256(X25519(sk, pk) || ML-KEM-768 shared secret)`, 32 bytes (`hybrid.py`). Older documents said "64 bytes, concatenated"; the code is authoritative. |

## Where older project documents and the code disagree (the code wins)

- **Wrong framing:** early drafts described the package as a "classical algorithm" tested against FIPS 203/204/205. It is a wire-format and wrapper layer over liboqs and pyca, and it has no third-party accreditation or CMVP validation of any kind.
- **"All official vectors pass":** not true as stated. Until this correction the vector tests compared no output with any vector; now, with `PQBLOCKS_VECTORS` set, ML-KEM and the empty-context pure SLH-DSA ACVP vectors are checked, and ML-DSA is not. See [TESTING.md](TESTING.md).
- **Context strings:** ML-DSA was said to support context strings. `sign_mldsa` / `verify_mldsa` take no context argument.
- **Composite keygen arguments:** `generate_composite_keypair` takes no arguments and is fixed to ML-DSA-65 + Ed25519.

## Licence and provenance

- **Code:** Apache-2.0. No third-party cryptographic code is vendored.
- **Runtime dependencies:** cryptography (Apache-2.0 / BSD) and liboqs-python (MIT), with liboqs (MIT).
- **Optional test dependency:** kyber-py (MIT).
