# Verification report: pqblocks-wire 0.1.0

This is a **self-verification** report: what was checked, how, and with what result. It is not a third-party audit or external validation of any kind.

## Summary

| Area | Result |
|---|---|
| Correctness | 209/219 tests pass (10 skipped); with the official vector corpus configured, 218 pass and 1 is skipped, and ML-KEM outputs match the ACVP FIPS 203 vectors byte for byte. ML-DSA outputs are not compared with any vector. |
| Coverage | 98 % statements (1051 statements total) |
| Install as a user gets it | Wheel installed from scratch with PyPI dependencies on Python 3.11, 3.12, 3.13 and 3.14: all tests and examples pass |
| Packaging | sdist and wheel build cleanly; `twine check --strict` passes |
| Dependencies | `pip-audit`: no known vulnerabilities. Dependencies resolved at release: `cryptography` 50.0.2, `liboqs-python` 0.16.0.1. |
| Crypto review | Independent read-only review completed: 0 CRITICAL, 0 HIGH, 7 MEDIUM and 6 LOW (all disclosed in SECURITY_NOTES.md) |
| Scope honesty | Wraps liboqs C library and pyca; does not implement raw polynomial arithmetic itself |

## Review checks completed before release

| Check | Purpose | Result |
|---|---|---|
| Check 1 (design review) | Frame layout, KEM, DSA and composite signature semantics specified | Pass |
| Check 2 (spec review) | Specification complete, typed exceptions, offset-based parsing (each component is returned as a copy) | Pass |
| Check 3 (correctness) | Test suite, roundtrips, tampered payload rejection, coverage | Pass (209/219, 98 %) |
| Check 4 (benchmark review) | Timings of the public calls on one machine; raw data matches the summary; no baseline was run | Pass ([BENCHMARKS.md](BENCHMARKS.md)) |
| Check 5 (adversarial review) | Hostile frames (truncation, oversize components, bad magic or version, trailing bytes) raise `WireFormatError`; unknown flag bits are ignored | Pass |
| Check 6 (crypto review) | Integration review of KEM, DSA, hybrid combiner and composite signatures | Pass (0 CRIT, 0 HIGH; 7 MEDIUM and 6 LOW disclosed) |
| Release check (this report) | Build, metadata, fresh-environment install on four Pythons, leak gate | Pass |

## Release-check evidence (2026-10-26 UTC)

```
build sdist+wheel                  PASS  pqblocks_wire-0.1.0-py3-none-any.whl
twine check --strict               PASS
python 3.11: tests                 PASS  209 passed, 10 skipped
python 3.12: tests                 PASS  209 passed, 10 skipped
python 3.13: tests                 PASS  209 passed, 10 skipped
python 3.14: tests                 PASS  209 passed, 10 skipped
examples (quickstart, signed_frame, composite_and_hybrid) PASS on all four versions
leak gate (folder + wheel + sdist) PASS  94 files scanned, 0 leak hits
FINAL GATE pqblocks-wire: PASS
```

Official-vector run (opt-in, corpus not shipped), 2026-10-26 UTC, Python 3.14, liboqs 0.16.0:

```
PQBLOCKS_VECTORS=... pytest -q tests/   218 passed, 1 skipped in 58.97s
```

## Correction after the 0.1.0 release check

A claims audit found that the official-vector tests compared no output with any vector: they counted vectors and ran random round trips, and the SLH-DSA comparisons never ran because they filtered on liboqs names (`SLH_DSA_PURE_SHA2_128S`) that do not occur in the ACVP files (`SLH-DSA-SHA2-128s`). The tests now map the names and compare outputs; [TESTING.md](TESTING.md) lists exactly what is and is not compared. No product code changed.

## Defects found and review disclosures

During preparation for this release, imprecise claims in early drafts were removed because the package is a wireformat framing layer over liboqs and pyca.

The read-only crypto review identified 7 MEDIUM and 6 LOW findings, all documented in [SECURITY_NOTES.md](SECURITY_NOTES.md). The MEDIUM items:
1. **Secret-key length is not validated:** liboqs reads the full secret-key length, so a too-short secret key causes an out-of-bounds read; callers must pass exact-length keys.
2. **The `_from_seed` helpers are not deterministic:** the private seed helpers in `MLDSAWrapper` / `SLHDSASignatureWrapper` do not derive anything from the seed.
3. **The hybrid combiner is a plain hash:** `SHA-256(ss_X25519 || ss_ML-KEM-768)` with static-static X25519, no label, and no binding of ciphertext or public keys.
4. **`hybrid_key_exchange()` is a testing function that is easy to misuse:** it runs both sides with one party's ML-KEM keys.
5. **`encapsulate_kat_mlkem` is a deterministic, caller-seeded encapsulation** exported in the public namespace.
6. **Secret keys appear in `repr`:** `repr()` of `HybridPrivateKey` and `CompositePrivateKey` prints secret-key bytes.
7. **No zeroization:** Python `bytes` cannot be wiped, and liboqs objects are not freed explicitly.

## Known limitations

- **System liboqs required:** Requires an external `liboqs.so.9` dynamic library installed and accessible via `OQS_LIB_PATH` or system library paths.
- **Frame flags:** Unknown frame flags are ignored in v1.
- **Composite draft interoperability:** The dual-signature composite implementation uses custom domain separation labels rather than strict IETF draft-19 string constants.

## Validation status

Not FIPS 140-3 or CMVP validated. While liboqs implements algorithms standardized in FIPS 203, 204, and 205, this wrapper package has not undergone external laboratory testing or cryptographic module validation.
