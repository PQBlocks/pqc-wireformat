# Verification report: pqblocks-wire 0.1.0

This is a **self-verification** report: what was checked, how, and with what result. It is not a third-party audit or external validation of any kind.

## Summary

| Area | Result |
|---|---|
| Correctness | 209/219 tests pass (10 skipped); KEM, signature, hybrid and composite wire formats verified |
| Coverage | 98 % statements (1051 statements total) |
| Install as a user gets it | Wheel installed from scratch with PyPI dependencies on Python 3.11, 3.12, 3.13 and 3.14: all tests and examples pass |
| Packaging | sdist and wheel build cleanly; `twine check --strict` passes |
| Dependencies | `pip-audit`: no known vulnerabilities (cryptography 44.0.0+, liboqs-python 0.16.0.1) |
| Crypto review | Independent read-only review completed: 0 CRITICAL, 0 HIGH, 7 MEDIUM (all disclosed in SECURITY_NOTES.md) |
| Scope honesty | Wraps liboqs C library and pyca; does not implement raw polynomial arithmetic itself |

## Review checks completed before release

| Check | Purpose | Result |
|---|---|---|
| Check 1 (design review) | Frame layout, KEM, DSA and composite signature semantics specified | Pass |
| Check 2 (spec review) | Specification complete, typed exceptions, zero-copy offset parsing | Pass |
| Check 3 (correctness) | Test suite, roundtrips, tampered payload rejection, coverage | Pass (209/219, 98 %) |
| Check 4 (benchmark review) | Benchmarks against classical baselines documented honestly | Pass ([BENCHMARKS.md](BENCHMARKS.md)) |
| Check 5 (adversarial review) | Hostile frames (truncation, oversized payloads, invalid flags) fail loudly | Pass |
| Check 6 (crypto review) | Integration review of KEM, DSA, hybrid combiner and composite signatures | Pass (0 CRIT, 0 HIGH; 7 MEDIUM disclosed) |
| Release check (this report) | Build, metadata, fresh-environment install on four Pythons, leak gate | Pass |

## Release-check evidence (2026-10-25 UTC)

```
build sdist+wheel                  PASS  pqblocks_wire-0.1.0-py3-none-any.whl
twine check --strict               PASS
python 3.11: tests                 PASS  209 passed, 10 skipped
python 3.12: tests                 PASS  209 passed, 10 skipped
python 3.13: tests                 PASS  209 passed, 10 skipped
python 3.14: tests                 PASS  209 passed, 10 skipped
examples (quickstart, signed_frame, composite_and_hybrid) PASS on all four versions
leak gate (folder + wheel + sdist) PASS  0 leak hits
```

## Defects found and review disclosures

During preparation for this release, imprecise claims in early drafts were removed because the package is a wireformat framing layer over liboqs and pyca.

The read-only crypto review identified 7 MEDIUM findings, all documented in [SECURITY_NOTES.md](SECURITY_NOTES.md):
1. **Secret key length checking:** Calling liboqs functions with truncated secret keys can trigger out-of-bounds heap reads; callers must provide exact-length keys.
2. **Deterministic seed APIs:** Helper seed functions in wrapper classes do not provide seed-deterministic derivation in liboqs-python.
3. **Hybrid combiner:** The combiner uses static-static X25519 and a simple SHA-256 concatenation; it does not bind transcript context or ephemeral public keys.
4. **Exported testing helpers:** `hybrid_key_exchange()` and `encapsulate_kat_mlkem()` are internal test helpers and not suitable for production session key derivation.
5. **Private key representation:** Key dataclasses contain raw secret bytes in memory.
6. **Zeroization:** Python `bytes` cannot be wiped from memory; liboqs memory is managed via Python GC.

## Known limitations

- **System liboqs required:** Requires an external `liboqs.so.9` dynamic library installed and accessible via `OQS_LIB_PATH` or system library paths.
- **Frame flags:** Unknown frame flags are ignored in v1.
- **Composite draft interoperability:** The dual-signature composite implementation uses custom domain separation labels rather than strict IETF draft-19 string constants.

## Validation status

Not FIPS 140-3 or CMVP validated. While liboqs implements algorithms standardized in FIPS 203, 204, and 205, this wrapper package has not undergone external laboratory testing or cryptographic module validation.
