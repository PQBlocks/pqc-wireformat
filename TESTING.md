# Testing: pqblocks-wire

**Status at release 0.1.0:**
- 209 of 219 tests pass (10 skipped) on Python 3.11, 3.12, 3.13, and 3.14.
- Tested using the built wheel, installed in clean virtual environments with dependencies from PyPI.
- Statement coverage across all modules is **98 %**.

## Requirements and Environment

pqblocks-wire requires a system installation of `liboqs` (version 0.10.0+; 0.16.0 verified at release).

```bash
export OQS_LIB_PATH=~/.local/lib/liboqs.so.9
export LD_LIBRARY_PATH=~/.local/lib:${LD_LIBRARY_PATH}
```

## How to run

```bash
pip install "pqblocks-wire[test]"
pytest -q tests/
```

With coverage:

```bash
pytest -q tests/ --cov=pqblocks_wire --cov-report=term-missing
```

## Results (measured 2026-10-25 UTC)

| Python | Install source | Tests | Examples |
|---|---|---|---|
| 3.11 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |
| 3.12 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |
| 3.13 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |
| 3.14 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |

Dependencies resolved at release: `cryptography` 44.0.0+, `liboqs-python` 0.16.0.1.

### Statement coverage

| Module | Statements | Missed | Coverage |
|---|---|---|---|
| `__init__.py` | 9 | 0 | 100 % |
| `composite_sig.py` | 137 | 0 | 100 % |
| `hybrid.py` | 140 | 5 | 96 % |
| `lane_root_mlkem.py` | 156 | 4 | 97 % |
| `mldsa.py` | 92 | 2 | 98 % |
| `mlkem.py` | 240 | 11 | 95 % |
| `slhdsa.py` | 92 | 2 | 98 % |
| `wireformat.py` | 185 | 1 | 99 % |
| **Total** | **1051** | **25** | **98 %** |

## Test suites and what they check

### Wire format and serialization
- `test_Wire Format Assembler.py` (34 tests): frame encoding, parsing, flag validation, truncation detection, trailing junk rejection, zero-copy offset handling, and size cap enforcement (1568 bytes ML-KEM, 4627 bytes ML-DSA, 49856 bytes SLH-DSA).

### KEM and Signature operations
- `test_ML-KEM_Core_Operations.py` (26 tests): ML-KEM-512, ML-KEM-768, and ML-KEM-1024 keypair generation, encapsulation, decapsulation, and implicit rejection on altered ciphertext.
- `test_ML-DSA_Core_Operations.py` (17 tests): ML-DSA-44, ML-DSA-65, and ML-DSA-87 key generation, signature generation, signature verification, and rejection of modified messages or corrupted signatures.
- `test_SLH-DSA_Core_Operations.py` (20 tests): SLH-DSA parameter sets, roundtrip signing, verification, and rejection of tampered inputs.

### Hybrid and Composite constructions
- `test_Composite Signature Logic.py` (17 tests) & `test_Composite_Signature_Helper_Functions.py` (12 tests): dual-signature (ML-DSA-65 + Ed25519) generation, joint verification, and downgrade enforcement (rejects if either signature fails or is missing).
- `test_Hybrid Key Exchange.py` (17 tests) & `test_pqc_wireformat_hybrid.py` (12 tests): static-static X25519 + ML-KEM-768 dual secret derivation, combiner matching, and wire encoding.

### Skipped tests explanation
- 4 tests in `test_official_vectors.py`: skipped when offline NIST KAT `.rsp` files are not present in the local checkout.
- 6 tests in hybrid/mlkem suites: skipped when optional pure-Python `kyber-py` fallback is not installed.
