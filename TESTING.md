# Testing: pqblocks-wire

**Status at release 0.1.0:**
- 209 of 219 tests pass (10 skipped) on Python 3.11, 3.12, 3.13, and 3.14.
- Tested using the built wheel, installed in clean virtual environments with dependencies from PyPI.
- Statement coverage across all modules is **98 %**.

## Requirements and Environment

pqblocks-wire requires a system installation of liboqs 0.15.0 or later (SLH-DSA was added in 0.15.0); only 0.16.0 was tested.

```bash
export OQS_LIB_PATH=~/.local/lib/liboqs.so.9
export LD_LIBRARY_PATH=~/.local/lib:${LD_LIBRARY_PATH}
```

## How to run

```bash
git clone https://github.com/PQBlocks/pqc-wireformat && cd pqc-wireformat
pip install ".[test]"
pytest -q tests/
```

With coverage:

```bash
pytest -q tests/ --cov=pqblocks_wire --cov-report=term-missing
```

## Results (measured 2026-10-26 UTC)

| Python | Install source | Tests | Examples |
|---|---|---|---|
| 3.11 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |
| 3.12 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |
| 3.13 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |
| 3.14 | wheel + PyPI dependencies | 209 passed, 10 skipped | 3 / 3 passed |

Dependencies resolved at release: `cryptography` 50.0.2, `liboqs-python` 0.16.0.1.

### Official-vector run (opt-in)

The vector corpora are not shipped. To run the 9 official-vector tests, point `PQBLOCKS_VECTORS` at a directory holding
`ACVP-Server/gen-val/json-files/` (https://github.com/usnistgov/ACVP-Server) and `wycheproof/testvectors_v1/`
(https://github.com/C2SP/wycheproof):

```bash
PQBLOCKS_VECTORS=/path/to/vectors pytest -q tests/
```

Measured 2026-10-26 UTC on Python 3.14 with liboqs 0.16.0: **218 passed, 1 skipped in 58.97 s**.

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
- `test_Wire Format Assembler.py` (34 tests): frame encoding, parsing, flag validation, truncation detection, trailing junk rejection, offset-based parsing (each component is returned as a copy), and size cap enforcement (1568 bytes ML-KEM, 4627 bytes ML-DSA, 49856 bytes SLH-DSA).

### KEM and Signature operations
- `test_ML-KEM_Core_Operations.py` (26 tests): ML-KEM-512, ML-KEM-768, and ML-KEM-1024 keypair generation, encapsulation, decapsulation, and implicit rejection on altered ciphertext.
- `test_ML-DSA_Core_Operations.py` (16 tests): ML-DSA-44, ML-DSA-65, and ML-DSA-87 key generation, signature generation, signature verification, and rejection of modified messages or corrupted signatures.
- `test_SLH-DSA_Core_Operations.py` (21 tests): SLH-DSA parameter sets, roundtrip signing, verification, and rejection of tampered inputs.

### Hybrid and Composite constructions
- `test_Composite Signature Logic.py` (17 tests) & `test_Composite_Signature_Helper_Functions.py` (12 tests): dual-signature (ML-DSA-65 + Ed25519) generation, joint verification, and downgrade enforcement (rejects if either signature fails or is missing).
- `test_Hybrid Key Exchange.py` (17 tests) & `test_pqc_wireformat_hybrid.py` (12 tests): static-static X25519 + ML-KEM-768 dual secret derivation, combiner matching, and wire encoding.

### Skipped tests explanation
- 9 tests (4 in `test_official_vectors.py`, 1 in the ML-DSA suite, 4 in the SLH-DSA suite) skip unless `PQBLOCKS_VECTORS` points at ACVP-Server and Wycheproof checkouts. None skips for kyber-py.
- 1 placeholder test in `test_Hybrid Key Exchange.py` is skipped unconditionally.

### What the official-vector tests compare

ACVP names SLH-DSA parameter sets `SLH-DSA-SHA2-128s`; liboqs names the same set `SLH_DSA_PURE_SHA2_128S`. The tests map one to the other (`tests/conftest.py`, `acvp_to_liboqs`). Before 0.1.0 was corrected, the tests filtered on the liboqs names, so no SLH-DSA comparison ever ran, and the ML-KEM test only counted vectors and ran a random round trip.

| Test | Vectors | What is compared |
|---|---|---|
| `test_mlkem_official_vectors` | ACVP `ML-KEM-keyGen-FIPS203` (75) | liboqs seeded key generation from `d \|\| z` gives the vector's `ek` and `dk` byte for byte. This checks the backend; the wrapper has no seeded key generation. |
| | ACVP `ML-KEM-encapDecap-FIPS203` and `-tr1`, encapsulation (150) | `MLKEMWrapper.encapsulate_kat(ek, ps, m)` (kyber-py) gives the vector's `c` and `k`; `decapsulate_mlkem(dk, c)` gives `k`. |
| | same, decapsulation (90) | `decapsulate_mlkem(dk, c)` gives the vector's `k`, including implicit rejection of invalid ciphertexts. |
| `test_slhdsa_official_vectors` | ACVP `SLH-DSA-keyGen-FIPS205` (120, all 12 sets) | `sk` = `SK.seed \|\| SK.prf \|\| PK.seed \|\| PK.root` and `pk` = `PK.seed \|\| PK.root` (FIPS 205 layout); for one vector per set, a wrapper signature made with the vector `sk` verifies under the vector `pk`. |
| | ACVP `SLH-DSA-sigGen-FIPS205`, external/pure, empty context (24) | The vector signature verifies with `SLHDSASignatureWrapper.verify`, and a fresh wrapper signature with the vector `sk` verifies under the vector `pk`. |
| | ACVP `SLH-DSA-sigVer-FIPS205`, external/pure, empty context (12) | The wrapper's verdict equals `testPassed` (2 valid, 10 invalid). |
| `test_slhdsa_128s_official_vectors_{keygen,sign,verify}` | the SLH-DSA-SHA2-128s subset of the three sets above | as above, for that one set |
| `test_mldsa_official_vectors`, `test_mldsa_load_vectors`, `test_slhdsa_load_vectors`, `test_vector_loading_infrastructure` | Wycheproof ML-DSA-65, ACVP sets | Only that the sets load and hold the expected number of cases. **No ML-DSA output is compared with any vector.** |

Not covered: the ML-KEM key-check groups (the wrapper has no key check), SLH-DSA vectors with a context string or pre-hash (the wrapper supports neither), the internal SLH-DSA interface, and byte-exact SLH-DSA signatures (liboqs signs with fresh randomness, so a deterministic signature cannot be reproduced through the wrapper).
