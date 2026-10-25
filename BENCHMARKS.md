# Benchmarks: pqblocks-wire

These are wall-clock timings of this package's public calls on one machine. **No performance claim is made.**

There is no competing package in the run, so these numbers do not show that anything is faster or slower than an alternative. The ML-KEM / ML-DSA / SLH-DSA timings are, almost entirely, the speed of liboqs plus this package's per-call overhead. The overhead comes from creating a fresh `oqs` object on every call. That overhead was not measured on its own.

Raw data:
- [benchmarks/bench_core_ops_2026-10-13.json](benchmarks/bench_core_ops_2026-10-13.json) has every individual timing.
- [benchmarks/BENCHMARK-SUMMARY.json](benchmarks/BENCHMARK-SUMMARY.json) has the medians and means.

The tables below are copied from the summary. All 60 summary values (30 medians, 30 means) were re-derived from the raw file and match it exactly.

## Setup

| Item | Value |
|---|---|
| Date of run | 2026-10-13 12:05:35 UTC |
| CPU | Intel Core i5-10300H @ 2.50 GHz, 8 logical CPUs, x86_64 |
| OS / Python | Linux 7.2.6 (glibc 2.44), Python 3.14.7 |
| Libraries | liboqs-python over liboqs, built for this machine. The exact liboqs version at run time was not recorded. |
| Method | 5 warm-up calls, then 100 timed calls per operation with `time.perf_counter`. Median and mean are reported. All 100 samples completed for every operation (checked in the raw file). |
| What is timed | One public call, including object setup inside the wrapper. **"decaps" times an encapsulation plus a decapsulation**, because the driver encapsulates afresh before each decapsulation. |

## Results (milliseconds per call)

### ML-KEM (`generate_mlkem_keypair`, `encapsulate_mlkem`, `decapsulate_mlkem`)

| Parameter set | keygen median / mean | encaps median / mean | encaps + decaps median / mean |
|---|---|---|---|
| ML-KEM-512 | 0.018 / 0.019 | 0.021 / 0.021 | 0.041 / 0.042 |
| ML-KEM-768 | 0.023 / 0.023 | 0.024 / 0.025 | 0.050 / 0.054 |
| ML-KEM-1024 | 0.027 / 0.029 | 0.031 / 0.034 | 0.059 / 0.066 |
| ML-KEM-512 (second run of the same set) | 0.018 / 0.020 | 0.019 / 0.021 | 0.038 / 0.042 |

### ML-DSA (`generate_mldsa_keypair`, `sign_mldsa`; 29-byte message)

| Parameter set | keygen median / mean | sign median / mean |
|---|---|---|
| ML-DSA-44 | 0.036 / 0.037 | 0.066 / 0.082 |
| ML-DSA-65 | 0.056 / 0.057 | 0.107 / 0.134 |
| ML-DSA-87 | 0.079 / 0.082 | 0.144 / 0.169 |
| ML-DSA-44 (second run of the same set) | 0.036 / 0.039 | 0.072 / 0.091 |

### SLH-DSA (`generate_slhdsa_keypair`, `sign_slhdsa`; 29-byte message)

| Parameter set | keygen median / mean | sign median / mean |
|---|---|---|
| SHA2-128s | 69.070 / 69.771 | 534.856 / 539.592 |
| SHA2-192s | 102.019 / 103.339 | 956.307 / 962.914 |
| SHA2-256s | 67.875 / 68.054 | 875.100 / 871.936 |
| SHA2-128f | 1.167 / 1.177 | 25.664 / 25.760 |

### Frame encode / decode (ML-KEM-768 ciphertext + ML-DSA-65 signature + 12-byte payload)

| Operation | median / mean |
|---|---|
| `encode_wire_format` | 0.002 / 0.002 |
| `decode_wire_format` | 0.003 / 0.003 |

## Losing cases and what to read into these numbers

- **SLH-DSA "s" variants are slow.** Signing takes 0.5 to 1 s per signature on this CPU. SHA2-128f signs in about 26 ms but gives a 17,088-byte signature. If you need the small variants at volume, budget for it.
- **The ML-DSA sign means sit 17-25 % above the medians.** This is ML-DSA's rejection-sampling loop: some signatures need more iterations. Use the mean for throughput planning.
- **No verify timings** (ML-DSA, SLH-DSA, composite) were collected, and no hybrid or composite timings either. They are "not measured".
- **Not measured:** the overhead of the wrapper against calling liboqs directly, and any comparison with other Python PQC packages. A 20 to 30 µs ML-KEM call does not separate liboqs time from Python call overhead.
- **One machine, one run, no confidence intervals.** The second runs of ML-KEM-512 and ML-DSA-44 show run-to-run spread of about 5-10 % on the medians.

## Reproducing

```bash
pip install pqblocks-wire
python benchmarks/bench_core_ops.py     # writes bench/runs/bench_core_ops_<time>.json and bench/BENCHMARK-SUMMARY.json
```

The SLH-DSA "s" sets dominate the run time, at 100 signatures each, so expect the full run to take several minutes.
