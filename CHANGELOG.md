# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-25

### Added
- `PQCWF1` frame: `encode_wire_format` and a strict `decode_wire_format`, for an ML-KEM ciphertext, ML-DSA and SLH-DSA signatures and a payload, with FIPS maximum-size caps.
- ML-KEM-512/768/1024, ML-DSA-44/65/87 and 12 SLH-DSA parameter sets, as thin wrappers over liboqs-python.
- Composite ML-DSA-65 + Ed25519 signature, in which both parts must verify.
- X25519 + ML-KEM-768 hybrid secret agreement (initiator and responder), with an X25519-only fallback.
- Examples: quickstart, a dual-signed frame, and composite plus hybrid. Each checks its own result.
- Timing benchmarks with raw data.
