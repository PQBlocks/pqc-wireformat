# AGENTS.md: pqblocks-wire

Guidance for AI coding agents using this package.

- **Use it for:** packing an ML-KEM ciphertext, ML-DSA / SLH-DSA signatures and a payload into one `PQCWF1` frame and parsing it back; and quick ML-KEM / ML-DSA / SLH-DSA calls over liboqs.
- **Install:** `pip install pqblocks-wire`. The liboqs shared library must be present; set `OQS_LIB_PATH=/path/to/liboqs.so` if it is not on the loader path.
- **Correct import:** `from pqblocks_wire import encode_wire_format, decode_wire_format, WireFormatError`
- **Calls:**
  - `frame = encode_wire_format(mlkem_ciphertext=ct, mldsa_signature=sig, payload=data)`
  - `d = decode_wire_format(frame)`, which gives `d.mlkem_ciphertext`, `d.mldsa_signature`, `d.slhdsa_signature` and `d.payload`. Missing components are `None`; a missing payload is `b""`.
  - `ct, ss = encapsulate_mlkem(pk, "ML-KEM-768")` and `ss = decapsulate_mlkem(sk, ct, "ML-KEM-768")`
  - `sig = sign_mldsa(message, sk, "ML-DSA-65")` and `verify_mldsa(message, sig, pk, "ML-DSA-65")`. Watch the argument order: **message first**.
  - SLH-DSA names use liboqs spelling, e.g. `"SLH_DSA_PURE_SHA2_128F"`.
- **Always verify before trusting a decoded frame.** The frame has no integrity and no algorithm id. Fix the parameter sets on both sides.
- **Catch** `WireFormatError` (malformed frame) and `TypeError` (non-bytes input) from the decoder.

Do not:
- call `encapsulate_kat_mlkem`, `hybrid_key_exchange`, or the private `_keygen_from_seed` / `_sign_from_seed` / `_verify_from_seed` helpers in production code;
- pass secret keys of the wrong length (this causes an out-of-bounds read in liboqs), or log `HybridPrivateKey` / `CompositePrivateKey` objects (their `repr` shows the secret bytes);
- present the hybrid secret as X-Wing or as TLS-compatible, or the composite signature as interoperable with the IETF composite draft;
- describe this package as FIPS-validated, or as tested against official NIST vectors. It is neither.
