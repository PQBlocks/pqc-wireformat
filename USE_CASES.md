# Use cases: pqblocks-wire

Each script below is in `examples/`. Each one prints a check it verifies itself, and each runs in the release check on Python 3.11 to 3.14 (see [TESTING.md](TESTING.md)). All of them need liboqs (see the README's "Requirements").

## 1. Ship an ML-KEM ciphertext together with application data

A service encapsulates a key to a peer's ML-KEM-768 public key. It sends the ciphertext and a payload in one frame, and the peer parses the frame and decapsulates.

```bash
python examples/quickstart.py
```
```
frame bytes: 1109
payload: b'hello'
shared secrets match: True
```

The frame is 8 header bytes, plus 4 + 1088 for the ciphertext, plus 4 + 5 for the payload. The frame gives no confidentiality and no integrity. Use the shared secret to derive keys for an AEAD over your data.

## 2. Dual-signed payloads (lattice + hash-based)

You sign a release manifest or a firmware descriptor with both ML-DSA-65 and SLH-DSA-SHA2-128f, so that a break of either family alone does not forge it. Both signatures travel in one frame with the payload. The receiver verifies both and rejects the frame if either fails.

```bash
python examples/signed_frame.py
```
```
signature sizes: 3309 17088
both signatures verify: True
tampered payload accepted: False
```

## 3. Composite ML-DSA-65 + Ed25519 signature, and an X25519 + ML-KEM-768 hybrid secret

This is for a migration period in which you want a classical and a post-quantum signature that verify as one unit. If the ML-DSA part is stripped, verification fails. The same script also shows the two-party hybrid secret agreement.

```bash
python examples/composite_and_hybrid.py
```
```
composite verifies: True | ML-DSA part stripped verifies: False
hybrid secrets match: True | length: 32
```

Read the limitations first:
- The composite format is **not** interoperable with draft-ietf-lamps-pq-composite-sigs.
- The hybrid secret is `SHA-256(X25519 || ML-KEM)` with no transcript binding.

## When to use something else

- **You must interoperate with TLS, X.509 or another implementation.** Use the standard encodings:
  - TLS hybrid groups, through your TLS stack;
  - RFC 9881 ML-DSA in X.509;
  - X-Wing for a hybrid KEM;
  - the IETF composite-signature encoding.

  The `PQCWF1` frame is understood only by this package.
- **You need a validated module (FIPS 140-3 / CMVP).** This package is not validated, and neither is liboqs.
- **You need a proof that every output matches the NIST vectors.** The opt-in vector tests cover ML-KEM (byte for byte) and the empty-context, pure SLH-DSA vectors; they do not cover ML-DSA, SLH-DSA with a context or pre-hash, or byte-exact SLH-DSA signatures. Rely on liboqs' own test results for the rest.
- **You need a hardened, constant-time, zeroizing secret-key API in Python.** See [SECURITY_NOTES.md](SECURITY_NOTES.md).
