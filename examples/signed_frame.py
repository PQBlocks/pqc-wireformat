"""Carry a payload with an ML-DSA-65 signature and an SLH-DSA-SHA2-128f signature in one frame.

The frame format itself has no integrity protection: the receiver must verify the signatures over the payload.
The example shows that a payload changed in transit fails both verifications.
"""
from pqblocks_wire import (decode_wire_format, encode_wire_format, generate_mldsa_keypair, generate_slhdsa_keypair,
                           sign_mldsa, sign_slhdsa, verify_mldsa, verify_slhdsa)

ML, SLH = "ML-DSA-65", "SLH_DSA_PURE_SHA2_128F"
payload = b"firmware manifest v42"
ml_pk, ml_sk = generate_mldsa_keypair(ML)
slh_pk, slh_sk = generate_slhdsa_keypair(SLH)

frame = encode_wire_format(mldsa_signature=sign_mldsa(payload, ml_sk, ML),
                           slhdsa_signature=sign_slhdsa(payload, slh_sk, SLH), payload=payload)
d = decode_wire_format(frame)
ok = verify_mldsa(d.payload, d.mldsa_signature, ml_pk, ML) and verify_slhdsa(d.payload, d.slhdsa_signature, slh_pk, SLH)

tampered = decode_wire_format(frame.replace(b"v42", b"v43"))
bad = verify_mldsa(tampered.payload, tampered.mldsa_signature, ml_pk, ML) or \
    verify_slhdsa(tampered.payload, tampered.slhdsa_signature, slh_pk, SLH)

print("signature sizes:", len(d.mldsa_signature), len(d.slhdsa_signature))   # 3309 17088
print("both signatures verify:", ok)
print("tampered payload accepted:", bad)
assert ok and not bad
