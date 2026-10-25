"""Composite ML-DSA-65 + Ed25519 signature (both must verify) and X25519 + ML-KEM-768 hybrid secret agreement."""
from pqblocks_wire import (CompositeSignature, composite_sign, composite_verify, generate_composite_keypair,
                           generate_hybrid_keypair, hybrid_key_exchange_initiator, hybrid_key_exchange_responder)

pk, sk = generate_composite_keypair()
sig = composite_sign(sk, b"release 1.2.3", context=b"example")
wire = sig.serialize()
ok = composite_verify(pk, b"release 1.2.3", CompositeSignature.deserialize(wire), context=b"example")
stripped = CompositeSignature(mldsa_signature=b"", ed25519_signature=sig.ed25519_signature)
print("composite verifies:", ok, "| ML-DSA part stripped verifies:", composite_verify(pk, b"release 1.2.3", stripped, b"example"))

alice_pub, alice_priv = generate_hybrid_keypair()
bob_pub, bob_priv = generate_hybrid_keypair()
ct, k_alice = hybrid_key_exchange_initiator(alice_priv.x25519_private_key, bob_pub.x25519_public_key,
                                            bob_pub.mlkem_public_key)
k_bob = hybrid_key_exchange_responder(bob_priv.x25519_private_key, alice_pub.x25519_public_key,
                                      bob_priv.mlkem_private_key, ct)
print("hybrid secrets match:", k_alice == k_bob, "| length:", len(k_alice))
assert ok and not composite_verify(pk, b"release 1.2.3", stripped, b"example") and k_alice == k_bob
