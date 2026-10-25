"""Quickstart: ML-KEM-768 key exchange, then pack the ciphertext into a PQCWF1 frame and parse it back."""
from pqblocks_wire import (decapsulate_mlkem, decode_wire_format, encapsulate_mlkem, encode_wire_format,
                           generate_mlkem_keypair)

pk, sk = generate_mlkem_keypair("ML-KEM-768")
ct, ss_sender = encapsulate_mlkem(pk, "ML-KEM-768")

frame = encode_wire_format(mlkem_ciphertext=ct, payload=b"hello")
received = decode_wire_format(frame)
ss_receiver = decapsulate_mlkem(sk, received.mlkem_ciphertext, "ML-KEM-768")

print("frame bytes:", len(frame))                          # 8 header + 4 + 1088 + 4 + 5 = 1109
print("payload:", received.payload)
print("shared secrets match:", ss_sender == ss_receiver)
assert len(frame) == 1109 and ss_sender == ss_receiver
