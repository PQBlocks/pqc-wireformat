"""PQC Wire Format Compatibility Package
Exposes ML-KEM, ML-DSA, and SLH-DSA operations as thin wrappers over maintained libraries.
"""
from .mlkem import (
    generate_mlkem_keypair,
    encapsulate_mlkem,
    decapsulate_mlkem,
    MLKEMWrapper,
    mlkem_test_all_operations,
)

# Expose KAT functions at package level
encapsulate_kat_mlkem = MLKEMWrapper.encapsulate_kat

# Import the KYBER_PY_AVAILABLE flag from mlkem module
from .mlkem import KYBER_PY_AVAILABLE

from .mldsa import (
    generate_mldsa_keypair,
    sign_mldsa,
    verify_mldsa,
    MLDSAWrapper,
    mldsa_test_all_operations,
)

from .slhdsa import (
    generate_slhdsa_keypair,
    sign_slhdsa,
    verify_slhdsa,
    SLHDSASignatureWrapper,
    slhdsa_test_all_operations,
)

from .hybrid import (
    HybridPublicKey,
    HybridPrivateKey,
    generate_hybrid_keypair,
    hybrid_key_exchange_initiator,
    hybrid_key_exchange_responder,
    classical_fallback,
    hybrid_key_exchange,
    hybrid_test_basic_operations,
)

from .wireformat import (
    encode_wire_format,
    decode_wire_format,
    DecodedWireFormat,
    WireFormatError,
    encode_composite_signatures,
    decode_composite_signatures,
)

from .composite_sig import (
    CompositePublicKey,
    CompositePrivateKey,
    CompositeSignature,
    generate_composite_keypair,
    composite_sign,
    composite_verify,
    composite_verify_individual,
)

__all__ = [
    "generate_mlkem_keypair",
    "encapsulate_mlkem",
    "decapsulate_mlkem",
    "MLKEMWrapper",
    "mlkem_test_all_operations",
    "KYBER_PY_AVAILABLE",
    "encapsulate_kat_mlkem",
    "generate_mldsa_keypair",
    "sign_mldsa",
    "verify_mldsa",
    "MLDSAWrapper",
    "mldsa_test_all_operations",
    "generate_slhdsa_keypair",
    "sign_slhdsa",
    "verify_slhdsa",
    "SLHDSASignatureWrapper",
    "slhdsa_test_all_operations",
    "HybridPublicKey",
    "HybridPrivateKey",
    "generate_hybrid_keypair",
    "hybrid_key_exchange_initiator",
    "hybrid_key_exchange_responder",
    "classical_fallback",
    "hybrid_key_exchange",
    "hybrid_test_basic_operations",
    "encode_wire_format",
    "decode_wire_format",
    "DecodedWireFormat",
    "WireFormatError",
    "encode_composite_signatures",
    "decode_composite_signatures",
    "CompositePublicKey",
    "CompositePrivateKey",
    "CompositeSignature",
    "generate_composite_keypair",
    "composite_sign",
    "composite_verify",
    "composite_verify_individual",
]