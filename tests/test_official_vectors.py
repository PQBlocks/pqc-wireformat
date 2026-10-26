"""Official-vector tests (NIST ACVP-Server and C2SP Wycheproof JSON corpora; set PQBLOCKS_VECTORS).

- ML-KEM: key generation (liboqs seeded keygen), deterministic encapsulation and decapsulation through the
  wrapper are compared byte for byte with the ACVP FIPS 203 vectors.
- SLH-DSA: the wrapper's sign/verify run on the ACVP FIPS 205 external/pure vectors with an empty context;
  ACVP names (SLH-DSA-SHA2-128s) are mapped to liboqs names (SLH_DSA_PURE_SHA2_128S).
- ML-DSA: only the presence and size of the Wycheproof sets are checked; no ML-DSA output is compared.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from .conftest import load_official_vectors, list_official_sets, acvp_to_liboqs, pure_empty_context_tests

# Import product code for ML-KEM
try:
    from pqblocks_wire.mlkem import (
        generate_mlkem_keypair,
        encapsulate_mlkem,
        decapsulate_mlkem
    )
    MLKEM_AVAILABLE = True
except ImportError:
    MLKEM_AVAILABLE = False

# Import product code for SLH-DSA
try:
    from pqblocks_wire.slhdsa import SLHDSASignatureWrapper
    SLHDSASignatureWrapper_AVAILABLE = True
except ImportError:
    SLHDSASignatureWrapper_AVAILABLE = False


def _load_vectors(name):
    """Load test vectors using the verification tooling."""
    return load_official_vectors(name)


def test_mlkem_official_vectors():
    """ML-KEM outputs compared byte for byte with the NIST ACVP FIPS 203 vectors."""
    from pqblocks_wire.mlkem import MLKEMWrapper
    import oqs

    keygen = _load_vectors('ML-KEM-keyGen-FIPS203')
    compared = 0
    for group in keygen:
        for t in group['tests']:
            # Backend check: liboqs seeded key generation with seed d || z must give the vector's ek and dk.
            kem = oqs.KeyEncapsulation(group['parameterSet'])
            ek = kem.generate_keypair_seed(bytes.fromhex(t['d'] + t['z']))
            assert ek == bytes.fromhex(t['ek']), "ek mismatch, tcId %s" % t['tcId']
            assert kem.export_secret_key() == bytes.fromhex(t['dk']), "dk mismatch, tcId %s" % t['tcId']
            compared += 1
    assert compared == sum(len(g['tests']) for g in keygen) >= 75, compared

    groups = _load_vectors('ML-KEM-encapDecap-FIPS203')
    encaps = decaps = 0
    for group in groups:
        ps, fn = group['parameterSet'], group['function']
        for t in group['tests']:
            if fn == 'encapsulation':
                # Product code: deterministic encapsulation with the vector's m.
                c, k = MLKEMWrapper.encapsulate_kat(bytes.fromhex(t['ek']), ps, bytes.fromhex(t['m']))
                assert c == bytes.fromhex(t['c']), "c mismatch, tcId %s" % t['tcId']
                assert k == bytes.fromhex(t['k']), "k mismatch, tcId %s" % t['tcId']
                encaps += 1
            if fn in ('encapsulation', 'decapsulation'):
                # Product code: decapsulation, including implicit rejection of the invalid ciphertexts.
                k = decapsulate_mlkem(bytes.fromhex(t['dk']), bytes.fromhex(t['c']), ps)
                assert k == bytes.fromhex(t['k']), "decapsulated k mismatch, tcId %s" % t['tcId']
                decaps += 1
    # The key-check groups have no counterpart in the wrapper and are not run.
    n_enc = sum(len(g['tests']) for g in groups if g['function'] == 'encapsulation')
    n_dec = sum(len(g['tests']) for g in groups if g['function'] == 'decapsulation')
    assert n_enc >= 75 and n_dec >= 30, (n_enc, n_dec)
    assert (encaps, decaps) == (n_enc, n_enc + n_dec), (encaps, decaps)


def test_mldsa_official_vectors():
    """Test ML-DSA against Wycheproof official vectors."""
    # Load ML-DSA verification test vectors (parameter set 65)
    mldsa_verify_groups = _load_vectors('mldsa_65_verify_test')

    assert len(mldsa_verify_groups) > 0, "No ML-DSA verify test vectors loaded"

    total_verify_tests = sum(len(group.get('tests', [])) for group in mldsa_verify_groups)
    assert total_verify_tests >= 210, f"Expected 210+ ML-DSA verify test cases, got {total_verify_tests}"

    # Also test signing vectors are available
    mldsa_65_sign_seed_groups = _load_vectors('mldsa_65_sign_seed_test')
    total_sign_seed_tests = sum(len(group.get('tests', [])) for group in mldsa_65_sign_seed_groups)
    assert total_sign_seed_tests >= 105, f"Expected 105+ ML-DSA sign seed test cases, got {total_sign_seed_tests}"

    # mldsa_65_sign_noseed_test variant
    mldsa_65_sign_noseed_groups = _load_vectors('mldsa_65_sign_noseed_test')
    total_sign_noseed_tests = sum(len(group.get('tests', [])) for group in mldsa_65_sign_noseed_groups)
    assert total_sign_noseed_tests >= 78, f"Expected 78+ ML-DSA sign noseed test cases, got {total_sign_noseed_tests}"


def test_slhdsa_official_vectors():
    """SLH-DSA vectors (ACVP FIPS 205, external/pure, empty context) run through the product wrapper."""
    W = SLHDSASignatureWrapper
    msg = b"PQBlocks SLH-DSA vector check"

    # keyGen: sk must be SK.seed || SK.prf || PK.seed || PK.root and pk = PK.seed || PK.root (FIPS 205 Alg. 18);
    # the wrapper must sign with the vector sk so that the vector pk verifies (one test per parameter set:
    # the "s" sets sign slowly).
    keygen = _load_vectors('SLH-DSA-keyGen-FIPS205')
    sets = 0
    for group in keygen:
        name = acvp_to_liboqs(group['parameterSet'])
        for i, t in enumerate(group['tests']):
            sk, pk = bytes.fromhex(t['sk']), bytes.fromhex(t['pk'])
            assert sk == bytes.fromhex(t['skSeed'] + t['skPrf']) + pk, "sk layout, tcId %s" % t['tcId']
            assert pk[:len(pk) // 2] == bytes.fromhex(t['pkSeed']), "pk layout, tcId %s" % t['tcId']
            if i == 0:
                assert W.verify(msg, W.sign(msg, sk, name), pk, name), "tcId %s" % t['tcId']
                sets += 1
    assert sets == 12, sets

    # sigGen: every vector signature verifies under the vector pk, and a fresh wrapper signature made with the
    # vector sk verifies too. liboqs signs with fresh randomness, so signatures are not compared byte for byte.
    siggen = list(pure_empty_context_tests(_load_vectors('SLH-DSA-sigGen-FIPS205')))
    for name, t in siggen:
        m, sk, pk = bytes.fromhex(t['message']), bytes.fromhex(t['sk']), bytes.fromhex(t['pk'])
        assert W.verify(m, bytes.fromhex(t['signature']), pk, name), "tcId %s" % t['tcId']
        assert W.verify(m, W.sign(m, sk, name), pk, name), "tcId %s" % t['tcId']
    assert len(siggen) == 24, len(siggen)

    # sigVer: the wrapper's verdict must equal testPassed, for valid and invalid signatures.
    sigver = list(pure_empty_context_tests(_load_vectors('SLH-DSA-sigVer-FIPS205')))
    for name, t in sigver:
        got = W.verify(bytes.fromhex(t['message']), bytes.fromhex(t['signature']), bytes.fromhex(t['pk']), name)
        assert got == t['testPassed'], "tcId %s" % t['tcId']
    assert len(sigver) == 12, len(sigver)
    assert any(not t['testPassed'] for _, t in sigver)


def test_vector_loading_infrastructure():
    """Test that the the verification tooling works correctly."""
    # Test that we can list available vector sets
    listed = [name for _, name, _ in list_official_sets('ML-KEM')]
    groups = load_official_vectors('ML-KEM-encapDecap-FIPS203')
    assert 'ML-KEM-encapDecap-FIPS203' in listed

    # Test that we can load without error
    groups = _load_vectors('ML-KEM-encapDecap-FIPS203')
    assert isinstance(groups, list)
    assert len(groups) > 0


if __name__ == '__main__':
    # Allow running directly for development/testing
    test_vector_loading_infrastructure()
    test_mlkem_official_vectors() 
    test_mldsa_official_vectors()
    test_slhdsa_official_vectors()
    print("All official vector infrastructure tests passed")