"""Shared test helpers: a loader for the official NIST ACVP and C2SP Wycheproof JSON corpora.

The corpora are large (about 140 MB for the SLH-DSA sets), so they are not shipped with the package.
Point the environment variable PQBLOCKS_VECTORS at a directory that contains

    ACVP-Server/gen-val/json-files/      (https://github.com/usnistgov/ACVP-Server)
    wycheproof/testvectors_v1/           (https://github.com/C2SP/wycheproof)

Tests that need the corpora are skipped when the variable is unset or the directory is missing.
"""
import json
import os

import pytest


def _roots():
    base = os.environ.get("PQBLOCKS_VECTORS", "")
    return (
        (os.path.join(base, "wycheproof", "testvectors_v1"), "wycheproof"),
        (os.path.join(base, "ACVP-Server", "gen-val", "json-files"), "acvp"),
    ) if base else ()


def list_official_sets(filt=""):
    """(kind, set name, path) for every corpus file whose name contains `filt` (case-insensitive)."""
    out = []
    for base, kind in _roots():
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            path = os.path.join(base, name)
            if kind == "acvp":
                path = os.path.join(path, "internalProjection.json")
                if not os.path.isfile(path):
                    continue
            elif not name.endswith(".json"):
                continue
            if filt.lower() in name.lower():
                out.append((kind, name.replace(".json", ""), path))
    return out


def acvp_to_liboqs(parameter_set):
    """ACVP parameter-set name -> liboqs pure SLH-DSA name, e.g. SLH-DSA-SHA2-128s -> SLH_DSA_PURE_SHA2_128S."""
    prefix = "SLH-DSA-"
    if not parameter_set.startswith(prefix):
        raise ValueError("not an SLH-DSA parameter set: %r" % parameter_set)
    return "SLH_DSA_PURE_" + parameter_set[len(prefix):].replace("-", "_").upper()


def pure_empty_context_tests(groups):
    """(liboqs name, test) for every external/pure SLH-DSA vector with an empty context.

    The wrapper signs and verifies with the empty FIPS 205 context only, so only these vectors apply to it.
    """
    for g in groups:
        if g.get("signatureInterface") != "external" or g.get("preHash") != "pure":
            continue
        for t in g.get("tests", []):
            if t.get("context", "") == "":
                yield acvp_to_liboqs(g["parameterSet"]), t


def load_official_vectors(name):
    """All test groups of every corpus set whose name contains `name`; skips the test if no corpus is configured."""
    if not any(os.path.isdir(base) for base, _ in _roots()):
        pytest.skip("official vector corpus not configured (set PQBLOCKS_VECTORS)")
    found = list_official_sets(name)
    if not found:
        raise FileNotFoundError("no official vector set matches %r under $PQBLOCKS_VECTORS" % name)
    groups = []
    for kind, set_name, path in found:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for g in doc.get("testGroups", []):
            g = dict(g)
            g["_source"] = "%s:%s" % (kind, set_name)
            groups.append(g)
    return groups
