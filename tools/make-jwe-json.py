#!/usr/bin/env python3
"""Write, or check, JWE JSON serializations made by jwcrypto.

    python3 tools/make-jwe-json.py           write the fixture
    python3 tools/make-jwe-json.py --check   check it

Maintainer tooling, never run at check time. Needs `jwcrypto`.

The JWE JSON serializations were checked only by round trip, so a bug
shared by zujose's writer and reader would pass (#101). These tokens are
written by jwcrypto, so the reading direction runs at check time;
tools/jwe-oracle/ checks both directions in development. The rows cover
what only the JSON serializations have: the flattened and the general
forms, one recipient and three, `aad` present and absent, a shared
unprotected header, and a per-recipient header on every recipient. The
key management algorithms cover each family: AES key wrap, AES-GCM key
wrap, RSA-OAEP, ECDH-ES direct and ECDH-ES with key wrap, and PBES2.

Keys are fixed: the private keys under tests/testthat/fixtures/oracle/
(written by tools/make-oracle-fixtures.py) and oct secrets of the bytes
1..n. CEKs, IVs and ephemeral keys are random, so tokens change on every
write. Writes tests/testthat/fixtures/oracle/jwe-json.tsv, one row per
token, with the recipients' keys as a private JWK Set and the plaintext in
hex, and adds its row to fixtures/oracle/MANIFEST.tsv. --check decrypts
every token with jwcrypto for each of its recipients, without
regenerating.
"""
import csv
import json
import os
import sys
from importlib.metadata import version

from jwcrypto import common, jwe, jwk

OUT = os.path.join("tests", "testthat", "fixtures", "oracle")
FILE = "jwe-json.tsv"
GENERATOR = "tools/make-jwe-json.py"
PLAINTEXT = "JWE JSON: été, 日本.".encode("utf-8")
AAD = "zujose aad: été".encode("utf-8")
UNPROTECTED = {"x-shared": "unprotected"}
# id, enc, aad?, then each recipient as (alg, kid).
CASES = [
    ("flattened-a128kw", "A128GCM", True, [("A128KW", "oct-16")]),
    ("flattened-ecdh-es", "A256CBC-HS512", True, [("ECDH-ES", "x25519")]),
    ("flattened-gcmkw-no-aad", "A192GCM", False, [("A192GCMKW", "oct-24")]),
    ("general-three", "A192CBC-HS384", True,
     [("A256KW", "oct-32"), ("RSA-OAEP-256", "rsa-2048"),
      ("ECDH-ES+A128KW", "ec-p256")]),
    ("general-three-no-aad", "A256GCM", False,
     [("PBES2-HS256+A128KW", "oct-20"), ("RSA-OAEP", "rsa-2048"),
      ("ECDH-ES+A256KW", "ec-p521")]),
]


def key(kid):
    if kid.startswith("oct-"):
        raw = bytes(range(1, int(kid[4:]) + 1))
        return jwk.JWK(kty="oct", kid=kid, k=common.base64url_encode(raw))
    with open(os.path.join(OUT, kid + ".pem"), "rb") as f:
        k = jwk.JWK.from_pem(f.read())
    members = json.loads(k.export(private_key=True))
    members["kid"] = kid
    return jwk.JWK(**members)


def public(k):
    return k if k["kty"] == "oct" else jwk.JWK.from_json(k.export_public())


def write():
    rows = []
    for cid, enc, aad, recipients in CASES:
        token = jwe.JWE(PLAINTEXT, json.dumps({"enc": enc, "cty": "text/plain"}),
                        unprotected=json.dumps(UNPROTECTED),
                        aad=AAD if aad else None)
        keys = jwk.JWKSet()
        for alg, kid in recipients:
            k = key(kid)
            keys.add(k)
            header = {"alg": alg, "kid": kid, "x-recipient": kid}
            if alg.startswith("PBES2"):
                header["p2c"] = 10000
            token.add_recipient(public(k), header=json.dumps(header))
        rows.append({"id": cid, "enc": enc,
                     "algs": ",".join(a for a, _ in recipients),
                     "kids": ",".join(k for _, k in recipients),
                     "keys": keys.export(private_keys=True),
                     "plaintext": PLAINTEXT.hex(),
                     "token": token.serialize(compact=False)})
    with open(os.path.join(OUT, FILE), "w", newline="") as f:
        w = csv.DictWriter(f, list(rows[0]), delimiter="\t",
                           lineterminator="\n", quoting=csv.QUOTE_NONE,
                           quotechar=None)
        w.writeheader()
        w.writerows(rows)
    path = os.path.join(OUT, "MANIFEST.tsv")
    with open(path) as f:
        manifest = [r for r in csv.DictReader(f, delimiter="\t")
                    if r["file"] != FILE]
    manifest.append({"file": FILE,
                     "source": "jwcrypto %s" % version("jwcrypto"),
                     "generator": GENERATOR})
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, ["file", "source", "generator"], delimiter="\t",
                           lineterminator="\n")
        w.writeheader()
        w.writerows(manifest)
    print("wrote %d tokens" % len(rows))


def check():
    with open(os.path.join(OUT, FILE)) as f:
        rows = list(csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE))
    n = 0
    for row in rows:
        keys = jwk.JWKSet.from_json(row["keys"])
        for kid in row["kids"].split(","):
            token = jwe.JWE()
            token.deserialize(row["token"], key=keys.get_key(kid))
            if token.payload != bytes.fromhex(row["plaintext"]):
                sys.exit("make-jwe-json: FAILED %s %s" % (row["id"], kid))
            n += 1
    print("make-jwe-json: %d tokens decrypt for %d recipients with "
          "jwcrypto %s." % (len(rows), n, version("jwcrypto")))


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif not sys.argv[1:]:
        write()
    else:
        sys.exit(__doc__)
