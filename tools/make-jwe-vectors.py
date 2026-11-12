#!/usr/bin/env python3
"""Write, or check, JWE known answers made by jwcrypto with fixed keys.

    python3 tools/make-jwe-vectors.py           write the fixture
    python3 tools/make-jwe-vectors.py --check   check it

Maintainer tooling, never run at check time. Needs `jwcrypto`.

The RFCs give no known answer for the Concat KDF's second round (keys over
256 bits: ECDH-ES with A192CBC-HS384 or A256CBC-HS512), nor for A192GCM,
A192KW or A192GCMKW. jwcrypto is an independent implementation, so tokens
it makes are the known answers zujose decrypts at check time (#102). The
rows are chosen to cover those gaps and no more:

  - `dir` with every A*GCM and with A192CBC-HS384 and A256CBC-HS512, under
    the header zujose writes, so zujose re-encrypting at the token's CEK
    and IV must give the token byte for byte;
  - ECDH-ES in direct mode with A192CBC-HS384, A256CBC-HS512 and A192GCM
    on each curve, where the derived key is the CEK;
  - ECDH-ES+A192KW, A192KW and A192GCMKW, each with A192GCM.

Every key is fixed. Recipients are the private keys under
tests/testthat/fixtures/oracle/ (written by tools/make-oracle-fixtures.py)
and the oct secrets bytes 1..n. jwcrypto always generates its ECDH-ES
ephemeral key, so this script replaces `JWK.generate` while it encrypts,
to return a fixed ephemeral key made from SHA-256("zujose ephemeral
<curve>"). jwcrypto's CEK and IVs stay random, and every row records the
CEK jwcrypto used. Writes tests/testthat/fixtures/oracle/jwe-vectors.tsv,
with the recipient key, the ephemeral key (private, so zujose can redo
the derivation), the CEK and the plaintext, and adds its row to
fixtures/oracle/MANIFEST.tsv. --check decrypts every token with jwcrypto
and compares the plaintext and the CEK, without regenerating.
"""
import csv
import hashlib
import json
import os
import sys
from importlib.metadata import version

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from jwcrypto import common, jwe, jwk

OUT = os.path.join("tests", "testthat", "fixtures", "oracle")
FILE = "jwe-vectors.tsv"
GENERATOR = "tools/make-jwe-vectors.py"
PLAINTEXT = "Known answer: été, 日本.".encode("utf-8")
CURVES = {"ec-p256": ("P-256", ec.SECP256R1), "ec-p384": ("P-384", ec.SECP384R1),
          "ec-p521": ("P-521", ec.SECP521R1), "x25519": ("X25519", None)}
CASES = (
    [("dir-" + enc, "dir", enc, "oct-%d" % n)
     for enc, n in [("A128GCM", 16), ("A192GCM", 24), ("A256GCM", 32),
                    ("A192CBC-HS384", 48), ("A256CBC-HS512", 64)]]
    + [("ecdh-es-%s-%s" % (enc.lower(), kid), "ECDH-ES", enc, kid)
       for enc in ["A192CBC-HS384", "A256CBC-HS512", "A192GCM"]
       for kid in CURVES]
    + [("ecdh-es-a192kw", "ECDH-ES+A192KW", "A192GCM", "ec-p384"),
       ("a192kw", "A192KW", "A192GCM", "oct-24"),
       ("a192gcmkw", "A192GCMKW", "A192GCM", "oct-24")]
)


def oct_key(n):
    return jwk.JWK(kty="oct", k=common.base64url_encode(bytes(range(1, n + 1))))


def recipient(kid):
    if kid.startswith("oct-"):
        return oct_key(int(kid[4:]))
    with open(os.path.join(OUT, kid + ".pem"), "rb") as f:
        return jwk.JWK.from_pem(f.read())


def ephemeral(kid):
    crv, curve = CURVES[kid]
    seed = hashlib.sha256(("zujose ephemeral " + crv).encode()).digest()
    if curve is None:
        return jwk.JWK.from_pyca(x25519.X25519PrivateKey.from_private_bytes(seed))
    return jwk.JWK.from_pyca(
        ec.derive_private_key(int.from_bytes(seed, "big"), curve()))


def encrypt(alg, enc, key, eph):
    real = jwk.JWK.generate
    jwk.JWK.generate = classmethod(lambda cls, **kw: eph)
    try:
        # dir's header is the one zujose writes, members in its order.
        token = jwe.JWE(PLAINTEXT, json.dumps({"alg": alg, "enc": enc},
                                              separators=(",", ":")))
        token.add_recipient(key)
        return token.serialize(compact=True), token.cek
    finally:
        jwk.JWK.generate = real


def write():
    rows = []
    for cid, alg, enc, kid in CASES:
        key = recipient(kid)
        eph = ephemeral(kid) if alg.startswith("ECDH") else None
        public = key if key["kty"] == "oct" else \
            jwk.JWK.from_json(key.export_public())
        compact, cek = encrypt(alg, enc, public, eph)
        rows.append({"id": cid, "alg": alg, "enc": enc,
                     "key": key.export(private_key=True),
                     "ephemeral": eph.export(private_key=True) if eph else "",
                     "cek": cek.hex(), "plaintext": PLAINTEXT.hex(),
                     "token": compact})
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
    for row in rows:
        token = jwe.JWE()
        token.deserialize(row["token"], key=jwk.JWK.from_json(row["key"]))
        if (token.payload != bytes.fromhex(row["plaintext"])
                or token.cek.hex() != row["cek"]):
            sys.exit("make-jwe-vectors: FAILED " + row["id"])
    print("make-jwe-vectors: %d tokens decrypt with jwcrypto %s."
          % (len(rows), version("jwcrypto")))


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif not sys.argv[1:]:
        write()
    else:
        sys.exit(__doc__)
