#!/usr/bin/env python3
"""Write, or check, the oracle fixtures: JWTs and PEM keys made by Python.

    python3 tools/make-oracle-fixtures.py           write the fixtures
    python3 tools/make-oracle-fixtures.py --check   check them

Maintainer tooling, never run at check time. Needs `PyJWT` and
`cryptography`, for example in a virtual environment:

    python3 -m venv venv && venv/bin/pip install pyjwt cryptography

PyJWT is an independent JOSE implementation, so its tokens are the oracle
for zujose's JWS and JWT code (design section 10). Writes, under
tests/testthat/fixtures/oracle/:

  - keys: `rsa-2048`, `rsa-1024`, `ec-p256`, `ec-p384` and `ec-p521`, each
    as a PKCS #8 private key (`<id>.pem`) and an SPKI public key
    (`<id>.pub.pem`), written by `cryptography`;
  - tokens.tsv: one JWT per row, signed by PyJWT with the HMAC secret
    bytes 1..64 (`hmac`), the same reversed (`hmac-wrong`), or one of the
    keys. Claims are fixed, with `exp` = 2000000000, so tests decode them
    at a fixed time;
  - MANIFEST.tsv: every file, with the library versions that wrote it.

Keys and the randomised signatures (PS*, ES*) change on every write.
--check does not regenerate: it verifies every token with PyJWT against
its key, and exits non-zero on the first failure.
"""
import csv
import os
import sys

import cryptography
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

OUT = os.path.join("tests", "testthat", "fixtures", "oracle")
GENERATOR = "tools/make-oracle-fixtures.py"
SECRET = bytes(range(1, 65))
CLAIMS = {"sub": "u2", "aud": "api", "exp": 2000000000, "n": 42}
CURVES = {"ec-p256": ec.SECP256R1, "ec-p384": ec.SECP384R1,
          "ec-p521": ec.SECP521R1}
TOKENS = [
    ("hs256", "HS256", "hmac"), ("hs384", "HS384", "hmac"),
    ("hs512", "HS512", "hmac"), ("hs256-wrong", "HS256", "hmac-wrong"),
    ("rs256", "RS256", "rsa-2048"), ("rs384", "RS384", "rsa-2048"),
    ("rs512", "RS512", "rsa-2048"), ("ps256", "PS256", "rsa-2048"),
    ("ps384", "PS384", "rsa-2048"), ("ps512", "PS512", "rsa-2048"),
    ("es256", "ES256", "ec-p256"), ("es384", "ES384", "ec-p384"),
    ("es512", "ES512", "ec-p521"),
]


def source():
    return "PyJWT %s, cryptography %s" % (jwt.__version__,
                                          cryptography.__version__)


def signing_key(name, keys):
    if name == "hmac":
        return SECRET
    if name == "hmac-wrong":
        return SECRET[::-1]
    return keys[name]


def write():
    os.makedirs(OUT, exist_ok=True)
    keys = {"rsa-2048": rsa.generate_private_key(65537, 2048),
            "rsa-1024": rsa.generate_private_key(65537, 1024)}
    keys.update({k: ec.generate_private_key(c()) for k, c in CURVES.items()})

    files = []
    for name, key in keys.items():
        private = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        for suffix, data in ((".pem", private), (".pub.pem", public)):
            with open(os.path.join(OUT, name + suffix), "wb") as f:
                f.write(data)
            files.append(name + suffix)

    rows = [{"id": tid, "alg": alg, "key": kname,
             "token": jwt.encode(CLAIMS, signing_key(kname, keys),
                                 algorithm=alg)}
            for tid, alg, kname in TOKENS]
    with open(os.path.join(OUT, "tokens.tsv"), "w", newline="") as f:
        w = csv.DictWriter(f, ["id", "alg", "key", "token"], delimiter="\t",
                           lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    files.append("tokens.tsv")

    with open(os.path.join(OUT, "MANIFEST.tsv"), "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["file", "source", "generator"])
        for name in files:
            w.writerow([name, source(), GENERATOR])
    print("wrote %d keys and %d tokens" % (len(keys), len(rows)))


def check():
    keys = {}
    for name in ["rsa-2048", "rsa-1024", *CURVES]:
        with open(os.path.join(OUT, name + ".pub.pem"), "rb") as f:
            keys[name] = serialization.load_pem_public_key(f.read())
    n = 0
    with open(os.path.join(OUT, "tokens.tsv")) as f:
        for row in csv.DictReader(f, delimiter="\t"):
            claims = jwt.decode(row["token"], signing_key(row["key"], keys),
                                algorithms=[row["alg"]], audience="api",
                                options={"verify_exp": False})
            if claims != CLAIMS:
                sys.exit("make-oracle-fixtures: FAILED " + row["id"])
            n += 1
    print("make-oracle-fixtures: %d tokens verify with %s." % (n, source()))


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif not sys.argv[1:]:
        write()
    else:
        sys.exit(__doc__)
