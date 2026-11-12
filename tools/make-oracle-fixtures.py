#!/usr/bin/env python3
"""Write, or check, the oracle fixtures: JWTs and PEM keys made by Python.

    python3 tools/make-oracle-fixtures.py              write the fixtures
    python3 tools/make-oracle-fixtures.py --keys ID..  write only these keys
    python3 tools/make-oracle-fixtures.py --check      check them

Maintainer tooling, never run at check time. Needs `PyJWT` and
`cryptography`, for example in a virtual environment:

    python3 -m venv venv && venv/bin/pip install pyjwt cryptography

PyJWT is an independent JOSE implementation, so its tokens are the oracle
for zujose's JWS and JWT code (design section 10). Writes, under
tests/testthat/fixtures/oracle/:

  - keys: `rsa-2048`, `rsa-1024`, `ec-p256`, `ec-p384`, `ec-p521` and
    `x25519`, each as a PKCS #8 private key (`<id>.pem`) and an SPKI
    public key (`<id>.pub.pem`), written by `cryptography`. They are the
    oracle for zujose's PEM export too: `jwk_pem()` of a key read back
    must give the file's bytes;
  - tokens.tsv: one JWT per row, signed by PyJWT with the HMAC secret
    bytes 1..64 (`hmac`), the same reversed (`hmac-wrong`), or one of the
    keys. Claims are fixed, with `exp` = 2000000000, so tests decode them
    at a fixed time;
  - MANIFEST.tsv: a row for every file, with the library versions that
    wrote it. Rows of files other tools write are kept.

Keys and the randomised signatures (PS*, ES*) change on every write.
`--keys` writes only the named keys, and no tokens, so a key added later
does not rewrite the others: `x25519` was added that way.
--check does not regenerate: it verifies every token with PyJWT against
its key, checks that `cryptography` reads every key and writes each one's
two files back byte for byte, and exits non-zero on the first failure.
"""
import csv
import os
import sys

import cryptography
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519

OUT = os.path.join("tests", "testthat", "fixtures", "oracle")
GENERATOR = "tools/make-oracle-fixtures.py"
SECRET = bytes(range(1, 65))
CLAIMS = {"sub": "u2", "aud": "api", "exp": 2000000000, "n": 42}
CURVES = {"ec-p256": ec.SECP256R1, "ec-p384": ec.SECP384R1,
          "ec-p521": ec.SECP521R1}
KEYS = ["rsa-2048", "rsa-1024", *CURVES, "x25519"]
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


def generate(name):
    if name.startswith("rsa-"):
        return rsa.generate_private_key(65537, int(name[4:]))
    if name == "x25519":
        return x25519.X25519PrivateKey.generate()
    return ec.generate_private_key(CURVES[name]())


def pem_files(key):
    private = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return {".pem": private, ".pub.pem": public}


def write_keys(names):
    keys, files = {}, []
    for name in names:
        keys[name] = generate(name)
        for suffix, data in pem_files(keys[name]).items():
            with open(os.path.join(OUT, name + suffix), "wb") as f:
                f.write(data)
            files.append(name + suffix)
    return keys, files


def write_manifest(files):
    path = os.path.join(OUT, "MANIFEST.tsv")
    rows = []
    if os.path.exists(path):
        with open(path) as f:
            rows = [r for r in csv.DictReader(f, delimiter="\t")
                    if r["file"] not in files]
    by_file = {r["file"]: r for r in rows}
    for name in files:
        by_file[name] = {"file": name, "source": source(),
                         "generator": GENERATOR}
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, ["file", "source", "generator"], delimiter="\t",
                           lineterminator="\n")
        w.writeheader()
        w.writerows(by_file.values())


def write():
    os.makedirs(OUT, exist_ok=True)
    keys, files = write_keys(KEYS)

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
    write_manifest(files)
    print("wrote %d keys and %d tokens" % (len(keys), len(rows)))


def check():
    keys = {}
    for name in KEYS:
        files = {}
        for suffix in (".pem", ".pub.pem"):
            with open(os.path.join(OUT, name + suffix), "rb") as f:
                files[suffix] = f.read()
        private = serialization.load_pem_private_key(files[".pem"], None)
        if pem_files(private) != files:
            sys.exit("make-oracle-fixtures: FAILED key " + name)
        keys[name] = private.public_key()
    n = 0
    with open(os.path.join(OUT, "tokens.tsv")) as f:
        for row in csv.DictReader(f, delimiter="\t"):
            claims = jwt.decode(row["token"], signing_key(row["key"], keys),
                                algorithms=[row["alg"]], audience="api",
                                options={"verify_exp": False})
            if claims != CLAIMS:
                sys.exit("make-oracle-fixtures: FAILED " + row["id"])
            n += 1
    print("make-oracle-fixtures: %d keys and %d tokens check with %s."
          % (len(keys), n, source()))


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif sys.argv[1:2] == ["--keys"] and sys.argv[2:]:
        unknown = set(sys.argv[2:]) - set(KEYS)
        if unknown:
            sys.exit("make-oracle-fixtures: unknown keys " + str(unknown))
        _, files = write_keys(sys.argv[2:])
        write_manifest(files)
        print("wrote %d keys" % len(sys.argv[2:]))
    elif not sys.argv[1:]:
        write()
    else:
        sys.exit(__doc__)
