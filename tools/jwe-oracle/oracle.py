#!/usr/bin/env python3
"""The Python half of the JWE oracle (design section 10).

    python3 tools/jwe-oracle/oracle.py <dir>

Development only, never run at check time. Needs `jwcrypto`. Run after
`oracle.R keys` and `oracle.R encrypt`, and before `oracle.R decrypt`:

  1. decrypts every token in <dir>/r-tokens.tsv, which zujose encrypted,
     with the keys in <dir>/keys.jwks, and checks the plaintext;
  2. encrypts the same plaintext for every alg/enc pair, RSA1_5 included
     (zujose decrypts it but never encrypts it), into <dir>/py-tokens.tsv;
  3. decrypts every JSON serialization in <dir>/r-json.tsv for each of its
     recipients alone, and checks the plaintext, the `aad` and the merged
     protected, shared and per-recipient headers (#101);
  4. writes JSON serializations of its own into <dir>/py-json.tsv:
     flattened with one recipient and general with three, with and without
     `aad`, for every `enc`. jwcrypto writes one recipient as flattened
     only, so a general one-recipient token goes only from zujose.

Exits non-zero on the first failure.
"""
import csv
import json
import os
import sys

from importlib.metadata import version

from jwcrypto import jwe, jwk

PLAINTEXT = "zujose JWE oracle: été, 日本, \U0001f511.".encode("utf-8")
ENCS = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"]
OCT_ALGS = ["A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW",
            "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW",
            "PBES2-HS512+A256KW"]
ECDH_ALGS = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
             "ECDH-ES+A256KW"]
CURVE_KIDS = ["ec-p256", "ec-p384", "ec-p521", "x25519"]
ALLOWED = jwe.default_allowed_algs + ["RSA1_5"]
# ?jwe_encrypt documents p2c = 10000 as the count other implementations
# read; oracle.R writes it, and it must be read under jwcrypto's default
# cap, which this script never raises (#140).
DOCUMENTED_P2C = 10000


def cases():
    for enc in ENCS:
        yield "dir", enc, "dir-" + enc
        for alg in OCT_ALGS:
            yield alg, enc, alg
        for alg in ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"]:
            yield alg, enc, "rsa"
        for alg in ECDH_ALGS:
            for kid in CURVE_KIDS:
                yield alg, enc, kid


def main(out):
    with open(os.path.join(out, "keys.jwks")) as f:
        keys = jwk.JWKSet.from_json(f.read())

    n = 0
    with open(os.path.join(out, "r-tokens.tsv")) as f:
        for row in csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE):
            token = jwe.JWE()
            token.allowed_algs = ALLOWED
            token.deserialize(row["token"], key=keys.get_key(row["kid"]))
            header = json.loads(token.objects["protected"])
            if (token.payload != PLAINTEXT or header["alg"] != row["alg"]
                    or header["enc"] != row["enc"]):
                sys.exit("oracle.py: FAILED %s %s" % (row["alg"], row["enc"]))
            if (row["alg"].startswith("PBES2")
                    and header.get("p2c") != DOCUMENTED_P2C):
                sys.exit("oracle.py: FAILED %s %s: p2c is not %d"
                         % (row["alg"], row["enc"], DOCUMENTED_P2C))
            n += 1
    print("oracle.py: jwcrypto %s decrypted %d zujose tokens"
          % (version("jwcrypto"), n))

    rows = []
    for alg, enc, kid in cases():
        key = keys.get_key(kid)
        public = jwk.JWK.from_json(key.export_public()) \
            if key["kty"] != "oct" else key
        token = jwe.JWE(PLAINTEXT, json.dumps(
            {"alg": alg, "enc": enc, "kid": kid}))
        token.allowed_algs = ALLOWED
        token.add_recipient(public)
        rows.append({"alg": alg, "enc": enc, "kid": kid,
                     "token": token.serialize(compact=True)})
    with open(os.path.join(out, "py-tokens.tsv"), "w", newline="") as f:
        w = csv.DictWriter(f, ["alg", "enc", "kid", "token"], delimiter="\t",
                           lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print("oracle.py: jwcrypto encrypted %d tokens" % len(rows))


JSON_AAD = "zujose JWE oracle aad: été".encode("utf-8")
# id, aad?, then each recipient as (alg, kid).
JSON_CASES = [
    ("flattened-aad", True, [("A128KW", "A128KW")]),
    ("flattened", False, [("ECDH-ES", "ec-p256")]),
    ("general-three-aad", True,
     [("A256GCMKW", "A256GCMKW"), ("RSA-OAEP-256", "rsa"),
      ("ECDH-ES+A256KW", "x25519")]),
    ("general-three", False,
     [("PBES2-HS384+A192KW", "PBES2-HS384+A192KW"), ("A128KW", "A128KW"),
      ("ECDH-ES+A128KW", "ec-p521")]),
]


def check_json(out, keys):
    n = 0
    with open(os.path.join(out, "r-json.tsv"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE))
    for row in rows:
        aad = row["aad"].encode("utf-8") if row["aad"] else None
        raw = json.loads(row["token"])
        form = "general" if "recipients" in raw else "flattened"
        if form != row["id"].split("-")[0]:
            sys.exit("oracle.py: FAILED %s: %s" % (row["id"], form))
        algs = row["algs"].split(",")
        for alg, kid in zip(algs, row["kids"].split(",")):
            token = jwe.JWE()
            token.allowed_algs = ALLOWED
            token.deserialize(row["token"], key=keys.get_key(kid))
            # jwcrypto's jose_header leaves out a general token's
            # per-recipient header; take it from the recipient named kid.
            header = dict(token.jose_header)
            if form == "general":
                mine = [r["header"] for r in raw["recipients"]
                        if r.get("header", {}).get("kid") == kid]
                if len(mine) != 1:
                    sys.exit("oracle.py: FAILED %s: kid %s" % (row["id"], kid))
                header.update(mine[0])
            if (token.payload != PLAINTEXT
                    or token.objects.get("aad") != aad
                    or header.get("alg") != alg
                    or header.get("enc") != row["enc"]
                    or header.get("cty") != "text/plain"
                    or header.get("x-shared") != "unprotected"
                    or header.get("x-recipient") != kid):
                sys.exit("oracle.py: FAILED JSON %s %s %s"
                         % (row["id"], row["enc"], kid))
            n += 1
    print("oracle.py: jwcrypto decrypted %d zujose JSON tokens for %d "
          "recipients" % (len(rows), n))


def write_json(out, keys):
    rows = []
    for enc in ENCS:
        for cid, aad, recipients in JSON_CASES:
            token = jwe.JWE(PLAINTEXT,
                            json.dumps({"enc": enc, "cty": "text/plain"}),
                            unprotected=json.dumps({"x-shared": "unprotected"}),
                            aad=JSON_AAD if aad else None)
            token.allowed_algs = ALLOWED
            for alg, kid in recipients:
                key = keys.get_key(kid)
                public = jwk.JWK.from_json(key.export_public()) \
                    if key["kty"] != "oct" else key
                header = {"alg": alg, "kid": kid, "x-recipient": kid}
                if alg.startswith("PBES2"):
                    header["p2c"] = DOCUMENTED_P2C
                token.add_recipient(public, header=json.dumps(header))
            rows.append({"id": cid, "enc": enc,
                         "algs": ",".join(a for a, _ in recipients),
                         "kids": ",".join(k for _, k in recipients),
                         "token": token.serialize(compact=False)})
    with open(os.path.join(out, "py-json.tsv"), "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, ["id", "enc", "algs", "kids", "token"],
                           delimiter="\t", lineterminator="\n",
                           quoting=csv.QUOTE_NONE, quotechar=None)
        w.writeheader()
        w.writerows(rows)
    print("oracle.py: jwcrypto encrypted %d JSON tokens" % len(rows))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
    with open(os.path.join(sys.argv[1], "keys.jwks")) as f:
        json_keys = jwk.JWKSet.from_json(f.read())
    check_json(sys.argv[1], json_keys)
    write_json(sys.argv[1], json_keys)
