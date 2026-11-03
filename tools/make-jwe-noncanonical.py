#!/usr/bin/env python3
"""Write, or check, JWE vectors whose protected header is not canonical JSON.

    python3 tools/make-jwe-noncanonical.py           write the fixture
    python3 tools/make-jwe-noncanonical.py --check   check it

Maintainer tooling, never run at check time. Needs `jwcrypto`.

A JWE's AAD is the protected header exactly as received (RFC 7516 section
5.2, step 14). Every other JWE in the suite has a header that re-serializes
to the same bytes, so a decoder that rebuilt the header would still pass.
These tokens have headers another implementation could send: members out
of order, spaces and a newline, escaped "/", \\u escapes and raw UTF-8. A
decoder that re-serializes the header computes the wrong AAD and fails.

jwcrypto keeps a protected header given as a string byte for byte. The keys
are fixed, so the fixture is reproducible except for the random CEK and IV.
Writes tests/testthat/fixtures/oracle/jwe-noncanonical.tsv, with the key
and plaintext in hex, and adds its row to fixtures/oracle/MANIFEST.tsv.
"""
import csv
import json
import os
import sys
from importlib.metadata import version

from jwcrypto import common, jwe, jwk

OUT = os.path.join("tests", "testthat", "fixtures", "oracle")
FILE = "jwe-noncanonical.tsv"
GENERATOR = "tools/make-jwe-noncanonical.py"
PLAINTEXT = "Non-canonical header: été.".encode("utf-8")
CASES = [
    ("a128kw-cbc", bytes(range(16)),
     '{"enc": "A128CBC-HS256",\n "alg": "A128KW", "kid": "k\\/1", '
     '"note": "\\u00e9t\\u00e9"}'),
    ("dir-gcm", bytes(range(32)),
     '{ "alg" : "dir" , "enc" : "A256GCM" }'),
    ("a256kw-utf8", bytes(range(100, 132)),
     '{"zip_note":"raw été","enc":"A128GCM","alg":"A256KW","uri":"a\\/b"}'),
]


def key(raw):
    return jwk.JWK(kty="oct", k=common.base64url_encode(raw))


def write():
    rows = []
    for cid, raw, header in CASES:
        token = jwe.JWE(PLAINTEXT, header)
        token.add_recipient(key(raw))
        compact = token.serialize(compact=True)
        got = common.base64url_decode(compact.split(".")[0]).decode("utf-8")
        if got != header:
            sys.exit("make-jwe-noncanonical: jwcrypto rewrote the header")
        h = json.loads(header)
        rows.append({"id": cid, "alg": h["alg"], "enc": h["enc"],
                     "key": raw.hex(), "plaintext": PLAINTEXT.hex(),
                     "token": compact})
    with open(os.path.join(OUT, FILE), "w", newline="") as f:
        w = csv.DictWriter(f, ["id", "alg", "enc", "key", "plaintext",
                               "token"], delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    path = os.path.join(OUT, "MANIFEST.tsv")
    with open(path) as f:
        manifest = [r for r in csv.DictReader(f, delimiter="\t")
                    if r["file"] != FILE]
    manifest.append({"file": FILE, "source": "jwcrypto %s" % version("jwcrypto"),
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
        token.deserialize(row["token"], key=key(bytes.fromhex(row["key"])))
        if token.payload != bytes.fromhex(row["plaintext"]):
            sys.exit("make-jwe-noncanonical: FAILED " + row["id"])
    print("make-jwe-noncanonical: %d tokens decrypt with jwcrypto %s."
          % (len(rows), version("jwcrypto")))


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif not sys.argv[1:]:
        write()
    else:
        sys.exit(__doc__)
