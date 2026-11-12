#!/usr/bin/env python3
"""Write, or check, RFC 7638 thumbprints computed by jwcrypto.

    python3 tools/make-jwk-thumbprints.py           write the fixture
    python3 tools/make-jwk-thumbprints.py --check   check it

Maintainer tooling, never run at check time. Needs `jwcrypto`.

jwcrypto is an independent JOSE implementation, so its `JWK.thumbprint()`
is the oracle for zujose's thumbprints of every key type (#105). The keys
are fixed, so the fixture is reproducible:

  - `rsa-2048`, `ec-p256`, `ec-p384`, `ec-p521` and `x25519`: the
    private keys under tests/testthat/fixtures/oracle/, which
    tools/make-oracle-fixtures.py wrote;
  - `ed25519`: the RFC 8037 A.1 private key;
  - `oct-16`, `oct-32` and `oct-64`: the secret bytes 1..16, 1..32 and
    1..64.

Writes tests/testthat/fixtures/oracle/thumbprints.tsv, one row per key and
hash (SHA-256, SHA-384, SHA-512), with the key as jwcrypto exports it,
private members included, and adds its row to fixtures/oracle/MANIFEST.tsv.
--check recomputes every thumbprint from the committed JWK with jwcrypto,
and exits non-zero on the first that differs.
"""
import csv
import os
import sys
from importlib.metadata import version

from cryptography.hazmat.primitives import hashes
from jwcrypto import common, jwk

OUT = os.path.join("tests", "testthat", "fixtures", "oracle")
FILE = "thumbprints.tsv"
GENERATOR = "tools/make-jwk-thumbprints.py"
PEMS = ["rsa-2048", "ec-p256", "ec-p384", "ec-p521", "x25519"]
ED25519 = {"kty": "OKP", "crv": "Ed25519",
           "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
           "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
HASHES = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
          "sha512": hashes.SHA512()}


def keys():
    out = {}
    for name in PEMS:
        with open(os.path.join(OUT, name + ".pem"), "rb") as f:
            out[name] = jwk.JWK.from_pem(f.read())
    out["ed25519"] = jwk.JWK(**ED25519)
    for n in (16, 32, 64):
        out["oct-%d" % n] = jwk.JWK(
            kty="oct", k=common.base64url_encode(bytes(range(1, n + 1))))
    return out


def write():
    rows = []
    for name, key in keys().items():
        for hname, h in HASHES.items():
            rows.append({"id": name, "hash": hname,
                         "jwk": key.export(private_key=True),
                         "thumbprint": key.thumbprint(h)})
    with open(os.path.join(OUT, FILE), "w", newline="") as f:
        w = csv.DictWriter(f, ["id", "hash", "jwk", "thumbprint"],
                           delimiter="\t", lineterminator="\n",
                           quoting=csv.QUOTE_NONE, quotechar=None)
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
    print("wrote %d thumbprints" % len(rows))


def check():
    with open(os.path.join(OUT, FILE)) as f:
        rows = list(csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE))
    for row in rows:
        key = jwk.JWK.from_json(row["jwk"])
        if key.thumbprint(HASHES[row["hash"]]) != row["thumbprint"]:
            sys.exit("make-jwk-thumbprints: FAILED %s %s"
                     % (row["id"], row["hash"]))
    print("make-jwk-thumbprints: %d thumbprints check with jwcrypto %s."
          % (len(rows), version("jwcrypto")))


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif not sys.argv[1:]:
        write()
    else:
        sys.exit(__doc__)
