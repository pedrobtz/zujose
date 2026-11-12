#!/usr/bin/env python3
"""Write, or check, PyJWT's claim verdicts over a grid (#106).

    python3 tools/make-claim-verdicts.py            write the fixture
    python3 tools/make-claim-verdicts.py --check    check it

Maintainer tooling, never run at check time. Needs `PyJWT`, as
tools/make-oracle-fixtures.py does. Writes, under
tests/testthat/fixtures/oracle/:

  - claims.tsv: one row per case, a claims set PyJWT signs with HS256 and
    the secret bytes 1..64, the arguments it is decoded with, and PyJWT's
    verdict, `accept` or `reject`, with the exception PyJWT raised;
  - its row in MANIFEST.tsv. Rows of files other tools write are kept.

The clock is frozen at NOW, so the verdicts do not depend on when this
runs. The grid:

  - time: `exp`, `nbf` and `iat` each at NOW plus -61, -60, -59, -1,
    -0.5, 0, 0.5, 1, 59, 60 and 61 seconds, and as a numeric string, a
    `null`, `true` and 1e20, with leeway 0 and 60. A row testing `nbf` or
    `iat` also has an `exp` an hour ahead, so only the claim tested decides;
  - required: a claims set with and without `exp`, with PyJWT's default
    `require` (none), `require: ["exp"]` and `require: []`. Every other
    row requires `exp`, as jwt_decode() does by default;
  - audience: `aud` absent, a matching or other string, arrays that do or
    do not hold it, `[]`, `""`, `null`, `0`, `false`, `1` and a mixed
    array, against no audience, `"api"` and `["api", "b"]`;
  - issuer and subject: `iss` and `sub` absent, matching, other, a number,
    `null` and an array, against none and a single string.

Columns: id, the claims as JSON, leeway, audience and issuer and subject
(JSON, empty for None), required (`default`, or a JSON array), the token,
the verdict and PyJWT's exception. tests/testthat/test-oracle.R decodes
each token with jwt_decode() at NOW and asserts the same verdict, except
for the deliberate divergences it lists, each with its reason.

--check does not regenerate: it signs and decides every row again and
exits non-zero if any token or verdict differs.
"""
import csv
import json
import os
import sys
from datetime import datetime, timezone

import jwt
import jwt.api_jwt

OUT = os.path.join("tests", "testthat", "fixtures", "oracle")
FILE = "claims.tsv"
GENERATOR = "tools/make-claim-verdicts.py"
SECRET = bytes(range(1, 65))
NOW = 1000000000
COLUMNS = ["id", "claims", "leeway", "audience", "issuer", "subject",
           "required", "token", "verdict", "pyjwt"]


class Frozen(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime.fromtimestamp(NOW, tz or timezone.utc)


jwt.api_jwt.datetime = Frozen


def number(x):
    return "%g" % x if isinstance(x, float) else str(x)


def grid():
    rows = []

    def add(name, claims, leeway=0, audience=None, issuer=None,
            subject=None, required=("exp",)):
        rows.append({"id": name, "claims": claims, "leeway": leeway,
                     "audience": audience, "issuer": issuer,
                     "subject": subject,
                     "required": (required if required == "default"
                                  else list(required))})

    later = NOW + 3600
    offsets = [-61, -60, -59, -1, -0.5, 0, 0.5, 1, 59, 60, 61]
    odd = {"string": str(NOW + 30), "null": None, "true": True,
           "huge": 1e20}
    for claim in ("exp", "nbf", "iat"):
        values = {"%+g" % d: NOW + d for d in offsets}
        values.update(odd)
        for label, value in values.items():
            for leeway in (0, 60):
                claims = {claim: value}
                if claim != "exp":
                    claims["exp"] = later
                add("%s%s-l%d" % (claim, label, leeway), claims, leeway)

    for label, claims in (("exp", {"exp": later}), ("no-exp", {"sub": "u"})):
        for req_label, req in (("default", "default"), ("exp", ["exp"]),
                               ("none", [])):
            add("required-%s-%s" % (req_label, label), claims,
                required=req)

    auds = {"absent": None, "api": "api", "other": "x",
            "array-api": ["api"], "array-both": ["x", "api"],
            "array-other": ["x"], "array-empty": [], "empty": "",
            "null": "null", "zero": 0, "false": False, "one": 1,
            "array-mixed": ["api", 1]}
    audiences = {"none": None, "api": "api", "two": ["api", "b"]}
    for label, aud in auds.items():
        for a_label, audience in audiences.items():
            claims = {"exp": later}
            if label == "null":
                claims["aud"] = None
            elif aud is not None:
                claims["aud"] = aud
            add("aud-%s-%s" % (label, a_label), claims, audience=audience)

    values = {"absent": None, "match": "me", "other": "x", "number": 1,
              "null": "null", "array": ["me"]}
    for claim, arg in (("iss", "issuer"), ("sub", "subject")):
        for label, value in values.items():
            for e_label, expected in (("none", None), ("me", "me")):
                claims = {"exp": later}
                if label == "null":
                    claims[claim] = None
                elif value is not None:
                    claims[claim] = value
                add("%s-%s-%s" % (claim, label, e_label), claims,
                    **{arg: expected})
    return rows


def decide(row):
    # jwt.encode() refuses a non-string `iss`, so the JWS layer signs the
    # claims as JSON.
    payload = json.dumps(row["claims"], separators=(",", ":")).encode()
    token = jwt.api_jws.encode(payload, SECRET, algorithm="HS256",
                               headers={"typ": "JWT"})
    options = {}
    if row["required"] != "default":
        options["require"] = row["required"]
    try:
        jwt.decode(token, SECRET, algorithms=["HS256"],
                   audience=row["audience"], issuer=row["issuer"],
                   subject=row["subject"], leeway=row["leeway"],
                   options=options)
        verdict, error = "accept", ""
    except jwt.PyJWTError as e:
        verdict, error = "reject", type(e).__name__
    return token, verdict, error


def as_json(x):
    return "" if x is None else json.dumps(x, separators=(",", ":"))


def table():
    out = []
    for row in grid():
        token, verdict, error = decide(row)
        out.append({
            "id": row["id"], "claims": as_json(row["claims"]),
            "leeway": number(row["leeway"]),
            "audience": as_json(row["audience"]),
            "issuer": as_json(row["issuer"]),
            "subject": as_json(row["subject"]),
            "required": (row["required"] if row["required"] == "default"
                         else as_json(row["required"])),
            "token": token, "verdict": verdict, "pyjwt": error,
        })
    return out


def tsv(rows):
    lines = ["\t".join(COLUMNS)]
    lines += ["\t".join(r[c] for c in COLUMNS) for r in rows]
    return "\n".join(lines) + "\n"


def write_manifest():
    path = os.path.join(OUT, "MANIFEST.tsv")
    with open(path) as f:
        rows = [r for r in csv.DictReader(f, delimiter="\t")
                if r["file"] != FILE]
    rows.append({"file": FILE, "source": "PyJWT %s" % jwt.__version__,
                 "generator": GENERATOR})
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, ["file", "source", "generator"], delimiter="\t",
                           lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main():
    rows = table()
    path = os.path.join(OUT, FILE)
    if sys.argv[1:] == ["--check"]:
        with open(path, encoding="ascii") as f:
            if f.read() != tsv(rows):
                sys.exit("make-claim-verdicts: FAILED, %s differs" % FILE)
        print("make-claim-verdicts: %d verdicts check with PyJWT %s."
              % (len(rows), jwt.__version__))
    elif not sys.argv[1:]:
        with open(path, "w", encoding="ascii") as f:
            f.write(tsv(rows))
        write_manifest()
        print("wrote %d verdicts" % len(rows))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
