#!/usr/bin/env python3
"""Generate differential fuzz cases for zujose's token parsing (#96).

    python3 tools/fuzz/gen.py --seed N --cases M --out DIR

Development only, never run at check time; `fuzz.yaml` runs it weekly.
Needs `jwcrypto`, `PyJWT` and `cryptography`, at the versions fuzz.yaml
pins. Run from the package root.

Writes DIR/cases.tsv and DIR/keys.tsv. Each case is a token mutated from a
seed, with the verdict of each reference implementation on it, under the
same key and algorithm allow-list that tools/fuzz/replay.R gives zujose:

  - jwcrypto, for JWS and JWE in every serialization;
  - PyJWT, for compact JWS (`PyJWS.decode_complete()`) and for JWT
    (`jwt.decode()`, `aud` = "api", no claim required).

A verdict is `accept`, with the payload (JWS) or plaintext (JWE), or
`reject`; `na` where the reference does not apply.

Seeds are every token in tests/testthat/fixtures/rfc7520/ whose key
is an RFC 7520 key, and the oracle fixtures tokens.tsv,
zujose-tokens.tsv, jwe-noncanonical.tsv, jwe-vectors.tsv and
jwe-json.tsv. Every seed is a case as it is. Each further case applies,
in order:

  1. with some probability, header and payload edits followed by a fresh
     signature (JWS) or a fresh content encryption under the seed's own
     CEK (JWE), so that the edit reaches the header rules rather than
     only breaking the signature or the tag: `alg`, `enc`, `crit`,
     `b64`, `zip`, `kid`, `epk`, `p2c`, `p2s`, duplicate and unknown
     members, an embedded attacker `jwk`, non-object headers;
  2. a re-serialization: compact, flattened or general JSON;
  3. zero to two token edits: byte flips, part swaps, truncation and
     part counts; Base64url edge cases (padding, `+/`, non-zero trailing
     bits, whitespace) on one part; and JSON edits (extra or missing
     members, `signatures` versus `signature`, `recipients` shapes).

A fresh signature covers either the received part text or its canonical
re-encoding, because jwcrypto verifies over the latter and PyJWT over
the former. The mutation labels, joined with ";", name the edits that
tools/fuzz/allow.tsv matches.

Generation is deterministic for a seed: every random choice comes from
`random.Random(seed)`, ES* signatures are deterministic (RFC 6979), and
IVs, salts and CEKs come from the same generator. PS* seeds and the
RSA-OAEP and ECDH-ES key management are never redone; their edits keep
the seed's signature or encrypted key.
"""
import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import random
import struct
import sys
import warnings
import zlib

import jwt
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from jwcrypto import jwa, jwe, jwk, jws

warnings.simplefilter("ignore")

FIXTURES = os.path.join("tests", "testthat", "fixtures")
HS = ["HS256", "HS384", "HS512"]
RS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
ES = ["ES256", "ES384", "ES512"]
OCT_KM = ["dir", "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW",
          "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW",
          "PBES2-HS512+A256KW"]
RSA_KM = ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256"]
ECDH_KM = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]
ENCS = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
        "A192GCM", "A256GCM"]
ENC_BYTES = {"A128CBC-HS256": 32, "A192CBC-HS384": 48, "A256CBC-HS512": 64,
             "A128GCM": 16, "A192GCM": 24, "A256GCM": 32}
COLUMNS = ["id", "seed", "kind", "mutation", "key", "algs", "encs", "token",
           "jwcrypto", "jwcrypto_payload", "pyjwt", "pyjwt_payload", "note"]


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def tsv(path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = [r for r in f.read().split("\n") if r and not r.startswith("#")]
    head = rows[0].split("\t")
    return [dict(zip(head, r.split("\t"))) for r in rows[1:]]


# Keys --------------------------------------------------------------------

class Keys:
    """Every key a seed uses: the JWK text the verifiers get (`public`
    for a signature key), and the private JWK the generator signs with."""

    def __init__(self):
        self.text = {}      # name -> JWK or JWK Set text, as verified
        self.private = {}   # name -> jwcrypto JWK that signs

    def add(self, name, key, verify_public=False):
        if isinstance(key, str):
            key = jwk.JWK.from_json(key)
        self.private[name] = key
        pub = key.export_public() if verify_public else key.export()
        self.text[name] = canonical_json(json.loads(pub))
        return name

    def add_set(self, name, text):
        self.text[name] = canonical_json(json.loads(text))
        return name

    def jwcrypto(self, name):
        d = json.loads(self.text[name])
        if "keys" in d:
            return jwk.JWKSet.from_json(self.text[name])
        return jwk.JWK.from_json(self.text[name])

    def pyjwt(self, name):
        d = json.loads(self.text[name])
        if "keys" in d:
            return None
        k = jwk.JWK.from_json(self.text[name])
        if d["kty"] == "oct":
            return b64d(d["k"])
        if d["kty"] in ("RSA", "EC"):
            return k.export_to_pem()
        return None


def canonical_json(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def oct_jwk(raw):
    return jwk.JWK(kty="oct", k=b64e(raw))


def pem_jwk(name):
    data = read(os.path.join(FIXTURES, "oracle", name + ".pem")).encode()
    return jwk.JWK.from_pem(data)


def rfc_key(figure):
    return read(os.path.join(FIXTURES, "rfc7520", "key-%03d.json" % figure))


def sig_algs(key_text):
    d = json.loads(key_text)
    if "keys" in d:
        return HS + RS + ES
    return {"oct": HS, "RSA": RS, "EC": ES}.get(d["kty"], HS + RS + ES)


def enc_algs(key_text):
    d = json.loads(key_text)
    if "keys" in d:
        return OCT_KM + RSA_KM + ECDH_KM
    return {"oct": OCT_KM, "RSA": RSA_KM}.get(d["kty"], ECDH_KM)


# Seeds -------------------------------------------------------------------

def load_seeds(keys):
    seeds = []

    def seed(name, kind, token, key, signer=None):
        algs = sig_algs(keys.text[key]) if kind != "jwe" else enc_algs(
            keys.text[key])
        seeds.append({"name": name, "kind": kind, "token": token, "key": key,
                      "signer": signer, "algs": algs})

    # RFC 7520: which key opens which figure is found by trying them.
    sig_keys = {
        "rfc-ec-p521": (rfc_key(2), True), "rfc-rsa": (rfc_key(4), True),
        "rfc-hmac": (rfc_key(5), False), "rfc-rsa-224": (rfc_key(224), True),
    }
    enc_keys = {"rfc-%03d" % f: rfc_key(f)
                for f in (73, 84, 108, 120, 130, 138, 151)}
    password = read(os.path.join(FIXTURES, "rfc7520", "text-096.txt"))
    enc_keys["rfc-pbes2"] = oct_jwk(password.strip().encode()).export()
    for name, (text, public) in sig_keys.items():
        keys.add(name, text, verify_public=public)
    for name, text in enc_keys.items():
        keys.add(name, text)

    for row in tsv(os.path.join(FIXTURES, "rfc7520", "MANIFEST.tsv")):
        token = read(os.path.join(FIXTURES, "rfc7520", row["file"])).strip()
        names = sig_keys if row["type"] == "JWS" else enc_keys
        kind = row["type"].lower()
        for name in names:
            ok, _ = jwcrypto_verdict(kind, token, keys.jwcrypto(name),
                                     sig_algs(keys.text[name]) if kind == "jws"
                                     else enc_algs(keys.text[name]))
            if ok == "accept":
                seed("rfc7520-" + row["figure"], kind, token, name,
                     name if kind == "jws" else None)
                break

    keys.add("hmac", oct_jwk(bytes(range(1, 65))))
    keys.add("hmac-wrong", oct_jwk(bytes(range(64, 0, -1))))
    for name in ("rsa-2048", "rsa-1024", "ec-p256", "ec-p384", "ec-p521"):
        keys.add(name, pem_jwk(name), verify_public=True)
    for row in tsv(os.path.join(FIXTURES, "oracle", "tokens.tsv")):
        signer = row["key"] if row["key"] != "hmac-wrong" else None
        seed("tokens-" + row["id"], "jwt", row["token"], row["key"], signer)
        seed("tokens-" + row["id"], "jws", row["token"], row["key"], signer)
    for row in tsv(os.path.join(FIXTURES, "oracle", "zujose-tokens.tsv")):
        seed("zujose-" + row["id"], row["kind"], row["token"], row["key"],
             row["key"])

    for row in tsv(os.path.join(FIXTURES, "oracle", "jwe-noncanonical.tsv")):
        name = keys.add("noncanonical-" + row["id"],
                        oct_jwk(bytes.fromhex(row["key"])))
        seed("noncanonical-" + row["id"], "jwe", row["token"], name)
    for row in tsv(os.path.join(FIXTURES, "oracle", "jwe-vectors.tsv")):
        name = keys.add("vectors-" + row["id"], row["key"])
        seed("vectors-" + row["id"], "jwe", row["token"], name)
    for row in tsv(os.path.join(FIXTURES, "oracle", "jwe-json.tsv")):
        name = keys.add_set("json-" + row["id"], row["keys"])
        seed("json-" + row["id"], "jwe", row["token"], name)
    return seeds


# Reference verdicts ------------------------------------------------------

def as_bytes(x):
    return x if isinstance(x, bytes) else str(x).encode("utf-8")


def jwcrypto_verdict(kind, token, key, algs, encs=ENCS):
    try:
        if kind == "jwe":
            obj = jwe.JWE()
            obj.allowed_algs = list(algs) + list(encs)
            obj.deserialize(token, key=key)
            return "accept", as_bytes(obj.payload)
        obj = jws.JWS()
        obj.allowed_algs = list(algs)
        obj.deserialize(token, key=key)
        return "accept", as_bytes(obj.objects["payload"])
    except Exception as e:  # noqa: BLE001: any failure is a rejection
        return "reject", type(e).__name__


def pyjwt_verdict(kind, token, key, algs):
    try:
        if kind == "jwt":
            claims = jwt.decode(token, key, algorithms=algs, audience="api",
                                options={"require": []})
            return "accept", canonical_json(claims).encode()
        out = jwt.PyJWS().decode_complete(token, key, algorithms=algs)
        return "accept", as_bytes(out["payload"])
    except Exception as e:  # noqa: BLE001
        return "reject", type(e).__name__


# Parsed forms ------------------------------------------------------------

def parse_jws(token):
    """The seed as a list of signatures and a payload, or None."""
    t = token.strip()
    if t.startswith("{"):
        d = json.loads(t)
        sigs = d["signatures"] if "signatures" in d else [d]
        out = {"payload": d.get("payload"), "sigs": [], "shape":
               "general" if "signatures" in d else "flattened"}
        for s in sigs:
            out["sigs"].append({"protected": b64d(s["protected"])
                                if "protected" in s else None,
                                "header": s.get("header"),
                                "signature": b64d(s["signature"])})
        return out
    p = t.split(".")
    return {"payload": p[1], "shape": "compact",
            "sigs": [{"protected": b64d(p[0]), "header": None,
                      "signature": b64d(p[2])}]}


def parse_jwe(token):
    t = token.strip()
    if t.startswith("{"):
        d = json.loads(t)
        recips = d["recipients"] if "recipients" in d else [
            {k: d[k] for k in ("header", "encrypted_key") if k in d}]
        return {"protected": b64d(d["protected"]) if "protected" in d
                else None,
                "unprotected": d.get("unprotected"),
                "recipients": [{"header": r.get("header"),
                                "ek": b64d(r.get("encrypted_key", ""))}
                               for r in recips],
                "aad": b64d(d["aad"]) if "aad" in d else None,
                "iv": b64d(d["iv"]), "ct": b64d(d["ciphertext"]),
                "tag": b64d(d["tag"]),
                "shape": "general" if "recipients" in d else "flattened"}
    p = t.split(".")
    return {"protected": b64d(p[0]), "unprotected": None,
            "recipients": [{"header": None, "ek": b64d(p[1])}],
            "aad": None, "iv": b64d(p[2]), "ct": b64d(p[3]),
            "tag": b64d(p[4]), "shape": "compact"}


# Header text: an ordered list of (name, JSON text) pairs, so that a
# duplicate member or a non-JSON value survives.

def pairs_of(protected):
    d = json.loads(protected)
    return [(k, json.dumps(v, ensure_ascii=False)) for k, v in d.items()]


def text_of(pairs):
    if isinstance(pairs, str):   # a non-object header
        return pairs.encode("utf-8")
    body = ",".join(json.dumps(k) + ":" + v for k, v in pairs)
    return ("{" + body + "}").encode("utf-8")


def get(pairs, name):
    if isinstance(pairs, str):
        return None
    val = None
    for k, v in pairs:
        if k == name:
            try:
                val = json.loads(v)
            except ValueError:
                val = None
    return val


def put(pairs, name, value):
    """Set `name`, in place: a repeated member stays repeated."""
    text = json.dumps(value)
    if any(k == name for k, _ in pairs):
        return [(k, text if k == name else v) for k, v in pairs]
    return pairs + [(name, text)]


def drop(pairs, name):
    return [(k, v) for k, v in pairs if k != name]


# Header edits ------------------------------------------------------------

def header_edits(rng, pairs, kind, seed_alg, algs):
    """One or two edits; returns (pairs, labels, b64 or None)."""
    labels = []
    b64 = None
    options = ["alg", "crit", "b64", "zip", "kid", "dup", "unknown",
               "non-object", "cty", "jwk"]
    if kind == "jwe":
        options += ["enc", "p2c", "p2s", "epk", "iv-tag"]
        options.remove("jwk")
    # Distinct edits, `b64` and `crit` never together, and a repeated
    # member or a non-object header last, so no later edit undoes them.
    whats = rng.sample(options, rng.choice([1, 1, 1, 2]))
    if {"b64", "crit"} <= set(whats):
        whats = whats[:1]
    whats.sort(key=lambda w: w in ("dup", "non-object"))
    for what in whats:
        if isinstance(pairs, str):
            break
        if what == "alg":
            choice = rng.choice(["family", "family", "none", "None", "",
                                 "number", "missing", "other"])
            fam = [a for a in algs if a != seed_alg] or algs
            value = {"family": rng.choice(fam), "none": "none",
                     "None": "None", "": "", "number": 256,
                     "other": rng.choice([a for a in HS + RS + ES + OCT_KM +
                                          RSA_KM if a != seed_alg])}
            if choice == "missing":
                pairs = drop(pairs, "alg")
            else:
                pairs = put(pairs, "alg", value[choice])
            labels.append("header:alg-" + choice)
        elif what == "enc":
            choice = rng.choice(["other", "unknown", "missing", "number"])
            value = {"other": rng.choice(ENCS), "unknown": "A128CTR",
                     "number": 1}
            if choice == "missing":
                pairs = drop(pairs, "enc")
            else:
                pairs = put(pairs, "enc", value[choice])
            labels.append("header:enc-" + choice)
        elif what == "crit":
            choice = rng.choice(["b64", "unknown", "empty", "string",
                                 "registered", "repeat", "absent"])
            value = {"b64": ["b64"], "unknown": ["exp"], "empty": [],
                     "string": "b64", "registered": ["alg"],
                     "repeat": ["b64", "b64"], "absent": ["x-absent"]}
            pairs = put(pairs, "crit", value[choice])
            if choice in ("b64", "repeat"):
                value = rng.choice([True, False])
                pairs = put(pairs, "b64", value)
                if value is False and kind != "jwe":
                    b64 = False
            if choice == "unknown":
                pairs = put(pairs, "exp", 1)
            labels.append("header:crit-" + choice)
        elif what == "b64" and kind != "jwe":
            choice = rng.choice(["false-crit", "false-no-crit", "true-crit",
                                 "string"])
            value = {"false-crit": False, "false-no-crit": False,
                     "true-crit": True, "string": "false"}[choice]
            pairs = put(pairs, "b64", value)
            if choice.endswith("-crit") and choice != "false-no-crit":
                pairs = put(pairs, "crit", ["b64"])
            if value is False:
                b64 = False
            labels.append("header:b64-" + choice)
        elif what == "b64":
            pairs = put(pairs, "b64", False)
            labels.append("header:b64-jwe")
        elif what == "zip":
            choice = rng.choice(["DEF", "unknown", "number"])
            pairs = put(pairs, "zip", {"DEF": "DEF", "unknown": "GZIP",
                                       "number": 1}[choice])
            labels.append("header:zip-" + choice)
        elif what == "kid":
            choice = rng.choice(["other", "number", "missing", "long",
                                 "empty"])
            value = {"other": "fuzz-kid", "number": 7, "empty": "",
                     "long": "k" * 300}
            if choice == "missing":
                pairs = drop(pairs, "kid")
            else:
                pairs = put(pairs, "kid", value[choice])
            labels.append("header:kid-" + choice)
        elif what == "dup":
            names = [k for k, _ in pairs] or ["alg"]
            name = rng.choice(names)
            same = rng.random() < 0.5
            value = dict(pairs).get(name, '"x"') if same else '"dup"'
            pairs = pairs + [(name, value)]
            labels.append("header:dup-" + ("same" if same else "other"))
        elif what == "unknown":
            pairs = put(pairs, rng.choice(["x-fuzz", "foo", "été"]),
                        rng.choice([1, "v", None, [1], {"a": 1}]))
            labels.append("header:unknown-member")
        elif what == "non-object":
            pairs = rng.choice(["[]", "null", "\"alg\"", "1", "{", ""])
            labels.append("header:non-object")
        elif what == "cty":
            name = rng.choice(["cty", "typ"])
            value = rng.choice(["JWT", "jwt", "application/json", 1])
            pairs = put(pairs, name, value)
            labels.append("header:%s-%s" % (name, "number" if value == 1
                                             else value.lower()))
        elif what == "jwk":
            labels.append("header:embedded-jwk")
            pairs = put(pairs, "jwk", "ATTACKER")   # filled in by the signer
        elif what == "p2c":
            choice = rng.choice(["0", "1", "999", "1000", "16384", "16385",
                                 "600000", "600001", "huge", "float",
                                 "string", "missing"])
            value = {"huge": 2**40, "float": 1000.5, "string": "1000"}
            if choice == "missing":
                pairs = drop(pairs, "p2c")
            else:
                pairs = put(pairs, "p2c", value.get(choice, None)
                            if choice in value else int(choice))
            labels.append("header:p2c-" + choice)
        elif what == "p2s":
            choice = rng.choice(["empty", "short", "7", "8", "noncanonical",
                                 "missing", "number"])
            value = {"empty": "", "short": b64e(b"abc"),
                     "7": b64e(b"1234567"), "8": b64e(b"12345678"),
                     "noncanonical": b64e(b"12345678")[:-1] + "B",
                     "number": 8}
            if choice == "missing":
                pairs = drop(pairs, "p2s")
            else:
                pairs = put(pairs, "p2s", value[choice])
            labels.append("header:p2s-" + choice)
        elif what == "epk":
            choice = rng.choice(["missing", "wrong-crv", "not-object",
                                 "private", "off-curve"])
            epk = get(pairs, "epk")
            if not isinstance(epk, dict):
                epk = {"kty": "EC", "crv": "P-256", "x": b64e(b"\0" * 32),
                       "y": b64e(b"\0" * 32)}
            if choice == "missing":
                pairs = drop(pairs, "epk")
            elif choice == "not-object":
                pairs = put(pairs, "epk", "epk")
            else:
                epk = dict(epk)
                if choice == "wrong-crv":
                    epk["crv"] = {"P-256": "P-384"}.get(epk.get("crv"),
                                                        "P-256")
                elif choice == "private":
                    epk["d"] = b64e(b"\1" * 32)
                else:
                    epk["x"] = b64e(b"\1" * len(b64d(epk.get("x", "AA"))))
                pairs = put(pairs, "epk", epk)
            labels.append("header:epk-" + choice)
        elif what == "iv-tag":
            name = rng.choice(["iv", "tag"])
            pairs = put(pairs, name, rng.choice(["", b64e(b"\0" * 11),
                                                 b64e(b"\0" * 13), 1]))
            labels.append("header:gcmkw-" + name)
    return pairs, labels, b64


def payload_edits(rng, kind, payload):
    if kind != "jwt":
        choice = rng.choice(["empty", "binary", "dot", "unicode"])
        value = {"empty": b"", "binary": bytes(range(256)),
                 "dot": b"a.b.c", "unicode": "été \U0001f511".encode()}
        return value[choice], "payload:" + choice
    choice = rng.choice(["array", "string", "not-json", "dup-claim",
                         "exp-past", "exp-string", "nbf-future", "aud-list",
                         "aud-other", "iat-future", "no-exp", "bom"])
    claims = '"sub":"u2","aud":"api","exp":2000000000,"n":42'
    value = {
        "array": "[1,2]", "string": '"claims"', "not-json": "{sub:u2}",
        "dup-claim": "{" + claims + ',"n":43}',
        "exp-past": '{"sub":"u2","aud":"api","exp":1000000000}',
        "exp-string": '{"sub":"u2","aud":"api","exp":"2000000000"}',
        "nbf-future": "{" + claims + ',"nbf":2000000000}',
        "aud-list": '{"sub":"u2","aud":["x","api"],"exp":2000000000}',
        "aud-other": '{"sub":"u2","aud":"other","exp":2000000000}',
        "iat-future": "{" + claims + ',"iat":2000000000}',
        "no-exp": '{"sub":"u2","aud":"api"}',
        "bom": "﻿{" + claims + "}",
    }[choice]
    return value.encode("utf-8"), "payload:" + choice


# Signing -----------------------------------------------------------------

def sign(alg, key, data):
    if alg in HS:
        h = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
             "HS512": hashlib.sha512}[alg]
        return hmac.new(b64d(key["k"]), data, h).digest()
    if alg in ES:
        h = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(),
             "ES512": hashes.SHA512()}[alg]
        priv = key.get_op_key("sign")
        der = priv.sign(data, ec.ECDSA(h, deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        n = (priv.curve.key_size + 7) // 8
        return r.to_bytes(n, "big") + s.to_bytes(n, "big")
    return jwa.JWA.signing_alg(alg).sign(key, data)


def jws_resign(rng, seed, keys):
    """Edit the header and maybe the payload of a JWS seed, and sign it
    again with the seed's key. Returns (form, labels)."""
    form = parse_jws(seed["token"])
    key = keys.private[seed["signer"]]
    def alg_of(s):
        return json.loads(s["protected"] or "{}").get("alg") or (
            s["header"] or {}).get("alg")
    mine = [s for s in form["sigs"] if s["protected"] is not None and
            alg_of(s) in seed["algs"]]
    if not mine:
        return None
    sig = mine[0]
    seed_alg = alg_of(sig)
    pairs, labels, b64 = header_edits(rng, pairs_of(sig["protected"]),
                                      seed["kind"], seed_alg, seed["algs"])
    payload = b64d(form["payload"]) if form["payload"] else b""
    if rng.random() < 0.3:
        payload, label = payload_edits(rng, seed["kind"], payload)
        labels.append(label)
    signer, alg = key, get(pairs, "alg")
    if get(pairs, "jwk") == "ATTACKER":
        signer = attacker_key(rng, key, keys)
        pairs = put(pairs, "jwk", json.loads(
            signer.export() if signer["kty"] == "oct" else
            signer.export_public()))
    if not isinstance(alg, str) or alg not in sig_algs(signer.export()) or (
            alg.startswith("PS")) or (alg in ES and not curve_fits(alg,
                                                                  signer)):
        alg = seed_alg if not seed_alg.startswith("PS") else None
    if alg is None:
        return None
    protected = text_of(pairs)
    # Sign over the canonical text, or over text edited after signing.
    payload_part = b64e(payload).encode() if b64 is not False else payload
    signature = sign(alg, signer, b64e(protected).encode() + b"." +
                     payload_part)
    form = {"payload": b64e(payload) if b64 is not False else payload,
            "b64": b64 is not False, "shape": form["shape"],
            "sigs": [{"protected": protected, "header": sig["header"],
                      "signature": signature}]}
    if cross_dup(pairs, [sig["header"]]):
        labels.append("header:cross-dup")
    labels.insert(0, "resign")
    return form, labels


def cross_dup(pairs, headers):
    """Whether an edited protected header shares a member name with an
    unprotected one."""
    if isinstance(pairs, str):
        return False
    names = {k for k, _ in pairs}
    return any(names & set(h or {}) for h in headers)


def attacker_key(rng, key, keys):
    """A key of the same type and curve as `key`, but not `key`."""
    if key["kty"] == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                 "P-521": ec.SECP521R1()}[key["crv"]]
        priv = ec.derive_private_key(rng.randrange(1, 2**250), curve)
        return jwk.JWK.from_pyca(priv)
    names = ["hmac-wrong", "hmac"] if key["kty"] == "oct" else [
        "rsa-2048", "rfc-rsa"]
    for name in names:
        if keys.private[name].thumbprint() != key.thumbprint():
            return keys.private[name]


def curve_fits(alg, key):
    want = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg]
    return key.get("crv") == want


def jws_text(form, shape):
    sigs = form["sigs"]
    payload = form["payload"]
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", "replace")
    if shape == "compact" and len(sigs) == 1 and not sigs[0]["header"] and (
            sigs[0]["protected"] is not None):
        return ".".join([b64e(sigs[0]["protected"]), payload or "",
                         b64e(sigs[0]["signature"])])
    entries = []
    for s in sigs:
        e = {}
        if s["protected"] is not None:
            e["protected"] = b64e(s["protected"])
        if s["header"]:
            e["header"] = s["header"]
        e["signature"] = b64e(s["signature"])
        entries.append(e)
    out = {}
    if payload is not None:
        out["payload"] = payload
    if shape == "flattened" and len(entries) == 1:
        out.update(entries[0])
    else:
        out["signatures"] = entries
    return json.dumps(out, ensure_ascii=False, separators=(",", ":"))


# Content encryption ------------------------------------------------------

def seal(enc, cek, iv, aad, plaintext):
    if enc.endswith("GCM"):
        out = AESGCM(cek).encrypt(iv, plaintext, aad)
        return out[:-16], out[-16:]
    half = len(cek) // 2
    mac_key, enc_key = cek[:half], cek[half:]
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    e = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    h = {32: hashlib.sha256, 48: hashlib.sha384, 64: hashlib.sha512}[len(cek)]
    tag = hmac.new(mac_key, aad + iv + ct + struct.pack(">Q", len(aad) * 8),
                   h).digest()[:half]
    return ct, tag


def recover(form, key, algs):
    """The CEK, plaintext and recipient index of a JWE seed, by jwcrypto's
    key management. None if this key opens no recipient."""
    prot = json.loads(form["protected"]) if form["protected"] else {}
    keyset = sorted(key["keys"], key=lambda k: k.thumbprint()) \
        if isinstance(key, jwk.JWKSet) else [key]
    for i, r in enumerate(form["recipients"]):
        header = dict(prot)
        header.update(form["unprotected"] or {})
        header.update(r["header"] or {})
        if header.get("alg") not in algs:
            continue
        for k in keyset:
            try:
                enc = jwa.JWA.encryption_alg(header["enc"])
                km = jwa.JWA.keymgmt_alg(header["alg"])
                cek = km.unwrap(k, enc.wrap_key_size, r["ek"], header)
                aad = b64e(form["protected"] or b"").encode()
                if form["aad"] is not None:
                    aad += b"." + b64e(form["aad"]).encode()
                pt = enc.decrypt(cek, aad, form["iv"], form["ct"],
                                 form["tag"])
                if header.get("zip") == "DEF":
                    pt = zlib.decompress(pt, -15)
                return cek, pt, i, header
            except Exception:  # noqa: BLE001
                continue
    return None


def pbes2_wrap(alg, password, p2s, p2c, cek):
    h = {"PBES2-HS256+A128KW": (hashes.SHA256(), 16),
         "PBES2-HS384+A192KW": (hashes.SHA384(), 24),
         "PBES2-HS512+A256KW": (hashes.SHA512(), 32)}[alg]
    salt = alg.encode() + b"\0" + p2s
    kek = PBKDF2HMAC(algorithm=h[0], length=h[1], salt=salt,
                     iterations=p2c).derive(password)
    return aes_key_wrap(kek, cek)


def jwe_reseal(rng, seed, keys):
    """Edit the protected header of a JWE seed and encrypt its plaintext
    again under the seed's CEK, so the tag holds. For PBES2 the key is
    wrapped again under the edited `p2c` and `p2s` when they make sense."""
    form = parse_jwe(seed["token"])
    if form["protected"] is None:
        return None
    got = recover(form, keys.jwcrypto(seed["key"]), seed["algs"])
    if got is None:
        return None
    cek, plaintext, index, merged = got
    pairs, labels, _ = header_edits(rng, pairs_of(form["protected"]), "jwe",
                                    merged.get("alg"), seed["algs"])
    if rng.random() < 0.2:
        what = rng.choice(["empty", "long", "binary"])
        plaintext = {"empty": b"", "long": b"x" * 1000,
                     "binary": bytes(range(256))}[what]
        labels.append("payload:plaintext-" + what)
    alg = merged.get("alg")
    p2c, p2s = get(pairs, "p2c"), get(pairs, "p2s")
    key = keys.jwcrypto(seed["key"])
    if (alg or "").startswith("PBES2") and isinstance(key, jwk.JWK) and \
            isinstance(p2c, int) and 0 < p2c <= 700000 and isinstance(p2s, str):
        try:
            ek = pbes2_wrap(alg, b64d(key["k"]), b64d(p2s), p2c, cek)
            form["recipients"][index]["ek"] = ek
            labels.append("rewrap")
        except Exception:  # noqa: BLE001
            pass
    if get(pairs, "zip") == "DEF":
        c = zlib.compressobj(wbits=-15)
        plaintext = c.compress(plaintext) + c.flush()
    protected = text_of(pairs)
    iv = rng.randbytes(12 if merged["enc"].endswith("GCM") else 16)
    aad = b64e(protected).encode()
    if form["aad"] is not None:
        aad += b"." + b64e(form["aad"]).encode()
    ct, tag = seal(merged["enc"], cek, iv, aad, plaintext)
    form.update(protected=protected, iv=iv, ct=ct, tag=tag)
    if cross_dup(pairs, [form["unprotected"]] +
                 [r["header"] for r in form["recipients"]]):
        labels.append("header:cross-dup")
    labels.insert(0, "reseal")
    return form, labels


def jwe_text(form, shape):
    r = form["recipients"]
    if shape == "compact" and len(r) == 1 and not r[0]["header"] and \
            not form["unprotected"] and form["aad"] is None and \
            form["protected"] is not None:
        return ".".join(b64e(x) for x in (form["protected"], r[0]["ek"],
                                          form["iv"], form["ct"],
                                          form["tag"]))
    out = {}
    if form["protected"] is not None:
        out["protected"] = b64e(form["protected"])
    if form["unprotected"]:
        out["unprotected"] = form["unprotected"]
    entries = []
    for x in r:
        e = {}
        if x["header"]:
            e["header"] = x["header"]
        if x["ek"]:
            e["encrypted_key"] = b64e(x["ek"])
        entries.append(e)
    if shape == "flattened" and len(entries) == 1:
        out.update(entries[0])
    else:
        out["recipients"] = entries
    if form["aad"] is not None:
        out["aad"] = b64e(form["aad"])
    out.update(iv=b64e(form["iv"]), ciphertext=b64e(form["ct"]),
               tag=b64e(form["tag"]))
    return json.dumps(out, ensure_ascii=False, separators=(",", ":"))


# Token edits -------------------------------------------------------------

FLIPS = list("AZaz09-_.=+/ \n\t\"{}[],:") + ["é", "\\"]


def b64_edit(rng, part):
    """A Base64url edge case on one part's text."""
    choice = rng.choice(["pad", "plus-slash", "trailing-bits", "space",
                         "newline", "std-alphabet", "len-mod-4-1"])
    if choice == "pad":
        return part + "=" * rng.choice([1, 2, (-len(part)) % 4 or 4]), choice
    if choice == "plus-slash":
        i = rng.randrange(len(part)) if part else 0
        return part[:i] + rng.choice("+/") + part[i + 1:], choice
    if choice == "trailing-bits":
        if len(part) % 4 in (2, 3):
            alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                        "0123456789-_")
            v = alphabet.index(part[-1]) if part[-1] in alphabet else 0
            mask = 0x0F if len(part) % 4 == 2 else 0x03
            v = (v & ~mask) | rng.randint(1, mask)
            return part[:-1] + alphabet[v], choice
        return mod_4_1(part), "len-mod-4-1"
    if choice in ("space", "newline"):
        i = rng.randrange(len(part) + 1)
        return part[:i] + (" " if choice == "space" else "\n") + part[i:], \
            choice
    if choice == "std-alphabet":
        return part.replace("-", "+").replace("_", "/"), choice
    return mod_4_1(part), choice


def mod_4_1(part):
    """`part` grown to a length of 1 modulo 4, which no Base64 has."""
    return part + "A" * ((1 - len(part)) % 4 or 4)


B64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
             "0123456789-_")


def noncanonical(part):
    """Whether a Base64url part decodes but is not the canonical encoding
    of what it decodes to (non-zero trailing bits)."""
    if not part or not set(part) <= B64URL or len(part) % 4 == 1:
        return False
    return b64e(b64d(part)) != part


def token_edit(rng, token, kind):
    t = token
    is_json = t.lstrip().startswith("{")
    choice = rng.choice(["flip", "flip", "truncate", "b64", "b64", "b64"] +
                        (["json", "json", "json"] if is_json else
                         ["swap", "parts"]))
    if choice == "flip" and t:
        i = rng.randrange(len(t))
        c = rng.choice(FLIPS)
        what = "-b64char" if c in "+/=" else "-space" if c.isspace() else ""
        t = t[:i] + c + t[i + 1:]
        if not is_json and any(noncanonical(p) for p in t.split(".")):
            what = "-b64char"   # a flip into a part's trailing bits
        return t, "edit:flip" + what
    if choice == "truncate" and t:
        return t[:rng.randrange(len(t))], "edit:truncate"
    if choice == "b64":
        if is_json:
            d = json.loads(t)
            fields = [(None, k) for k in ("protected", "payload", "signature",
                                          "encrypted_key", "iv", "ciphertext",
                                          "tag", "aad") if k in d]
            for i, s in enumerate(d.get("signatures", [])):
                fields += [(("signatures", i), k) for k in s
                           if k in ("protected", "signature")]
            for i, s in enumerate(d.get("recipients", [])):
                fields += [(("recipients", i), k) for k in s
                           if k == "encrypted_key"]
            if not fields:
                return t, "edit:none"
            where, name = rng.choice(fields)
            target = d if where is None else d[where[0]][where[1]]
            if not isinstance(target.get(name), str):
                return t, "edit:none"
            before = target[name]
            target[name], label = b64_edit(rng, before)
            if target[name] == before:
                return t, "edit:none"
            return json.dumps(d, ensure_ascii=False, separators=(",", ":")), \
                "b64:%s-%s" % (label, name)
        parts = t.split(".")
        i = rng.randrange(len(parts))
        before = parts[i]
        parts[i], label = b64_edit(rng, before)
        if parts[i] == before:
            return t, "edit:none"
        return ".".join(parts), "b64:%s-part%d" % (label, i)
    if choice == "swap":
        parts = t.split(".")
        if len(parts) > 1:
            i, j = rng.sample(range(len(parts)), 2)
            parts[i], parts[j] = parts[j], parts[i]
        return ".".join(parts), "edit:swap"
    if choice == "parts":
        parts = t.split(".")
        how = rng.choice(["drop", "add", "empty"])
        if how == "drop":
            parts.pop(rng.randrange(len(parts)))
        elif how == "add":
            parts.insert(rng.randrange(len(parts) + 1), rng.choice(["", "e30"]))
        else:
            parts[rng.randrange(len(parts))] = ""
        return ".".join(parts), "edit:parts-" + how
    if choice == "json":
        return json_edit(rng, json.loads(t), kind)
    return t, "edit:none"


def json_edit(rng, d, kind):
    choice = rng.choice(["extra", "missing", "both-shapes", "rename",
                         "type", "recipients", "header-dup", "array",
                         "header-unprotected"])
    label = "json:" + choice
    keys = list(d)
    if choice == "extra":
        d[rng.choice(["x-fuzz", "payload2", "jwk"])] = rng.choice(
            [1, "v", {"a": 1}])
    elif choice == "missing" and keys:
        name = rng.choice(keys)
        del d[name]
        label += "-" + name
    elif choice == "both-shapes":
        # Only when a member of each shape ends up in the token.
        if "signatures" in d and d["signatures"]:
            d.update(d["signatures"][0])
        elif "signature" in d:
            d["signatures"] = [{k: d[k] for k in ("protected", "header",
                                                  "signature") if k in d}]
        elif d.get("recipients") and set(d["recipients"][0]) & {
                "header", "encrypted_key"}:
            d.update(d["recipients"][0])
        elif "header" in d or "encrypted_key" in d:
            d["recipients"] = [{k: d[k] for k in ("header", "encrypted_key")
                                if k in d}]
        else:
            return json.dumps(d), "edit:none"
    elif choice == "rename":
        swaps = {"signatures": "signature", "signature": "signatures",
                 "recipients": "recipient", "encrypted_key": "encryptedKey",
                 "protected": "Protected"}
        hits = [k for k in keys if k in swaps]
        if hits:
            k = rng.choice(hits)
            d[swaps[k]] = d.pop(k)
            label += "-" + k
    elif choice == "type" and keys:
        k = rng.choice(keys)
        d[k] = rng.choice([1, None, True, [], {}, [d[k]]])
        label += "-" + k
    elif choice == "recipients":
        r = d.get("recipients", d.get("signatures"))
        name = "recipients" if "recipients" in d else "signatures"
        if r is None:
            return json.dumps(d), "edit:none"
        how = rng.choice(["empty", "object", "dup", "null-entry",
                          "string-entry"])
        d[name] = {"empty": [], "object": r[0] if r else {},
                   "dup": r + r, "null-entry": r + [None],
                   "string-entry": r + ["x"]}[how]
        label += "-" + how
    elif choice == "header-dup":
        text = json.dumps(d, separators=(",", ":"))
        k = rng.choice(keys) if keys else "x"
        return text[:-1] + "," + json.dumps(k) + ":" + json.dumps(
            d.get(k)) + "}", label
    elif choice == "array":
        return json.dumps([d]), label
    elif choice == "header-unprotected":
        where = "unprotected" if kind == "jwe" else "header"
        target = d if kind == "jwe" or "signatures" not in d else (
            d["signatures"][0] if d["signatures"] else d)
        h = dict(target.get(where) or {})
        name = rng.choice(["alg", "kid", "crit", "b64", "zip", "enc", "x"])
        value = rng.choice(["HS256", "x", ["b64"], False, "DEF", "A128GCM"])
        h[name] = value
        target[where] = h
        label += "-%s-%s" % (name, type(value).__name__)
        others = [target.get("protected", "")]
        others += [r.get("header") for r in d.get("recipients", [])
                   if isinstance(r, dict)]
        others += [target.get("header") if where != "header" else None]
        for other in others:
            if isinstance(other, str):
                try:
                    other = json.loads(b64d(other) or "{}")
                except ValueError:
                    other = {}
            if isinstance(other, dict) and name in other:
                label += ";header:cross-dup"
                break
    return json.dumps(d, ensure_ascii=False, separators=(",", ":")), label


# Cases -------------------------------------------------------------------

def make_case(rng, seed, keys):
    labels = []
    token = seed["token"]
    shape = "compact" if not token.lstrip().startswith("{") else None
    if rng.random() < 0.6:
        made = None
        try:
            if seed["kind"] == "jwe":
                made = jwe_reseal(rng, seed, keys)
            elif seed["signer"]:
                made = jws_resign(rng, seed, keys)
        except Exception as e:  # noqa: BLE001: report, never hide
            raise RuntimeError("gen.py: %s: %r" % (seed["name"], e)) from e
        if made:
            form, labels = made
            shape = rng.choice(["compact", "compact", "flattened", "general"])
            if seed["kind"] == "jwt":
                shape = "compact"
            text = jwe_text if seed["kind"] == "jwe" else jws_text
            token = text(form, shape)
            labels.append("ser:" + shape)
    for _ in range(rng.choice([0, 1, 1, 2])):
        try:
            token, label = token_edit(rng, token, seed["kind"])
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            label = "edit:none"
        labels.append(label)
        if label.startswith(("json:", "b64:")):
            break   # a later edit could undo this one
    return token, ";".join(labels) or "seed"


def verdicts(seed, token, keys):
    kind = seed["kind"]
    jc, jc_out = ("na", b"")
    if kind in ("jws", "jwe"):
        jc, jc_out = jwcrypto_verdict(kind, token, keys.jwcrypto(seed["key"]),
                                      seed["algs"])
    py, py_out = ("na", b"")
    pykey = keys.pyjwt(seed["key"])
    compact = not token.lstrip().startswith("{")
    if kind in ("jws", "jwt") and pykey is not None and compact:
        py, py_out = pyjwt_verdict(kind, token, pykey, seed["algs"])
    note = []
    if jc == "reject":
        note.append("jwcrypto:" + jc_out)
    if py == "reject":
        note.append("pyjwt:" + py_out)
    return (jc, b64e(jc_out) if jc == "accept" else "",
            py, b64e(py_out) if py == "accept" else "", " ".join(note))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--cases", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    keys = Keys()
    seeds = load_seeds(keys)
    rng = random.Random(args.seed)
    rows = []

    def add(seed, token, mutation):
        jc, jcp, py, pyp, note = verdicts(seed, token, keys)
        rows.append({
            "id": "s%d-%d" % (args.seed, len(rows) + 1),
            "seed": seed["name"], "kind": seed["kind"],
            "mutation": mutation, "key": seed["key"],
            "algs": ",".join(seed["algs"]),
            "encs": ",".join(ENCS) if seed["kind"] == "jwe" else "",
            "token": b64e(token.encode("utf-8")),
            "jwcrypto": jc, "jwcrypto_payload": jcp,
            "pyjwt": py, "pyjwt_payload": pyp, "note": note})

    for seed in seeds:
        add(seed, seed["token"], "seed")
    while len(rows) < args.cases:
        seed = rng.choice(seeds)
        token, mutation = make_case(rng, seed, keys)
        if "\0" not in token:   # an R string cannot hold a NUL
            add(seed, token, mutation)

    with open(os.path.join(args.out, "cases.tsv"), "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, COLUMNS, delimiter="\t", lineterminator="\n",
                           quoting=csv.QUOTE_NONE, escapechar=None)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out, "keys.tsv"), "w", newline="",
              encoding="utf-8") as f:
        f.write("name\tjwk\n")
        for name in sorted(keys.text):
            f.write("%s\t%s\n" % (name, keys.text[name]))
    counts = {}
    for r in rows:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    print("gen.py: %d cases from %d seeds (%s), seed %d" % (
        len(rows), len(seeds), ", ".join("%s %d" % kv for kv in
                                         sorted(counts.items())), args.seed))


if __name__ == "__main__":
    sys.exit(main())
