#!/usr/bin/env python3
"""Project Wycheproof vectors for zujose (#98, #99).

    python3 tools/make-wycheproof.py DIR            write the fixtures
    python3 tools/make-wycheproof.py --check DIR    check them

Maintainer tooling, never run at check time; it needs only the Python
standard library. DIR holds the files below, downloaded once from
C2SP Wycheproof at the pinned COMMIT, for example:

    for f in <each name in SIGNATURES and JOSE below>; do
      curl -sSfLo DIR/$f \\
        https://raw.githubusercontent.com/C2SP/wycheproof/$COMMIT/testvectors_v1/$f
    done

Each file is checked against its SHA-256 before it is read. The raw JSON
is not committed. Wycheproof says of each case whether a correct
implementation must accept it ("valid"), must reject it ("invalid"), or
may do either ("acceptable"), with flags naming what it probes. Writes,
under tests/testthat/fixtures/wycheproof/:

  - keys.tsv: every key a case uses, as JWK or JWK Set JSON, by id;
  - signatures.tsv (#99): the signature verification cases JWS can
    express, for zujose's internal verifier on the signing input. ECDSA in
    IEEE P1363 form (JOSE's raw r || s) for P-256/SHA-256, P-384/SHA-384
    and P-521/SHA-512 (ES256, ES384, ES512); RSASSA-PKCS1-v1_5 with SHA-256,
    384 and 512 on 2048-bit keys (RS*); RSASSA-PSS with MGF1 of the same
    hash and a salt of the hash length (PS256 and PS384 on 2048 bits, PS512
    on 4096), and PSS-SHA-256 with a salt of 0, which a JOSE verifier must
    refuse (RFC 7518 section 3.5); HMAC SHA-256, 384 and 512 with the full
    tag and a key at least the hash size, as RFC 7518 section 3.2 requires
    (HS*). Columns: file, tc_id, alg, key, msg, sig (Base64url), result,
    flags;
  - jose.tsv (#98): the cases of the JOSE files, json_web_signature,
    json_web_encryption, json_web_key and json_web_crypto, with the key a
    verifier or decrypter is given (`public` when the group has one, else
    `private`). Columns: file, tc_id, kind (jws or jwe), key, enc, token
    (compact text, or the JSON serialization as compact JSON), pt (hex,
    empty when the case has none), result, flags, comment;
  - MANIFEST.tsv: a row per fixture file with its source and generator.

The full corpus is about 3100 cases and 1.2 MB, more than a CRAN tarball
should carry and, at zucrypt's speed on P-384 and P-521, more than the
test time budget, so a subset ships. A kind is a file's result and flag
set. Of each kind that is not valid the first 8 cases are kept, and of
each valid kind the first 2 in signatures.tsv; for ES384 and ES512, half
as many. In jose.tsv, cases with no flags, each a distinct attack, are
all kept. What is cut is repetition: the 117 InvalidAsnInPadding and 75
ModifiedPadding variants of each RSA file, the same RS256 padding cases
again as JWS, the 54 to 123 SpecialCaseHash valid signatures of each
file, and the ECDSA ArithmeticError cases beyond the first few. Every
kind stays. The whole corpus, written by setting the limits to infinity,
agrees with zujose but for the cases test-wycheproof.R lists.

--check does not regenerate: it reads DIR again and exits non-zero if any
fixture or MANIFEST.tsv differs from what this script would write.
"""
import base64
import hashlib
import json
import os
import sys

COMMIT = "a3d5d1423f2592d6646836a45a21a1b209da9f4d"  # 2026-10-23, as zucrypt
GENERATOR = "tools/make-wycheproof.py"
OUT = os.path.join("tests", "testthat", "fixtures", "wycheproof")

# file -> (alg, sha256 of the file at COMMIT), and for JOSE file -> sha256.
SIGNATURES = {
    "ecdsa_secp256r1_sha256_p1363_test.json": ("ES256", "c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986"),
    "ecdsa_secp384r1_sha384_p1363_test.json": ("ES384", "e27344bf6daae75fa19663620883809f91c79fc4b4420eff9eae8036b34476be"),
    "ecdsa_secp521r1_sha512_p1363_test.json": ("ES512", "d294cbe0485dff0a2c53f6b363103ddb81c444e7e5ee44df56549ea92b873840"),
    "rsa_signature_2048_sha256_test.json": ("RS256", "94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393"),
    "rsa_signature_2048_sha384_test.json": ("RS384", "c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d"),
    "rsa_signature_2048_sha512_test.json": ("RS512", "16ea24b039905d054bdb6004f5fd179374e150b7b6d73a7ba654b6d00eab12ef"),
    "rsa_pss_2048_sha256_mgf1_32_test.json": ("PS256", "7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c"),
    "rsa_pss_2048_sha256_mgf1_0_test.json": ("PS256", "b22a8d9a2e7e47f681d0ff1d1a55455daaf325d989c64ad005f848bd50b9b4c0"),
    "rsa_pss_2048_sha384_mgf1_48_test.json": ("PS384", "66d464778b0b2f683a1d1a20e94f77e9472b8cc393b45f423fa08a48e677063c"),
    "rsa_pss_4096_sha512_mgf1_64_test.json": ("PS512", "c93ceaa56a190c9fd4707441c5c6a75839f108202d88aec891697f9623042547"),
    "hmac_sha256_test.json": ("HS256", "2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f"),
    "hmac_sha384_test.json": ("HS384", "28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0"),
    "hmac_sha512_test.json": ("HS512", "b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207"),
}
JOSE = {
    "json_web_signature_test.json": "8e687a06fe8359f4ec51480f1a9f73c8faebd6f4c01b818b843b44eee54fd5d9",
    "json_web_encryption_test.json": "2fee073795830ee029ddb84d2d7bcbad05fde6e55ee2d00b153a0aa40a72d7d2",
    "json_web_key_test.json": "be983255bce26406f97020ec5458b33930a90d5f868e604fcd569c300aba2862",
    "json_web_crypto_test.json": "dcd58ac9548a7d6173437a691e4cc307dcd3cec9fd814a39cd2a94531cf4f8ce",
}
VALID_PER_KIND = 2
OTHER_PER_KIND = 8
# zucrypt's P-384 and P-521 verification is slow, so these keep half.
SLOW = {"ES384", "ES512"}
SIG_COLUMNS = ["file", "tc_id", "alg", "key", "msg", "sig", "result",
               "flags"]
JOSE_COLUMNS = ["file", "tc_id", "kind", "key", "enc", "token", "pt",
                "result", "flags", "comment"]


def read(directory, name, sha):
    with open(os.path.join(directory, name), "rb") as f:
        data = f.read()
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        sys.exit("%s: sha256 %s, pinned %s" % (name, got, sha))
    return json.loads(data)


def b64(hex_text):
    raw = bytes.fromhex(hex_text)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unsigned(hex_text):
    """An ASN.1 INTEGER's bytes without the sign byte, as JWK wants them."""
    while hex_text.startswith("00") and len(hex_text) > 2:
        hex_text = hex_text[2:]
    return hex_text


def compact(x):
    return json.dumps(x, separators=(",", ":"), ensure_ascii=True)


class Keys:
    """Keys by content: the id is a prefix of the JSON's SHA-256."""

    def __init__(self):
        self.rows = {}

    def add(self, jwk):
        text = compact(jwk)
        key_id = hashlib.sha256(text.encode()).hexdigest()[:16]
        if self.rows.setdefault(key_id, text) != text:
            sys.exit("key id %s used for two keys" % key_id)
        return key_id


def keep(seen, kind, result, slow=False):
    """The subset: VALID_PER_KIND valid cases of each kind, OTHER_PER_KIND
    of the others, half as many when slow; a kind is the file's result and
    flag set."""
    seen[kind] = seen.get(kind, 0) + 1
    limit = VALID_PER_KIND if result == "valid" else OTHER_PER_KIND
    return seen[kind] <= (limit // 2 if slow else limit)


def signature_rows(name, doc, keys):
    alg = SIGNATURES[name][0]
    bits = int(alg[2:])
    out, seen = [], {}
    for gi, g in enumerate(doc["testGroups"]):
        key = None
        if alg.startswith("HS"):
            if g["tagSize"] != bits or g["keySize"] < bits:
                continue
        elif alg.startswith("ES"):
            # Not every group has publicKeyJwk, so the JWK is built from
            # the coordinates, each left-padded to the curve's size.
            pk = g["publicKey"]
            crv, size = {"ES256": ("P-256", 32), "ES384": ("P-384", 48),
                         "ES512": ("P-521", 66)}[alg]
            jwk = {"kty": "EC", "crv": crv,
                   "x": b64(unsigned(pk["wx"]).rjust(2 * size, "0")),
                   "y": b64(unsigned(pk["wy"]).rjust(2 * size, "0"))}
        else:
            pk = g["publicKey"]
            jwk = {"kty": "RSA", "n": b64(unsigned(pk["modulus"])),
                   "e": b64(unsigned(pk["publicExponent"]))}
        for t in g["tests"]:
            flags = ",".join(t["flags"])
            if not keep(seen, (t["result"], flags), t["result"],
                        alg in SLOW):
                continue
            if alg.startswith("HS"):
                key = keys.add({"kty": "oct", "k": b64(t["key"])})
                sig = t["tag"]
            else:
                key = keys.add(jwk)
                sig = t["sig"]
            out.append({"file": name, "tc_id": str(t["tcId"]), "alg": alg,
                        "key": key, "msg": b64(t["msg"]), "sig": b64(sig),
                        "result": t["result"], "flags": flags})
    return out


def jose_rows(name, doc, keys):
    out, seen = [], {}
    for g in doc["testGroups"]:
        key_jwk = g.get("public") or g.get("private")
        for t in g["tests"]:
            flags = ",".join(t["flags"])
            if flags and not keep(seen, (t["result"], flags), "invalid"):
                continue
            kind = "jws" if "jws" in t else "jwe"
            token = t[kind]
            if not isinstance(token, str):
                token = compact(token)
            if kind == "jwe":
                # Decryption needs the private key.
                key_jwk_t = g.get("private")
            else:
                key_jwk_t = key_jwk
            key = keys.add(key_jwk_t)
            for field in (token, t["comment"]):
                if "\t" in field or "\n" in field or "\r" in field:
                    sys.exit("%s %d: a tab or line break" % (name, t["tcId"]))
            out.append({"file": name, "tc_id": str(t["tcId"]), "kind": kind,
                        "key": key, "enc": t.get("enc", ""), "token": token,
                        "pt": t.get("pt") or "", "result": t["result"],
                        "flags": flags,
                        "comment": t["comment"]})
    return out


def tsv(columns, rows):
    lines = ["\t".join(columns)]
    lines += ["\t".join(r[c] for c in columns) for r in rows]
    return "\n".join(lines) + "\n"


def build(directory):
    keys, sigs, jose = Keys(), [], []
    for name, (_, sha) in SIGNATURES.items():
        sigs += signature_rows(name, read(directory, name, sha), keys)
    for name, sha in JOSE.items():
        jose += jose_rows(name, read(directory, name, sha), keys)
    key_rows = [{"id": k, "jwk": v} for k, v in keys.rows.items()]
    source = "C2SP Wycheproof %s testvectors_v1/" % COMMIT
    files = {
        "keys.tsv": tsv(["id", "jwk"], key_rows),
        "signatures.tsv": tsv(SIG_COLUMNS, sigs),
        "jose.tsv": tsv(JOSE_COLUMNS, jose),
    }
    manifest = ["file\tsource\tgenerator"]
    manifest += [
        "keys.tsv\t%s, the keys of the files below\t%s" % (source, GENERATOR),
        "signatures.tsv\t%s%s\t%s" % (source, ", ".join(SIGNATURES),
                                      GENERATOR),
        "jose.tsv\t%s%s\t%s" % (source, ", ".join(JOSE), GENERATOR),
    ]
    files["MANIFEST.tsv"] = "\n".join(manifest) + "\n"
    return files, len(sigs), len(jose)


def main():
    args = sys.argv[1:]
    check = args[:1] == ["--check"]
    if check:
        args = args[1:]
    if len(args) != 1 or not os.path.isdir(args[0]):
        sys.exit(__doc__)
    files, n_sig, n_jose = build(args[0])
    if check:
        for name, text in files.items():
            path = os.path.join(OUT, name)
            if not os.path.exists(path) or \
                    open(path, encoding="ascii").read() != text:
                sys.exit("make-wycheproof --check: %s differs" % name)
        print("make-wycheproof --check: %d signature and %d JOSE cases match"
              % (n_sig, n_jose))
        return
    os.makedirs(OUT, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(OUT, name), "w", encoding="ascii") as f:
            f.write(text)
    print("wrote %d signature and %d JOSE cases, %d bytes"
          % (n_sig, n_jose, sum(len(t) for t in files.values())))


if __name__ == "__main__":
    main()
