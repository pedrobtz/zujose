import json, sys
from jwcrypto import jwk, jwe
from jwcrypto.common import json_decode
cases = json.load(open(sys.argv[1]))
bad = 0
allowed = jwe.default_allowed_algs + ["RSA1_5","PBES2-HS256+A128KW","PBES2-HS384+A192KW","PBES2-HS512+A256KW"]
for c in cases:
    try:
        k = jwk.JWK.from_json(c["key"])
        if k["kty"] == "oct" and c["name"].startswith("PBES2"):
            import base64
            kk = k["k"]; k = base64.urlsafe_b64decode(kk + "=" * (-len(kk) % 4)).decode("utf-8")
        t = jwe.JWE(algs=allowed)
        try:
            t.deserialize(c["token"], key=k)
        except jwe.InvalidJWEData as e:
            if c["pt"] == "" and t.plaintext == b"" and "Success" in repr(e): pass  # jwcrypto treats empty plaintext as failure
            else: raise
        ok = t.plaintext.hex() == c["pt"]
        if c.get("aad"):
            j = json.loads(c["token"])
            ok = ok and ("aad" in j)
        if not ok:
            bad += 1; print("MISMATCH", c["name"], t.payload.hex(), c["pt"])
    except Exception as e:
        bad += 1; print("FAIL", c["name"], repr(e)[:200])
print(len(cases), "cases", bad, "bad")
