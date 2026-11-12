import json, base64
from jwcrypto import jwk, jwe, jwa
allowed = jwe.default_allowed_algs + ["PBES2-HS256+A128KW","PBES2-HS384+A192KW","PBES2-HS512+A256KW"]
seen = {}
for c in json.load(open("p08.json")):
    for kj in c["keys"]:
        k = jwk.JWK.from_json(kj); kid = k.get("kid")
        key = "password" if kid == "pw" else k
        try:
            t = jwe.JWE(algs=allowed); t.deserialize(c["token"], key=key)
            assert t.payload == c["pt"].encode(), t.payload
        except Exception as e: print("FAIL", c["name"], kid, repr(e)[:200])
    if c["token"].startswith("{"):
        j = json.loads(c["token"])
        for name in ("iv", "tag", "ciphertext"):
            seen.setdefault(name, []).append(j[name])
        for r in j.get("recipients", []):
            h = r["header"]
            for m in ("iv", "tag", "p2s"):
                if m in h: seen.setdefault("r." + m, []).append(h[m])
            if "epk" in h: seen.setdefault("epk", []).append(h["epk"]["x"])
            if "encrypted_key" in r: seen.setdefault("ek", []).append(r["encrypted_key"])
    print("done", c["name"])
for k, v in seen.items(): print(k, len(v), "unique", len(set(v)))
