import json, jwt, time
from jwcrypto import jwk, jwe, jwt as jjwt
for c in json.load(open("p13.json")):
    try:
        if c["alg"] == "enc-only":
            t = jjwt.JWT(key=jwk.JWK.from_json(c["enc_key"]), jwt=c["token"], expected_type="JWE"); print("ok enc-only", t.claims, t.header); continue
        key = c["pem"] if c["pem"] else bytes.fromhex(c["secret"])
        if c["alg"].startswith("nested"):
            e = jwe.JWE(); e.deserialize(c["token"], key=jwk.JWK.from_json(c["enc_key"]))
            hdr = json.loads(e.objects["protected"]) if isinstance(e.objects["protected"], str) else e.objects["protected"]
            assert e.jose_header.get("cty") == "JWT", e.jose_header
            tok = e.payload.decode(); alg = c["inner_alg"]
            # jwcrypto JWT route too
            t = jjwt.JWT(key=jwk.JWK.from_json(c["enc_key"]), jwt=c["token"], expected_type="JWE")
            inner = jjwt.JWT(key=jwk.JWK.from_json(c["sig_key"]), jwt=t.claims, algs=[alg], check_claims={"iss": "zujose", "aud": "a"})
        else:
            tok = c["token"]; alg = c["alg"]
        h = jwt.get_unverified_header(tok)
        cl = jwt.decode(tok, key, algorithms=[alg], audience="a", issuer="zujose", options={"require": ["exp", "iat", "nbf", "jti"]})
        assert h == {"alg": alg, "kid": c["kid"], "typ": "JWT"}, h
        assert cl["exp"] - cl["iat"] == 3600 and cl["nbf"] - cl["iat"] == -5 and abs(cl["iat"] - c["now"]) <= 2, cl
        assert all(isinstance(cl[x], int) for x in ("exp", "iat", "nbf")) and cl["n"] == 42 and cl["aud"] == ["a", "b"] and len(cl["jti"]) == 22
        print("ok", c["alg"])
    except Exception as e: print("FAIL", c["alg"], repr(e)[:300])
