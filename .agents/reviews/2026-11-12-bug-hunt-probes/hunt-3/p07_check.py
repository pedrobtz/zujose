import json
from jwcrypto import jwe
allowed = jwe.default_allowed_algs + ["PBES2-HS256+A128KW","PBES2-HS384+A192KW","PBES2-HS512+A256KW"]
for c in json.load(open("p07.json")):
    try:
        t = jwe.JWE(algs=allowed); t.deserialize(c["token"], key="password"); print("ok  ", c["label"], t.payload)
    except Exception as e: print("FAIL", c["label"], repr(e)[:150])
