import json
from jwcrypto import jwk
for c in json.load(open("p06.json")):
    try:
        k = jwk.JWK.from_json(c["given"]); print(c["name"], "jwcrypto accepts; thumb==zujose:", k.thumbprint() == c["tp"], "thumb==canonical:", k.thumbprint() == c["tp_canon"])
    except Exception as e: print(c["name"], "jwcrypto refuses:", repr(e)[:100])
