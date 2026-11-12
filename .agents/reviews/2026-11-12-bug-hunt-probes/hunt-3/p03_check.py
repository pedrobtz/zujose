import json, jwt
key = bytes(range(1, 33))
for c in json.load(open("p03.json")):
    try:
        h = jwt.get_unverified_header(c["token"])
        cl = jwt.decode(c["token"], key, algorithms=["HS256"], options={"verify_exp": False, "verify_nbf": False, "verify_iat": False, "verify_aud": False})
        print("ok  ", c["label"], h, cl)
    except Exception as e:
        print("FAIL", c["label"], repr(e))
