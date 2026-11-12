import json, os
from jwcrypto import jwk, jwe, jws
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
J = json.load(open(os.path.join(D, "jwe.json"))); S = json.load(open(os.path.join(D, "sig.json")))
def t(label, f):
    try: print(label, "-> OK", f())
    except Exception as e: print(label, "-> ERR", type(e).__name__, str(e)[:100])
def decw(tok, kj, **kw):
    k = json.loads(kj); k.update(kw); j = jwe.JWE(); j.deserialize(tok, jwk.JWK(**k)); return j.payload[:10]
t("jwcrypto rsa key_ops[decrypt] RSA-OAEP", lambda: decw(J["tok"]["oaep"], J["keys"]["rsa"], key_ops=["decrypt"]))
t("jwcrypto rsa key_ops[unwrapKey] RSA-OAEP", lambda: decw(J["tok"]["oaep"], J["keys"]["rsa"], key_ops=["unwrapKey"]))
t("jwcrypto ec key_ops[deriveBits] ECDH-ES", lambda: decw(J["tok"]["ecdh_p256"], J["keys"]["p256"], key_ops=["deriveBits"]))
t("jwcrypto ec key_ops[deriveKey] ECDH-ES", lambda: decw(J["tok"]["ecdh_p256"], J["keys"]["p256"], key_ops=["deriveKey"]))
t("jwcrypto oct key_ops[decrypt] dir", lambda: decw(J["tok"]["dir_gcm"], J["keys"]["oct32"], key_ops=["decrypt"]))
t("jwcrypto oct key_ops[] dir", lambda: decw(J["tok"]["dir_gcm"], J["keys"]["oct32"], key_ops=[]))
rp = json.loads(S["rsa_jwk_priv"]); rp["oth"] = [{"r": "AQAB", "d": "AQAB", "t": "AQAB"}]
t("jwcrypto rsa priv with oth", lambda: jwk.JWK(**rp).export_public()[:20])
import base64
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def ub64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
rpub = json.loads(S["rsa_jwk_pub"]); rpub["n"] = b64(b"\x00" + ub64(rpub["n"]))
def ver():
    k = jwk.JWK(**rpub); j = jws.JWS(); j.deserialize(S["tokens"]["RS256"], k); return k.thumbprint()
t("jwcrypto rsa n leading zero verify + thumbprint", ver); print("canonical thumbprint", jwk.JWK(**json.loads(S["rsa_jwk_pub"])).thumbprint())
import jwt
t("PyJWT b64? n/a; PyJWT rsa n leading zero", lambda: jwt.decode(S["tokens"]["RS256"], jwt.algorithms.RSAAlgorithm.from_jwk(rpub), algorithms=["RS256"]))
