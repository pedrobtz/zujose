import json, base64, hashlib, os, sys
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, x25519, utils
from cryptography.hazmat.primitives import hashes, serialization as ser
import jwt
from jwcrypto import jwk as jjwk
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
out = {}
def pem_priv(k, fmt=ser.PrivateFormat.PKCS8): return k.private_bytes(ser.Encoding.PEM, fmt, ser.NoEncryption()).decode()
def pem_pub(k, fmt=ser.PublicFormat.SubjectPublicKeyInfo): return k.public_key().public_bytes(ser.Encoding.PEM, fmt).decode()
rsa2048 = rsa.generate_private_key(65537, 2048); rsa1024 = rsa.generate_private_key(65537, 1024); rsa3 = rsa.generate_private_key(3, 2048)
out["rsa_priv_pkcs8"] = pem_priv(rsa2048); out["rsa_priv_pkcs1"] = pem_priv(rsa2048, ser.PrivateFormat.TraditionalOpenSSL)
out["rsa_pub_spki"] = pem_pub(rsa2048); out["rsa_pub_pkcs1"] = pem_pub(rsa2048, ser.PublicFormat.PKCS1)
out["rsa1024_pub"] = pem_pub(rsa1024); out["rsa1024_priv"] = pem_priv(rsa1024)
out["rsa_e3_priv"] = pem_priv(rsa3)
out["rsa_enc_priv"] = rsa2048.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(b"pw")).decode()
out["rsa_jwk_priv"] = jjwk.JWK.from_pem(out["rsa_priv_pkcs8"].encode()).export(private_key=True)
out["rsa_jwk_pub"] = jjwk.JWK.from_pem(out["rsa_priv_pkcs8"].encode()).export(private_key=False)
ecs = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1(), "secp256k1": ec.SECP256K1()}
eck = {n: ec.generate_private_key(c) for n, c in ecs.items()}
for n, k in eck.items():
    out["ec_%s_priv_pkcs8" % n] = pem_priv(k); out["ec_%s_priv_sec1" % n] = pem_priv(k, ser.PrivateFormat.TraditionalOpenSSL); out["ec_%s_pub" % n] = pem_pub(k)
    if n != "secp256k1":
        out["ec_%s_jwk_priv" % n] = jjwk.JWK.from_pem(out["ec_%s_priv_pkcs8" % n].encode()).export(private_key=True)
xk = x25519.X25519PrivateKey.generate()
out["x25519_priv"] = pem_priv(xk); out["x25519_pub"] = pem_pub(xk)
out["x25519_jwk_priv"] = jjwk.JWK.from_pem(out["x25519_priv"].encode()).export(private_key=True)
from cryptography.hazmat.primitives.asymmetric import ed25519
ed = ed25519.Ed25519PrivateKey.generate(); out["ed25519_priv"] = pem_priv(ed); out["ed25519_pub"] = pem_pub(ed)
out["ed25519_jwk"] = jjwk.JWK.from_pem(out["ed25519_priv"].encode()).export(private_key=False)
# tokens via PyJWT
pl = {"sub": "a", "exp": 4000000000}
toks = {}
for a in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]:
    toks[a] = jwt.encode(pl, rsa2048, algorithm=a)
toks["RS256_1024"] = jwt.encode(pl, rsa1024, algorithm="RS256")
toks["RS256_e3"] = jwt.encode(pl, rsa3, algorithm="RS256")
for a, n in [("ES256", "P-256"), ("ES384", "P-384"), ("ES512", "P-521")]:
    toks[a] = jwt.encode(pl, eck[n], algorithm=a)
toks["ES256K"] = jwt.encode(pl, eck["secp256k1"], algorithm="ES256K")
# hand-made: PS256 with max salt; RS256 header but PSS sig; ES256 variants
def mk(hdr, payload, sign):
    h = b64(json.dumps(hdr, separators=(",", ":")).encode()); p = b64(payload); si = (h + "." + p).encode()
    return h + "." + p + "." + b64(sign(si))
P = json.dumps(pl).encode()
toks["PS256_maxsalt"] = mk({"alg": "PS256"}, P, lambda m: rsa2048.sign(m, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256()))
toks["PS256_salt0"] = mk({"alg": "PS256"}, P, lambda m: rsa2048.sign(m, padding.PSS(padding.MGF1(hashes.SHA256()), 0), hashes.SHA256()))
toks["PS256_mgf1sha1"] = mk({"alg": "PS256"}, P, lambda m: rsa2048.sign(m, padding.PSS(padding.MGF1(hashes.SHA1()), 32), hashes.SHA256()))
toks["PS384_sha256sig"] = mk({"alg": "PS384"}, P, lambda m: rsa2048.sign(m, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256()))
toks["RS256_pss_sig"] = mk({"alg": "RS256"}, P, lambda m: rsa2048.sign(m, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256()))
toks["PS256_pkcs1_sig"] = mk({"alg": "PS256"}, P, lambda m: rsa2048.sign(m, padding.PKCS1v15(), hashes.SHA256()))
toks["RS256_sha1"] = mk({"alg": "RS256"}, P, lambda m: rsa2048.sign(m, padding.PKCS1v15(), hashes.SHA1()))
orders = {"P-256": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
 "P-384": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
 "P-521": int("01" + "F"*64 + "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16)}
sizes = {"P-256": 32, "P-384": 48, "P-521": 66}; hs = {"P-256": hashes.SHA256(), "P-384": hashes.SHA384(), "P-521": hashes.SHA512()}
def ecsig(n, m, f):
    r, s = utils.decode_dss_signature(eck[n].sign(m, ec.ECDSA(hs[n])))
    return f(r, s, orders[n], sizes[n], m)
raw = lambda r, s, L: r.to_bytes(L, "big") + s.to_bytes(L, "big")
for a, n in [("ES256", "P-256"), ("ES384", "P-384"), ("ES512", "P-521")]:
    toks[a + "_highS"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(r, max(s, q - s), L)))
    toks[a + "_lowS"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(r, min(s, q - s), L)))
    toks[a + "_der"] = mk({"alg": a}, P, lambda m: eck[n].sign(m, ec.ECDSA(hs[n])))
    toks[a + "_r0"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(0, s, L)))
    toks[a + "_s0"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(r, 0, L)))
    toks[a + "_rs0"] = mk({"alg": a}, P, lambda m: bytes(2 * sizes[n]))
    toks[a + "_r_plus_n"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(r + q, s, L) if (r + q).bit_length() <= 8 * L else b"SKIP"))
    toks[a + "_s_plus_n"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(r, s + q, L) if (s + q).bit_length() <= 8 * L else b"SKIP"))
    toks[a + "_rn"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(q, q, L)))
    toks[a + "_padded"] = mk({"alg": a}, P, lambda m: ecsig(n, m, lambda r, s, q, L, _: raw(r, s, L + 1)))
    toks[a + "_wronghash"] = mk({"alg": a}, P, lambda m: raw(*utils.decode_dss_signature(eck[n].sign(m, ec.ECDSA(hashes.SHA256() if a != "ES256" else hashes.SHA384()))), sizes[n]))
# ES512 using 64-byte halves (common mistake); ES256 alg with P-384 key signature
toks["ES256_with_p384"] = mk({"alg": "ES256"}, P, lambda m: raw(*utils.decode_dss_signature(eck["P-384"].sign(m, ec.ECDSA(hashes.SHA256()))), 48))
# many ES256/ES512 tokens to hit leading-zero r/s
many = []
for i in range(600):
    many.append(mk({"alg": "ES256"}, b"m%d" % i, lambda m: raw(*utils.decode_dss_signature(eck["P-256"].sign(m, ec.ECDSA(hashes.SHA256()))), 32)))
out["many_es256"] = many
many = []
for i in range(300):
    many.append(mk({"alg": "ES512"}, b"m%d" % i, lambda m: raw(*utils.decode_dss_signature(eck["P-521"].sign(m, ec.ECDSA(hashes.SHA512()))), 66)))
out["many_es512"] = many
out["tokens"] = toks
json.dump(out, open(os.path.join(D, "sig.json"), "w"), indent=1)
print(len(toks), "tokens")
