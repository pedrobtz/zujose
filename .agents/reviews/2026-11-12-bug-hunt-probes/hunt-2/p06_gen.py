import json, base64, os, hmac, hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad
from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
out = {"keys": {}, "tok": {}}
K = {
 "oct16": jwk.JWK.generate(kty="oct", size=128, kid="o16"), "oct24": jwk.JWK.generate(kty="oct", size=192), "oct32": jwk.JWK.generate(kty="oct", size=256, kid="o32"),
 "oct48": jwk.JWK.generate(kty="oct", size=384), "oct64": jwk.JWK.generate(kty="oct", size=512),
 "rsa": jwk.JWK.generate(kty="RSA", size=2048, kid="r1"), "p256": jwk.JWK.generate(kty="EC", crv="P-256", kid="e256"), "p384": jwk.JWK.generate(kty="EC", crv="P-384"),
 "p521": jwk.JWK.generate(kty="EC", crv="P-521"), "x25519": jwk.JWK.generate(kty="OKP", crv="X25519"), "pw": jwk.JWK(kty="oct", k=b64(b"correct horse battery")),
 "p256b": jwk.JWK.generate(kty="EC", crv="P-256"),
}
for n, k in K.items(): out["keys"][n] = k.export(private_key=True) if n not in () else None
PT = b'{"sub":"a","exp":4000000000}'
def enc(name, key, alg, e, extra=None, compact=True, aad=None, unprot=None):
    prot = {"alg": alg, "enc": e}; prot.update(extra or {})
    t = jwe.JWE(PT, json_encode(prot), aad=aad, unprotected=json_encode(unprot) if unprot else None)
    t.add_recipient(key)
    out["tok"][name] = t.serialize(compact=compact)
enc("dir_gcm", K["oct32"], "dir", "A256GCM"); enc("dir_cbc", K["oct32"], "dir", "A128CBC-HS256"); enc("dir_cbc512", K["oct64"], "dir", "A256CBC-HS512")
enc("kw", K["oct16"], "A128KW", "A128GCM"); enc("kw256", K["oct32"], "A256KW", "A256CBC-HS512"); enc("gcmkw", K["oct32"], "A256GCMKW", "A128CBC-HS256")
enc("pbes2", K["pw"], "PBES2-HS256+A128KW", "A128GCM", {"p2c": 1000}); enc("pbes2_512", K["pw"], "PBES2-HS512+A256KW", "A256GCM", {"p2c": 2000})
enc("oaep", K["rsa"], "RSA-OAEP", "A256GCM"); enc("oaep256", K["rsa"], "RSA-OAEP-256", "A128CBC-HS256")
try:
    enc("rsa15", K["rsa"], "RSA1_5", "A128CBC-HS256")
except Exception as ex:
    t = jwe.JWE(PT, json_encode({"alg": "RSA1_5", "enc": "A128CBC-HS256"}), algs=jwe.default_allowed_algs + ["RSA1_5"]); t.add_recipient(K["rsa"]); out["tok"]["rsa15"] = t.serialize(compact=True)
for c in ["p256", "p384", "p521", "x25519"]:
    enc("ecdh_" + c, K[c], "ECDH-ES", "A256GCM"); enc("ecdhkw_" + c, K[c], "ECDH-ES+A128KW", "A128CBC-HS256")
    enc("ecdh_apu_" + c, K[c], "ECDH-ES+A256KW", "A192GCM", {"apu": b64(b"Alice"), "apv": b64(b"Bob")})
    enc("ecdh_cbc512_" + c, K[c], "ECDH-ES", "A256CBC-HS512")
enc("flat_aad", K["oct16"], "A128KW", "A128GCM", compact=False, aad=b"extra aad")
enc("flat_unprot", K["oct16"], "A128KW", "A128GCM", compact=False, unprot={"kid": "o16", "foo": 1})
# general: protected only enc; recipients each with alg
t = jwe.JWE(PT, json_encode({"enc": "A128CBC-HS256"}), aad=b"aad2", unprotected=json_encode({"typ": "X"}))
t.add_recipient(K["oct16"], json_encode({"alg": "A128KW", "kid": "o16"})); t.add_recipient(K["rsa"], json_encode({"alg": "RSA-OAEP", "kid": "r1"})); t.add_recipient(K["p256"], json_encode({"alg": "ECDH-ES+A128KW", "kid": "e256"}))
out["tok"]["general3"] = t.serialize()
# no protected header at all: enc+alg unprotected
t = jwe.JWE(PT, None, unprotected=json_encode({"enc": "A128GCM", "alg": "A128KW"})); t.add_recipient(K["oct16"]); out["tok"]["flat_noprot"] = t.serialize()
t = jwe.JWE(PT, None, unprotected=json_encode({"enc": "A128GCM", "alg": "A128KW"}), aad=b"zz"); t.add_recipient(K["oct16"]); out["tok"]["flat_noprot_aad"] = t.serialize()
# zip
t = jwe.JWE(PT, json_encode({"alg": "dir", "enc": "A256GCM", "zip": "DEF"})); t.add_recipient(K["oct32"]); out["tok"]["zip"] = t.serialize(compact=True)
# --- handmade dir + A256GCM with full control
key32 = base64.urlsafe_b64decode(json.loads(K["oct32"].export())["k"] + "=")
def gcm(hdr, iv, pt=PT, key=key32, aadextra=None, ek=b""):
    h = b64(hdr if isinstance(hdr, bytes) else json.dumps(hdr, separators=(",", ":")).encode())
    ct = AESGCM(key).encrypt(iv, pt, h.encode()); return ".".join([h, b64(ek), b64(iv), b64(ct[:-16]), b64(ct[-16:])])
H = {"alg": "dir", "enc": "A256GCM"}
out["tok"]["hm_gcm"] = gcm(H, os.urandom(12))
out["tok"]["hm_gcm_iv16"] = gcm(H, os.urandom(16)); out["tok"]["hm_gcm_iv8"] = gcm(H, os.urandom(8))
out["tok"]["hm_gcm_empty_pt"] = gcm(H, os.urandom(12), b"")
out["tok"]["hm_gcm_ek"] = gcm(H, os.urandom(12), ek=b"\x00" * 8)
for nm, hd in [("crit_b64", {"alg": "dir", "enc": "A256GCM", "b64": True, "crit": ["b64"]}), ("crit_unknown", {"alg": "dir", "enc": "A256GCM", "crit": ["x"], "x": 1}),
               ("typ_cty", {"alg": "dir", "enc": "A256GCM", "typ": "JWT", "cty": "text/plain"}), ("jwk_hdr", {"alg": "dir", "enc": "A256GCM", "jwk": json.loads(K["oct32"].export())}),
               ("zip_null", {"alg": "dir", "enc": "A256GCM", "zip": None}), ("enc_num", {"alg": "dir", "enc": 1}), ("alg_none", {"alg": "none", "enc": "A256GCM"}),
               ("kid_o32", {"alg": "dir", "enc": "A256GCM", "kid": "o32"}), ("kid_zz", {"alg": "dir", "enc": "A256GCM", "kid": "zz"}),
               ("hdr_p2c", {"alg": "dir", "enc": "A256GCM", "p2c": 1e9, "epk": 5, "iv": 3, "tag": 4})]:
    out["tok"]["hm_" + nm] = gcm(hd, os.urandom(12))
out["tok"]["hm_dup"] = gcm(b'{"alg":"dir","enc":"A256GCM","enc":"A256GCM"}', os.urandom(12))
out["tok"]["hm_ws"] = gcm(b' {"enc" : "A256GCM",\n "alg":"dir"} ', os.urandom(12))
# CBC handmade (dir A128CBC-HS256 with 32-byte key)
def cbc(hdr, iv, pt=PT, key=key32, taglen=16, pad=True, ct_override=None):
    h = b64(json.dumps(hdr, separators=(",", ":")).encode()); mk, ek = key[:16], key[16:]
    if pad:
        p = sympad.PKCS7(128).padder(); pt = p.update(pt) + p.finalize()
    e = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor(); ct = e.update(pt) + e.finalize()
    al = struct.pack(">Q", len(h) * 8); tag = hmac.new(mk, h.encode() + iv + ct + al, hashlib.sha256).digest()[:taglen]
    return ".".join([h, "", b64(iv), b64(ct), b64(tag)])
HC = {"alg": "dir", "enc": "A128CBC-HS256"}
out["tok"]["hm_cbc"] = cbc(HC, os.urandom(16))
out["tok"]["hm_cbc_tag8"] = cbc(HC, os.urandom(16), taglen=8); out["tok"]["hm_cbc_tag32"] = cbc(HC, os.urandom(16), taglen=32)
out["tok"]["hm_cbc_badpad"] = cbc(HC, os.urandom(16), pt=b"A" * 32, pad=False)       # valid tag, invalid padding
out["tok"]["hm_cbc_pad0"] = cbc(HC, os.urandom(16), pt=b"A" * 31 + b"\x00", pad=False)
out["tok"]["hm_cbc_pad17"] = cbc(HC, os.urandom(16), pt=b"\x11" * 32, pad=False)
out["tok"]["hm_cbc_pad16all"] = cbc(HC, os.urandom(16), pt=b"\x10" * 16, pad=False)  # valid: empty plaintext
out["tok"]["hm_cbc_padmixed"] = cbc(HC, os.urandom(16), pt=b"A" * 13 + b"\x02\x03\x03", pad=False)  # valid pad 3? last 3 = 02 03 03 -> invalid
out["tok"]["hm_cbc_empty_pt"] = cbc(HC, os.urandom(16), pt=b"")
json.dump(out, open(os.path.join(D, "jwe.json"), "w"), indent=1)
# reference verdicts by jwcrypto for handmade
for n, tk in out["tok"].items():
    if not n.startswith("hm_"): continue
    try:
        j = jwe.JWE(); j.deserialize(tk, K["oct32"]); print(n, "jwcrypto OK", j.payload[:20])
    except Exception as ex: print(n, "jwcrypto ERR", type(ex).__name__, str(ex)[:80])
