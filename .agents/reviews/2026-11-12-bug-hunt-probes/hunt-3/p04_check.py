import json, base64, collections
from jwcrypto import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
def b64d(s):
    assert "=" not in s and "+" not in s and "/" not in s
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
bad = 0; stats = collections.Counter()
def err(*a):
    global bad; bad += 1; print(*a)
size = {"P-256": 32, "P-384": 48, "P-521": 66, "X25519": 32}
for c in json.load(open("p04.json")):
    try:
        n = c["name"]
        jp = json.loads(c["json_priv"]) if c["json_priv"] else None
        k = jwk.JWK.from_json(c["json_priv"] or c["json_pub"])
        for h, f in (("tp256","sha256"),("tp384","sha384"),("tp512","sha512")):
            from cryptography.hazmat.primitives import hashes
            hh = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[f]
            if k.thumbprint(hh) != c[h]: err("THUMB", n, h)
        if c["tp_pub"] and c["tp_pub"] != c["tp256"]: err("THUMB pub/priv", n)
        if c["uri"] != "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + c["tp256"]: err("URI", n, c["uri"])
        if c["kid_auto"] != c["tp256"]: err("KIDAUTO", n)
        if c["kty"] == "oct": continue
        pub = json.loads(c["json_pub"])
        if set(pub) & {"d","p","q","dp","dq","qi","oth","k"}: err("PUBLIC LEAK", n, list(pub))
        for m in set(jp) - {"d","p","q","dp","dq","qi"}:
            if pub.get(m) != jp[m]: err("PUB MEMBER", n, m)
        sk = serialization.load_pem_private_key(c["pem_priv"].encode(), None)
        pk = serialization.load_pem_public_key(c["pem_pub"].encode())
        if not c["pem_priv"].startswith("-----BEGIN PRIVATE KEY-----"): err("PEM priv form", n, c["pem_priv"][:40])
        if not c["pem_pub"].startswith("-----BEGIN PUBLIC KEY-----"): err("PEM pub form", n, c["pem_pub"][:40])
        if c["kty"] == "RSA":
            nums = sk.private_numbers(); pn = nums.public_numbers
            want = dict(n=pn.n, e=pn.e, d=nums.d, p=nums.p, q=nums.q, dp=nums.dmp1, dq=nums.dmq1, qi=nums.iqmp)
            for m, v in want.items():
                raw = b64d(jp[m])
                if raw[0] == 0: err("RSA non-minimal", n, m)
                if int.from_bytes(raw, "big") != v: err("RSA member", n, m)
            if pk.public_numbers() != pn: err("RSA pub pem", n)
            if pn.n != nums.p * nums.q: err("RSA n", n)
            stats["rsa bits %d" % pn.n.bit_length()] += 1
        elif c["kty"] == "EC":
            sz = size[jp["crv"]]
            nums = sk.private_numbers(); pn = nums.public_numbers
            for m, v in dict(x=pn.x, y=pn.y, d=nums.private_value).items():
                raw = b64d(jp[m])
                if len(raw) != sz: err("EC length", n, m, len(raw))
                if raw[0] == 0: stats[jp["crv"] + " lead0 " + m] += 1
                if int.from_bytes(raw, "big") != v: err("EC member", n, m)
            if pk.public_numbers() != pn: err("EC pub pem", n)
            if sk.curve.name != {"P-256":"secp256r1","P-384":"secp384r1","P-521":"secp521r1"}[jp["crv"]]: err("curve", n)
        else:
            assert isinstance(sk, x25519.X25519PrivateKey), type(sk)
            d = sk.private_bytes_raw(); x = sk.public_key().public_bytes_raw()
            if b64d(jp["d"]) != d or b64d(jp["x"]) != x or len(d) != 32: err("OKP member", n)
            if pk.public_bytes_raw() != x: err("OKP pub pem", n)
            if x[0] == 0 or d[0] == 0: stats["okp lead0"] += 1
        # jwcrypto export equals
        kj = json.loads(k.export(private_key=True))
        for m in kj:
            if kj[m] != jp.get(m): err("JWCRYPTO member", n, m)
    except Exception as e:
        err("FAIL", c["name"], repr(e)[:300])
print(bad, "bad", dict(stats))
