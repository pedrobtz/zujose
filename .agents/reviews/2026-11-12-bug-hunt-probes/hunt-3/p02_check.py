import json, sys, base64, collections, hmac, hashlib
from jwcrypto import jwk
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils
def b64d(s):
    assert "=" not in s
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
H = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
def verify(alg, k, inp, sig):
    h = H[alg[2:]]()
    if alg.startswith("HS"):
        return hmac.compare_digest(hmac.new(b64d(k["k"]), inp, "sha"+alg[2:]).digest(), sig)
    pub = serialization.load_pem_public_key(k.export_to_pem())
    if alg.startswith("RS"): pub.verify(sig, inp, padding.PKCS1v15(), h)
    elif alg.startswith("PS"): pub.verify(sig, inp, padding.PSS(padding.MGF1(h), h.digest_size), h)
    else:
        n = len(sig)//2
        pub.verify(sig, inp, ec.ECDSA(h)) if False else pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:n],"big"), int.from_bytes(sig[n:],"big")), inp, ec.ECDSA(h))
    return True
cases = json.load(open(sys.argv[1])); bad = 0
siglen = {"ES256":64,"ES384":96,"ES512":132,"HS256":32,"HS384":48,"HS512":64}
lz = collections.Counter()
def err(*a):
    global bad; bad += 1; print(*a)
for c in cases:
    try:
        k = jwk.JWK.from_json(c["pub"] or c["key"])
        pl = bytes.fromhex(c["payload"])
        if c["fmt"] == "compact":
            parts = c["token"].split(".")
            if len(parts) != 3: err("PARTS", c["name"]); continue
            entries = [dict(protected=parts[0], signature=parts[2])]; tp = parts[1] if not c["det"] else None
            if c["det"] and parts[1] != "": err("NOT DETACHED", c["name"])
        else:
            j = json.loads(c["token"])
            if c["det"] != ("payload" not in j): err("DETACHED?", c["name"])
            tp = j.get("payload")
            if c["fmt"] == "flattened":
                if "signatures" in j: err("FMT", c["name"])
                entries = [j]
            else:
                if set(j) - {"payload", "signatures"}: err("FMT", c["name"], list(j))
                entries = j["signatures"]
        if tp is not None:
            got = b64d(tp) if c["b64"] else tp.encode()
            if got != pl: err("PAYLOAD", c["name"], got[:30], pl[:30])
        okany = False
        for e in entries:
            ph = json.loads(b64d(e["protected"])); sig = b64d(e["signature"])
            if c["alg"] == "multi":
                if ph.get("kid") != c["kid"]: continue
                alg = ph["alg"]
            else:
                alg = c["alg"]
                if ph["alg"] != alg: err("ALG", c["name"])
                if c["kid"] and ph.get("kid") != c["kid"]: err("KID", c["name"], ph)
            if (not c["b64"]) != (ph.get("b64") is False and ph.get("crit") == ["b64"]): err("B64", c["name"], ph)
            if ("b64" in ph) and c["b64"]: err("B64 present", c["name"])
            if alg in siglen and len(sig) != siglen[alg]: err("SIGLEN", c["name"], len(sig))
            if alg.startswith("ES"):
                h = len(sig)//2
                if sig[0] == 0: lz[alg+" r0"] += 1
                if sig[h] == 0: lz[alg+" s0"] += 1
            inp = e["protected"].encode() + b"." + (base64.urlsafe_b64encode(pl).rstrip(b"=") if c["b64"] else pl)
            if not verify(alg, k, inp, sig): err("BADSIG", c["name"])
            okany = True
        if not okany: err("NO ENTRY", c["name"])
    except Exception as e:
        err("FAIL", c["name"], repr(e)[:200])
print(len(cases), "cases", bad, "bad", dict(lz))
