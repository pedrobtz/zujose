import json, hashlib, hmac, struct, collections
from cryptography.hazmat.primitives import keywrap, hashes, padding
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
bad = 0; n = collections.Counter()
def lp(b): return struct.pack(">I", len(b)) + b
for c in json.load(open("p14.json")):
    k = c["kind"]; n[k] += 1
    try:
        if k == "kw":
            try: want = keywrap.aes_key_wrap(bytes.fromhex(c["kek"]), bytes.fromhex(c["data"])).hex()
            except Exception as e: want = "ERR"
            if not (c["out"] == want or (want == "ERR" and c["out"].startswith("ERR"))): bad += 1; print("KW", len(c["kek"])//2, len(c["data"])//2, c["out"][:60], want[:60])
        elif k == "kdf":
            other = lp(c["id"].encode()) + lp(bytes.fromhex(c["apu"])) + lp(bytes.fromhex(c["apv"])) + struct.pack(">I", c["bits"])
            want = ConcatKDFHash(hashes.SHA256(), c["bits"] // 8, other).derive(bytes.fromhex(c["z"])).hex()
            if want != c["out"]: bad += 1; print("KDF", c["bits"], len(c["apu"])//2)
        elif k == "enc":
            cek, iv, pt, aad = (bytes.fromhex(c[x]) for x in ("cek", "iv", "pt", "aad"))
            if "GCM" in c["enc"]:
                o = AESGCM(cek).encrypt(iv, pt, aad); ct, tag = o[:-16], o[-16:]
            else:
                h = len(cek) // 2; mk, ek = cek[:h], cek[h:]
                p = padding.PKCS7(128).padder(); e = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
                ct = e.update(p.update(pt) + p.finalize()) + e.finalize()
                tag = hmac.new(mk, aad + iv + ct + struct.pack(">Q", 8 * len(aad)), "sha" + c["enc"][-3:]).digest()[:h]
            if ct.hex() != c["ct"] or tag.hex() != c["tag"]: bad += 1; print("ENC", c["enc"], len(pt), len(aad))
        else:
            hname = {"PBES2-HS256+A128KW": ("sha256", 16), "PBES2-HS384+A192KW": ("sha384", 24), "PBES2-HS512+A256KW": ("sha512", 32)}[c["alg"]]
            want = hashlib.pbkdf2_hmac(hname[0], bytes.fromhex(c["pw"]), c["alg"].encode() + b"\0" + bytes.fromhex(c["p2s"]), c["p2c"], hname[1]).hex()
            if want != c["out"]: bad += 1; print("PBES2", c["alg"])
    except Exception as e: bad += 1; print("EXC", k, repr(e)[:200])
print(dict(n), bad, "bad")
