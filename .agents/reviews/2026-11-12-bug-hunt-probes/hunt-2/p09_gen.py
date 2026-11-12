import json, base64, os, hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, x25519
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def ub64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
J = json.load(open(os.path.join(D, "jwe.json"))); keys = {k: json.loads(v) for k, v in J["keys"].items()}
PT = b'{"sub":"a","exp":4000000000}'; out = {}
def seal(hdr_bytes, cek, ek, aad_extra=None):
    h = b64(hdr_bytes); iv = os.urandom(12); ct = AESGCM(cek).encrypt(iv, PT, h.encode())
    return ".".join([h, b64(ek), b64(iv), b64(ct[:-16]), b64(ct[-16:])])
pw = ub64(keys["pw"]["k"])
def pbes2(name, p2c_text, p2c, salt=b"\x01" * 16, hdr=None):
    alg = "PBES2-HS256+A128KW"; cek = os.urandom(16)
    kek = PBKDF2HMAC(hashes.SHA256(), 16, alg.encode() + b"\x00" + salt, p2c).derive(pw)
    hb = hdr or ('{"alg":"%s","enc":"A128GCM","p2s":"%s","p2c":%s}' % (alg, b64(salt), p2c_text)).encode()
    out[name] = seal(hb, cek, aes_key_wrap(kek, cek))
pbes2("p2c_1000", "1000", 1000); pbes2("p2c_1e3", "1e3", 1000); pbes2("p2c_1000.0", "1000.0", 1000); pbes2("p2c_1", "1", 1); pbes2("p2c_999", "999", 999)
pbes2("p2c_str", '"1000"', 1000); pbes2("p2c_0", "0", 1); pbes2("p2c_neg", "-1000", 1000); pbes2("p2c_frac", "1000.5", 1000); pbes2("p2c_true", "true", 1); pbes2("p2c_null", "null", 1)
pbes2("p2c_arr", "[1000]", 1000); pbes2("p2c_1e400", "1e400", 1); pbes2("p2c_big", "4294967296", 1); pbes2("p2c_2e9", "2147483648", 1); pbes2("p2c_1e15", "1e15", 1); pbes2("p2c_negzero", "-0", 1)
pbes2("p2c_600000", "600000", 600000); pbes2("p2c_600001", "600001", 600001); pbes2("p2c_2000", "2000", 2000); pbes2("p2c_2001", "2001", 2001)
pbes2("p2s_7", "1000", 1000, salt=b"\x01" * 7); pbes2("p2s_8", "1000", 1000, salt=b"\x01" * 8); pbes2("p2s_big", "1000", 1000, salt=b"\x01" * 4096)
pbes2("p2s_missing", "1000", 1000, hdr=b'{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2c":1000}')
pbes2("p2c_missing", "1000", 1000, hdr=b'{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AQEBAQEBAQE"}')
pbes2("p2s_num", "1000", 1000, hdr=b'{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2c":1000,"p2s":5}')
pbes2("p2s_badb64", "1000", 1000, hdr=b'{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2c":1000,"p2s":"AQEBAQEBAQE="}')
# ECDH
def kdf(z, bits, algid, apu=b"", apv=b""):
    lp = lambda x: struct.pack(">I", len(x)) + x
    other = lp(algid.encode()) + lp(apu) + lp(apv) + struct.pack(">I", bits); o = b""; i = 1
    while len(o) * 8 < bits: o += hashlib.sha256(struct.pack(">I", i) + z + other).digest(); i += 1
    return o[: bits // 8]
def ecdh_tok(name, z, epk, extra=""):
    hb = ('{"alg":"ECDH-ES","enc":"A256GCM","epk":%s%s}' % (json.dumps(epk, separators=(",", ":")) if not isinstance(epk, str) else epk, extra)).encode()
    out[name] = seal(hb, kdf(z, 256, "A256GCM"), b"")
curves = {"p256": (ec.SECP256R1(), "P-256", 32), "p384": (ec.SECP384R1(), "P-384", 48), "p521": (ec.SECP521R1(), "P-521", 66)}
for n, (c, crv, L) in curves.items():
    kj = keys[n]; pub = ec.EllipticCurvePublicNumbers(int.from_bytes(ub64(kj["x"]), "big"), int.from_bytes(ub64(kj["y"]), "big"), c).public_key()
    def eph(cond=lambda x, y: True):
        while True:
            e = ec.generate_private_key(c); pn = e.public_key().public_numbers()
            if cond(pn.x, pn.y): return e, pn
    e, pn = eph(); z = e.exchange(ec.ECDH(), pub)
    X, Y = b64(pn.x.to_bytes(L, "big")), b64(pn.y.to_bytes(L, "big"))
    ecdh_tok("ec_ok_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": Y})
    ecdh_tok("ec_order_" + n, z, {"y": Y, "x": X, "kid": "eph", "use": "enc", "alg": "ECDH-ES", "crv": crv, "kty": "EC", "ext": True})
    ecdh_tok("ec_epk_d_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": Y, "d": b64(e.private_numbers().private_value.to_bytes(L, "big"))})
    ecdh_tok("ec_epk_dbad_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": Y, "d": 5})
    ecdh_tok("ec_xpad_" + n, z, {"kty": "EC", "crv": crv, "x": b64(pn.x.to_bytes(L + 1, "big")), "y": b64(pn.y.to_bytes(L + 1, "big"))})
    ecdh_tok("ec_offcurve_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": b64(((pn.y + 1) % (1 << (8 * L - 8))).to_bytes(L, "big"))})
    ecdh_tok("ec_zero_" + n, z, {"kty": "EC", "crv": crv, "x": b64(bytes(L)), "y": b64(bytes(L))})
    ecdh_tok("ec_wrongcrv_" + n, z, {"kty": "EC", "crv": "P-384" if crv == "P-256" else "P-256", "x": X, "y": Y})
    ecdh_tok("ec_noy_" + n, z, {"kty": "EC", "crv": crv, "x": X})
    ecdh_tok("ec_kty_okp_" + n, z, {"kty": "OKP", "crv": crv, "x": X, "y": Y})
    ecdh_tok("ec_apu_num_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": Y}, ',"apu":5')
    ecdh_tok("ec_apv_badb64_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": Y}, ',"apv":"A"')
    ecdh_tok("ec_apu_null_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": Y}, ',"apu":null')
    ecdh_tok("ec_apu_empty_" + n, z, {"kty": "EC", "crv": crv, "x": X, "y": Y}, ',"apu":""')
    if n == "p256":
        e, pn = eph(lambda x, y: x < (1 << 248)); z = e.exchange(ec.ECDH(), pub)   # x has a leading zero byte
        ecdh_tok("ec_xshort_" + n, z, {"kty": "EC", "crv": crv, "x": b64(pn.x.to_bytes(31, "big")), "y": b64(pn.y.to_bytes(L, "big"))})
        ecdh_tok("ec_xlead0_" + n, z, {"kty": "EC", "crv": crv, "x": b64(pn.x.to_bytes(32, "big")), "y": b64(pn.y.to_bytes(L, "big"))})
        # Z with a leading zero byte: search ephemeral
        for _ in range(4000):
            e = ec.generate_private_key(c); z = e.exchange(ec.ECDH(), pub)
            if z[0] == 0: break
        pn = e.public_key().public_numbers(); print("z leading zero found:", z[0] == 0, len(z))
        ecdh_tok("ec_zlead0_" + n, z, {"kty": "EC", "crv": crv, "x": b64(pn.x.to_bytes(L, "big")), "y": b64(pn.y.to_bytes(L, "big"))})
    ecdh_tok("epk_str_" + n, z, '"x"'); ecdh_tok("epk_null_" + n, z, 'null'); ecdh_tok("epk_arr_" + n, z, '[]'); ecdh_tok("epk_empty_" + n, z, '{}')
    out["epk_missing_" + n] = seal(b'{"alg":"ECDH-ES","enc":"A256GCM"}', kdf(z, 256, "A256GCM"), b"")
# X25519
xk = keys["x25519"]; xpub = x25519.X25519PublicKey.from_public_bytes(ub64(xk["x"]))
e = x25519.X25519PrivateKey.generate(); z = e.exchange(xpub); ex = e.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
ecdh_tok("x_ok", z, {"kty": "OKP", "crv": "X25519", "x": b64(ex)})
ecdh_tok("x_zero_point", bytes(32), {"kty": "OKP", "crv": "X25519", "x": b64(bytes(32))})          # low order: z = 0
ecdh_tok("x_one_point", bytes(32), {"kty": "OKP", "crv": "X25519", "x": b64(b"\x01" + bytes(31))})    # low order: z = 0
lo = bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
ecdh_tok("x_loworder8", bytes(32), {"kty": "OKP", "crv": "X25519", "x": b64(lo)})
ecdh_tok("x_31bytes", z, {"kty": "OKP", "crv": "X25519", "x": b64(ex[:31])}); ecdh_tok("x_33bytes", z, {"kty": "OKP", "crv": "X25519", "x": b64(ex + b"\x00")})
hb = bytearray(ex); hb[31] |= 0x80; ecdh_tok("x_highbit", z, {"kty": "OKP", "crv": "X25519", "x": b64(bytes(hb))})   # RFC 7748: high bit masked -> same z
ecdh_tok("x_kty_ec", z, {"kty": "EC", "crv": "X25519", "x": b64(ex)}); ecdh_tok("x_ed", z, {"kty": "OKP", "crv": "Ed25519", "x": b64(ex)}); ecdh_tok("x_with_y", z, {"kty": "OKP", "crv": "X25519", "x": b64(ex), "y": "AA"})
json.dump(out, open(os.path.join(D, "jwe2.json"), "w"), indent=1); print(len(out))
