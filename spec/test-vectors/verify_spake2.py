#!/usr/bin/env python3
"""Independent check of pairing-spake2.json using only the Python standard
library (textbook P-256 arithmetic; not constant time, for testing only).

    python3 verify_spake2.py [pairing-spake2.json]
"""
import hashlib, hmac, json, struct, sys, os

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
M_HEX = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
N_HEX = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

def add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0: return None
    if p1 == p2: l = (3 * p1[0] * p1[0] - 3) * pow(2 * p1[1], -1, P) % P
    else: l = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (l * l - p1[0] - p2[0]) % P
    return (x, (l * (p1[0] - x) - p1[1]) % P)

def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt, k = add(pt, pt), k >> 1
    return r

def decompress(h):
    b = bytes.fromhex(h); x = int.from_bytes(b[1:], "big")
    y = pow((x ** 3 - 3 * x + B) % P, (P + 1) // 4, P)
    return (x, y if y % 2 == b[0] - 2 else P - y)

def uncompressed(h):
    b = bytes.fromhex(h); assert b[0] == 4 and len(b) == 65
    return (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))

enc = lambda pt: b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
lp = lambda x: struct.pack("<Q", len(x)) + x

def hkdf(ikm, info, length):
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:length]

def check(v):
    M, Nn = decompress(M_HEX), decompress(N_HEX)
    pid, code, fp = v["pairing_id"].encode(), v["code"].encode(), bytes.fromhex(v["binding"])
    w = int.from_bytes(hashlib.sha512(lp(b"magic-pair-v1 w") + lp(pid) + lp(code)).digest(), "big") % N_ORDER
    assert w == int(v["w"], 16), "w"
    x, y = int(v["x"], 16), int(v["y"], 16)
    pA, pB = enc(add(mul(x, G), mul(w, M))), enc(add(mul(y, G), mul(w, Nn)))
    assert pA.hex() == v["pA"] and pB.hex() == v["pB"], "shares"
    kA = mul(x, add(uncompressed(v["pB"]), mul(N_ORDER - w, Nn)))
    kB = mul(y, add(uncompressed(v["pA"]), mul(N_ORDER - w, M)))
    assert kA == kB, "K"
    tt = lp(b"magic-pair-v1") + lp(pid) + lp(fp) + lp(pA) + lp(pB) + lp(enc(kA)) + lp(w.to_bytes(32, "big"))
    assert tt.hex() == v["TT"], "TT"
    keys = hkdf(hashlib.sha256(tt).digest()[16:], b"ConfirmationKeys", 64)
    assert hmac.new(keys[:32], tt, hashlib.sha256).hexdigest() == v["cA"], "cA"
    assert hmac.new(keys[32:], tt, hashlib.sha256).hexdigest() == v["cB"], "cB"

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "pairing-spake2.json")
    vectors = json.load(open(path))
    for v in vectors:
        check(v)
    print(f"{len(vectors)} vector(s) OK")
