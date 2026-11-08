#!/usr/bin/env python3
"""Independent check of the pairing test vectors using only the Python
standard library (textbook P-256 arithmetic; not constant time, for testing
only). Checks the official RFC 9382 vectors (rfc9382-spake2-p256.json) and
the Magic pairing vectors (pairing-spake2.json).

    python3 verify_spake2.py
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

enc = lambda pt: b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
lp = lambda x: struct.pack("<Q", len(x)) + x

def hkdf(ikm, info, length):
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:length]

def b32id(fp):
    import base64
    return base64.b32encode(fp[:16]).decode().rstrip("=").lower()

def spake2(w, x, y, A, B, aad):
    """RFC 9382 SPAKE2-P256-SHA256-HKDF-HMAC; returns all intermediate values."""
    M, Nn = decompress(M_HEX), decompress(N_HEX)
    pA, pB = add(mul(x, G), mul(w, M)), add(mul(y, G), mul(w, Nn))
    kA = mul(x, add(pB, mul(N_ORDER - w, Nn)))
    kB = mul(y, add(pA, mul(N_ORDER - w, M)))
    assert kA == kB, "K"
    tt = b"".join(lp(f) for f in [A, B, enc(pA), enc(pB), enc(kA), w.to_bytes(32, "big")])
    h = hashlib.sha256(tt).digest()
    kc = hkdf(h[16:], b"ConfirmationKeys" + aad, 32)
    return dict(pA=enc(pA).hex(), pB=enc(pB).hex(), K=enc(kA).hex(), TT=tt.hex(), Ke=h[:16].hex(), Ka=h[16:].hex(),
                KcA=kc[:16].hex(), KcB=kc[16:].hex(),
                A_conf=hmac.new(kc[:16], tt, hashlib.sha256).hexdigest(),
                B_conf=hmac.new(kc[16:], tt, hashlib.sha256).hexdigest())

def check_rfc(v):
    got = spake2(int(v["w"], 16), int(v["x"], 16), int(v["y"], 16), v["A"].encode(), v["B"].encode(), b"")
    for k, val in got.items():
        assert val == v[k], f"RFC vector A={v['A']!r} B={v['B']!r}: {k}"

def check_magic(v):
    pid, code, fp = v["pairing_id"].encode(), v["code"].encode(), bytes.fromhex(v["binding"])
    w = int.from_bytes(hashlib.sha512(lp(b"magic-pair-v1 w") + lp(pid) + lp(code)).digest(), "big") % N_ORDER
    assert w == int(v["w"], 16), "w"
    A, B, aad = pid, b32id(fp).encode(), b"magic-pair-v1" + fp
    assert (A.decode(), B.decode(), aad.hex()) == (v["A"], v["B"], v["AAD"]), "identities"
    got = spake2(w, int(v["x"], 16), int(v["y"], 16), A, B, aad)
    for k, ours in [("pA", "pA"), ("pB", "pB"), ("TT", "TT"), ("A_conf", "cA"), ("B_conf", "cB")]:
        assert got[k] == v[ours], f"Magic vector: {ours}"

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    rfc = json.load(open(os.path.join(here, "rfc9382-spake2-p256.json")))
    for v in rfc:
        check_rfc(v)
    magic = json.load(open(os.path.join(here, "pairing-spake2.json")))
    for v in magic:
        check_magic(v)
    print(f"{len(rfc)} RFC 9382 vector(s) and {len(magic)} Magic vector(s) OK")
