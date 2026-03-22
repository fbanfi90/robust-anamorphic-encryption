import hmac
import hashlib
import random

# Settings
runs = 10

# Public parameters for small test group
p = 1000000007
q = p - 1
g = 5

# Public parameters for Oakley group (RFC 2409)
# p = int("\
# FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
# 29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
# EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
# E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
# EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
# FFFFFFFFFFFFFFFF", 16)
# q = (p - 1) // 2
# g = 2

# Anamorphic Parameters
l = 100
s = 100


class PublicParams:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g


class AnamParams:
    def __init__(self, l, s):
        self.F = lambda pp, K, x: int.from_bytes(
            hmac.new(K, x.to_bytes(8, 'little'),
            hashlib.sha256).digest(), "big") % pp.q
        self.l = l
        self.s = s


class KeyPair:
    def __init__(self, sk, pk):
        self.sk = sk
        self.pk = pk


class DoubleKey:
    def __init__(self, K, T, pk):
        self.K = K
        self.T = T
        self.pk = pk


def Gen(pp):
    sk = random.randint(0, pp.q - 1)
    pk = pow(pp.g, sk, pp.p)
    return KeyPair(sk, pk)


def Enc(pp, pk, msg):
    r = random.randint(0, pp.q - 1)
    c0 = (msg * pow(pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    return c0, c1


def Dec(pp, sk, c):
    return (c[0] * pow(c[1], -sk, pp.p)) % pp.p


def aGen(pp, ap, pk):
    K = random.randbytes(16)
    T = dict()
    for i in range(ap.l):
        T[pow(pp.g, i, pp.p)] = i
    return DoubleKey(K, T, pk)


def aEncCtr(pp, ap, dk, msg, cm, x):
    x = (x + 1) % ap.s
    t = ap.F(pp, dk.K, x)
    r = (cm + t) % pp.q
    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    ctx = (c0, c1)
    return ctx, x


def aEnc(pp, ap, dk, msg, cm):
    x = random.randint(0, ap.s - 1)
    t = ap.F(pp, dk.K, x)
    r = (cm + t) % pp.q
    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    ctx = (c0, c1)
    return ctx


def aDec(pp, ap, dk, ctx):
    for x in range(ap.s):
        t = ap.F(pp, dk.K, x)
        s = (ctx[1] * pow(pp.g, -t, pp.p)) % pp.p
        if s in dk.T:
            return dk.T[s]
    return -1


def test():
    # Set and print public parameters
    pp = PublicParams(p, q, g)
    ap = AnamParams(l, s)
    print("p =", pp.p)
    print("q =", pp.q)
    print("g =", pp.g)
    print("l =", ap.l)
    print("s =", ap.s)

    # Generate keys
    kp = Gen(pp)
    dk = aGen(pp, ap, kp.pk)
    print("(sk, pk) = (%d, %d)" % (kp.sk, kp.pk))
    print("K =", dk.K)
    print("T = [", ", ".join(str(a) + "->" + str(b) for (a, b) in
        sorted([((pp.g ** i) % pp.p, i) for i in range(l)])), ']')

    # Test Enc -> Dec and Enc -> aDec
    for i in range(runs):
        msg = pow(pp.g, random.randint(1, pp.p - 1), pp.p)
        ctx = Enc(pp, kp.pk, msg)
        msg_ = Dec(pp, kp.sk, ctx)
        cm_ = aDec(pp, ap, dk, ctx)
        print("%d -> Enc -> (%d, %d) -> Dec -> %d"
            % (msg, ctx[0], ctx[1], msg_))
        print("%d -> Enc -> (%d, %d) -> aDec -> %d"
            % (msg, ctx[0], ctx[1], cm_), "(!)" if cm_ != -1 else "")

    # Test aEnc -> Dec and aEnc -> aDec
    msg = pow(pp.g, random.randint(1, pp.p - 1), pp.p)
    cm = random.randint(0, l - 1)
    ctxs = set()
    ctr = 0
    for i in range(runs):
        # ctx, ctr = aEncCtr(pp, ap, dk, msg, cm, ctr)
        ctx = aEnc(pp, ap, dk, msg, cm)
        ctxs.add(ctx)
        msg_ = Dec(pp, kp.sk, ctx)
        cm_ = aDec(pp, ap, dk, ctx)
        print("(%d, %d) -> aEnc -> (%d, %d) -> Dec -> %d"
            % (msg, cm, ctx[0], ctx[1], msg_))
        print("(%d, %d) -> aEnc -> (%d, %d) -> aDec -> %d"
            % (msg, cm, ctx[0], ctx[1], cm_))
    if len(ctxs) == runs:
        print("No duplicate ciphertexts detected")
    else:
        print(f"{runs - len(ctxs)} duplicate ciphertexts detected, "
            "increase s or use aEncCtr")


if __name__ == "__main__":
    test()