from Crypto.Util.number import *
from math import gcd

exec(open("out.txt", "r").read())


mod = [i + 1 for i in range(len(hint))]

r = int(crt(hint, mod))
m = int(LCM(mod))

K = Zmod(n)
P.<x> = PolynomialRing(K, implementation='NTL')
f = r + m * x
f *= pow(m, -1, n)

X = int((1 << 512) // m * 2)

beta = 0.499
epsilon = beta * beta - (X.bit_length() + 1) / 1024

_ = f.small_roots(beta=beta, epsilon=epsilon)[0]

p = int(r + m * _)
q = int(n // p)
d = int(pow(e, -1, (p - 1) * (q - 1)))
pt = int(pow(c, d, n))

print(bytes.fromhex(hex(pt)[2:]))