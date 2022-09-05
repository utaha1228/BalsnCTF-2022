from pwn import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
import math
from hashlib import sha256
from fpylll import *

def lll(matrix):
	A = IntegerMatrix.from_matrix(matrix)
	ret = [[0] * len(matrix[0]) for _ in range(len(matrix))]
	LLL.reduction(A).to_matrix(ret)
	return ret

KEY_SIZE = 512
PRIME_SIZE = 512
THRESHOLD = 40

r = process(["python3", "./chall.py"])
r.recvuntil(b"flag = ")
enc_flag = bytes.fromhex(r.recvline().strip().decode("ascii"))

def getShare():
	r.sendline(b"1")
	r.recvuntil(b"p = ")
	p = int(r.recvline().decode("ascii"))
	r.recvuntil(b"a = ")
	a = int(r.recvline().decode("ascii"))
	r.recvuntil(b"b = ")
	b = int(r.recvline().decode("ascii"))
	r.recvuntil(b"c = ")
	c = int(r.recvline().decode("ascii"))
	r.recvuntil(b"Commitment: ")
	p_ = int(r.recvuntil(b" ").decode("ascii"))
	g = int(r.recvuntil(b" ").decode("ascii"))
	y = int(r.recvline().decode("ascii"))
	return p, a, b, c, p_, g, y

def crt(ls: list) -> tuple:
	rem = 0
	mod = 1
	for q, r in ls:
		gcd = math.gcd(q, mod)
		if rem % gcd != r % gcd:
			return (-1, -1)
		rem += mod * ((r - rem) // gcd) * pow(mod // gcd, -1, q // gcd)
		mod = mod * q // gcd
		rem %= mod
	return rem

T = 30

info = []

print("Collecting Data")

for _ in range(T):
	TRY_COUNT = 0
	while True:
		TRY_COUNT += 1
		p, a, b, c, p_, g, y = getShare()

		quo, rem = 1, 0
		for q in sieve_base:
			if (p_ - 1) % q == 0 and pow(g, (p_ - 1) // q, p_) != 1:
				step_size = int(math.sqrt(q)) + 2

				_g = pow(g, (p_ - 1) // q, p_)
				_y = pow(y, (p_ - 1) // q, p_)

				step = pow(_g, step_size, p_)
				cur = 1
				big_step = {}
				for i in range(step_size):
					big_step[cur] = i * step_size
					cur = cur * step % p_

				cur = 1
				step = pow(_g, -1, p_)
				for i in range(step_size):
					tmp = _y * cur % p_
					if tmp in big_step:
						ans = (i + big_step[tmp]) % q
						rem += quo * pow(quo, -1, q) * (ans - rem)
						quo *= q
						rem %= quo
						break
					cur = cur * step % p_

		if quo >= (1 << THRESHOLD):
			break

	# (a + bx + cy) % p == rem + quo * mul
	mul_max = (p - 1 - rem) // quo
	info.append((p, b, c, (rem - a) % p, quo, mul_max))
	print(_, TRY_COUNT)

print("Constructing the matrix")
B, C, base = [crt([(t[0], t[i]) for t in info]) for i in [1, 2, 3]]
Q = 1
for t in info:
	Q *= t[0]

deltas = []
for i in range(len(info)):
	p, _, _, _, quo, mx = info[i]
	tmp = Q // p
	tmp *= (pow(tmp, -1, p) * quo) % p
	deltas.append(tmp)

# B * key1 + C * key2 = base + sum(deltas_i * a_i) (mod Q)
# where a_i < mx_i

B = pow(B, -1, Q)
C = C * B % Q
base = base * B % Q
deltas = [x * B % Q for x in deltas]

# key1 + C * key2 = base + sum(deltas_i * a_i) (mod Q)
# where a_i < mx_i

# mx_i should has (PRIME_SIZE - THRESHOLD) bits
# key2 should has KEY_SIZE bits
# it would be great if KEY_SIZE > PRIME_SIZE - THRESHOLD

mat = [
	[deltas[i]] + [1 << (KEY_SIZE - (PRIME_SIZE - THRESHOLD)) if j == i else 0 for j in range(len(deltas))] + [0, 0] for i in range(len(deltas))
]
mat.append([-C] + [0] * len(deltas) + [1, 0])
mat.append([base] + [0] * len(deltas) + [0, 1 << KEY_SIZE])
mat.append([Q] + [0] * len(deltas) + [0, 0])

print("Running LLL")
mat = lll(mat)

for row in mat:
	if row[0] < 0:
		row = [-x for x in row]

	if row[-1] != (1 << KEY_SIZE):
		continue
	key1 = row[0]
	key2 = row[-2]
	if key1 < 0 or key2 < 0:
		continue
	real_key = sha256(long_to_bytes(key1) + long_to_bytes(key2)).digest()[:16]
	cipher = AES.new(real_key, AES.MODE_ECB)
	flag = cipher.decrypt(enc_flag)
	print(flag)
