import base64
from itertools import product
from tqdm import tqdm
from Crypto.Util.number import *
from Crypto.Cipher import AES

N = 128
STEP = 8
BITS_NEEDED = 15


bits, enc_flag = open("out.txt", "r").read().split("\n")
bits = base64.b64decode(bits.encode())
bits = "".join(bin(x)[2:].zfill(8) for x in bits)
bits = [int(x) for x in bits]
enc_flag = bytes.fromhex(enc_flag)

def printFlag(key):
	key = int("".join(str(x) for x in key), 2)
	key = long_to_bytes(key)
	cipher = AES.new(key, AES.MODE_CBC, iv=b"\0" * 16)
	print(cipher.decrypt(enc_flag))

def getTapWithStep(tap, step):
	state = [1 << i for i in range(N)]
	while len(state) < step * N + 1:
		nxt_state = 0
		for x in tap:
			nxt_state ^= state[-N + x]
		state.append(nxt_state)

	# deduce the linear relation of state[0], state[step], ... state[step * N] 

	lb = [None] * N
	ret = []

	def add(value, mask):
		for i in range(N):
			if value & (1 << i):
				if lb[i] == None:
					lb[i] = [value, mask]
					return
				else:
					value ^= lb[i][0]
					mask ^= lb[i][1]

		if mask != 0:
			for i in range(N):
				if mask & (1 << i):
					ret.append(i)

	for i in range(N + 1):
		add(state[i * step], 1 << i)

	return ret


_t = getTapWithStep([0, 1, 2, 7], STEP)
_p = [0, 8, 16, 32, 64, 120]
assert all(x % STEP == 0 for x in _p)
_p = [x // STEP for x in _p]

_f = [[0], [2], [3], [5], [0, 1], [0, 3], [1, 4], [2, 3],\
      [0, 1, 4], [2, 3, 4], [0, 1, 2, 4, 5], [1, 2, 3, 4, 5]]

def f(bits):
	def _prod(L):
	    return all(x for x in L)

	def _sum(L):
	    return sum(L) & 1

	return _sum(_prod(bits[x] for x in term) for term in _f)

def check(bits):
	assert len(bits) == N + 1
	b = bits[-1]
	for x in _t:
		b ^= bits[x]
	return b == 0


def solve(seq):
	sols = [list(x) for x in product(range(2), repeat=BITS_NEEDED)]
	for b in tqdm(seq):
		print(len(sols))		
		new_sols = []
		for sol in sols:
			if f([sol[-BITS_NEEDED + d] for d in _p[:-1]] + [0]) == b and (len(sol) < N or check(sol[-N:] + [0])):
				new_sols.append(sol + [0])
			if f([sol[-BITS_NEEDED + d] for d in _p[:-1]] + [1]) == b and (len(sol) < N or check(sol[-N:] + [1])):
				new_sols.append(sol + [1])
		sols = new_sols
		if len(sols) == 1:
			break
	return sols

def main():
	initial_states = [None] * N
	for start in range(STEP):
		seq = bits[start:len(bits):STEP]

		sols = solve(seq)
		assert len(sols) == 1
		sol = sols[0]

		for i in range(N // STEP):
			initial_states[start + i * STEP] = sol[i]

	printFlag(initial_states)

main()