from utils import *

n = NIST_DH_PRIME
g = 2
password = b'password'

# S
salt = random_bytes(16)
x = to_int(sha256(salt + password))
v = pow(g, x, n)

a = random_number(n)
A = pow(g, a, n)

b = random_number(n)
B = pow(g, b, n)
u = to_int(random_bytes(16))

S = pow(B, a + u*x, n)
assert S == pow(A * pow(v, u, n), b, n)
K = sha256(from_int(S))

raise NotImplementedError()
