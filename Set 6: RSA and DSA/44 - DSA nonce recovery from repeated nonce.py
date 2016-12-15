from utils import *
import re
from itertools import combinations

y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
public = (DSA_P, DSA_Q, DSA_G, y)

def get_candidates():
    matches = re.findall(rb'msg: (.+?)\ns: (\d+)\nr: (\d+)\nm: ([0-9A-Fa-f]+)', read('44.txt'))
    for message, s, r, m in matches:
        s = int(s)
        r = int(r)
        m = from_hex(m.decode('ascii'))
        assert sha1(message) == m
        dsa_verify(public, m, (r, s))
        yield m, (r, s)

for a, b in combinations(get_candidates(), 2):
    m_a, (r_a, s_a) = a
    m_b, (r_b, s_b) = b
    k = (to_int(m_a) - to_int(m_b)) * invmod(s_a - s_b, DSA_Q) % DSA_Q
    try:
        private = break_dsa_known_k(public, m_a, (r_a, s_a), k)
        p, q, g, x = private
        assert sha1(hex(x)[2:].encode('ascii')) == from_hex('ca8f6f7c66fa362d40760d135b763eb8527d3d52')
    except AssertionError:
        continue
