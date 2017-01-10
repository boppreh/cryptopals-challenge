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

p, q, g, x = break_dsa_reused_k(public, get_candidates())
assert sha1(hex(x)[2:].encode('ascii')) == from_hex('ca8f6f7c66fa362d40760d135b763eb8527d3d52')
