from utils import *

with open('4.txt') as f:
    lines = [from_hex(line) for line in f.read().split('\n')]

score, key, plaintext = max(break_single_byte_xor(c)[0] for c in lines)
assert key == 53 and plaintext == b'Now that the party is jumping\n'
