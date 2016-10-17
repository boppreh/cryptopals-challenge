from utils import *

with open('4.txt') as f:
    candidates = [from_hex(line) for line in f.read().split('\n')]
candidate_triples = ((k, c, xor_decrypt(k, c)) for k in range(0xFF) for c in candidates)
score = lambda triple: english_score(triple[2])
key, candidate, decrypted = max(candidate_triples, key=score)
assert key == 53 and decrypted == b'Now that the party is jumping\n'
