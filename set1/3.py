from utils import *

a = from_hex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
key = max((i for i in range(0xFF)), key=lambda k: english_score(xor_decrypt(k, a)))
assert xor_decrypt(key, a) == b"Cooking MC's like a pound of bacon"
