from utils import *

a = from_hex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
score, key, plaintext = break_single_byte_xor(a)[0]
assert key == 88 and plaintext == b"Cooking MC's like a pound of bacon"
