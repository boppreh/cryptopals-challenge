from utils import *

key = random_bytes(16)
prefix = random_bytes(18)
secret = b'ABCDEFGHIJKL'
oracle = lambda value: aes_ecb_encrypt(key, prefix + value + secret)

assert detect_prefix_size_aes_ecb_oracle(oracle) == len(prefix)
