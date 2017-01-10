from utils import *

def log(a):
    print(divide(a, AES.BLOCK_SIZE))
    return a

key = random_bytes(16)

long_secret = from_base64(b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
""")

for prefix_length in [0, 5, 16, 20, 32, 33]:
    for secret in (b'short', long_secret):
        #if prefix_length != 5: continue
        prefix = b'unknown prefix that can be used with different lengths'[:prefix_length]
        encrypt = lambda value: aes_ecb_encrypt(key, prefix + value + secret)

        total_length = len(prefix) + len(secret)
        assert detect_blocks(encrypt) == (16, math.ceil(total_length / AES.BLOCK_SIZE), total_length)

        assert detect_prefix_length_aes_ecb_oracle(encrypt) == prefix_length
        broke = break_aes_ecb_oracle(encrypt)
        assert broke == secret
