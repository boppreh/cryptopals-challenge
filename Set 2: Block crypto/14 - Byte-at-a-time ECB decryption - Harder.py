from utils import *

def log(a):
    print(divide(a, AES.BLOCK_SIZE))
    return a

key = random_bytes(16)

for prefix_length in [0, 5, 16, 20, 32, 33]:
    print('=============== Prefix Length {} ==================='.format(prefix_length))
    prefix = b'unknown prefix that can be used with different lengths'[:prefix_length]
    secret = b'super secret api token that spans multiples blocks'
    encrypt = lambda value: aes_ecb_encrypt(key, log(prefix + value + secret))

    assert detect_prefix_length_aes_ecb_oracle(encrypt) == prefix_length
    assert break_aes_ecb_oracle(encrypt) == secret
