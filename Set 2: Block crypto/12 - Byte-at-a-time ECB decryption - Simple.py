from utils import *

mystery_append = from_base64(b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
""")

unknown_key = random_bytes(16)
encrypt = lambda t: encryption_oracle(t, key=unknown_key, append=mystery_append, prepend=b'', mode='ecb')

assert break_aes_ecb_oracle(encrypt) == mystery_append
