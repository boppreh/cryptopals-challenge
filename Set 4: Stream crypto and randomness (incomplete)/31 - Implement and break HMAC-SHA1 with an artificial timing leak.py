from utils import *
from time import sleep

key = random_bytes(20)

# Broken at the moment.
#serve_http(lambda b: print(b) or (200, b'result'), n_requests=2)
#print(send_http(b'data'))

assert hmac_sha1(b'', b'') == from_hex('fbdb1d1b18aa6c08324b7d64b71fb76370690e1d')
assert hmac_sha1(b'key', b'The quick brown fox jumps over the lazy dog') == from_hex('de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9')

