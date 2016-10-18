from utils import *

obj = {b'foo': b'bar', b'baz': b'qux', b'zap': b'zazzle'}
assert decode_k_v(b'foo=bar&baz=qux&zap=zazzle') == obj
assert decode_k_v(encode_k_v(obj)) == obj
try:
    encode_k_v({b'username': b'&invalid'})
    assert False
except ValueError:
    pass

random_key = random_bytes(16)
encrypt = lambda email: aes_ecb_encrypt(random_key, encode_k_v(profile_for(email)))
assert detect_mode(encrypt) == 'ecb'
test = lambda ciphertext: decode_k_v(aes_ecb_decrypt(random_key, ciphertext))[b'role']
assert test(encrypt(b'me')) == b'user'

assert test(insert_aes_ecb_oracle(encrypt, test, b'admin',)) == b'admin'
