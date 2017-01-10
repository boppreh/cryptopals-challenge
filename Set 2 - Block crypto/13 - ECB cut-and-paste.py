from collections import OrderedDict
from utils import *

def profile_for(email):
    """
    Generates a dummy user profile with the given email.
    """
    return OrderedDict([(b'email', email), (b'uid', b'10'), (b'role', b'user')])

def decode_k_v(text):
    """
    Returns a dictionary for a key-value string.
    
        >>> decode_k_v('foo=bar&baz=qux&zap=zazzle')
        {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
    """
    return OrderedDict(re.findall(b'([^=]*)=([^&]*)&?', text))

def encode_k_v(obj):
    """
    Converts a dictionary to a key-value string.

        >>> encode_k_v({'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'})
        'foo=bar&baz=qux&zap=zazzle'
    """
    parts = []
    for key, value in obj.items():
        if b'&' in key or b'&' in value or b'=' in key or b'=' in value:
            raise ValueError('Invalid character.')
        parts.append(key + b'=' + value)
    return b'&'.join(parts)

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
assert detect_blocks(encrypt) == (16, 2, 23)
email, ciphertext = replace_tail_aes_ecb_oracle(encrypt, len('user'), b'admin',)
assert decode_k_v(aes_ecb_decrypt(random_key, ciphertext))[b'role'] == b'admin'
