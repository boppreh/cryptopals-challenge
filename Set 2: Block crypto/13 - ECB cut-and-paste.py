from utils import *

obj = {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
assert decode_k_v('foo=bar&baz=qux&zap=zazzle') == obj
assert decode_k_v(encode_k_v(obj)) == obj
try:
    encode_k_v({'username': '&invalid'})
    assert False
except ValueError:
    pass
