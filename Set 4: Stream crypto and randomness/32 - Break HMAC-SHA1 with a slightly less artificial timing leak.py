from utils import *
from time import sleep

key = random_bytes(20)
expected = None
def test_hmac(file, signature):
    global expected
    expected = hmac_sha1(key, file)
    # Delay is small enough that system variations can trick the attacker.
    return insecure_comparison(signature, expected, delay=0.001)

assert not test_hmac(b'foo', b'')
    
assert expected in break_hmac_comparison_timing(lambda c: test_hmac(b'foo', c), average=5)
