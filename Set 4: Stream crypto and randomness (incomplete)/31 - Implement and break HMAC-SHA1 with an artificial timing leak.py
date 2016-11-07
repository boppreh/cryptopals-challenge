from utils import *
from time import sleep

key = random_bytes(16)
def test_hmac(
serve_http(lambda b: print(b) or (200, b'result'))
print(send_http(b'data'))
