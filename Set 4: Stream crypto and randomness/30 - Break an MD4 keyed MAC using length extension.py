from utils import *

assert to_hex(md4(b'')) == '31d6cfe0d16ae931b73c59d7e0c089c0'

assert to_hex(md4(b'a')) == 'bde52cb31de33e46245e05fbdbd6fb24'
assert to_hex(md4(b'12345678901234567890123456789012345678901234567890123456789012345678901234567890')) == 'e33b4ddc9c38f2199c3e7b164fcc0536'

key = ''.join(str(random_number(0, 10)) for i in range(random_number(5, 20))).encode('ascii')
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
mac = md4(key + message)
candidates = extend_hash(md4, 'little', mac, b';admin=true')
found = False
for i in range(200):
    tail, new_mac = next(candidates)
    assert b';admin=true' in tail
    if new_mac == md4(key + message + tail):
        found = True
assert found
