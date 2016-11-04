from utils import *

key = ''.join(str(random_number(0, 10)) for i in range(random_number(5, 20))).encode('ascii')
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
mac = sha1mac(key, message)
candidates = extend_sha1(mac, b';admin=true')
found = False
for i in range(200):
    tail, new_mac = next(candidates)
    assert b';admin=true' in tail
    if new_mac == sha1mac(key, message + tail):
        found = True
assert found
