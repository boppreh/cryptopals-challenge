from utils import *

for i in range(3):
    server = SRPServer(NIST_DH_PRIME, 2, 3, b'password')
    salt, key = break_srp_zero_key(server, key=NIST_DH_PRIME*i)
    assert server.test(hmac_sha256(key, salt))
