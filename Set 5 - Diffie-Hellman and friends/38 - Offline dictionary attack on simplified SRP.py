from utils import *

n = NIST_DH_PRIME
g = 2
password = b'password'

def original_protocol():
    # S
    salt = random_bytes(16)
    x = to_int(sha256(salt + password))
    v = pow(g, x, n)

    a = random_number(n)
    # C->S
    A = pow(g, a, n)

    b = random_number(n)
    # S->C
    salt
    B = pow(g, b, n)
    u = to_int(random_bytes(16))

    # C
    x = to_int(sha256(salt + password))
    S = pow(B, a + u*x, n)
    K = sha256(from_int(S))

    # S
    assert S == pow(A * pow(v, u, n), b, n)
    K = sha256(from_int(S))
    
    # C->S
    return hmac_sha256(K, salt)

original_protocol()

def mitm_protocol():
    a = random_number(n)
    # C->S
    A = pow(g, a, n)

    salt = random_bytes(16)
    b = random_number(n)
    # S->C
    salt
    B = pow(g, b, n)
    u = to_int(random_bytes(16))

    # C
    x = to_int(sha256(salt + password))
    S = pow(B, a + u*x, n)
    K = sha256(from_int(S))

    # C->S
    target_hmac = hmac_sha256(K, salt)
    def try_candidate(password):
        x = to_int(sha256(salt + password))
        v = pow(g, x, n)
        S = pow(A * pow(v, u, n), b, n)
        K = sha256(from_int(S))
        return hmac_sha256(K, salt) == target_hmac
    return try_candidate

try_candidate = mitm_protocol()
assert any(map(try_candidate, [b'swordfish', b'correct horse battery staple', b'123456', b'password']))
