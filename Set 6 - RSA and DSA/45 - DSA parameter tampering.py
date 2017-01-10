from utils import *

p = DSA_P
q = DSA_Q
g = 0
keypair1 = generate_dsa_keypair(p, q, g)
keypair2 = generate_dsa_keypair(p, q, g)
assert keypair1.public == keypair2.public

signature = dsa_sign(keypair1.private, b'Hello, world', allow_zero=True)
dsa_verify(keypair1.public, b'Goodbye, world', signature, allow_zero=True)
dsa_verify(keypair1.public, b'Goodbye, world', (0, 1), allow_zero=True)

g = p+1

keypair = generate_dsa_keypair(p, q, g)
magic_signature = forge_dsa_magic_signature(keypair.public)
dsa_verify(keypair.public, b'Hello, world', magic_signature)
dsa_verify(keypair.public, b'Goodbye, world', magic_signature)
