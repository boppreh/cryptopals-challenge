from utils import *

p, q, g = DSA_P, DSA_Q, DSA_G
params = (p, q, g)

keypair = generate_dsa_keypair(*params)
message = b'hi mom'

signature = dsa_sign(keypair.private, message)
dsa_verify(keypair.public, message, signature)

p, q, g, x = keypair.private
k = random_number(1, q)
r = pow(g, k, p) % q
s = (invmod(k, q) * (to_int(message) + x * r)) % q
signature = (r, s)

assert keypair.private == break_dsa_known_k(keypair.public, message, signature, k)

y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
public = (p, q, g, y)

r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
signature = (r, s)

message = sha1(b"""For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
""")
assert message == from_int(0xd2d0714f014a9784047eaeccf956520045c45265)

private = break_dsa_brute_force_k(public, message, signature, range(1, 2**16))
p, q, g, x = private
assert sha1(hex(x)[2:].encode('ascii')) == from_hex('0954edd5e0afe5542a4adf012611a91912a3ec16')
