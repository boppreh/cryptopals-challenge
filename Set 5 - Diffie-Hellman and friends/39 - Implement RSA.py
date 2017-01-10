from utils import *

assert not is_prime(1)
assert is_prime(2)
assert is_prime(3)
assert not is_prime(4)
assert is_prime(5)
assert is_prime(1009)
assert not is_prime(1010)
assert not is_prime(1011)
assert is_prime(2**31 - 1)
assert not is_prime(2 ** 32 - 1)

assert invmod(5, 1009) * 5 % 1009 == 1
assert invmod(5, 2**31 - 1) * 5 % (2**31-1) == 1
assert invmod(17, 3120) == 2753

for i in range(10):
    assert is_prime(random_prime(2**10))

keypair = generate_rsa_keypair(2**256, e=3)
message = b'attack at dawn'
assert rsa_decrypt(keypair.private, rsa_encrypt(keypair.public, message)) == message
