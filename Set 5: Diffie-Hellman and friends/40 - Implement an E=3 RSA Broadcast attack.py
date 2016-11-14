from utils import *

keypair1 = generate_rsa_keypair(2**256)
keypair2 = generate_rsa_keypair(2**256)
keypair3 = generate_rsa_keypair(2**256)
message = b'attack at dawn'
ciphertext1 = rsa_encrypt(keypair1.public, message)
ciphertext2 = rsa_encrypt(keypair2.public, message)
ciphertext3 = rsa_encrypt(keypair3.public, message)

assert break_rsa_crt(ciphertext1, keypair1.public, ciphertext2, keypair2.public, ciphertext3, keypair3.public) == message
