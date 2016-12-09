from utils import *

keypair = generate_rsa_keypair(2**256)
seen = set()
def oracle(ciphertext):
    if ciphertext in seen:
        raise ValueError('This value has been decrypted already.')
    seen.add(ciphertext)
    return rsa_decrypt(keypair.private, ciphertext)

message = b'attack at dawn'
ciphertext = rsa_encrypt(keypair.public, message)
assert oracle(ciphertext) == message

assert break_rsa_decryption_oracle(oracle, ciphertext, keypair.public) == message
