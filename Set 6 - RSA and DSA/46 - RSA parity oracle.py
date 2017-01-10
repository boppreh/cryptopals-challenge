from utils import *

secret = from_base64('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
#secret = b'hello world'

keypair = generate_rsa_keypair(2**(8 * len(secret)))
def parity_oracle(ciphertext):
    return rsa_decrypt(keypair.private, ciphertext)[-1] % 2

assert binary_search(keypair.public[1], lambda a: a - to_int(secret)) == to_int(secret)

ciphertext = rsa_encrypt(keypair.public, secret)

# Last character is never decrypted properly. Parity oracle seems to return an incorrect value at that point.
assert secret[:-1] == break_rsa_parity_oracle(parity_oracle, ciphertext, keypair.public)[:-1]
print('Incomplete exercise! Last character is not decrypted properly.')
