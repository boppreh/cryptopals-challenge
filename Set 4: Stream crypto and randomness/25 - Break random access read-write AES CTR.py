from utils import *

plaintext = aes_ecb_decrypt(b'YELLOW SUBMARINE', from_base64(read('25.txt')))
key = random_aes_key()
nonce = random_ctr_nonce()
ciphertext = aes_ctr_encrypt(key, plaintext, nonce)
edited = aes_ctr_edit(key, ciphertext, nonce, 10, b'ABC')
assert aes_ctr_decrypt(key, edited, nonce)[10:13] == b'ABC'
