from utils import *

key = b'YELLOW SUBMARINE'
plaintext = b'beatles' * 10
assert aes_ecb_decrypt(key, aes_ecb_encrypt(key, plaintext)) == plaintext

ciphertext = from_base64(read('10.txt'))
plaintext = aes_cbc_decrypt(key, ciphertext, iv=b'\x00'*AES.BLOCK_SIZE)
assert plaintext.startswith(b"I'm back and I'm ringin' the bell")
assert plaintext.endswith(b"Play that funky music \n")
