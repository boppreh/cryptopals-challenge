from utils import *
from aes import AES

key = b'YELLOW SUBMARINE'
ciphertext = from_base64(read('7.txt'))
plaintext = aes_decrypt_ecb(key, ciphertext)
assert plaintext.startswith(b"I'm back and I'm ringin' the bell")
assert plaintext.endswith(b"Play that funky music \n")
