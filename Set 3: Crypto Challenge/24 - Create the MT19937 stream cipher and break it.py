from utils import *

key = 12345
message = random_bytes(10) + b'PLAINTEXT'
assert twister_decrypt(key, twister_encrypt(key, message)) == message
