from utils import *
import time

t = int(time.time())
password_reset_token = twister_encrypt(t, b'\x00' * 16)
time.sleep(random_number(1, 10))
assert break_twister_time(password_reset_token) == t

key = 12345
message = random_bytes(random_number(10, 20)) + b'PLAINTEXT'
ciphertext = twister_encrypt(key, message)
assert twister_decrypt(key, ciphertext) == message

assert break_twister(ciphertext, b'PLAINTEXT') == key
