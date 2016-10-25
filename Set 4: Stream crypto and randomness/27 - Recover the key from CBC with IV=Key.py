from utils import *

key = random_aes_key()
iv = key # Important part.

def oracle(ciphertext):
    plaintext = aes_cbc_decrypt(key, ciphertext, iv)
    if not is_ascii_text(plaintext):
        return plaintext
    # 0.0015% chance of failing.
    raise ValueError()
ciphertext = aes_cbc_encrypt(key, b'\x00' * 100, iv)

assert break_aes_cbc_iv_oracle(oracle, ciphertext) == iv == key
