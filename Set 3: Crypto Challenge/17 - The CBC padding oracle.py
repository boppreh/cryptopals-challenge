from utils import *
import random

def log(a):
    print(divide(a, AES.BLOCK_SIZE))
    return a

strings = [from_base64(s) for s in b"""MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
        MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
        MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
        MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
        MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
        MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
        MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
        MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
        MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
        MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".split()]

key = random_aes_key()
for string in strings:
    def encrypt():
        iv = random_iv()
        return iv + aes_cbc_encrypt(key, string, iv)

    def padding_oracle(ciphertext):
        try:
            aes_cbc_decrypt(key, ciphertext)
            return True
        except PaddingError:
            return False

    assert break_aes_cbc_padding_oracle(padding_oracle, encrypt()) == string
