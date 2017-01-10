from utils import *

def log(a):
    print(divide(a, AES.BLOCK_SIZE))
    return a

prefix = b"comment1=cooking%20MCs;userdata=" 
suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
def encode(input):
    return prefix + input.replace(b'=', b'.').replace(b';', b'.') + suffix

assert encode(b'mcs') == b"comment1=cooking%20MCs;userdata=mcs;comment2=%20like%20a%20pound%20of%20bacon"
assert encode(b';admin=true;') == b"comment1=cooking%20MCs;userdata=.admin.true.;comment2=%20like%20a%20pound%20of%20bacon"

key = random_bytes(16)
iv = random_bytes(AES.BLOCK_SIZE)

encrypt = lambda input: aes_cbc_encrypt(key, encode(input), iv=iv)
test = lambda ciphertext: b';admin=true;' in aes_cbc_decrypt(key, ciphertext, iv=iv)

assert not test(encrypt(b';admin=true;'))

ciphertext = insert_aes_cbc_oracle(encrypt, len(prefix), b';admin=true;')
assert test(ciphertext)
