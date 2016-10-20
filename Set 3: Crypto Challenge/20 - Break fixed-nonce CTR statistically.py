from utils import *

ciphertexts = [from_base64(line) for line in read('20.txt').split()]
assert all(is_ascii_text(plain) for plain in break_aes_ctr_repeated_nonce(ciphertexts))
