from utils import *

ciphertext = from_base64(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

assert is_ascii_text(aes_ctr_decrypt(b'YELLOW SUBMARINE', ciphertext, b'\x00' * 8))
