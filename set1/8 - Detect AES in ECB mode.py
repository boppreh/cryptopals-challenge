from utils import * 

for i, line in enumerate(open('8.txt')):
    ciphertext = from_hex(line.strip())
    assert not detect_aes_ecb(ciphertext) or i == 132
