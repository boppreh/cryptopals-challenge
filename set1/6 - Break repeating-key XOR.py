from utils import *

assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37
assert hamming_distance(b'this is a test', b'wokka wokka!!!', b'this is a test') == 37

ciphertext = from_base64(read('6.txt'))
score, key, plaintext = max(break_multi_byte_xor(ciphertext, keysize=range(2, 41)))
assert key == b'Terminator X: Bring the noise'
assert plaintext[:20] == b"I'm back and I'm rin"
