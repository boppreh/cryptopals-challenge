from utils import *

assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37
assert hamming_distance(b'this is a test', b'wokka wokka!!!', b'this is a test') == 37

ciphertext = from_base64(read('6.txt'))
#ciphertext = xor_encrypt(b'YELLOW SUBMARINE', read('6.py'))

keysize_scoring = lambda k: hamming_distance(*divide(ciphertext, k)[:2]) / k
print('Normalized hamming weight for each keysize:')
graph({keysize: keysize_scoring(keysize) for keysize in range(2, 40)})
candidates = []
for keysize in sorted(range(2, 40), key=keysize_scoring):
    print('Trying', keysize)
    results = break_multi_byte_xor(ciphertext, keysize)
    score, key, plaintext = results[0]
    print('Preview:', int(score), key, plaintext[:50])
    candidates.extend(results)
for score, key, plaintext in sorted(candidates):
    print(int(score), key, plaintext[:50])
