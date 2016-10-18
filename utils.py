import math
from base64 import b64encode, b64decode
from itertools import chain, cycle, repeat, count, combinations, combinations_with_replacement, product

bin_chars = '01'
hex_chars = '0123456789abcdef'

def get_chars_per_byte(base_chars):
    """
    Calculates how many characters are required to represent a byte
    in the base with the given symbol list.
    """
    chars_per_byte = math.log(2**8, len(base_chars))
    assert chars_per_byte == int(chars_per_byte), chars_per_byte
    return  int(chars_per_byte)

def divide(items, block_size):
    """
    Divides a list of items into blocks of `block_size`. The last block contains
    the remaining items even if there are less than `block_size` of them.
    """
    return [items[i*block_size:(i+1)*block_size] for i in range(math.ceil(len(items)/block_size))]

def decode_base(string, base_chars):
    """
    Decodes the given string in a byte array by using the given base.

        decode_base('01110101', '01')
    """
    chars_per_byte = get_chars_per_byte(base_chars)
    assert len(string) % chars_per_byte == 0
    string = string.lower()

    groups = divide(string, chars_per_byte)
    return bytes(sum(base_chars.index(char) * len(base_chars) ** i
                     for i, char in enumerate(reversed(group)))
                 for group in groups)

def encode_base(bytes, base_chars):
    """
    Encodes the given bytes in a string using the symbols from `base_chars`.

        encode_base([0xFF], '01')
    """
    chars_per_byte = get_chars_per_byte(base_chars)

    chars = []
    for b in bytes:
        for i in reversed(range(chars_per_byte)):
            power = len(base_chars)**i
            chars.append(base_chars[int(b / power)])
            b %= power
    return ''.join(chars)

from_hex = lambda string: decode_base(string, hex_chars)
to_hex = lambda bytes: encode_base(bytes, hex_chars)
from_bin = lambda string: decode_base(string, bin_chars)
to_bin = lambda bytes: encode_base(bytes, bin_chars)
from_base64 = lambda string: b64decode(string)
to_base64 = lambda bytes: b64encode(bytes).decode('ascii')

def xor(a, b):
    """ XORs two equal length byte arrays. """
    assert len(a) == len(b)
    return bytes(x^y for x, y in zip(a, b))

def xor_encrypt(key, a):
    """ XORs a byte array with a repeated key. """
    if isinstance(key, int):
        key = [key]
    return bytes(x^y for x, y in zip(cycle(key), a))

xor_decrypt = xor_encrypt

def is_ascii_text(bytes):
    """ Returns True if all characters are ASCII printable. """
    return all(32 <= b <= 126 or b in (9, 10, 13) for b in bytes)

def is_letter(byte):
    """ Returns True if byte is an ASCII letter between A and Z. """
    return 'a' <= chr(byte).lower() <= 'z'

ENGLISH_FREQUENCY = 'zqxjkvbpygfwmucldrhsnioate'

def english_score(bytes, skip_non_ascii=True):
    """ Returns a number representing the English-ness of a byte array. """
    if skip_non_ascii and not is_ascii_text(bytes): return 0
    return sum(ENGLISH_FREQUENCY.index(chr(b).lower()) if is_letter(b) else 0 for b in bytes) / len(bytes)

def read(path):
    """ Return the binary contents of a file. """
    with open(path, 'rb') as f:
        return f.read()

def hamming_distance(*lists):
    """
    Computes the number of different bits between pairwise byte arrays.
    """
    pairs = [(a, b) for a, b in zip(lists, lists[1:])]
    return sum(sum(to_bin([x^y]).count('1') for x, y in zip(a, b)) for a, b in pairs) / len(pairs)

def break_single_byte_xor(ciphertext, measure=english_score):
    """
    If ciphertext was encrypted with XOR using a single-byte key, brute forces
    the key and looks for the most English looking plaintext.

    Returns a generator of candidate (score, key, plaintext) triples.
    """
    keys_and_plaintexts = [(k, xor_decrypt(k, ciphertext)) for k in range(0xFF)]
    return ((measure(p), k, p) for k, p in keys_and_plaintexts)

def break_multi_byte_xor_keysize(ciphertext, expected_range=range(1, 65)):
    """
    Given a ciphertext encrypted with a mult-byte XOR, attempts to find the
    keysize used by comparing the hamming distance between blocks.

    Returns a generator of candidate (score, keysize) tuples.
    """
    expected_range = expected_range or count()
    keysize_scoring = lambda k: hamming_distance(*divide(ciphertext, k)[:2]) / k
    return ((keysize_scoring(keysize), keysize) for keysize in expected_range)

def break_multi_byte_xor(ciphertext, keysize=range(1, 65), measure=english_score, subkeys_cap=1):
    """
    Given a ciphertext encrypted with multi-byte XOR, attempts to find tkey
    byte-by-byte and searchs for most English looking plaintext.

    - `keysize`: the known number of key bytes, or a list containing candidate
    keysizes.
    - `measure`: function used for scoring candidates.
    - `subkeys_cap`: limit the number of individual key bytes candidates. For
    example, a `subkeys_cap` of 1 will yield only one candidate, with a key
    formed by the bytes with best individual scores. A `subkeys_cap` of 5 will
    return candidates with all possible combinations of the 5 best individual
    key bytes. A `subkeys_cap` of 0 or None will return all possible candidates
    with all possible key bytes, and is equivalent to a brute-force approach.

    Returns a generator of candidate (score, key, plaintext) candidates.
    """
    if not isinstance(keysize, int):
        for score, keysize_candidate in break_multi_byte_xor_keysize(ciphertext, keysize):
            candidates = break_multi_byte_xor(ciphertext, keysize_candidate,
                    measure=measure, subkeys_cap=subkeys_cap)
            for score, key, plaintext in candidates:
                yield score, key, plaintext
        return
                
    blocks = divide(ciphertext, keysize)
    if len(ciphertext) % keysize:
        blocks.pop()
    transposed = zip(*blocks)
    if subkeys_cap:
        cap = lambda subkey_candidates: sorted(subkey_candidates, reverse=True)[:subkeys_cap]
    else:
        cap = lambda s: s

    candidate_matrix = [cap(break_single_byte_xor(t, measure)) for t in transposed]

    for subparts in product(*candidate_matrix):
        score = sum(s for s, k, p in subparts)
        key = bytes(k for s, k, p in subparts)
        transposed_plaintext = (p for s, k, p in subparts)
        yield (score, key, xor_decrypt(key, ciphertext))

def graph(data):
    """
    graph({'a': 2, 'b': 5, 'c': 3})

    a ==========================
    c ========================================
    b ==================================================================
    """
    max_key_length = max(len(str(i)) for i in data.keys())
    top = max(data.values())
    scaling = 40 / top
    for key, value in data.items():
        print(str(key).ljust(max_key_length), '=' * int(value * scaling), value)

if __name__ == '__main__':
    import os
    for name in sorted(os.listdir('.')):
        if name.endswith('.py') and name != 'utils.py':
            print('Testing {}...'.format(name))
            os.system('python3 "{}"'.format(name))
