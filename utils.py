import math
from base64 import b64encode, b64decode
from itertools import chain, cycle, repeat

hex_chars = '0123456789abcdef'

def get_chars_per_byte(base_chars):
    """
    Calculates how many characters are required to represent a byte
    in the base with the given symbol list.
    """
    chars_per_byte = math.log(2**8, len(base_chars))
    assert chars_per_byte == int(chars_per_byte), chars_per_byte
    return  int(chars_per_byte)

def decode_base(string, base_chars):
    """
    Decodes the given string in a byte array by using the given base.

        decode_base('01110101', '01')
    """
    chars_per_byte = get_chars_per_byte(base_chars)
    assert len(string) % chars_per_byte == 0
    string = string.lower()

    groups = [string[i:i+chars_per_byte]
              for i in range(0, len(string), chars_per_byte)]
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
    return all(32 <= b <= 126 or b == 10 for b in bytes)
def is_letter(byte):
    return 'a' <= chr(byte).lower() <= 'z'

ENGLISH_FREQUENCY = 'zqxjkvbpygfwmucldrhsnioate'

def english_score(bytes):
    if not is_ascii_text(bytes): return 0
    return sum(ENGLISH_FREQUENCY.index(chr(b).lower()) for b in bytes if is_letter(b))

if __name__ == '__main__':
    import os
    for name in os.listdir('.'):
        if name.endswith('.py') and name != 'utils.py':
            os.system('python3 ' + name)
