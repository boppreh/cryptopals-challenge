import math
from base64 import b64encode, b64decode

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

    result = []
    for i in range(0, len(string), chars_per_byte):
        chars = string[i:i+chars_per_byte]
        b = 0
        for i, char in enumerate(reversed(chars)):
            b += base_chars.index(char) * len(base_chars) ** i
        result.append(b)
    return bytes(result)

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

string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
assert to_hex(from_hex(string)) == string
assert to_base64(from_hex(string)) == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
