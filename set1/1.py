import math

hex_chars = '0123456789abcdef'

def decode_base(string, base_chars):
    """
    Decodes the given string in a byte array by using  the given base.

        decode_base('01110101', '01')
    """
    chars_per_byte = math.log(2**8, len(base_chars))
    assert chars_per_byte == int(chars_per_byte)
    chars_per_byte = int(chars_per_byte)

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

def from_hex(string):
    return decode_base(string, hex_chars)

string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
print(from_hex(string))
