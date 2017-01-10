from utils import *

assert pad_pkcs7(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'

assert expected_padding_length(b'0123456789') == 6
assert expected_padding_length(b'') == 16
assert expected_padding_length(b'0123456789ABCDEF') == 16
assert expected_padding_length(b'0123456789ABCDEF0123') == 12
