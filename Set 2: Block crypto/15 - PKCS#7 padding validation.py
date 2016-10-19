from utils import *

assert unpad_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04") == b'ICE ICE BABY'

try:
    unpad_pkcs7(b'ICE ICE BABY\x05\x05\x05\x05')
    assert False
except PaddingError:
    pass

try:
    unpad_pkcs7(b'ICE ICE BABY\x01\x02\x03\x04')
    assert False
except PaddingError:
    pass
