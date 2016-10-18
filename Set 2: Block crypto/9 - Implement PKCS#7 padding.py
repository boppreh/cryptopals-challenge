from utils import *

assert pad_pkcs7(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
