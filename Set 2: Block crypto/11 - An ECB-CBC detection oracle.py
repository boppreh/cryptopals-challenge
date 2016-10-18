from utils import *

for i in range(100):
    mode = 'ecb' if random_bool() else 'cbc'
    encrypt = lambda t: encryption_oracle(t, mode)
    assert detect_mode(encrypt) == mode
