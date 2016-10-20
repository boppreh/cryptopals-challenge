from utils import *

for seed in (0xDEADBEEF, 0xCAFEBABE):
    twister = Twister(seed)
    for i in range(624):
        assert untemper_twister(twister.next()) == twister.state[i]
