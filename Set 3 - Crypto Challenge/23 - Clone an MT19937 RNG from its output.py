from utils import *

for seed in (0xDEADBEEF, 0xCAFEBABE):
    twister = Twister(seed)
    clone = Twister(0)
    for i in range(624):
        clone.state[i] = untemper_twister(twister.next())
        assert clone.state[i] == twister.state[i]
    clone.twist()

    for i in range(10000):
        assert clone.next() == twister.next()

