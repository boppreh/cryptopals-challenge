from utils import *
from time import sleep, time

seed = int(time())
twister = Twister(seed)
sleep(random_number(1, 10))
output = twister.next()
assert break_twister_time(output) == seed
