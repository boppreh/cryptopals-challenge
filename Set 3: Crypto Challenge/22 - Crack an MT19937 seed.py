from utils import *
from time import sleep, time

sleep(random_number(1, 10))
seed = int(time())
twister = Twister(seed)
sleep(random_number(1, 10))
output = twister.next()
assert break_twister_time([output], int(time())) == seed
