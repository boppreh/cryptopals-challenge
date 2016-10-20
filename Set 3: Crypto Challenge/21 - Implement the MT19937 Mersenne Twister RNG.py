from utils import *

expected_outputs = [0xD091BB5C, 0x22AE9EF6, 0xE7E1FAEE, 0xD5C31F79, 0x2082352C, 0xF807B7DF, 0xE9D30005, 0x3895AFE1, 0xA1E24BBA, 0x4EE4092B]

for actual, expected in zip(Twister(5489).stream32(), expected_outputs):
    assert actual == expected

