from collections import Counter
import sys

counter = Counter(sys.stdin.buffer.read())
for i in range(0x100):
    print(counter.get(i, 0), end=', ')
