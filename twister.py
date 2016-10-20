def truncate(i):
    return i & 0xFFFFFFFF

# MT19937.
w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 0x6C078965

upper_mask = 1 << r
lower_mask = (1 << r) - 1

class Twister:
    def __init__(self, seed):
        self.state = [0] * n
        self.index = n
        self.state[0] = seed
        for i in range(1, n):
            self.state[i] = truncate(f * (self.state[i-1] ^ (self.state[i-1] >> (w-2))) + i)

    def next(self):
        if self.index >= n:
            self.twist()

        y = self.state[self.index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)

        self.index += 1
        return truncate(y)

    def twist(self):
        for i in range(n):
            x = (self.state[i] & upper_mask) + (self.state[(i+1) % n] & lower_mask)
            xA = x >> 1
            if x & 1:
                xA = xA ^ a
            self.state[i] = self.state[(i + m) % n] ^ xA
        self.index = 0

    def stream(self):
        while True:
            yield self.next()