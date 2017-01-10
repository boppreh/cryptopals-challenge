from utils import *

p = 37

alice = DHClient(p, 0)
bob = DHClient()
alice.link(bob)
assert alice.public == 0 and bob.public == 0
assert alice.shared_secret in break_weak_dh(p, 0)

alice = DHClient(p, 1)
bob = DHClient()
alice.link(bob)
assert alice.public == 1 and bob.public == 1
assert alice.shared_secret in break_weak_dh(p, 1)

alice = DHClient(p, p)
bob = DHClient()
alice.link(bob)
assert alice.public == 0 and bob.public == 0
assert alice.shared_secret in break_weak_dh(p, p)

alice = DHClient(p, p-1)
bob = DHClient()
alice.link(bob)
assert alice.public in (1, p-1) and bob.public in (1, p-1)
assert alice.shared_secret in break_weak_dh(p, p-1)
