from utils import *

p = 37
g = 5
message = b'attack at dawn'

alice = DHClient(p, g)
bob = DHClient(on_receive=lambda m: m)
alice.link(bob)
assert alice.send(message) == message

decrypted_messages = []
bug = lambda m: decrypted_messages.append(m) or m

alice = DHClient(p, g)
mallory = DHMITMParameterInjectionClient(on_receive=bug)
bob = DHClient(on_receive=lambda m: m)
alice.link(mallory)
mallory.link(bob)
assert alice.send(message) == message
assert decrypted_messages[0] == message
