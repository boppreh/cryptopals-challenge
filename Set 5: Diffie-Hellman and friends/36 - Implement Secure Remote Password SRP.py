from utils import *

client = SRPClient(NIST_DH_PRIME, 2, 3, b'password')
server = SRPServer(NIST_DH_PRIME, 2, 3, b'password')
client.link(server)
assert client.K == server.K
assert client.verify(server)
