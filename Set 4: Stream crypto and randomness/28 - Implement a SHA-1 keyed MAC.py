from utils import *

assert sha1mac(b'key', b'message') == sha1mac(b'key', b'message')
assert sha1mac(b'key', b'message') != sha1mac(b'key', b'messagE')
assert sha1mac(b'key', b'message') != sha1mac(b'Key', b'message')
