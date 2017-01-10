from utils import *

keypair = generate_rsa_keypair(2**1024, e=3)
message = b'hi mom'
signature = rsa_sign_pkcs15(keypair.private, message)
rsa_verify_pkcs15_buggy(keypair.public, message, signature)

fake_signature = break_rsa_signature_pkcs15_buggy(message)
rsa_verify_pkcs15_buggy(keypair.public, message, fake_signature)
