import math
import struct

def pad(message, length, byteorder='little'):
    message += b'\x80'
    # 55 = 64 - 8 (length bytes) - 1 (0x80 already prepended).
    message += b'\x00' * ((55 - length) % 64)
    message += (length * 8).to_bytes(8, byteorder=byteorder)
    return message

def left_rotate(x, amount):
    return ((x<<amount) | (x>>(32-amount))) & 0xFFFFFFFF

# Adapted from http://rosettacode.org/wiki/MD5/Implementation#Python
def md5(message, message_length=None, state=b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10'):
    """
    Computes the MD5 of a byte message, optionally starting from an existing state.
    """
    rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
     
    constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + \
                16*[lambda b, c, d: (d & b) | (~d & c)] + \
                16*[lambda b, c, d: b ^ c ^ d] + \
                16*[lambda b, c, d: c ^ (b | ~d)]
     
    index_functions = 16*[lambda i: i] + \
                      16*[lambda i: (5*i + 1)%16] + \
                      16*[lambda i: (3*i + 5)%16] + \
                      16*[lambda i: (7*i)%16]

    message_length = message_length or len(message)
    message = pad(message, message_length, 'little')
 
    hash_pieces = list(struct.unpack('<LLLL', state))
 
    for chunk_ofst in range(0, len(message), 64):
        a, b, c, d = hash_pieces
        chunk = message[chunk_ofst:chunk_ofst+64]
        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g:4*g+4], byteorder='little')
            to_rotate &= 0xFFFFFFFF
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c
        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF

    return struct.pack('<LLLL', *hash_pieces)

# Adapted from https://github.com/ajalt/python-sha1
def sha1(message, message_length=None, state=b'gE#\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0'):
    hash_pieces = list(struct.unpack('>LLLLL', state))
    
    message_length = message_length or len(message)
    message = pad(message, message_length, 'big')

    for i in range(0, len(message), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
    
        a, b, c, d, e = hash_pieces
    
        for i in range(80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                            a, left_rotate(b, 30), c, d)
    
        for i, val in enumerate([a, b, c, d, e]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF
    
    return struct.pack('>LLLLL', *hash_pieces)
