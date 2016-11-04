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


# Copied from http://www.acooke.org/cute/PurePython0.html

def little_endian_bytes(words, n):
    '''convert n-byte words to bytes (little endian)'''
    for word in words:
        for _ in range(n):
            yield word & 0xff
            word >>= 8

def big_endian_bytes(words, n):
    '''convert n-byte words to bytes (big endian)'''
    for word in words:
        yield from reversed(list(little_endian_bytes([word], n)))

def big_endian_words(b, n):
    '''convert bytes into n-byte words (big endian)'''
    for g in grouped(b, n):
        w = 0
        for b in g:
            w = w << 8 | b
        yield w

def little_endian_words(b, n):
    '''convert bytes into n-byte words (little endian)'''
    for g in grouped(b, n):
        yield from big_endian_words(reversed(g), n)

from itertools import zip_longest

def grouped(iterable, n, fillvalue=None):
    '''group in to chunks - http://stackoverflow.com/a/434411/181772'''
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)

import struct

# https://raw.github.com/ajalt/python-sha1/master/sha1.py
# (modified)

# http://www.oocities.org/rozmanov/python/md4.html
# Copyright (C) 2001-2002  Dmitry Rozmanov (LGPL)
# modified


def left_rotate(n, b):
    return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def md_pad_64(message, length_to_bytes, fake_byte_len=None):
    original_byte_len = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    original_bit_len = (fake_byte_len if fake_byte_len else original_byte_len) * 8
    message += bytes(length_to_bytes(original_bit_len))
    return message

def make_md_hash_64(compress, state_to_hash, length_to_bytes):
    def md_hash(message, fake_byte_len=None, state=None):
        message = md_pad_64(message, length_to_bytes, fake_byte_len=fake_byte_len)
        for i in range(0, len(message), 64):
            state = compress(message[i:i+64], state)
        return state_to_hash(state)
    return md_hash


def f(x, y, z): return x & y | ~x & z
def g(x, y, z): return x & y | x & z | y & z
def h(x, y, z): return x ^ y ^ z

def f1(a, b, c, d, k, s, X): return left_rotate(a + f(b, c, d) + X[k], s)
def f2(a, b, c, d, k, s, X): return left_rotate(a + g(b, c, d) + X[k] + 0x5a827999, s)
def f3(a, b, c, d, k, s, X): return left_rotate(a + h(b, c, d) + X[k] + 0x6ed9eba1, s)

def md4_compress(block, state=None):

    if not state: state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    a, b, c, d = h0, h1, h2, h3 = state

    x = list(little_endian_words(block, 4))

    a = f1(a,b,c,d, 0, 3, x)
    d = f1(d,a,b,c, 1, 7, x)
    c = f1(c,d,a,b, 2,11, x)
    b = f1(b,c,d,a, 3,19, x)
    a = f1(a,b,c,d, 4, 3, x)
    d = f1(d,a,b,c, 5, 7, x)
    c = f1(c,d,a,b, 6,11, x)
    b = f1(b,c,d,a, 7,19, x)
    a = f1(a,b,c,d, 8, 3, x)
    d = f1(d,a,b,c, 9, 7, x)
    c = f1(c,d,a,b,10,11, x)
    b = f1(b,c,d,a,11,19, x)
    a = f1(a,b,c,d,12, 3, x)
    d = f1(d,a,b,c,13, 7, x)
    c = f1(c,d,a,b,14,11, x)
    b = f1(b,c,d,a,15,19, x)

    a = f2(a,b,c,d, 0, 3, x)
    d = f2(d,a,b,c, 4, 5, x)
    c = f2(c,d,a,b, 8, 9, x)
    b = f2(b,c,d,a,12,13, x)
    a = f2(a,b,c,d, 1, 3, x)
    d = f2(d,a,b,c, 5, 5, x)
    c = f2(c,d,a,b, 9, 9, x)
    b = f2(b,c,d,a,13,13, x)
    a = f2(a,b,c,d, 2, 3, x)
    d = f2(d,a,b,c, 6, 5, x)
    c = f2(c,d,a,b,10, 9, x)
    b = f2(b,c,d,a,14,13, x)
    a = f2(a,b,c,d, 3, 3, x)
    d = f2(d,a,b,c, 7, 5, x)
    c = f2(c,d,a,b,11, 9, x)
    b = f2(b,c,d,a,15,13, x)

    a = f3(a,b,c,d, 0, 3, x)
    d = f3(d,a,b,c, 8, 9, x)
    c = f3(c,d,a,b, 4,11, x)
    b = f3(b,c,d,a,12,15, x)
    a = f3(a,b,c,d, 2, 3, x)
    d = f3(d,a,b,c,10, 9, x)
    c = f3(c,d,a,b, 6,11, x)
    b = f3(b,c,d,a,14,15, x)
    a = f3(a,b,c,d, 1, 3, x)
    d = f3(d,a,b,c, 9, 9, x)
    c = f3(c,d,a,b, 5,11, x)
    b = f3(b,c,d,a,13,15, x)
    a = f3(a,b,c,d, 3, 3, x)
    d = f3(d,a,b,c,11, 9, x)
    c = f3(c,d,a,b, 7,11, x)
    b = f3(b,c,d,a,15,15, x)

    return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff]

MD4 = make_md_hash_64(md4_compress, lambda state: little_endian_bytes(state, 4), lambda length: little_endian_bytes([length], 8))

def md4(message, message_length=None, state=None):
    if state is not None:
        state = list(little_endian_words(state, 4))
    return bytes(MD4(message, message_length, state))
