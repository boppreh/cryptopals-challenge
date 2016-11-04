import math
import time
import os
import re
from base64 import b64encode, b64decode
from itertools import chain, cycle, repeat, count, combinations, combinations_with_replacement, product, islice
from aes import AES
from collections import Counter, OrderedDict
from twister import Twister
from hashes import sha1, md5, md4

bin_chars = '01'
hex_chars = '0123456789abcdef'

single_bytes = [bytes([i]) for i in range(0x100)]

class PaddingError(Exception): pass

def get_chars_per_byte(base_chars):
    """
    Calculates how many characters are required to represent a byte
    in the base with the given symbol list.
    """
    chars_per_byte = math.log(2**8, len(base_chars))
    assert chars_per_byte == int(chars_per_byte), chars_per_byte
    return  int(chars_per_byte)

def divide(items, block_size):
    """
    Divides a list of items into blocks of `block_size`. The last block contains
    the remaining items even if there are less than `block_size` of them.
    """
    return [items[i*block_size:(i+1)*block_size] for i in range(math.ceil(len(items)/block_size))]

def decode_base(string, base_chars):
    """
    Decodes the given string in a byte array by using the given base.

        decode_base('01110101', '01')
    """
    chars_per_byte = get_chars_per_byte(base_chars)
    assert len(string) % chars_per_byte == 0
    string = string.lower()

    groups = divide(string, chars_per_byte)
    return bytes(sum(base_chars.index(char) * len(base_chars) ** i
                     for i, char in enumerate(reversed(group)))
                 for group in groups)

def encode_base(bytes, base_chars):
    """
    Encodes the given bytes in a string using the symbols from `base_chars`.

        encode_base([0xFF], '01')
    """
    chars_per_byte = get_chars_per_byte(base_chars)

    chars = []
    for b in bytes:
        for i in reversed(range(chars_per_byte)):
            power = len(base_chars)**i
            chars.append(base_chars[int(b / power)])
            b %= power
    return ''.join(chars)

from_hex = lambda string: decode_base(string, hex_chars)
to_hex = lambda bytes: encode_base(bytes, hex_chars)
from_bin = lambda string: decode_base(string, bin_chars)
to_bin = lambda bytes: encode_base(bytes, bin_chars)
from_base64 = lambda string: b64decode(string)
to_base64 = lambda bytes: b64encode(bytes).decode('ascii')

def xor(a, b, truncate=False):
    """ XORs two equal length byte arrays. """
    assert len(a) == len(b) or truncate
    return bytes(x^y for x, y in zip(a, b))

def xor_encrypt(key, a):
    """ XORs a byte array with a repeated key. """
    if isinstance(key, int):
        key = [key]
    return bytes(x^y for x, y in zip(cycle(key), a))

xor_decrypt = xor_encrypt

def is_ascii_text(bytes):
    """ Returns True if all characters are ASCII printable. """
    return all(32 <= b <= 126 or b in (9, 10, 13) for b in bytes)

def is_letter(byte):
    """ Returns True if byte is an ASCII letter between A and Z. """
    return 'a' <= chr(byte).lower() <= 'z'

ASCII_ENGLISH_FREQUENCY = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 155603, 0, 0, 155603, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1639895, 3205, 21729, 105, 655, 35, 357, 11297, 1953, 1953, 3899, 754, 113215, 50967, 74191, 2546, 4683, 6818, 3304, 1893, 1469, 1492, 1036, 1087, 1713, 1330, 3752, 9933, 0, 0, 0, 3450, 70, 18931, 9268, 10527, 8056, 17967, 7419, 8954, 11716, 35987, 1776, 1764, 10297, 8994, 13095, 12765, 12247, 494, 11398, 18772, 25169, 4825, 2285, 8507, 577, 4694, 213, 976, 0, 976, 0, 6430, 0, 453655, 83647, 153957, 239955, 731796, 139438, 119292, 324830, 382031, 7206, 43450, 235686, 140056, 406180, 443262, 105787, 5799, 356907, 361152, 520577, 167610, 56153, 123272, 9634, 106489, 3711, 0, 17720, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 0, 0, 0, 5, 0, 22, 62, 1, 10, 0, 0, 1, 0, 0, 131, 0, 5, 2, 0, 4, 0, 0, 1, 0, 1, 2, 0, 0, 0]

def english_score(bytes, skip_non_ascii=True):
    """ Returns a number representing the English-ness of a byte array. """
    if skip_non_ascii and not is_ascii_text(bytes): return 0
    return sum(ASCII_ENGLISH_FREQUENCY[b] for b in bytes) / len(bytes)

def read(path):
    """ Return the binary contents of a file. """
    with open(path, 'rb') as f:
        return f.read()

def hamming_distance(*lists):
    """
    Computes the number of different bits between pairwise byte arrays.
    """
    pairs = [(a, b) for a, b in zip(lists, lists[1:])]
    return sum(sum(to_bin([x^y]).count('1') for x, y in zip(a, b)) for a, b in pairs) / len(pairs)

def sha1mac(key, message):
    """ Computes the SHA1 MAC for the given key and message. """
    return sha1(key + message)

def break_single_byte_xor(ciphertext, measure=english_score):
    """
    If ciphertext was encrypted with XOR using a single-byte key, brute forces
    the key and looks for the most English looking plaintext.

    Returns a generator of candidate (score, key, plaintext) triples.
    """
    keys_and_plaintexts = [(k, xor_decrypt(k, ciphertext)) for k in range(0x100)]
    return ((measure(p), k, p) for k, p in keys_and_plaintexts)

def break_multi_byte_xor_keysize(ciphertext, expected_range=range(1, 65)):
    """
    Given a ciphertext encrypted with a mult-byte XOR, attempts to find the
    keysize used by comparing the hamming distance between blocks.

    Returns a generator of candidate (score, keysize) tuples.
    """
    expected_range = expected_range or count()
    keysize_scoring = lambda k: hamming_distance(*divide(ciphertext, k)[:2]) / k
    return ((keysize_scoring(keysize), keysize) for keysize in expected_range)

def break_multi_byte_xor(ciphertext, keysize=range(1, 65), measure=english_score, subkeys_cap=1):
    """
    Given a ciphertext encrypted with multi-byte XOR, attempts to find tkey
    byte-by-byte and searchs for most English looking plaintext.

    - `keysize`: the known number of key bytes, or a list containing candidate
    keysizes.
    - `measure`: function used for scoring candidates.
    - `subkeys_cap`: limit the number of individual key bytes candidates. For
    example, a `subkeys_cap` of 1 will yield only one candidate, with a key
    formed by the bytes with best individual scores. A `subkeys_cap` of 5 will
    return candidates with all possible combinations of the 5 best individual
    key bytes. A `subkeys_cap` of 0 or None will return all possible candidates
    with all possible key bytes, and is equivalent to a brute-force approach.

    Returns a generator of candidate (score, key, plaintext) candidates.
    """
    if not isinstance(keysize, int):
        for score, keysize_candidate in break_multi_byte_xor_keysize(ciphertext, keysize):
            candidates = break_multi_byte_xor(ciphertext, keysize_candidate,
                    measure=measure, subkeys_cap=subkeys_cap)
            for score, key, plaintext in candidates:
                yield score, key, plaintext
        return
                
    blocks = divide(ciphertext, keysize)
    if len(ciphertext) % keysize:
        blocks.pop()
    transposed = zip(*blocks)
    if subkeys_cap:
        cap = lambda subkey_candidates: sorted(subkey_candidates, reverse=True)[:subkeys_cap]
    else:
        cap = lambda s: s

    candidate_matrix = [cap(break_single_byte_xor(t, measure)) for t in transposed]

    for subparts in product(*candidate_matrix):
        score = sum(s for s, k, p in subparts)
        key = bytes(k for s, k, p in subparts)
        transposed_plaintext = (p for s, k, p in subparts)
        yield (score, key, xor_decrypt(key, ciphertext))

def graph(data):
    """
    graph({'a': 2, 'b': 5, 'c': 3})

    a ==========================
    c ========================================
    b ==================================================================
    """
    max_key_length = max(len(str(i)) for i in data.keys())
    top = max(data.values())
    scaling = 40 / top
    for key, value in data.items():
        print(str(key).ljust(max_key_length), '=' * int(value * scaling), value)

def aes_ecb_decrypt(key, ciphertext):
    """
    Decrypts a ciphertext that was encrypted with AES in ECB mode.
    """
    aes = AES(key)
    decrypted_blocks = [aes.decrypt_block(b) for b in divide(ciphertext, AES.BLOCK_SIZE)]
    return unpad_pkcs7(b''.join(decrypted_blocks))

def aes_ecb_encrypt(key, plaintext):
    """
    Encrypts a plaintext using AES in ECB mode.
    """
    aes = AES(key)
    padded = pad_pkcs7(plaintext)
    return b''.join(aes.encrypt_block(b) for b in divide(padded, AES.BLOCK_SIZE))

def detect_aes_ecb(ciphertext):
    """
    If ciphertext is an AES ciphertext, returns True if it was definitely
    encrypted using ECB mode, or False if it can't be asserted. This is done
    by looking for identical blocks.
    """
    blocks = divide(ciphertext, AES.BLOCK_SIZE)
    return len(set(blocks)) != len(blocks)

def aes_cbc_decrypt(key, ciphertext, iv=None):
    """
    Decrypts a ciphertext that was encrypted with AES en CBC mode. If IV is not
    given take the first ciphertext block.
    """
    aes = AES(key)

    encrypted_blocks = divide(ciphertext, AES.BLOCK_SIZE)
    if not iv:
        iv = encrypted_blocks.pop(0)

    decrypted_blocks = []
    previous = iv
    for block in encrypted_blocks:
        data = xor(previous, aes.decrypt_block(block))
        previous = block
        decrypted_blocks.append(data)

    return unpad_pkcs7(b''.join(decrypted_blocks))

def aes_cbc_encrypt(key, ciphertext, iv):
    """
    Encrypts a plaintext using AES in CBC mode.
    """
    aes = AES(key)

    previous = iv
    encrypted_blocks = []
    for block in divide(pad_pkcs7(ciphertext), AES.BLOCK_SIZE):
        encrypted_block = aes.encrypt_block(xor(previous, block))
        encrypted_blocks.append(encrypted_block)
        previous = encrypted_block

    return b''.join(encrypted_blocks)

def twister_encrypt(seed, data):
    """
    "Encrypts" data with a MersenneTwister generator seeded with the given
    value. Please don't pretend this is cryptography.
    """
    return stream_encrypt(Twister(seed).stream8(), data)
twister_decrypt = twister_encrypt

def stream_encrypt(stream, data):
    """
    Helper function that XORs data with a stream.
    """
    ciphertext = []
    for plaintext_byte, stream_byte in zip(data, stream):
        ciphertext.append(plaintext_byte ^ stream_byte)
    return bytes(ciphertext)

def aes_ctr_stream(key, nonce, endianness='little'):
    """
    Returns a generator of single-bytes suitable to encrypt or decrypt
    plaintexts.
    """
    aes = AES(key)
    nonce_int = int.from_bytes(nonce, endianness)
    block_pad = b'\x00' * (AES.BLOCK_SIZE - len(nonce))
    for i in count():
        text = block_pad + nonce_int.to_bytes(len(nonce), endianness)
        for byte in aes.encrypt_block(text):
            yield byte
        nonce_int += 1

def aes_ctr_encrypt(key, data, nonce, endianess='little'):
    """
    Encrypts or decrypts a text using AES in CTR mode.
    """
    return stream_encrypt(aes_ctr_stream(key, nonce, endianess), data)
aes_ctr_decrypt = aes_ctr_encrypt

def aes_ctr_edit(key, ciphertext, nonce, offset, replacement):
    """
    Decrypts the ciphertext, changes the plaintext and encrypts it again under
    the same key and nonce.
    """
    bytes_list = list(ciphertext)
    stream = aes_ctr_stream(key, nonce)
    for i in range(offset): next(stream)
    for j, byte in enumerate(replacement):
        bytes_list[offset+j] = next(stream) ^ byte
    return bytes(bytes_list)

def random_bool():
    """
    Returns a random boolean value.
    """
    return ord(random_bytes(1)) % 2

def random_number(start, end=None):
    """
    Returns a random number in the interval [start, end).
    """
    if end is None:
        end = start
        start = 0

    while True:
        # This looks stupid, but avoids biases. Using mod is not as balanced.
        number = ord(random_bytes(1))
        if start <= number < end:
            return number

def random_bytes(n_bytes):
    """
    Returns a random byte array of length `n_bytes`.
    """
    return os.urandom(n_bytes)

def unpad_pkcs7(padded, block_size=AES.BLOCK_SIZE):
    """
    Removes a PKCS#7 padding by removing the last `n` bytes, where `n` is the
    last byte.
    """
    padding_length = padded[-1]
    padding = padded[-padding_length:]
    if not 0 < padding_length <= block_size or padding != bytes([padding_length]) * padding_length:
        raise PaddingError()
    return padded[:-padding_length]

def expected_padding_length(text, block_size=AES.BLOCK_SIZE):
    """
    Returns the number of bytes that the given text should be padded with.
    """
    return (-len(text)) % block_size or block_size

def pad_pkcs7(text, block_size=AES.BLOCK_SIZE):
    """
    Pads a byte array according to PKCS#7, adding `n` times the byte `n`.
    """
    padding_length = expected_padding_length(text, block_size)
    return text + bytes([padding_length]) * padding_length

def encryption_oracle(text, key=None, mode=None, append=None, prepend=None):
    """
    Randomly appends and prepends data to text, then encrypt it with AES in
    either CBC or ECB mode (50%/50%). In case of CBC mode the IV is also random.
    """
    mode = mode or ['ecb', 'cbc'][random_bool()]
    key = key or random_bytes(16)
    prepend = prepend if prepend is not None else random_bytes(random_number(5, 11))
    append = append if append is not None else random_bytes(random_number(5, 11))
    plaintext = prepend + text + append
    if mode == 'cbc':
        iv = random_bytes(AES.BLOCK_SIZE)
        return aes_cbc_encrypt(key, plaintext, iv)
    else:
        return aes_ecb_encrypt(key, plaintext)

def detect_mode(encrypt):
    """
    Use the provided function to encrypt one specific plaintext (plus random
    data appended and prepended), then returns if the block cipher mode is ECB
    or CBC.
    """
    # By providing a message that spans (almost) three blocks we ensure that
    # at least two full blocks will contain the same plaintext, regardless of
    # how much data is before or after our message.
    data = (AES.BLOCK_SIZE * 3 - 1) * b'A'
    return 'ecb' if detect_aes_ecb(encrypt(data)) else 'cbc'

def detect_blocks(encrypt):
    """
    Given an encryption oracle, encrypts messages of differentes sizes to
    detect (block_size, n_blocks, plaintext_size).
    """
    minimum_size = len(encrypt(b''))
    for i in count(1):
        size = len(encrypt(b'A' * i))
        if size != minimum_size:
            block_size = size - minimum_size
            n_blocks = minimum_size / block_size
            assert int(n_blocks) == n_blocks
            n_blocks = int(n_blocks)
            return (block_size, n_blocks, n_blocks * block_size - i)

    raise ValueError('Could not detect block information.')

def get_block(data, block_number, block_size=AES.BLOCK_SIZE):
    """
    Divides the given data into blocks and returns the i-th.
    """
    return data[block_number*block_size:(block_number+1)*block_size]

def break_aes_ecb_oracle(encrypt, prefix_length=None):
    """
    Given an encryption oracle
        
        encrypt(input) = aes_ecb_encrypt(key, prefix + input + secret)

    using PKCS#7 padding, returns the value of `secret`.
    """
    # We expect block_size to be 16 (AES.BLOCK_SIZE), but just to be sure.
    block_size, n_blocks, plaintext_size  = detect_blocks(encrypt)

    if prefix_length is None:
        prefix_length = detect_prefix_length_aes_ecb_oracle(encrypt)

    plaintext_blocks = []

    prefix_padding = (-prefix_length) % AES.BLOCK_SIZE
    start_block = math.ceil((prefix_length + prefix_padding) / AES.BLOCK_SIZE)
    # Sort bytes by presence in ASCII alphabet, so we try more likely bytes
    # first.
    all_bytes = sorted(single_bytes, key=is_ascii_text, reverse=True)
    bait_text = b'B' * block_size
    for block_number in count(start_block):
        plaintext_so_far = b''
        for byte_number in range(block_size):
            bait = b'P' * prefix_padding + bait_text[byte_number + 1:]
            target_block = get_block(encrypt(bait), block_number, block_size)
            def victory(byte):
                injection = bait + plaintext_so_far + byte
                block = get_block(encrypt(injection), start_block, block_size)
                return block == target_block
            try:
                plaintext_so_far += next(filter(victory, all_bytes))
            except StopIteration:
                # This exception only happens if the Oracle is misbehaving by
                # not returning consistent results. The most likely reason is
                # that it's using PKCS#7, which changes the last bytes as
                # we slide through them.
                # We check this by making sure we are at the last block and we
                # we last saw a 0x01 byte (a one byte padding).
                assert plaintext_so_far[-1] == 1
                full_plaintext = b''.join(plaintext_blocks) + plaintext_so_far[:-1]
                assert len(full_plaintext) == plaintext_size - prefix_length
                return full_plaintext

        plaintext_blocks.append(plaintext_so_far)
        bait_text = plaintext_so_far

    return b''.join(plaintext_blocks)

def detect_prefix_length_aes_ecb_oracle(encrypt):
    """
    Given an encryption oracle
        
        encrypt(input) = aes_ecb_encrypt(key, prefix + input + suffix)

    returns the size of `prefix`.
    """
    marker = bytes(range(AES.BLOCK_SIZE)) * 2
    for i in range(AES.BLOCK_SIZE):
        blocks = divide(encrypt(b'A' * i + marker), AES.BLOCK_SIZE)
        for index in range(len(blocks)-1):
            if blocks[index] == blocks[index+1]:
                return index * AES.BLOCK_SIZE - i

    raise ValueError('Could not find prefix size.')

def replace_tail_aes_ecb_oracle(encrypt, tail, replacement, padding_character=b'A'):
    """
    Given an oracle

        encrypt(input) = aes_ecb_encrypt(key, prefix + input + suffix + tail)

    using PKCS#7 padding and with a known `tail` value (or just its length) and
    a desired `replacement`, returns a tuple (padding, ciphertext) such that

        ciphertext = aes_ecb_encrypt(key, prefix + padding + suffix + replacement)

    Assumes the existing prefix, suffix and tail don't generate duplicate ECB
    blocks.
    """
    if isinstance(tail, str):
        tail_length = len(tail)
    elif isinstance(tail, int):
        tail_length = tail

    block_size, n_blocks, plaintext_size = detect_blocks(encrypt)
    last_block_length = plaintext_size % block_size

    bait = padding_character * (block_size - last_block_length + tail_length)
    # This makes our target spill over to a block by itself, which we discard.
    good_blocks = divide(encrypt(bait), AES.BLOCK_SIZE)[:-1]

    fake_plaintext_block = pad_pkcs7(replacement)

    # Find the placement of our input by testing different left paddings and
    # seeing which one generates a ciphertext with repeated blocks, meaning
    # the input aligned with the start of a block.
    # TODO: more elegant solution that allows existing duplicated blocks.
    replications = 2
    for i in range(block_size):
        infected_ciphertext = encrypt(b'A' * i + replications * fake_plaintext_block)
        infected_blocks = divide(infected_ciphertext, block_size)
        fake_ciphertext_block, n = Counter(infected_blocks).most_common(1)[0]
        if n == replications:
            break

    ciphertext = b''.join(good_blocks) + fake_ciphertext_block
    return bait, ciphertext

def insert_aes_cbc_oracle(encrypt, prefix_length, data, remainig_char=b' '):
    """
    Given an encryption oracle
        
        encrypt(input) = aes_cbc_encrypt(key, prefix + escape(input) + suffix)

    and the length of the prefix, returns a ciphertext that when decrypted
    contains `data`. The ciphertext will contain two extra blocks, one of them
    containing garbage and the other the given data plus repetitions of
    `remaining char`.
    """
    n_blocks_prefix = math.ceil(prefix_length / AES.BLOCK_SIZE)
    padding = b'P' * ((AES.BLOCK_SIZE - prefix_length) % AES.BLOCK_SIZE)
    block_to_corrupt = b'A' * AES.BLOCK_SIZE
    injected_block = b'\x00' * AES.BLOCK_SIZE
    ciphertext_blocks = divide(encrypt(padding + block_to_corrupt + injected_block), AES.BLOCK_SIZE)
    corruption = data + remainig_char * (AES.BLOCK_SIZE - len(data))
    ciphertext_blocks[n_blocks_prefix] = xor(ciphertext_blocks[n_blocks_prefix], corruption)
    return b''.join(ciphertext_blocks)

def break_aes_cbc_padding_oracle(padding_oracle, ciphertext, unpad=True):
    """
    Given a padding oracle

        padding_oracle(ciphertext) = has_correct_padding(aes_cbc_decrypt(key, ciphertext))

    and a ciphertext, returns the corresponding plaintext.
    """
    *first_blocks, victim, last = divide(ciphertext, AES.BLOCK_SIZE)

    ciphertext_prefix = b''.join(first_blocks)

    bytes_found = []
    for byte_position in range(1, AES.BLOCK_SIZE+1):

        copy = list(victim)
        for i, byte in enumerate(bytes_found, 1):
            copy[i-byte_position] ^= byte ^ byte_position

        for xored in range(1, 0x100):
            copy[-byte_position] = victim[-byte_position] ^ xored
            if padding_oracle(ciphertext_prefix + bytes(copy) + last):
                byte_found = xored ^ byte_position
                bytes_found.insert(0, byte_found)
                break

        if len(bytes_found) < byte_position:
            bytes_found.insert(0, byte_position)

    if first_blocks:
        prefix = break_aes_cbc_padding_oracle(padding_oracle, ciphertext[:-AES.BLOCK_SIZE], unpad=False)
    else:
        prefix = b''

    plaintext = prefix + bytes(bytes_found)
    if unpad:
        return unpad_pkcs7(plaintext)
    else:
        return plaintext

def break_aes_cbc_iv_oracle(decrypt, ciphertext):
    """
    Given an AES CBC ciphertext with unknown IV, and an oracle that decrypts
    arbitrary messages, returns the IV.

    In some cases the oracle only reveals the plaintext if it fails some tests,
    like containing only ASCII characters. However since we will be passing a
    corrupted ciphertext, the chance of it containing only ASCII characters is
    tiny.
    """
    blocks = divide(ciphertext, AES.BLOCK_SIZE)
    blocks[2] = blocks[0]
    blocks[1] = b'\x00' * AES.BLOCK_SIZE
    plaintext_blocks = divide(decrypt(b''.join(blocks)), AES.BLOCK_SIZE)
    return xor(plaintext_blocks[0], plaintext_blocks[2])

def break_aes_ctr_repeated_nonce(ciphertexts, measure=english_score):
    """
    Given a list of ciphertexts that were encrypted with AES CTR mode with the
    same nonce, returns the guessed plaintexts. Accuracy increases with number
    of ciphertexts provided.
    """
    max_len = max(map(len, ciphertexts))

    transposed = [[c[i] for c in ciphertexts if len(c) > i] for i in range(max_len)]
    stream_guess = b''
    for cipher_letters in transposed:
        guesses = [(bytes([i]), bytes(c ^ i for c in cipher_letters)) for i in range(0x100)]
        key_byte, score = max(guesses, key=lambda p: english_score(p[1]))
        stream_guess += key_byte

    return [xor(stream_guess, ciphertext, truncate=True) for ciphertext in ciphertexts]

def break_twister_time(first_output, max_time=None):
    """
    Given the first output of a MersenneTwister seeded with a timestamp,
    brute-forces and returns the seed.
    """
    max_time = max_time or int(time.time()) + 100
    if isinstance(first_output, int):
        test = lambda seed: Twister(seed).next() == first_output
    else:
        blank = b'\x00' * len(first_output)
        test = lambda seed: twister_encrypt(seed, blank) == first_output
    return next(seed for seed in range(max_time, 0, -1) if test(seed))

def untemper_twister(y):
    """
    Given an output from a MersenneTwister, returns the corresponding
    internal state.
    """
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18

    y ^= y >> l
    y ^= ((y ^ c) << t) & c

    copy = y
    for i in range(1, 5):
        y_ = y & ~(d << (i*s))
        y = copy ^ ((y_ << s) & b)

    copy = y
    y ^= y >> u
    return copy ^ (y >> u)

def break_twister(ciphertext, known_substring, max_key=2**32):
    """
    Given a ciphertext encrypted by a MersenneTwister "encryption" stream and
    a known substring, finds the generator seed.
    """
    for key in range(max_key):
        if known_substring in twister_decrypt(key, ciphertext):
            return key
    raise ValueError('Key not found.')

def break_stream_edit_oracle(edit_oracle, ciphertext=None):
    """
    Given an oracle that allows making changes to the plaintext (without
    revealing it) and internally uses a stream cipher, returns the plaintext.
    """
    ciphertext = ciphertext or edit_oracle(0, b'')
    stream = edit_oracle(0, len(ciphertext) * b'\x00')
    return xor(ciphertext, stream)

def insert_aes_ctr_oracle(encrypt, prefix_length, data, padding=b'A'):
    """
    Given an encryption oracle

        encrypt(text) = aes_ctr_encrypt(key, prefix + escape(text) + suffix, nonce)

    and the length of the prefix, returns a ciphertext that contains `data`.
    """
    zeroed_ciphertext_bytes = list(encrypt(padding * len(data)))
    for i, data_byte in enumerate(data, prefix_length):
        zeroed_ciphertext_bytes[i] ^= ord(padding) ^ data_byte
    return bytes(zeroed_ciphertext_bytes)
    
def extend_sha1(hashed, extension, starting_length=0):
    return extend_hash(sha1, 'big', hashed, extension, starting_length)

def extend_hash(hash_fn, endianness, hashed, extension, starting_length=0):
    """
    Given

        hashed = hash_fn(message)

    for an unknown message, generates candidates of the form (tail, new_hash)
    for each possible message length. The correct will one will have the
    property:

        tail.endswith(extension)
        hash_fn(message + extension) == new_hash 

    for an unknown message.
    """
    for existing_length in count(starting_length):
        padding = b'\x80' + b'\x00' * ((55 - existing_length) % 64) + (existing_length * 8).to_bytes(8, byteorder=endianness)
        tail = padding + extension
        new_hash = hash_fn(extension, message_length=existing_length + len(tail), state=hashed)
        yield (tail, new_hash)

def print_word(i):
    print('{0:032b}'.format(i))

def random_iv():
    return random_bytes(AES.BLOCK_SIZE)

def random_aes_key():
    return random_bytes(16)

def random_ctr_nonce():
    return random_bytes(8)

if __name__ == '__main__':
    import os
    for name in sorted(os.listdir('.')):
        if name.endswith('.py') and name[0].isdigit():
            print('Testing {}...'.format(name))
            os.system('~/Python-3.5.2/python "{}"'.format(name))
