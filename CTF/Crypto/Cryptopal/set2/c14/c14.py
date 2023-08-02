#the attack under random_sized key and unknown prefix + message + plaintext 
# attack under the mode AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key) and decrypt target-bytes
#find the block_size prefix_size and decrypt the prefix
# the only thing I know is the attacker-controlled-bytes
#first we detect the prefix length 
#detect the block_size like the c12
#send one byte to the message and find the first-different ciphertext block
#extend and repeat the byte of the message until this block of cipher is equal
#find the message length of this time,and the prefix len should be eq_blocks * block_size + 
#block_size - message_len
#then we use the one-byte enumration attack to decrypt the target-byte
from itertools import count
from base64 import b64decode
from typing import Callable
from os.path import commonprefix
from os import urandom
from Crypto.Cipher import AES
BLOCK_SIZE = AES.block_size

KEY_SIZE = 32

ECBOracleType = Callable[[bytes], bytes]
prefix_size = 58
def bytes_to_chunks(b: bytes, chunk_size: int) -> list[bytes]:
    chunks = [b[ind: ind + chunk_size] for ind in range(0, len(b), chunk_size)]
    return chunks

def pkcs7(b: bytes, block_size:int = 16) -> bytes:
    if(block_size == 16):
        pad_len = block_size - (len(b) % 16)
    else: 
        pad_len = block_size - len(b)%block_size
    return b + bytes([pad_len] * pad_len)


def strip_pkcs7(b: bytes) -> bytes:

    n = b[-1]

    return b[:-n]
    
def find_block_size_and_postfix_length(enc:  ECBOracleType) -> tuple[int, int]:
    block_size = None
    postfix_len = None
    l = len(enc(b'A'))
    for i in count(2):
        l2 = len(enc(b'A' * i))
        if(l2 > l):
            block_size = l2 - l
            postfix_len = l - i
            break
    return block_size , postfix_len

def detect_ecb(oracle):
    ct = oracle(bytes(32))
    if(ct[: 16] == ct[16: 32]):
        return True

def make_oracle() -> ECBOracleType:
    f = open('c12.txt')
    target_bytes = f.read().encode()
    _key = urandom(KEY_SIZE)
    prefix = urandom(58)
    def oracle(message: bytes) -> bytes:
        dec = AES.new(_key, AES.MODE_ECB)
        ret = dec.encrypt(pkcs7(prefix + message + target_bytes))
        return ret
    return oracle

def detect_prefixlen(oracle: ECBOracleType, block_size):
    buf1 = oracle(b'\x01')
    buf2 = oracle(b'\x02')
    s = len(commonprefix((buf1, buf2))) // block_size
    index = (s + 1) * block_size
    for i in range(1, 17):
        buf3 = oracle(b'\x01' * i)
        buf4 = oracle(b'\x01'* (i + 1))
        if(buf3[:index] == buf4[:index]):
        	 return index - i 
def guess_byte(prefix: bytes, target: bytes,  oracle: ECBOracleType) -> bytes:
    for b in range(256):
        b = bytes([b])
        msg = prefix + b
        first_block = oracle(msg)[:16]
        if(first_block == target):
            return b

#one byte attack upon the AES in ECB MODE
def one_byte_attack(oracle: ECBOracleType, postfix_len: int) ->  bytes: 
    ciphertexts = [bytes_to_chunks(oracle(bytes(15 - n)), BLOCK_SIZE) for n in range(16)]
    transposed = [block for blocks in zip(*ciphertexts) for block in blocks]
    blocks_to_attack = transposed[:postfix_len]
    pt = bytes(15)
    for block in blocks_to_attack:
        pt += guess_byte(pt[-15: ], block, oracle)
    pt = pt[15:]
    return pt

def wrap_oracle(oracle: ECBOracleType, block_size: int, prefix_len: int) -> ECBOracleType:
    pad_len = block_size - (prefix_len % block_size)
    index = pad_len + prefix_len
    def wrapped_oracle(message: bytes) -> bytes:
        return oracle(bytes(pad_len) + message)[index: ]
    return wrapped_oracle

oracle = make_oracle()
block_size ,affix_len = find_block_size_and_postfix_length(oracle)
prefix_len = detect_prefixlen(oracle, block_size)
oracle = wrap_oracle(oracle, block_size, prefix_len)
postfix_len = affix_len - prefix_len
#print(prefix_len)
#print(postfix_len)
#print(block_size)
print(one_byte_attack(oracle, postfix_len))
