from pwn import *
from Crypto.Cipher import AES
def pkcs7(b: bytes, block_size:int = 16) -> bytes:
    if(block_size == 16):
        pad_len = block_size - (len(b) % 16)
    else: 
        pad_len = block_size - len(b)%block_size
    return b + bytes([pad_len] * pad_len)


def strip_pkcs7(b: bytes) -> bytes:
    n = b[-1]
    return b[:-n]


pad = b'ICE ICE BABY\x04\x04\x04\x04'

pad = b"ICE ICE BABY\x05\x05\x05\x05"
if(strip_pkcs7(pad) != b'ICE ICE BABY'):

    raise Exception('Oh no!')



