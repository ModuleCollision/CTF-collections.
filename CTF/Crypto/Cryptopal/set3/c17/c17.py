from os import urandom
from Crypto.Cipher import AES
from base64 import b64decode
import random

key = urandom(16)

messages = []

f = open('plain.txt')

lines = f.readlines()

BLOCK_SIZE = AES.block_size



for l in lines:
    messages.append(l)

for i in range(len(lines)):
    lines[i] = lines[i].strip('\n').encode()

def strip_pkcs7(b: bytes) -> bytes:
    n = b[-1]
    return b[:-n]

def pkcs7(b: bytes, block_size:int = 16) -> bytes:
    if(block_size == 16):
        pad_len = block_size - (len(b) % 16)
    else:
        pad_len = block_size - len(b) % block_size
    return b + bytes([pad_len] * pad_len)
    

def get_encrypted_message() -> bytes:
    message = b64decode(random.choice(messages))
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(pkcs7(message, BLOCK_SIZE))

def bytes_xor(a:bytes, b: bytes) -> bytes:
    return bytes(bytes1 ^ bytes2 for bytes1, bytes2 in zip(a, b))
    
def check_padding(message: bytes) -> bool:
    if(len(message) % 16 != 0):
        return False
    iv = message[:16]
    ct = message[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    d  = cipher.decrypt(ct)
    l = len(d)
    pad = d[-1]
    for i in range(l - 1,l - 1 - pad, -1):
        if(d[i] != pad):
            return False
    return True

def recover_plaintext(message: bytes) -> bytes:
    ct_blocks = [message[i: i + 16] for i in range(16, len(message), 16)]
    #message is the target bytes we want to generate to pass the server check
    pt = b''
    prev_block = message[: 16]
    for block in ct_blocks:
        iv = urandom(16)
        keystream = b''
        for i in range(1, 17):
            for b in range(256):
                iv = iv[:16 - i] + bytes([b]) + bytes_xor(bytes([i]) * len(keystream), keystream)
                if(check_padding(iv + block)):
                    keystream = bytes([b ^ i]) + keystream
                    break               
        
        pt +=  bytes_xor(keystream, prev_block)
        prev_block = block
    return pt

message = get_encrypted_message()

pt = recover_plaintext(message)

print(pt)
