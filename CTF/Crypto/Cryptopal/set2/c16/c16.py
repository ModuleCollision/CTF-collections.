#The one-bit-flip attack towards the AES in CBC mode
#
from Crypto.Cipher import AES
from os import urandom

def bytes_xor(a:bytes, b: bytes) -> bytes:
    return bytes(bytes1 ^ bytes2 for bytes1, bytes2 in zip(a, b))

BLOCK_SIZE = AES.block_size

def pkcs7(b: bytes, block_size:int = 16) -> bytes:
    if(block_size == 16):
        pad_len = block_size - (len(b) % 16)
    else:
        pad_len = block_size - len(b)%block_size
    return b + bytes([pad_len] * pad_len)


def strip_pkcs7(b: bytes) -> bytes:
    n = b[-1]
    return b[:-n]
KEY_SIZE = 32
_key = urandom(KEY_SIZE)
iv = urandom(BLOCK_SIZE)

def wrap_userdata(data: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    data = data.replace(b';', b'%3B')
    data = data.replace(b'=', b'%3D')
    wrapped = prefix + data + suffix
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7(data))

def check_for_admin(data: bytes) -> bool:
    cipher = AES.new(_key,AES.MODE_CBC, iv)
    plaintext = strip_pkcs7(cipher.decrypt(data))
    return b';admin=true;' in plaintext

def make_admin() -> bytes:
    a_block = b'A' * BLOCK_SIZE
    ct = wrap_userdata(a_block * 2)
    flipper = bytes_xor(a_block, b';admin=true;'.rjust(BLOCK_SIZE, b'A'))
    padded = flipper.rjust(BLOCK_SIZE * 3, b'\x00').ljust(len(ct), b'\x00')
    new_ct = bytes_xor(ct, padded)
    return new_ct

forged_ct = make_admin()
print("Admin check:{}".format(check_for_admin(forged_ct)))
