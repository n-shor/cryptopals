from lib1 import *

# Challenge 9

def pkcs7_padding(block: bytes, length: int):
    padding = length - len(block)
    print(padding)
    if padding < 0:
        raise ValueError("Block length must not be larger than padding size")
    return block + padding * padding.to_bytes()
