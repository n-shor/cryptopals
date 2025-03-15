from lib1 import *

# Challenge 9

def pkcs7_padding(block: bytes, length: int) -> bytes:
    padding = length - len(block)
    if padding < 0:
        raise ValueError("Block length must not be larger than padding size")
    return block + padding * padding.to_bytes()


# Challenge 10

def pkcs7_unpadding(block: bytes) -> bytes:
    padding = block[-1]
    if padding > len(block):
        return block

    for i in range(1, padding + 1):
        if block[-i] != padding:
            return block

    return block[:-padding]


def cbc_mode_decryption(iv: bytes, key: bytes, ciphertext: bytes) -> bytes:
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    prev_ciphertext = iv
    decrypted = b""

    for block in blocks:
        dec_block = decrypt_aes_128_ecb(block, key)
        decrypted += bytes_xor(dec_block, prev_ciphertext)
        prev_ciphertext = block

    pkcs7_unpadding(decrypted) # remove the padding from the last block (if there is padding)

    return decrypted
