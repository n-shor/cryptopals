from lib1 import *
import os
import random
from collections.abc import Callable

def split_to_blocks(data: bytes, size: int=16) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


# Challenge 9

def pkcs7_padding(block: bytes, length: int=16) -> bytes:
    padding = (-len(block)) % length

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


def decrypt_aes_128_cbc(iv: bytes, ciphertext: bytes, key: bytes,) -> bytes:
    blocks = split_to_blocks(ciphertext)
    prev_ciphertext = iv
    decrypted = b""

    for block in blocks:
        dec_block = decrypt_aes_128_ecb(block, key)
        decrypted += bytes_xor(dec_block, prev_ciphertext)
        prev_ciphertext = block

    decrypted = pkcs7_unpadding(decrypted) # remove the padding from the last block (if there is padding)

    return decrypted


# Challenge 11

def encrypt_aes_128_ecb(data: bytes, key: bytes) -> bytes:
    padded_data = pkcs7_padding(data)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def encrypt_aes_128_cbc(iv: bytes, data: bytes, key: bytes) -> bytes:
    data = pkcs7_padding(data)  # add the padding to the last block (if needed)

    blocks = split_to_blocks(data)
    prev_ciphertext = iv
    encrypted = b""

    for block in blocks:
        enc_block = encrypt_aes_128_ecb(bytes_xor(block, prev_ciphertext), key)
        encrypted += enc_block
        prev_ciphertext = enc_block

    return encrypted


def decrypt_aes_128_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Replacement for the old function from challenge 7"""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded = pkcs7_unpadding(decrypted_data)
    return unpadded


def generate_random_bytes(size: int=16) -> bytes:
    return os.urandom(size)


def encryption_oracle(data: bytes, use_ecb : int = random.randint(0, 1), key : bytes = generate_random_bytes(), no_padding : bool = False) -> bytes:
    if not no_padding:
        start_padding = os.urandom(random.randint(5, 10))
        end_padding = os.urandom(random.randint(5, 10))
        data = start_padding + data + end_padding
    

    # 1 is ECB, 0 is CBC
    if use_ecb:
        return encrypt_aes_128_ecb(data, key)
    else:
        return encrypt_aes_128_cbc(generate_random_bytes(), data, key)


def is_ecb(data: bytes, use_ecb : int = random.randint(0, 1)) -> bool:
    for _ in range(10):
        encrypted = encryption_oracle(b"a" * 16 * 3 + data, use_ecb=use_ecb) # need at least 3 blocks to ensure at least # 2 blocks of only b'a' exist after padding
        blocks = split_to_blocks(encrypted)

        if len(set(blocks)) != len(blocks):
            return True
        else:
            return False


# Challenge 12

def find_oracle_block_size(oracle : Callable) -> int:
    base = oracle(b"a" * 1, no_padding = True) # No padding cuz idk how to do it otherwise
    enc = base
    
    i = 2
    while (len(base) == len(enc)):
        enc = oracle(b"a" * i) # No padding cuz idk how to do it otherwise
        i += 1

    return len(enc) - len(base)


key = generate_random_bytes()

def ecb_pad_encrypt(data: bytes, key: bytes) -> bytes:
    padding = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    return encrypt_aes_128_ecb(data + base64_to_bytes(padding), key)


def ecb_pad_decrypt(key: bytes) -> bytes:
    "This only takes a key because ecb_pad_encrypt needs to take a key, we could make that function not take a key and have it as a hardcoded variable there"
    "and in that case we would not need to have this function take a key"
    encrypted = ecb_pad_encrypt(b"A" * 64, key)
    block_size = find_oracle_block_size(encryption_oracle)
    block_count = len(ecb_pad_encrypt(b"", key)) // block_size + 1
    using_ecb = is_ecb(encrypted)

    decrypted = b""
    for block_index in range(block_count):
        for i in range(block_size):
            baseline = ecb_pad_encrypt(b"A" * (block_size - 1 - i), key)[block_index * block_size:(block_index + 1) * block_size]
            for c in range(256):
                cmp = ecb_pad_encrypt(b"A" * (block_size - 1 - i) + decrypted + c.to_bytes(), key)[block_index * block_size:(block_index + 1) * block_size]
                if cmp == baseline:
                    decrypted += c.to_bytes()
                    break
                
    return pkcs7_unpadding(decrypted)
    