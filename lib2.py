from lib1 import *
import os
import random

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


def encryption_oracle(data: bytes) -> bytes:
    start_padding = os.urandom(random.randint(5, 10))
    end_padding = os.urandom(random.randint(5, 10))
    key = generate_random_bytes()
    padded_data = start_padding + data + end_padding

    # 0 is ECB, 1 is CBC
    if random.randint(0, 1) == 1:
        return encrypt_aes_128_ecb(padded_data, key)
    else:
        return encrypt_aes_128_cbc(generate_random_bytes(), padded_data, key)


def detect_ecb_or_cbc():
    for _ in range(10):
        encrypted = encryption_oracle(b"a" * 16 * 3) # need at least 3 blocks to ensure at least # 2 blocks of only b'a' exist after padding
        blocks = split_to_blocks(encrypted)

        if len(set(blocks)) != len(blocks):
            print("Detected ECB")
        else:
            print("Detected CBC")

