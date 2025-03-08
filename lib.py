import math
import subprocess

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def hex_to_bytes(hex_str: str) -> bytes:
    hex_str = hex_str.lower()

    hex_map = {c: i for (i, c) in enumerate("0123456789abcdef")}

    byte_list = [
        (hex_map[hex_str[i]] << 4)
        + hex_map[hex_str[i + 1]]
        for i in range(0, len(hex_str), 2)
    ]

    return bytes(byte_list)


def bytes_to_hex(byte_data: bytes) -> str:
    hex_chars = "0123456789abcdef"

    return "".join(hex_chars[b >> 4] + hex_chars[b & 0x0F] for b in byte_data)


def bytes_to_binary(data: bytes) -> str:
    return "".join(format(i, "08b") for i in data)


def str_to_binary(data: str) -> str:
    return "".join(format(ord(i), "08b") for i in data)


def hex_to_base_64(hex_str: str) -> str:
    index_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    byte_data  = hex_to_bytes(hex_str)
    binary_str = bytes_to_binary(byte_data)

    base64_str = ""
    for i in range(0, len(binary_str), 6):
        segment = binary_str[i:i+6].ljust(6, "0")
        base64_str += index_table[int(segment, 2)]

    return base64_str + "=" * ((-1 * len(base64_str)) % 4)


def base64_to_bytes(base64_string: str) -> bytes:
    index_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    base64_string = base64_string.rstrip("=")

    result = []
    accumulated_bits = 0
    bits_count = 0

    for char in base64_string:
        val = index_table.index(char)
        accumulated_bits = (accumulated_bits << 6) | val
        bits_count += 6

        if bits_count >= 8:
            bits_count -= 8
            result.append((accumulated_bits >> bits_count) & 0xFF)
            accumulated_bits &= (1 << bits_count) - 1

    return bytes(result)


def byte_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes((b1[i % len(b1)] ^ b2[i % len(b2)]) for i in range(max(len(b1), len(b2))))


def hex_xor(hex1: str, hex2: str) -> str:
    bytes1, bytes2 = hex_to_bytes(hex1), hex_to_bytes(hex2)
    return bytes_to_hex(byte_xor(bytes1, bytes2))


def is_valid_ascii(char: int) -> bool:
    return (0x20 <= char <= 0x7E) or char in (0x0A, 0x0D)

def calculate_frequency_score(text: bytes) -> float:
    expected = {
        'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
        'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
        'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
        'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
        'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
        'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
        'Y': 0.01974, 'Z': 0.00074,
        ' ': 0.13000,
        '.': 0.065, ',': 0.061, "'": 0.024, '"': 0.024,
        '!': 0.010, '?': 0.010, ';': 0.010, ':': 0.010, '-': 0.020
    }

    valid_chars = set(expected.keys())
    text_upper = text.upper()
    text_length = len(text)
    chi_squared = 0.0

    for char in valid_chars:
        count = text_upper.count(char.encode())
        observed = count / text_length
        expected_freq = expected[char]

        chi_squared += ((observed - expected_freq) ** 2) / expected_freq

    for byte in text:
        if not is_valid_ascii(byte):
            chi_squared += 5

    return chi_squared


def single_char_xor_bruteforce(encoded_hex: str) -> tuple[bytes, int]:
    encoded_bytes = hex_to_bytes(encoded_hex)
    best_score = math.inf # lower is better
    best_result = b"0"
    best_xor_byte = 0

    for candidate in range(128):
        result = bytes(byte ^ candidate for byte in encoded_bytes)

        curr_score = calculate_frequency_score(result)
        if best_score > curr_score:
            best_xor_byte = candidate
            best_result = result
            best_score = curr_score

    return best_result, best_xor_byte


def detect_single_char_xor(hex_list: list[str]) -> tuple[str, bytes]:
    best_score = math.inf
    best_res, best_hex = "", ""

    for hex_str in hex_list:
        curr_res = single_char_xor_bruteforce(hex_str)[0]
        curr_score = calculate_frequency_score(curr_res)

        if curr_score < best_score:
            best_hex = hex_str
            best_res = curr_res
            best_score = curr_score

    return best_hex, best_res


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    res = []

    for i in range(len(data)):
        res.append(data[i] ^ key[i % len(key)])

    return bytes(res)


def hamming_distance(data1: bytes, data2: bytes) -> int:
    bits1, bits2 = map(bytes_to_binary, (data1, data2))
    return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))


def guess_repeating_xor_key_length(data: bytes) -> int:
    """Assumes data is at least 160 bytes long. This function is NOT safe for general use.
    Also, this function may return multiples of the correct key length - this is OK because a repeating key with k times
    the size would be the original key repeated k times, which, after decrypting, would lead to the same result."""
    best_guess = 0
    smallest_distance = math.inf

    for len_guess in range(2, 41):
        block_num = len(data) // len_guess

        blocks = [data[i * len_guess:(i + 1) * len_guess] for i in range(block_num)]
        distances = []

        for i in range(0, block_num - 1, 2):
            if i + 1 < block_num:
                distance = hamming_distance(blocks[i], blocks[i + 1]) / len_guess
                distances.append(distance)

        avg_distance = sum(distances) / len(distances)
        if avg_distance < smallest_distance:
            smallest_distance = avg_distance
            best_guess = len_guess

    return best_guess


def break_repeating_key_xor() -> str:
    base64_data = subprocess.check_output(["curl", "--silent", "https://cryptopals.com/static/challenge-data/6.txt"]).decode("ascii").replace("\n", "")

    bytes_data = base64_to_bytes(base64_data)
    key_len = guess_repeating_xor_key_length(bytes_data)

    full_block_num = len(bytes_data) // key_len

    blocks = [bytes_data[key_len * i:key_len * (i + 1)] for i in range(full_block_num)]

    # Add non-full block if necessary
    if full_block_num != len(bytes_data) / key_len:
        blocks.append(bytes_data[key_len * full_block_num:])

    transposed_blocks = []
    for i in range(len(blocks[0])):
        transposed_blocks.append([block[i] for block in blocks if i < len(block)]) # Add the data only if the block is long enough, necessary for last block

    key = []
    for transposed_block in transposed_blocks:
        block_bytes = bytes(transposed_block)
        hex_block = bytes_to_hex(block_bytes)
        key_byte = single_char_xor_bruteforce(hex_block)[1]
        key.append(key_byte)

    decrypted_bytes = repeating_key_xor(bytes_data, bytes(key)) # xorring a xorred value will result in the original value
    return decrypted_bytes.decode()


def decrypt_aes_128_ecb(data: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def detect_aes_128_ecb(data_list: list[bytes]) -> bytes:
    """ I don't know if there's a better solution, but it's extremely unlikely to have duplicate blocks in short ciphertexts,
    so if duplicate blocks exist in the ciphertext, it's likely been encrypted with ECB"""
    for data in data_list:
        if len(data) % 16 != 0:
            continue

        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        if len(set(blocks)) != len(blocks):
            return data

    return b"Failed to detect ECB"
