import math

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

    return base64_str + '=' * ((-1 * len(byte_data)) % 3)


def byte_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes((b1[i % len(b1)] ^ b2[i % len(b2)]) for i in range(max(len(b1), len(b2))))


def hex_xor(hex1: str, hex2: str) -> str:
    bytes1, bytes2 = hex_to_bytes(hex1), hex_to_bytes(hex2)
    return bytes_to_hex(byte_xor(bytes1, bytes2))


def is_valid_ascii(char: int) -> bool:
    return 0x20 <= char <= 0x7E


def calculate_frequency_score(text: bytes):
    score = 0

    for char in text:
        if not is_valid_ascii(char):
            score += 0.03

    letter_frequencies = {
        'A': 0.082,
        'B': 0.015,
        'C': 0.028,
        'D': 0.043,
        'E': 0.127,
        'F': 0.022,
        'G': 0.020,
        'H': 0.061,
        'I': 0.070,
        'J': 0.0015,
        'K': 0.0077,
        'L': 0.040,
        'M': 0.024,
        'N': 0.067,
        'O': 0.075,
        'P': 0.019,
        'Q': 0.00095,
        'R': 0.060,
        'S': 0.063,
        'T': 0.091,
        'U': 0.028,
        'V': 0.0098,
        'W': 0.024,
        'X': 0.0015,
        'Y': 0.020,
        'Z': 0.00074
    }

    text = text.upper()

    # ignore non-letter values
    for letter, frequency in zip(letter_frequencies.keys(), letter_frequencies.values()):
        if 0x41 <= ord(letter) <= 0x5A:
            score += abs(letter_frequencies[letter] - (text.count(letter.encode()) / len(text)))

    return score


def single_char_xor_bruteforce(encoded_hex: str) -> bytes:
    encoded_bytes = hex_to_bytes(encoded_hex)
    best_score = math.inf # lower is better
    best_result = b'0'

    for curr_xor_byte in range(0, 127):
        result = 0

        for byte in encoded_bytes:
            result <<= 8
            result += curr_xor_byte ^ byte

        result = result.to_bytes((result.bit_length() + 7) // 8 or 1, byteorder="big")

        curr_score = calculate_frequency_score(result)
        if best_score > curr_score:
            best_result = result
            best_score = curr_score

    return best_result


def detect_single_char_xor(hex_list: list[str]) -> tuple[str, bytes]:
    best_score = math.inf
    best_res, best_hex = '', ''

    for hex_str in hex_list:
        curr_res = single_char_xor_bruteforce(hex_str)
        curr_score = calculate_frequency_score(curr_res)

        if curr_score < best_score:
            best_hex = hex_str
            best_res = curr_res
            best_score = curr_score

    return best_hex, best_res


def repeating_key_xor(data: str, key: str) -> str:
    byte_data = data.encode()
    byte_key = key.encode()
    byte_res = []

    for i in range(len(byte_data)):
        byte_res.append(byte_data[i] ^ byte_key[i % len(byte_key)])

    return bytes_to_hex(bytes(byte_res))


def hamming_distance(data1: str, data2: str) -> int:
    bits1, bits2 = map(str_to_binary, (data1, data2))
    return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))
