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


def hex_to_base_64(hex_str: str) -> str:
    index_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    byte_data  = hex_to_bytes(hex_str)
    binary_str = "".join(f"{b:08b}" for b in byte_data)

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
