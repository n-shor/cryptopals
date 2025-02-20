def hex_to_byte_str(hex_str: str):
    hex_map = {
        '0': 0,
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        '6': 6,
        '7': 7,
        '8': 8,
        '9': 9,
        'A': 10,
        'a': 10,
        'B': 11,
        'b': 11,
        'C': 12,
        'c': 12,
        'D': 13,
        'd': 13,
        'E': 14,
        'e': 14,
        'F': 15,
        'f': 15
    }

    hex_bytes = ""

    for char in hex_str:
        hex_bytes += "{0:b}".format(hex_map[char]).rjust(4, '0')

    return hex_bytes


def byte_str_to_hex(binary_str: str) -> str:
    if len(binary_str) % 4 != 0:
        raise ValueError("Binary string length must be multiple of 4")

    bin_map = {
        '0000': '0',
        '0001': '1',
        '0010': '2',
        '0011': '3',
        '0100': '4',
        '0101': '5',
        '0110': '6',
        '0111': '7',
        '1000': '8',
        '1001': '9',
        '1010': 'a',
        '1011': 'b',
        '1100': 'c',
        '1101': 'd',
        '1110': 'e',
        '1111': 'f'
    }

    hex_str = ""
    # Process binary string in chunks of 4 bits
    for i in range(0, len(binary_str), 4):
        chunk = binary_str[i:i + 4]
        hex_str += bin_map[chunk]

    return hex_str

def hex_to_base_64(hex_str: str):
    index_table = ['A', 'B', 'C', 'D',
                'E', 'F', 'G', 'H',
                'I', 'J', 'K', 'L',
                'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T',
                'U', 'V', 'W', 'X',
                'Y', 'Z', 'a', 'b',
                'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j',
                'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r',
                's', 't', 'u', 'v',
                'w', 'x', 'y', 'z',
                '0', '1', '2', '3',
                '4', '5', '6', '7',
                '8', '9', '+', '/']

    base_64_str = ""
    hex_bytes = hex_to_byte_str(hex_str)

    for i in range(0, len(hex_bytes), 6):
        j = 0
        char_byte = 0
        for j in range(6):
            char_byte *= 2
            if i + j < len(hex_bytes):
                char_byte += int(hex_bytes[i + j])

        base_64_str += index_table[char_byte]

    return base_64_str + '=' * ((-1 * len(hex_str) * 4) % 3)

def hex_xor(hex_first: str, hex_second: str):
    if len(hex_first) != len(hex_second):
        raise "Non-equal hex sizes for XOR!"

    bytes_first, bytes_second = hex_to_byte_str(hex_first), hex_to_byte_str(hex_second)
    res_bytes = ''

    for i in range(len(bytes_first)):
        if bytes_first[i] == bytes_second[i]:
            res_bytes += '0'
        else:
            res_bytes += '1'

    return byte_str_to_hex(res_bytes)
