def hex_to_base_64(hex_str: str):
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
    hex_bytes = ""

    for char in hex_str:
        hex_bytes += "{0:b}".format(hex_map[char]).rjust(4, '0')

    for i in range(0, len(hex_bytes), 6):
        j = 0
        char_byte = 0
        for j in range(6):
            char_byte *= 2
            if i + j < len(hex_bytes):
                char_byte += int(hex_bytes[i + j])

        base_64_str += index_table[char_byte]

    return base_64_str + '=' * ((-1 * len(hex_str) * 4) % 3)
