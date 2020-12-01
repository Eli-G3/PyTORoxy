# public variable constants
CMD_ENUM = {
    'PADDING': 0,
    'CREATE': 1,
    'CREATED': 2,
    'RELAY': 3,
    'DESTROY': 4,
    'CREATE_FAST': 5,
    'CREATED_FAST': 6,
    'NETINFO': 8,
    'RELAY_EARLY': 9,
    'CREATE2': 10,
    'CREATED2': 11,
    'PADDING_NEGOTIATE': 12,
    'VERSIONS': 7,
    'VPADDING': 128,
    'CERTS': 129,
    'AUTH_CHALLENGE': 130,
    'AUTHENTICATE': 131,
    'AUTHORIZE': 132
}


FORBIDDEN_LIST = [b'grammarly',b'windows', b'activity', b'gstatic']


PAYLOAD_LEN = 509
CMD_LEN = 1
LENGTH_LEN = 2
VERSION_LEN = 2
TIMESTAMP_LEN = 4
RELAY_PAYLOAD_HEADER_LEN = 11
DIGEST_LEN = 4
RECOGNIZED_LEN = 2
PACKED_IP_ADDR_LEN = 4
TTL_LEN = 4
DESCRIPTORS_IN_FILE = 7


def CIRCID_LEN(version: int):
    if 0 < version <= 3:
        return 2
    elif version >= 4:
        return 4


def CELL_LEN(version: int):
    return CIRCID_LEN(version) + CMD_LEN + PAYLOAD_LEN


