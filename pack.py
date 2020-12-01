import struct
import public_constants
import re
import socket
from crypto.crypto_constants import CryptoConstants
from crypto import core_crypto

PACK_FMT = {
    1: '!B',
    2: '!H',
    4: '!I',
    8: '!Q',
}

PARSE_FMT = {
    's': 1,
    'B': 1,
    'H': 2,
    'I': 4,
    'Q': 8
}

PACK_CMD_ENUM = {
    0: 'PADDING',
    1: 'CREATE',
    2: 'CREATED',
    3: 'RELAY',
    4: 'DESTROY',
    5: 'CREATE_FAST',
    6: 'CREATED_FAST',
    8: 'NETINFO',
    9: 'RELAY_EARLY',
    10: 'CREATE2',
    11: 'CREATED2',
    12: 'PADDING_NEGOTIATE',
    7: 'VERSIONS',
    128: 'VPADDING',
    129: 'CERTS',
    130: 'AUTH_CHALLENGE',
    131: 'AUTHENTICATE',
    132: 'AUTHORIZE'
}

RELAY_CMD_ENUM = {
    'RELAY_BEGIN': 1,
    'RELAY_DATA': 2,
    'RELAY_END': 3,
    'RELAY_CONNECTED': 4,
    'RELAY_SENDME': 5,
    'RELAY_EXTEND': 6,
    'RELAY_EXTENDED': 7,
    'RELAY_TRUNCATE': 8,
    'RELAY_TRUNCATED': 9,
    'RELAY_DROP': 10,
    'RELAY_RESOLVE': 11,
    'RELAY_RESOLVED': 12,
    'RELAY_BEGIN_DIR': 13,
    'RELAY_EXTEND2': 14,
    'RELAY_EXTENDED2': 15
}

RELAY_END_REASONS = {

    1: 'REASON_MISC: (catch-all for unlisted reasons)',
    2: 'REASON_RESOLVEFAILED: (couldnt look up hostname)',
    3: 'REASON_CONNECTREFUSED: (remote host refused connection)',
    4: 'REASON_EXITPOLICY: (OR refuses to connect to host or port)',
    5: 'REASON_DESTROY: (Circuit is being destroyed)',
    6: 'REASON_DONE: (Anonymized TCP connection was closed)',
    7: 'REASON_TIMEOUT: (Connection timed out, or OR timed out while connecting)',
    8: 'REASON_NOROUTE: (Routing error while attempting to contact destination)',
    9: 'REASON_HIBERNATING: (OR is temporarily hibernating)',
    10: 'REASON_INTERNAL:(Internal error at the OR)',
    11: 'REASON_RESOURCELIMIT: (OR has no resources to fulfill request)',
    12: 'REASON_CONNRESET: (Connection was unexpectedly reset)',
    13: 'REASON_TORPROTOCOL: (Sent when closing connection because of Tor protocol violations.)',
    14: 'REASON_NOTDIRECTORY   (Client sent RELAY_BEGIN_DIR to a non-directory relay.)'
}

RELAY_DIGEST_POS = 5
RELAY_RECOGNIZED_POS = 1
RELAY_END_REASON_LEN = 1
RELAY_SENDME_HEADER_LEN = 3


def get_pack_fmt(bytes_len):
    """
    Return the struct string format based on the length with a dict lookup
    :param bytes_len: given length in bytes
    :return: the string pack format for the struct module
    """
    return PACK_FMT[bytes_len]


def pack_value(value_len: int, value):
    """
    Pack a certain value into bytes
    :param value_len: the length of the value
    :param value: the value itself
    :return: a byte array of the value
    """
    fmt = get_pack_fmt(value_len)
    # Check that the value valid
    assert value >= 0
    assert value < 2 ** (8 * value_len) - 1
    return bytearray(struct.pack(fmt, value))


def find_payload_len(payload_fmt_str: str):
    """
    Find the length of bytes of a payload based on its string format
    :param payload_fmt_str: the given string format
    :return: the length of the bytes sequence described the format
    """
    byte_len = 0
    # for each character use the PARSE_FMT dict
    for i in range(len(payload_fmt_str)):
        if payload_fmt_str[i] == 'B':
            byte_len += PARSE_FMT[payload_fmt_str[i]]
        elif payload_fmt_str[i] == 'H':
            byte_len += PARSE_FMT[payload_fmt_str[i]]
        elif payload_fmt_str[i] == 'I':
            byte_len += PARSE_FMT[payload_fmt_str[i]]
        elif payload_fmt_str[i] == 'Q':
            byte_len += PARSE_FMT[payload_fmt_str[i]]
        elif re.search(r'\d', payload_fmt_str[i]):
            number = ''
            while re.search(r'\d', payload_fmt_str[i]):
                number += payload_fmt_str[i]
                i += 1
            byte_len += int(number) * PARSE_FMT[payload_fmt_str[i]]
    return byte_len


def check_first_byte(payload: bytes):
    """
    Check the first byte of a byte sequence
    :param payload: the sequence of bytes
    :return: the unpacked first byte
    """
    return struct.unpack('!B', payload[:1])[0]


def pack_cell(cell):
    """
    Turn a cell object into a sequence of bytes
    :param cell: the cell object
    :return: the sequence of bytes
    """
    # Use the cells fmt string
    fmt = cell.fmt_string
    fmt_len = len(cell.fmt_string_arr[:-1])
    args = []
    for i in range(fmt_len):
        # Get the value of the attribute of the cell
        val = getattr(cell, cell.fmt_string_arr[i])
        args.append(val)

    header = struct.pack(fmt, *args)
    # return a bytes object containing the packed strings
    return header + cell.payload


def recognized(payload_bytes: bytearray, hash_context):
    """
    Check if a sequence of bytes which represents the payload of a relay cell is 'recognized'
    :param payload_bytes: the payload in bytes
    :param hash_context: the running digest of cells sent or received between the OP and the OR
    :return: True if recognized, False if not, and a temporary updated digest
    """
    recog_pos = RELAY_RECOGNIZED_POS
    # The unpacked value of the recognized field
    recog = struct.unpack(PACK_FMT[public_constants.RECOGNIZED_LEN],
                          payload_bytes[recog_pos:(recog_pos + public_constants.RECOGNIZED_LEN)])[0]
    if recog != 0:
        return False, hash_context
    else:
        # If the Cell is recognized, calculate the updated hash to see if it fits the given hash value
        digest_pos = RELAY_DIGEST_POS
        given_digest = payload_bytes[digest_pos:(digest_pos + public_constants.DIGEST_LEN)]
        payload_bytes = bytearray(payload_bytes)
        # Change the cells digest field to 0, because digest is calculated with the cells digest field set to zero
        payload_bytes[digest_pos:(digest_pos + public_constants.DIGEST_LEN)] = bytes(public_constants.DIGEST_LEN)
        temp_context = core_crypto.Hash.hash_update(hash_context, payload_bytes, inplace=False)
        calculated_digest = core_crypto.Hash.hash_extract(temp_context)
        # Check if calculated digest equals the given digest
        equal_digest = (given_digest == calculated_digest[:public_constants.DIGEST_LEN])
        if not equal_digest:
            print("[*] Digest does not fit...")
        return equal_digest, temp_context


def separate_cell_from_buffer(buffer: bytes, cell, link_version: int = 1):
    """
    Separates CELL LEN bytes from a given buffer and turns them into a cell object
    :param buffer: the given buffer
    :param cell: the empty cell object
    :param link_version: the link version for knowing CELL LEN
    :return: The updated buffer
    """
    # Get the first fields of the cell
    circID, command, buffer = unpack_cell_header(buffer, link_version)
    # If its a variable length cell, get the length field as well
    if command == 7 or command >= 128:
        payload_length = struct.unpack('!H', buffer[:2])[0]
        buffer = buffer[2:]
    else:
        # Otherwise the length of the payload is PAYLOAD LEN (509)
        payload_length = public_constants.PAYLOAD_LEN

    payload = buffer[:payload_length]
    # Update the buffer
    buffer = buffer[payload_length:]

    # Add params to cell
    cell.circID = circID
    cell.command = command
    cell.payload_len = payload_length
    cell.payload = payload

    return buffer


def get_cell_cmd(cell_bytes: bytes, link_version: int):
    """
    Get the command of a cell which is represented in bytes
    :param cell_bytes: the bytes of the cell
    :param link_version: the link version of the cell
    :return: the cells command
    """
    cmd = struct.unpack(PACK_FMT[public_constants.CMD_LEN], cell_bytes[public_constants.CIRCID_LEN(
        link_version):public_constants.CIRCID_LEN(link_version) + public_constants.CMD_LEN])[0]
    return cmd


def get_relay_cmd(cell_bytes: bytes, link_version: int):
    """
    Get the command of the relay cell which is in bytes
    :param cell_bytes: the cell bytes
    :param link_version: the link version of the cell
    :return: the relay command
    """
    cmd = struct.unpack(PACK_FMT[public_constants.CMD_LEN], cell_bytes[public_constants.CIRCID_LEN(
        link_version) + public_constants.CMD_LEN:public_constants.CIRCID_LEN(
        link_version) + public_constants.CMD_LEN * 2])[0]
    return cmd


def unpack_cell_header(bytes_cell: bytes, link_version: int):
    """
    Unpack the header of a given cell in bytes (Header is CIRCID_LEN + COMMAND_LEN)
    :param bytes_cell: the cell bytes
    :param link_version: the link version of the cell
    :return: the cells circuit id, command, payload, and if its a higher link cell
    """
    # Unpack the bytes with struct.unpack and update the cell bytes
    if 0 < link_version <= 3:
        fmt_str = '!HB'
        circID, command = struct.unpack(fmt_str, bytes_cell[:3])
        bytes_cell = bytes_cell[3:]
    elif link_version >= 4:
        fmt_str = '!IB'
        circID, command = struct.unpack(fmt_str, bytes_cell[:5])
        bytes_cell = bytes_cell[5:]
    else:
        print("[*] Invalid link version")
    return circID, command, bytes_cell


def pack_payload(fmt_str: str, *argv):
    """
    Pack a number of values into bytes with struct.pack
    :param fmt_str: the string format fro the struct module
    :param argv: the list of args to pack
    :return: a bytearray of the packed values
    """
    return struct.pack(fmt_str, *argv)


def unpack_VERSIONS_payload(payload: bytes):
    """ The payload in a VERSIONS cell is a series of big-endian two-byte integers. """
    fmt_string = '!' + str(int(len(payload) / 2)) + 'H'
    link_version_list = list(struct.unpack(fmt_string, payload))
    return link_version_list


def unpack_NETINFO_paylaod(payload: bytes, fmt_str: str):
    """NETINFO cell.  The cell's payload is:

      TIME       (Timestamp)                     [4 bytes]
      OTHERADDR  (Other OR's address)            [variable]
         ATYPE   (Address type)                  [1 byte]
         ALEN    (Adress length)                 [1 byte]
         AVAL    (Address value in NBO)          [ALEN bytes]
      NMYADDR    (Number of this OR's addresses) [1 byte]
        NMYADDR times:
          ATYPE   (Address type)                 [1 byte]
          ALEN    (Adress length)                [1 byte]
          AVAL    (Address value in NBO))        [ALEN bytes]"""
    timestamp, _, _, other_or_ip, _, _, _, our_ip = struct.unpack(fmt_str, payload)
    return timestamp, socket.inet_ntoa(other_or_ip), socket.inet_ntoa(our_ip)


def unpack_CREATED_payload(payload: bytes):
    """The payload for a CREATED cell, or the relay payload for an
   EXTENDED cell, contains:

         DH data (g^y)                 [DH_LEN bytes]
         Derivative key data (KH)      [HASH_LEN bytes]"""
    gy = payload[:CryptoConstants.DH_LEN]
    hash = payload[CryptoConstants.DH_LEN:(CryptoConstants.DH_LEN + CryptoConstants.HASH_LEN)]
    return gy, hash


def unpack_RELAY_payload_header(fmt_str: str, payload: bytes):
    """
    The payload of each unencrypted RELAY cell consists of:

         Relay command           [1 byte]
         'Recognized'            [2 bytes]
         StreamID                [2 bytes]
         Digest                  [4 bytes]
         Length                  [2 bytes]
         Data                    [PAYLOAD_LEN-11 bytes]"""
    command, recognized, streamID, digest, length = struct.unpack(fmt_str,
                                                                  payload[:public_constants.RELAY_PAYLOAD_HEADER_LEN])
    data = payload[public_constants.RELAY_PAYLOAD_HEADER_LEN:(public_constants.RELAY_PAYLOAD_HEADER_LEN + length)]
    return command, recognized, streamID, digest, length, data


def unpack_RELAY_CONNECTED_data(data: bytes):
    """The exit node replies with a RELAY_CONNECTED cell, whose
   payload is in one of the following formats:

       The IPv4 address to which the connection was made [4 octets]
       A number of seconds (TTL) for which the address may be cached [4 octets]"""
    ip = socket.inet_ntoa(data[:public_constants.PACKED_IP_ADDR_LEN])
    ttl = struct.unpack(PACK_FMT[public_constants.TTL_LEN], data[
                                                            public_constants.PACKED_IP_ADDR_LEN:public_constants.PACKED_IP_ADDR_LEN + public_constants.TTL_LEN])[
        0]
    return ip, ttl


def unpack_RELAY_SENDME_data(data: bytes):
    """A circuit-level RELAY_SENDME cell always has its StreamID=0.
    The RELAY_SENDME payload contains the following:

      VERSION     [1 byte]
      DATA_LEN    [2 bytes]
      DATA        [DATA_LEN bytes]"""
    fmt_string = '!BH'
    version, sendme_length = struct.unpack(fmt_string, data[:RELAY_SENDME_HEADER_LEN])
    sendme_data = data[RELAY_SENDME_HEADER_LEN:RELAY_SENDME_HEADER_LEN + sendme_length]
    return version, sendme_length, sendme_data


def unpack_RELAY_END_data(data: bytes):
    """ The payload of a RELAY_END cell begins with a single 'reason' byte to
   describe why the stream is closing.  For some reasons, it contains
   additional data (depending on the reason.)"""
    return struct.unpack(PACK_FMT[RELAY_END_REASON_LEN], data)[0]
