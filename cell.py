import pack
import public_constants
import socket
import time
import os
from crypto.crypto_constants import CryptoConstants


class Cell:
    """
    This Class Represents a general Cell. The basic structure of communication in TOR.
    It is meant to be inherited by subclasses which represent the different types of Cells.
    Note: The difference betwenn each cell type is seen in the payload, and command. The circuit ID always stays the same
    """

    def __init__(self, circID: int = 0, command: str = 'PADDING', payload: bytes = None, payload_len: int = None,
                 cell=None, link_version: int = 1):
        """
        The initialization function for the Cell object.
        :param circID: the cells circuit id
        :param command: the cells command
        :param payload: the payload
        :param payload_len: the length of the cells payload
        :param cell: an optionally given cell which would pass on its attributes
        :param link_version: the link version of the cell
        """
        # If a cell is given, Inherit its attributes
        if cell is not None:
            self.circID = cell.circID
            self.command = cell.command
            self.payload = cell.payload
            self.payload_len = cell.payload_len
            self.link_version = cell.link_version
        else:
            self.circID = circID
            self.command = public_constants.CMD_ENUM[command]
            self.payload = payload
            self.payload_len = payload_len
            self.link_version = link_version
        # The fmt string is used by the pack module to pack the cell
        self.fmt_string = ''
        self.fmt_string_arr = ['circID', 'command', 'payload']
        self.set_fmt_string()

    def set_fmt_string(self):
        """
        Sets the string format of the cell based on the link version.
        :return: None
        """
        if public_constants.CIRCID_LEN(self.link_version) == 2:
            self.fmt_string = '!HB'
        else:
            self.fmt_string = '!LB'

    def add_padding_zeros(self, byte_len):
        """
        add padding zeros to a cells payload if it is less than PAYLOAD LEN (509 bytes)
        :param byte_len: How many bytes to padd
        :return: None
        """
        padding_bytes = bytearray(byte_len)
        self.payload += padding_bytes
        assert len(self.payload) == public_constants.PAYLOAD_LEN

    def pack_cell(self):
        """
        A general inherited and oftenly used function that takes a cell object and represents it as bytes
        :return:
        """
        self.set_fmt_string()
        self.pack_payload()
        return pack.pack_cell(self)

    def unpack_cell(self, cell_bytes: bytes):
        """
        A general inherited and oftenly used function that takes a given buffer of bytes and turns it into a cell object
        :param cell_bytes: a given buffer of bytes
        :return:
        """
        buffer = pack.separate_cell_from_buffer(cell_bytes, self, self.link_version)
        self.unpack_payload()
        return buffer

    def unpack_payload(self):
        """
        An abstract function which varies with each inheritance based on the structure of a cell type's payload.
        It takes the cells payload (which are bytes) and derives attributes from it.
        :return:
        """
        pass

    def pack_payload(self):
        """
        An abstract function which varies with each inheritance based on the structure of a cell type's payload.
        It takes the attributes from the cell objects's payload and creates a payload (in bytes).
        :return:
        """
        pass


class CreateCell(Cell):
    """
     The format of a CREATE cell is:

       HDATA     (Client Handshake Data)     [TAP_C_HANDSHAKE_LEN bytes]
    """

    def __init__(self, client_handshake_data: bytes, circID: int = 0, command: str = 'CREATE', payload: bytes = None,
                 payload_len: int = None,
                 cell=None, link_version: int = 1):
        super().__init__(circID, command, payload, payload_len, cell, link_version)
        self.handshake_data = client_handshake_data

    def pack_payload(self):
        if self.handshake_data is None:
            print("[*] Unable to pack payload... No Client Handshake Data Supplied")
        else:
            self.payload = self.handshake_data
            self.add_padding_zeros(public_constants.PAYLOAD_LEN - len(self.payload))

    def unpack_payload(self):
        # we don't need to do anything because as an OP we should only be getting CREATED cells back
        pass


class CreatedCell(Cell):
    """
     The format of a CREATED cell is:

       HDATA     (Server Handshake Data)     [TAP_S_HANDSHAKE_LEN bytes]
    """

    def __init__(self, circID: int = 0, command: str = 'PADDING', payload: bytes = None, payload_len: int = None,
                 cell=None, link_version: int = 1):
        super().__init__(circID, command, payload, payload_len, cell, link_version)
        self.handshake_data = None
        self.hash_of_dh_key = None

    def unpack_payload(self):
        if self.payload is None:
            print("[*] No payload to unpack")
        else:
            self.handshake_data, self.hash_of_dh_key = pack.unpack_CREATED_payload(self.payload)

    def pack_payload(self):
        # we don't need to do anything because as an OP we should only be getting CREATED cells back
        pass


class NetInfoCell(Cell):
    '''
     If version 2 or higher is negotiated, each party sends the other a
   NETINFO cell.  The cell's payload is:

      TIME       (Timestamp)                     [4 bytes]
      OTHERADDR  (Other OR's address)            [variable]
         ATYPE   (Address type)                  [1 byte]
         ALEN    (Adress length)                 [1 byte]
         AVAL    (Address value in NBO)          [ALEN bytes]
      NMYADDR    (Number of this OR's addresses) [1 byte]
        NMYADDR times:
          ATYPE   (Address type)                 [1 byte]
          ALEN    (Adress length)                [1 byte]
          AVAL    (Address value in NBO))        [ALEN bytes]

   Recognized address types (ATYPE) are:

     [04] IPv4.
     [06] IPv6.
    '''
    ADDR_TYPE = 4
    ADDR_LEN = 4
    NUM_ADDRESESS = 1
    PAYLOAD_FMT_STR = '!IBB' + str(ADDR_LEN) + 's' + 'BBB' + str(ADDR_LEN) + 's'

    def __init__(self, other_or_ip: str = None, our_ip: str = None, timestamp: int = int(time.time()), circID: int = 0,
                 command: str = 'NETINFO', payload: bytes = None,
                 payload_len: int = pack.find_payload_len(PAYLOAD_FMT_STR), cell=None,
                 link_version: int = 1):
        super().__init__(circID, command, payload, payload_len, cell, link_version)
        self.timestamp = timestamp
        self.other_or_ip = other_or_ip
        self.our_ip = our_ip

    def pack_payload(self):
        if self.other_or_ip is not None and self.our_ip is not None:
            self.payload = pack.pack_payload(NetInfoCell.PAYLOAD_FMT_STR, self.timestamp, NetInfoCell.ADDR_TYPE,
                                             NetInfoCell.ADDR_LEN,
                                             socket.inet_aton(self.other_or_ip), NetInfoCell.NUM_ADDRESESS,
                                             NetInfoCell.ADDR_TYPE,
                                             NetInfoCell.ADDR_LEN, socket.inet_aton(self.our_ip))
            self.add_padding_zeros(public_constants.PAYLOAD_LEN - len(self.payload))
        else:
            print("[*] Can't pack payload... IP addresses not given")

    def unpack_payload(self):
        if self.payload_len < len(self.payload):
            self.timestamp, self.other_or_ip, self.our_ip = pack.unpack_NETINFO_paylaod(self.payload[:self.payload_len],
                                                                                        NetInfoCell.PAYLOAD_FMT_STR)
        else:
            self.timestamp, self.other_or_ip, self.our_ip = pack.unpack_NETINFO_paylaod(self.payload,
                                                                                        NetInfoCell.PAYLOAD_FMT_STR)


class VarLenCell(Cell):
    '''
    On a version 2 or higher connection, all cells are as in version 1
   connections, except for variable-length cells, whose format is:

        CircID                                [CIRCID_LEN octets]
        Command                               [1 octet]
        Length                                [2 octets; big-endian integer]
        Payload (some commands MAY pad)       [Length bytes]
    '''

    def __init__(self, circID: int = 0, command: str = 'VERSIONS', payload: bytes = None, payload_len: int = None,
                 cell=None, link_version: int = 1):
        super().__init__(circID, command, payload, payload_len, cell, link_version)
        self.fmt_string_arr = ['circID', 'command', 'payload_len', 'payload']

    def calculate_len(self):
        if self.payload is None:
            print("[*] Length can't calculate. Create payload first.")
        self.payload_len = len(self.payload)

    def set_fmt_string(self):
        if public_constants.CIRCID_LEN(self.link_version) == 2:
            self.fmt_string = '!HBH'
        else:
            self.fmt_string = '!LBH'


class VersionsCell(VarLenCell):
    """
     The payload in a VERSIONS cell is a series of big-endian two-byte
   integers.
    """

    def __init__(self, circID: int = 0, command: str = 'VERSIONS', payload: bytes = None, payload_len: int = None,
                 link_version_list: list = [3, 4, 5], cell=None, link_version: int = 1):
        super().__init__(circID, command, payload, payload_len, cell, link_version)
        self.link_version_list = link_version_list

    def pack_payload(self):
        packed_version_list = []
        for version in self.link_version_list:
            packed_version_list.append(pack.pack_value(public_constants.VERSION_LEN, version))
        self.payload = bytearray().join(packed_version_list)
        self.calculate_len()

    def unpack_payload(self):
        if self.payload is None:
            print("[*] No Payload to unpack!!!")
        self.link_version_list = pack.unpack_VERSIONS_payload(self.payload)


class RelayCell(Cell):
    """
    The payload of each unencrypted RELAY cell consists of:

         Relay command           [1 byte]
         'Recognized'            [2 bytes]
         StreamID                [2 bytes]
         Digest                  [4 bytes]
         Length                  [2 bytes]
         Data                    [PAYLOAD_LEN-11 bytes]
    """
    DIGEST_LEN = 4
    PAYLOAD_FMT_STR = '!BHH' + str(DIGEST_LEN) + 'sH'
    RELAY_HEADER_LEN = 11

    def __init__(self, circID: int = 0, command: str = 'RELAY', payload: bytes = None, payload_len: int = None,
                 cell=None, link_version: int = 1,
                 relay_command: str = 'RELAY_BEGIN', streamID: int = None, digest: bytes = bytes(4), length: int = None,
                 data: bytes = None):
        super().__init__(circID, command, payload, payload_len, cell, link_version)
        self.payload_fmt_arr = ['relay_command', 'recognized', 'streamID', 'digest', 'length', 'data']
        self.relay_command = pack.RELAY_CMD_ENUM[relay_command]
        self.recognized = 0
        self.streamID = streamID
        self.digest = digest
        self.length = length
        self.data = data
        self.padding = None

    def unpack_payload(self):
        self.relay_command, self.recognized, \
        self.streamID, self.digest, \
        self.length, self.data = pack.unpack_RELAY_payload_header(RelayCell.PAYLOAD_FMT_STR, self.payload)

    def check_digest(self, digest):
        return self.digest == digest

    def is_recognized(self):
        return self.recognized == 0

    def pack_payload(self):
        self.payload = pack.pack_payload(RelayExtend.PAYLOAD_FMT_STR, self.relay_command, self.recognized,
                                         self.streamID, self.digest, self.length)

    @staticmethod
    def get_padding_random(byte_len):
        padding_bytes = bytearray(os.urandom(byte_len))
        return padding_bytes


class RelayData(RelayCell):
    """
    The payload of a relay data cell is the raw data that a client sends
    """

    def __init__(self, data: bytes = None,
                 circID: int = 0, command: str = 'RELAY', payload: bytes = None, payload_len: int = None,
                 cell=None,
                 link_version: int = 1,
                 relay_command: str = 'RELAY_DATA', streamID: int = 0, digest: bytes = bytes(4),
                 length: int = None):
        super().__init__(circID, command, payload, payload_len, cell, link_version, relay_command, streamID, digest,
                         length, data)
        if self.length is None and self.data is not None:  # This means we are sending the cell
            if streamID == 0:
                print("[*] Warning, StreamID in Relay Data Cell is 0...")
            self.length = len(self.data)
            self.padding = RelayCell.get_padding_random(
                public_constants.PAYLOAD_LEN - (RelayCell.RELAY_HEADER_LEN + self.length))
        self.set_fmt_string()

    def pack_payload(self):
        super().pack_payload()
        self.payload += self.data
        self.payload += self.padding

    # NOTICE: No need to define unpack payload for subclass because in this case its the same as the super


class RelayBegin(RelayCell):
    """
     RELAY_BEGIN cell with a payload encoding the address
   and port of the destination host.  The payload format is:

         ADDRPORT [nul-terminated string]
         FLAGS    [4 bytes]

   ADDRPORT is made of ADDRESS | ':' | PORT | [00]
    """
    FLAGS_LEN = 4

    def __init__(self, addr_port: str, flags: bytes = bytes(4),
                 circID: int = 0, command: str = 'RELAY', payload: bytes = None, payload_len: int = None,
                 cell=None,
                 link_version: int = 1,
                 relay_command: str = 'RELAY_BEGIN', streamID: int = 0, digest: bytes = bytes(4),
                 length: int = None, data: bytes = None):
        if streamID == 0:
            print("[*] Warning, StreamID in Relay Begin Cell is 0...")
        super().__init__(circID, command, payload, payload_len, cell, link_version, relay_command, streamID, digest,
                         length, data)
        self.addr_port = addr_port.encode() + bytes(1)
        self.flags = flags
        if self.length is None:
            self.length = len(self.addr_port) + RelayBegin.FLAGS_LEN
        self.padding = RelayCell.get_padding_random(
            public_constants.PAYLOAD_LEN - (RelayCell.RELAY_HEADER_LEN + self.length))
        self.set_fmt_string()

    def pack_payload(self):
        super().pack_payload()
        data_fmt = str(self.length) + 's'
        self.data = pack.pack_payload(data_fmt, self.addr_port + self.flags)
        self.payload += self.data
        self.payload += self.padding


class RelaySendMe(RelayCell):
    """
    A circuit-level RELAY_SENDME cell always has its StreamID=0.
    The RELAY_SENDME payload contains the following:

      VERSION     [1 byte]
      DATA_LEN    [2 bytes]
      DATA        [DATA_LEN bytes]
    """
    DATA_FMT_STR = '!BH'
    '''Currently we are only receivng theese cells and not sending them, becuase we ahve no need to monitor flow control'''

    def __init__(self, version: str = 0, sendme_data_len: int = 0, sendme_data: bytes = None,
                 circID: int = 0, command: str = 'RELAY', payload: bytes = None, payload_len: int = None,
                 cell=None,
                 link_version: int = 1,
                 relay_command: str = 'RELAY_BEGIN', streamID: int = 0, digest: bytes = bytes(4),
                 length: int = None, data: bytes = None):
        super().__init__(circID, command, payload, payload_len, cell, link_version, relay_command, streamID, digest,
                         length, data)
        self.version = version
        self.sendme_data_len = sendme_data_len
        self.sendme_data = sendme_data
        self.set_fmt_string()

    def unpack_payload(self):
        super().unpack_payload()
        if self.length != 0:
            self.version, self.sendme_data_len, self.sendme_data = pack.unpack_RELAY_SENDME_data(self.data)


class RelayConnected(RelayCell):
    '''
    The exit node replies with a RELAY_CONNECTED cell, whose
   payload is in one of the following formats:

       The IPv4 address to which the connection was made [4 octets]
       A number of seconds (TTL) for which the address may be cached [4 octets]
    '''

    def __init__(self, ip_addr: bytes = None, ttl: bytes = None,
                 circID: int = 0, command: str = 'RELAY', payload: bytes = None, payload_len: int = None,
                 cell=None,
                 link_version: int = 1,
                 relay_command: str = 'RELAY_BEGIN', streamID: int = 0, digest: bytes = bytes(4),
                 length: int = None, data: bytes = None):
        super().__init__(circID, command, payload, payload_len, cell, link_version, relay_command, streamID, digest,
                         length, data)
        self.ip_addr = ip_addr
        self.ttl = ttl
        if self.length is None:
            self.length = public_constants.PACKED_IP_ADDR_LEN + public_constants.TTL_LEN
        self.padding = None
        self.set_fmt_string()

    def unpack_payload(self):
        super().unpack_payload()
        self.ip_addr, self.ttl = pack.unpack_RELAY_CONNECTED_data(self.data)


class RelayExtend(RelayCell):
    """
    The relay payload for an EXTEND relay cell consists of:

         Address                       [4 bytes]
         Port                          [2 bytes]
         Onion skin                    [TAP_C_HANDSHAKE_LEN bytes]
         Identity fingerprint          [HASH_LEN bytes]

    """
    PORT_LEN = 2
    DATA_LEN = 4 + 2 + CryptoConstants.TAP_C_HANDSHAKE_LEN + CryptoConstants.HASH_LEN

    def __init__(self, address: str, port: int, onion_skin: bytes, identity_fingerprint: bytes,
                 circID: int = 0, command: str = 'RELAY_EARLY', payload: bytes = None, payload_len: int = None,
                 cell=None,
                 link_version: int = 1,
                 relay_command: str = 'RELAY_EXTEND', streamID: int = 0, digest: bytes = bytes(4),
                 length: int = None, data: bytes = None):
        super().__init__(circID, command, payload, payload_len, cell, link_version, relay_command, streamID, digest,
                         length, data)
        self.address = address
        self.port = port
        self.onion_skin = onion_skin
        self.identity_fingerprint = identity_fingerprint
        if self.length is None:
            self.length = RelayExtend.DATA_LEN
        self.set_fmt_string()
        self.padding = RelayCell.get_padding_random(
            public_constants.PAYLOAD_LEN - (RelayCell.RELAY_HEADER_LEN + self.length))

    def pack_payload(self):
        """Packs the entire paylaod (cell format specified in section 6 fo tor-spec)"""
        self.data = socket.inet_aton(self.address)
        self.data += pack.pack_value(RelayExtend.PORT_LEN, self.port)
        self.data += self.onion_skin
        self.data += self.identity_fingerprint
        super().pack_payload()
        self.payload += self.data
        self.payload += self.padding


class RelayExtended(RelayCell):
    """
    The payload of an EXTENDED cell is the same as the payload of a
   CREATED cell.
    """

    def __init__(self, circID: int = 0, command: str = 'RELAY', payload: bytes = None, payload_len: int = None,
                 cell=None, link_version: int = 1,
                 relay_command: str = 'RELAY_EXTENDED', streamID: int = 0, digest: bytes = bytes(4),
                 length: int = None, data: bytes = None):
        super().__init__(circID, command, payload, payload_len, cell, link_version, relay_command, streamID, digest,
                         length, data)
        self.length = CryptoConstants.TAP_S_HANDSHAKE_LEN
        self.set_fmt_string()
        self.handshake_data = None
        self.hash_of_dh_key = None
        self.padding = None

    def unpack_payload(self):
        super().unpack_payload()
        self.handshake_data, self.hash_of_dh_key = pack.unpack_CREATED_payload(self.data)


class RelayEnd(RelayCell):
    """
    The payload of a RELAY_END cell begins with a single 'reason' byte to
   describe why the stream is closing.  For some reasons, it contains
   additional data (depending on the reason.)  The values are:

       1 -- REASON_MISC           (catch-all for unlisted reasons)
       2 -- REASON_RESOLVEFAILED  (couldn't look up hostname)
       3 -- REASON_CONNECTREFUSED (remote host refused connection) [*]
       4 -- REASON_EXITPOLICY     (OR refuses to connect to host or port)
       5 -- REASON_DESTROY        (Circuit is being destroyed)
       6 -- REASON_DONE           (Anonymized TCP connection was closed)
       7 -- REASON_TIMEOUT        (Connection timed out, or OR timed out
                                   while connecting)
       8 -- REASON_NOROUTE        (Routing error while attempting to
                                   contact destination)
       9 -- REASON_HIBERNATING    (OR is temporarily hibernating)
      10 -- REASON_INTERNAL       (Internal error at the OR)
      11 -- REASON_RESOURCELIMIT  (OR has no resources to fulfill request)
      12 -- REASON_CONNRESET      (Connection was unexpectedly reset)
      13 -- REASON_TORPROTOCOL    (Sent when closing connection because of
                                   Tor protocol violations.)
      14 -- REASON_NOTDIRECTORY   (Client sent RELAY_BEGIN_DIR to a
                                   non-directory relay.)
    """
    REASON_END_LEN = 1

    def __init__(self, reason: bytes = None,
                 circID: int = 0, command: str = 'RELAY', payload: bytes = None, payload_len: int = None,
                 cell=None,
                 link_version: int = 1,
                 relay_command: str = 'RELAY_END', streamID: int = 0, digest: bytes = bytes(4),
                 length: int = 1, data: bytes = None):
        super().__init__(circID, command, payload, payload_len, cell, link_version, relay_command, streamID, digest,
                         length, data)
        self.reason = reason
        self.padding = RelayCell.get_padding_random(
            public_constants.PAYLOAD_LEN - (RelayCell.RELAY_HEADER_LEN + self.length))
        self.set_fmt_string()

    def pack_payload(self):
        super().pack_payload()
        self.payload += pack.pack_value(RelayEnd.REASON_END_LEN, self.reason)
        self.payload += self.padding

    def unpack_payload(self):
        super().unpack_payload()
        self.reason = pack.unpack_RELAY_END_data(self.data[:RelayEnd.REASON_END_LEN])
