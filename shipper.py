from crypto import core_crypto
import connect
import pack
import public_constants
import cell

CMD_CELLS_ENUM = {
    1: cell.CreateCell,
    2: cell.CreatedCell,
    3: cell.RelayCell,
    8: cell.NetInfoCell,
    9: cell.RelayCell,
    7: cell.VersionsCell,
}

RELAY_CMD_CELLS_ENUM = {
    1: cell.RelayBegin,
    2: cell.RelayData,
    3: cell.RelayEnd,
    4: cell.RelayConnected,
    5: cell.RelaySendMe,
    6: cell.RelayExtend,
    7: cell.RelayExtended,
}


def generate_cell(cell_bytes: bytes, link_version: int):
    """
    Module level method that generates a cell out of a given command corresponding to that cell
    :param cell_bytes: the cell in bytes
    :param link_version: the protocol link version
    :return: the generated cell
    """
    # Extract the cell command out of the bytes
    cmd = pack.get_cell_cmd(cell_bytes, link_version)
    # if relay cell, generate cell with relay cell dictionary
    if cmd == 3:
        cmd = pack.get_relay_cmd(cell_bytes, link_version)
        return RELAY_CMD_CELLS_ENUM[cmd](link_version=link_version)
    # Else use regular cell dictionary
    else:
        return CMD_CELLS_ENUM[cmd](link_version=link_version)


class Shipper:
    """
    This Class represents a Shipper - an abstract way of sending and receiveing cells.
    Each shipper has a corresponding circuit, and it handles everything from Encryption and Decryption all the way to message digests
    """

    def __init__(self, node_list: list, context: dict, circID: int, link_version: int):
        """
        The initialization function
        :param node_list: the same list of node a shippers corresponding circuit has
        :param context: the context of sockets
        :param circID: the circuit ID of the circuit
        :param link_version: the link protocol version
        """
        self.node_list = node_list
        self.context = context
        self.circID = circID
        self.link_version = link_version
        self.max_response_len = None

    def send(self, cell, target_node):
        """
        Sends a given cell to a given target node.
        :param cell: the cell to be sent
        :param target_node: the target_node which the cell is intended for
        :return: status code, hash context
        """
        try:
            assert target_node in self.node_list
            # handle digest
            updated_hash_context = self.handle_digest(cell, target_node)
            # encrypt layers
            for node in self.node_list[self.node_list.index(target_node)::-1]:
                cell.payload = core_crypto.SymCipher.AES_crypt(cell.payload, node.crypto_context['Kf'])
            # after encryption send through socket
            cell_bytes = pack.pack_cell(cell)
            connect.tls_write(self.context, cell_bytes)
            return 0, updated_hash_context
        except Exception as exc:
            print("[*] Error in shipping Cell:{}".format(exc))
            return 1, None

    def receive(self, buffer: bytes = b''):
        """
        Receives bytes from the buffer and translates them into a cell.
        :param buffer: an optionally given buffer if the current buffer is not empty
        :return: new generated cell, buffer, status code"""
        # Set the Max Response Len for buffer
        self.max_response_len = public_constants.CELL_LEN(self.link_version) * 4
        # Initialize a Cell
        _cell = cell.Cell(link_version=self.link_version)
        # If the buffer is empty, fill it
        if buffer == b'':
            buffer += connect.tls_read(self.context, max_response_len=self.max_response_len)
            # Fill the buffer until the amount of bytes in the buffer is divisible by CELL LEN
            while (len(buffer) % public_constants.CELL_LEN(self.link_version)) != 0:
                buffer += connect.tls_read(self.context, max_response_len=self.max_response_len)
        print("[*] Handling incoming Cell...")
        # If the first couple of bytes are recognizable, unpack CELL_LEN bytes from buffer into a cell
        if self.buffer_ok(buffer):
            buffer = _cell.unpack_cell(buffer)
            recognized = False
            counter = 0
            # While the Cell is not 'recognized' (recognized field is not 0), decrypt the cel payload with the corresponding nodes key (with AES)
            while not recognized and counter < len(self.node_list):
                _cell.payload = core_crypto.SymCipher.AES_crypt(_cell.payload,
                                                                self.node_list[counter].crypto_context['Kb'])
                recognized, running_digest_context = pack.recognized(_cell.payload,
                                                                     self.node_list[counter].crypto_context['Db'])
                counter += 1
            if recognized:
                # generate the recognized cell
                cell_bytes = pack.pack_cell(_cell)
                _cell = generate_cell(cell_bytes, self.link_version)
                # Update to payload fields to there unencrypted values
                _cell.unpack_cell(cell_bytes)
                # Note: we do counter -1 because after recognized is true counter increases
                self.node_list[(counter - 1)].crypto_context['Db'] = running_digest_context
                return _cell, buffer, 0
            else:
                print("[*] Cell Not Recognized... Needs to be Dropped")
                return None, buffer, 1
        # If a padding cell is recognized (CELL LEN zeros), ignore it
        elif buffer == b'\x00' * public_constants.CELL_LEN(self.link_version):
            print("[*] Received Padding Cell... Ignoring")
            buffer = buffer[public_constants.CELL_LEN(self.link_version):]
            return None, buffer, 2
        else:
            print("[*] Cell Not Recognized... Needs to be Dropped")
            return None, buffer, 1

    def handle_digest(self, given_cell: cell.Cell, target_node):
        """
        Adds a given cell to the running digest and calculates a new digest to put in the digest feld before sending a cell
        :param given_cell: cell to be sent
        :param target_node: target node for which the cell is intended
        :return: a temporay hash context of the updated digest
        """
        # Generate the Cell's payload
        given_cell.pack_payload()
        # Calculate the new digest
        temp_hash_context = core_crypto.Hash.hash_update(target_node.crypto_context['Df'], given_cell.payload,
                                                         inplace=False)
        updated_digest = core_crypto.Hash.hash_extract(temp_hash_context)
        given_cell.digest = updated_digest[:cell.RelayCell.DIGEST_LEN]
        # Re-Generate the cell payload with new digest
        given_cell.pack_payload()
        return temp_hash_context

    def buffer_ok(self, buffer: bytes):
        """
        Checks if the buffer starts with the correct circuit ID
        :param buffer: buffer of bytes from the read
        :return:True if recognized, False otherwise
        """
        return int.from_bytes(buffer[:public_constants.CIRCID_LEN(self.link_version)], 'big') == self.circID
