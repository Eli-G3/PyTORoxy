import connect
from node import *
import cell
from crypto import core_crypto
from cryptography.hazmat.primitives import serialization
import pack
import shipper
import socket
import time

OUR_IP_ADDR = '10.0.0.35'


class Circuit:
    """
    This Class Represents a Circuit of connected tor realys. Through which we send the data
    """

    def __init__(self, circID: int = 0, node_list: list = None):
        """
        Init func for the class circuit
        :param circID: given circuit ID
        :param node_list: given list of node items
        """
        self.circID = circID
        self.node_list = node_list
        self.context = None
        self.link_version = 0
        self.shipper = None

    def open_connection(self, node):
        """
        Opens a tls connection to the guard node
        :param node: the guard node
        :return: status code
        """
        try:
            # initialize the dict of sockets (context) and personal shipper for the circuit
            self.context = connect.tls_open(node.host, node.port)
            self.shipper = shipper.Shipper(self.node_list, self.context, self.circID, None)
            return 0
        except Exception as exc:
            print("[*] Error Opening Secure Connection: {}".format(exc))
            return 1

    def build_hop_1(self):
        """
        Build the hop between the proxy and guard
        :return: status code
        """
        try:
            self.in_protocol_handshake()
            self.create_circuit_conn()
            return 0
        except Exception as exc:
            print(exc)
            return 1

    def build_hop_2(self):
        """
        Build the hop between the guard and middle
        :return: status code
        """
        try:
            self.extend_circuit_conn(node=self.node_list[1], extending_node=self.node_list[0])
            return 0
        except Exception as exc:
            print(exc)
            return 1

    def build_hop_3(self):
        """
        Build the hop between the middle and exit
        :return: status code
        """
        try:
            self.extend_circuit_conn(node=self.node_list[2], extending_node=self.node_list[1])
            return 0
        except Exception as exc:
            print(exc)
            return 1

    def in_protocol_handshake(self):
        """
        Does the "in protocol handshake" based on the tor spec. Sends versions and netinfo cells.
        :return: None
        """
        # Create and send Versions Cell
        version_cell = cell.VersionsCell(circID=0)
        version_cell.pack_payload()
        version_cell_bytes = version_cell.pack_cell()
        print("[*] About to Send Versions Cell to OR...")
        connect.tls_write(self.context, version_cell_bytes)
        buffer = connect.tls_read(self.context)
        print("[*] OR's Responded...")
        # Get the response version cell from the guard
        response_version_cell = cell.VersionsCell()
        buffer = response_version_cell.unpack_cell(buffer)
        response_version_cell.unpack_payload()
        # Find highest shared link version with or, and set hand it off to circuit and shipper
        self.link_version = Circuit.highest_common_version(version_cell.link_version_list,
                                                           response_version_cell.link_version_list)
        self.shipper.link_version = self.link_version
        print("[*] Connection to OR will be a version link {} connection".format(self.link_version))
        # Send Netinfo Cell
        netinfo_cell = cell.NetInfoCell(circID=0, link_version=self.link_version,
                                        other_or_ip=self.node_list[0].host, our_ip=OUR_IP_ADDR)
        netinfo_cell_bytes = netinfo_cell.pack_cell()
        connect.tls_write(self.context, netinfo_cell_bytes)

    def create_circuit_conn(self):
        """
        Creates the inintal circuit connection with the guard node. Does this with Create Cells
        :return:None
        """
        # Create the TAP handshake data - RSA encrypted DH key, with the rest of it being AES encrpyted
        # Also known as legacy hybrid encryption
        x, handshake_data = core_crypto.Handshake.create_TAP_C_DATA(self.node_list[0].onion_key)
        # build and send CREATE cell
        create_cell = cell.CreateCell(handshake_data, self.circID, link_version=self.link_version)
        create_cell_bytes = create_cell.pack_cell()
        print("[*] Sending Create Cell to OR...")
        connect.tls_write(self.context, create_cell_bytes)
        # Recevie Created Cell
        print("[*] Reading OR Response...")
        buffer = connect.tls_read(self.context)
        if not self.shipper.buffer_ok(buffer):
            print("[*] Re-Reading OR Response...")
            buffer = connect.tls_read(self.context)
        created_cell = cell.CreatedCell(link_version=self.link_version)
        buffer = created_cell.unpack_cell(buffer)
        # Derive the key dictionary out of key material with kdf TOR
        key_dict = core_crypto.DH.derrive_shared_key(x, created_cell.handshake_data, created_cell.hash_of_dh_key)
        crypto_context = core_crypto.Handshake.create_crypto_context(key_dict)
        # Update Key and Crypto contexts
        self.node_list[0].key_dict = key_dict
        self.node_list[0].crypto_context = crypto_context
        print("[*] Guard Node at: {} connected".format(self.node_list[0].host))

    def extend_circuit_conn(self, node: Node, extending_node: Node):
        """
        Extend the circuit to a second node
        :param node: the node to extend to
        :param extending_node: the node which will be extending
        :return: None
        """
        # Create TAP handshake data as before
        x, handshake_data = core_crypto.Handshake.create_TAP_C_DATA(node.onion_key)
        # Create a hash of the nodes identity key of authentication purposes
        identity_hash = core_crypto.Hash.hash_bytes(node.identity_key.public_bytes(encoding=serialization.Encoding.DER,
                                                                                   format=serialization.PublicFormat.PKCS1))  # defaults to SHA1 hash
        relay_extend_cell = cell.RelayExtend(circID=self.circID, link_version=self.link_version,
                                             address=node.host, port=node.port, onion_skin=handshake_data,
                                             identity_fingerprint=identity_hash)

        # Send the Relay Extend Cell, and Update the message digest
        print("[*] Sending Encrypted Relay Extend Cell to OR...")
        status_code, updated_digest_context = self.shipper.send(relay_extend_cell, extending_node)
        if status_code == 0:
            extending_node.crypto_context['Df'] = updated_digest_context
        print("[*] Reading OR Response...")
        print("[*] Attempting to exchange keys...")
        # Receive the Relay Extended cell
        relay_extended_cell, buffer, status_code = self.shipper.receive()
        # If padding cell, ignore it and read again from buffer
        while status_code == 2:
            relay_extended_cell, buffer, status_code = self.shipper.receive()
        # if cell is recognized, derive keys from key material
        if status_code == 0:
            print("[*] Cell is Recognized...")
            key_dict = core_crypto.DH.derrive_shared_key(x, relay_extended_cell.handshake_data,
                                                         relay_extended_cell.hash_of_dh_key)
            node.key_dict = key_dict
            node.crypto_context = core_crypto.Handshake.create_crypto_context(key_dict)
            print("[*] Node at {} connected".format(node.host))
        else:
            raise Exception("[*] Relay Cell not recognized, but we are the last stop!... Destroying Circuit")

    def receive_data(self):
        """
           Receive data from the circuit as a response to sent RELAY DATA cells.
           :return: None
           """
        status_code = 0
        response = bytes(0)
        buffer = bytes(0)
        end_stream = False
        max_padding_cells = 3
        print("[*] Receiving Circuit Reply...")
        # If we get a a recognized cell (not padding or timeout), then process it
        try:
            while status_code == 0:
                # buffer is empty, read again for more data cells
                if buffer == b'':
                    reply_relay_data_cell, buffer, status_code = self.shipper.receive()
                # if there is still more on buffer than one cell process the next cell in buffer
                else:
                    reply_relay_data_cell, buffer, status_code = self.shipper.receive(buffer)

                # If a padding cell was received, handle it
                stream_timeout_padding, reply_relay_data_cell, buffer, status_code = self.padding_timeout(buffer,
                                                                                                          status_code,
                                                                                                          max_padding_cells,
                                                                                                          reply_relay_data_cell)
                # If we received a bunch of padding and timeouts, return the server response
                if stream_timeout_padding:
                    print("[*] Received a bunch of Padding Cells... Done Receiving... Sending Data back to Client")
                    print("[*] Final Response:{}".format(response))
                    return response, end_stream
                # If its a realy data cell, add it to the final response and keep reading for more cells
                if isinstance(reply_relay_data_cell, cell.RelayData):
                    print('[*] Received RELAY DATA cell as a response...')
                    response += reply_relay_data_cell.data
                # If its a relay end cell. stop the data stream and return the final response
                elif isinstance(reply_relay_data_cell, cell.RelayEnd):
                    print('[*] Received RELAY_END cell with reason: {}'.format(
                        pack.RELAY_END_REASONS[reply_relay_data_cell.reason]))
                    end_stream = True

        except socket.timeout:
            print("[*] Done Receiving... Sending Data back to Client")
        print("[*] Final Response:{}".format(response))
        return response, end_stream
        # """
        # Receive data from the circuit as a response to sent RELAY DATA cells.
        # :return: None
        # """
        # buffer = bytes(0)
        # response = bytes(0)
        # end_stream = False
        # max_padding_cells = 2
        # status_code = 0
        # print("[*] Receiving Circuit Reply...")
        # # If we get a a recognized cell (not padding or timeout), then process it
        # while status_code == 0:
        #     try:
        #         # buffer is empty, read again for more data cells
        #         if buffer == b'':
        #             reply_relay_data_cell, buffer, status_code = self.shipper.receive()
        #         # if there is still more on buffer than one cell process the next cell in buffer
        #         else:
        #             reply_relay_data_cell, buffer, status_code = self.shipper.receive(buffer)
        #
        #         # If a padding cell was received, handle it
        #         if status_code == 2:
        #             stream_timeout_padding, reply_relay_data_cell, buffer, status_code = self.padding_timeout(buffer, status_code, max_padding_cells, reply_relay_data_cell)
        #             # If we received a bunch of padding and timeouts, return the server response
        #             if stream_timeout_padding:
        #                 print("[*] Received a bunch of Padding Cells... Done Receiving... Sending Data back to Client")
        #                 break
        #         # If its a realy data cell, add it to the final response and keep reading for more cells
        #         if isinstance(reply_relay_data_cell, cell.RelayData):
        #             print('[*] Received RELAY DATA cell as a response...')
        #             response += reply_relay_data_cell.data
        #         # If its a relay end cell. stop the data stream and return the final response
        #         elif isinstance(reply_relay_data_cell, cell.RelayEnd):
        #             print('[*] Received RELAY_END cell with reason: {}'.format(pack.RELAY_END_REASONS[reply_relay_data_cell.reason]))
        #             end_stream = True
        #
        #         if end_stream:
        #             break
        #     except socket.timeout:
        #         time.sleep(3)
        #         pass
        #
        # print("[*] Done Receiving... Sending Data back to Client")
        # return response, end_stream

    def send_data(self, data: bytes, streamID: int):
        """
        Sends data from client through circuit to server
        :param data: the data to be sent
        :param streamID: the uniwue stream ID
        :return: status code
        """
        # Create a relay Data Cell out of the data and send it
        relay_data_cell = cell.RelayData(streamID=streamID, circID=self.circID, data=data,
                                         link_version=self.link_version)
        status_code, updated_digest_context = self.shipper.send(relay_data_cell, self.node_list[2])
        # If successful, update the message digest after sending data to exit node
        if status_code == 0:
            self.node_list[2].crypto_context['Df'] = updated_digest_context
        return status_code

    def start_stream(self, streamID, addr_port: str = 'www.ucla.edu:80'):
        """
        Sends a Realy Begin to open the clients requested server
        :param streamID: the unique stream ID
        :param addr_port: the hostname and port to connect to
        :return: status code
        """
        try:
            # Create the Relay Begin Cell, Send it, and Receive a Response
            relay_begin_cell = cell.RelayBegin(streamID=streamID, circID=self.circID, addr_port=addr_port,
                                               link_version=self.link_version)
            print("[*] Sending Relay Begin to Exit Node")
            status_code, updated_digest_context = self.shipper.send(relay_begin_cell, self.node_list[2])
            relay_connected_cell, _, status_code = self.shipper.receive()
            # If the Response is a padding cell, receive again from buffer
            while status_code == 2:
                relay_connected_cell, buffer, status_code = self.shipper.receive()
        except socket.timeout():
            status_code = 1
        if status_code == 0:
            # If send was successful, update message digest
            self.node_list[2].crypto_context['Df'] = updated_digest_context
        # If got a realy connected cell, return success
        if isinstance(relay_connected_cell, cell.RelayConnected):
            print("[*] Exit Connected to Server at: {} with {} seconds to keep in cache (TTL)".format(
                relay_connected_cell.ip_addr, relay_connected_cell.ttl))
        # If got a relay END cell, report the reason
        elif isinstance(relay_connected_cell, cell.RelayEnd):
            print('[*] FAILED to connect to host. RELAY_END cell with reason: {}'.format(
                pack.RELAY_END_REASONS[relay_connected_cell.reason]))
        return status_code

    def padding_timeout(self, buffer: bytes, status_code: int = 2, max_padding_cells: int = 3,
                        reply_relay_data_cell=None):
        """
        Handles the situation in which we get a padding cell or a socket timeout
        :param buffer: the current buffer from the read/recv
        :param status_code: the current status code- 0 = success, 1 = error, 2 = ignore
        :param max_padding_cells: the max number of consecutive times we can receive padding cells before establishing that the server is done sending data
        :param reply_relay_data_cell: the reply cell
        :return: Is Server Done Taking, reply cell, buffer, status code
        """
        padding_times = 0
        # While we get padding cells
        while status_code == 2:
            try:
                if buffer == b'':
                    # if buffer is empty, fill and procces a cell from it
                    reply_relay_data_cell, buffer, status_code = self.shipper.receive()
                else:
                    # if buffer is not empty, proccess a cell from it
                    reply_relay_data_cell, buffer, status_code = self.shipper.receive(buffer)
            except socket.timeout:
                padding_times += 1
                pass
            # If we received too many padding cells, that means server is done taking
            if padding_times >= max_padding_cells:
                return True, None, None, None
            # padding_times += 1
        return False, reply_relay_data_cell, buffer, status_code

    @staticmethod
    def highest_common_version(version_list1: list, version_list2: list):
        """
        Static Method for finding the highest comman link version between to version lists
        :param version_list1: our version list
        :param version_list2: guard version list
        :return: highest common number from both lists
        """
        # Turn the list into set
        combined_set = set(version_list1)
        # Do a set intersection
        combined_set.intersection_update(set(version_list2))
        # Sort and return the highest value
        ret_val = sorted(list(combined_set))[-1]
        return ret_val
