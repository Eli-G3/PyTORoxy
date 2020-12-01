import circuit
from Authority_Directories import descriptor_getter, descriptor_parser
import connect
import socket
import public_constants
import re
import node
import random
import time

CONNECT_RESPONSE_SUCCESS = 'HTTP/1.1 200 Connection Established\r\nConnection: close\r\nKeep-Alive: timeout=5, max=1000\r\n\r\n'.encode()
RECOGNIZED_METHODS = ['GET', 'POST', 'CONNECT', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH']


def start():
    """
    The main function that brings, everything together. Gets Nodes, Then Builds Circuit, Then Handles Client
    :return: None
    """
    # temporarily hardcode onion key
    onion_key1 = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK9ym96O+nobfp9zEvQiqOXLp6PagchM80XUvlrPvOympVj0X3pvOHZY
9+ducXmZCOtTTRTAa/upcxcm+i4A0JUz6Mf3nlInUliJvQdilns0CfDuWdjsXY/1
lk3FgUELf6bKGUynzN/cGjVqzC0536nW/MOiu0g0PNx2std+QVR5AgMBAAE=
-----END RSA PUBLIC KEY-----"""
    identity_key1 = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK9ym96O+nobfp9zEvQiqOXLp6PagchM80XUvlrPvOympVj0X3pvOHZY
9+ducXmZCOtTTRTAa/upcxcm+i4A0JUz6Mf3nlInUliJvQdilns0CfDuWdjsXY/1
lk3FgUELf6bKGUynzN/cGjVqzC0536nW/MOiu0g0PNx2std+QVR5AgMBAAE=
-----END RSA PUBLIC KEY-----"""

    onion_key2 = '''-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMJt5sVg6Zb0S5Kdzp8JiQxt9gW3uLXeG9pwMH6NYbFcebrVfjRWgAiA
o2cV8Lgs823EXo+E+3/KMckME3P+45uqrILUKAJRrNH6yBnna5KqY+HgH02wADir
VyuxTKjKaHDlN3BnTzx9d5rvurH6KpmGgIYhLn6gAOy54/UCRM9TAgMBAAE=
-----END RSA PUBLIC KEY-----'''

    identity_key2 = '''-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALQj7xBzd+XE5M7cIuE5T/XTxvJkXq9EOw2YRrJ/4tkCc4ziP+PmyfZd
ckV23TrpZnIncezX7XTjhkRYwT31Di7WSTMNuyRWSijKBT6X1NYGddTznmVbeVlz
/kJfTV/jJQh0WtoOJhcXrRsYbp8aWlHibu5DFxj2IumOpy1U3VGlAgMBAAE=
-----END RSA PUBLIC KEY-----'''

    n1 = node.Node(host='10.0.0.28', port=9150, onion_key=onion_key1, identity_key=identity_key1)
    n2 = node.Node(host='10.0.0.33', port=443, onion_key=onion_key2, identity_key=identity_key2)

    # Clear existing Server Descriptors because we are getting new ones
    # descriptor_getter.clear_cache("Authority_Directories/GuardNodes.txt")
    # descriptor_getter.clear_cache("Authority_Directories/MiddleNodes.txt")
    # descriptor_getter.clear_cache("Authority_Directories/ExitNodes.txt")
    # print("[*] Files Cleared")
    #
    # # Get Server Descriptors from directory servers with stem
    # descriptor_getter.get_node_desc("GUARD")
    # descriptor_getter.get_node_desc("MIDDLE")
    # descriptor_getter.get_node_desc("EXIT")

    # Parse the server descriptors and return three created Node classes
    node_list = descriptor_parser.get_circuit_nodes()
    print("[*] Guard at: %s\n[*] Middle at: %s\n[*] Exit at: %s" % (node_list[0].host, node_list[1].host, node_list[2].host))

    # Generate Random Circuit ID with MSB set to 1 (According to tor protocol)
    circutID = get_random_circID()
    # Initailize Circuit with CircID and Node_List
    cir = circuit.Circuit(circID=circutID, node_list=node_list)
    # Open Connection to guard node
    status_code = cir.open_connection(node_list[0])
    # if all is well, start building circuit
    if status_code == 0:
        print("[*] Process Done. Socket is connected. Building Circuit...")
        status_code = build_circuit(cir)
        if status_code == 0:
            # if circuit is built successfully, listen for client connecting
            print("[*] Circuit Built. Currently Listening for Incoming TCP Connections...")
            # Bind listen accept for our Onion Port
            context = connect.listener_open()
            flag = False
            cir.context['ssl_socket'].setblocking(0)
            while True:
                # Listen for client connecting
                client_soc = connect.listen_for_connection(context)
                # Handle the connection
                flag = handle_clientsoc(client_soc, context, cir, flag)


def handle_clientsoc(client_soc: socket.socket, context: dict, cir: circuit.Circuit, flag):
    """
    Main Handler function for onion proxy, it sends relay cells with the client data to and from the server
    :param client_soc: the client socket connection
    :param context: a dict of socket connections to our guard node
    :param cir: the created circuit object
    :return: None
    """
    # Set the client socket timeout to 2 seconds, and initialize data variable
    client_soc.settimeout(2.0)
    data = b''
    # cir.context['ssl_socket'].setblocking(0)
    # Receive Data from client. If client is done sending data, socket will either timeout, or receive will be none
    try:
        while True:
            # Use Socket.Recv function from socket library
            receive = client_soc.recv(1024)
            data += receive
            if not receive:
                break
    except socket.timeout:
        pass

    # # Little snippet of code for http delete later
    if not flag:
        while b'iplocation' not in data:
            client_soc = connect.listen_for_connection(context)
            client_soc.settimeout(1.0)
            try:
                while True:
                    data = client_soc.recv(1024)
                    if not data:
                        break
            except socket.timeout:
                pass

    # end snippet

    print("[*] Data Received from Client:{}".format(data))
    if data:
        flag = True
        # Determine the connection type - for example get, post, connect ...
        connection_method = determine_connnection(data)
        if connection_method is not None:
            # If all is good handle the request from the client
            handle_request(connection_method, client_soc, cir, data)
            return flag
        # If we cant recognize the http command close the connection
        else:
            print("[*] Unrecognized Command from Client...\n[*] Connection Closing...")
            client_soc.close()


def build_circuit(cir: circuit.Circuit):
    """
    Main function to build a circuit
    :param cir: given initialized circuit object
    :return: status code
    """
    # Incrementally build the circuit hops and if something wrong happens at some point return error
    status_code = cir.build_hop_1()
    if status_code == 0:
        status_code = cir.build_hop_2()
        if status_code == 0:
            status_code = cir.build_hop_3()
            return status_code
    return 1


def get_addrport(data: bytes, conn_method: str):
    """
    Gets the hostname/ip address and port of the server that client wants to connect to via parsing
    :param data:
    :param conn_method:
    :return:hostname + port
    """
    if conn_method == 'CONNECT':
        # if method is connect it will look like CONNECT www.example.com:443
        addrport = data.decode().split()[1]
    else:
        # If its not connect get the addr_port from the Host header
        port = 80
        hostname = re.findall(r'Host: .+\r\n', data.decode())
        if hostname is None:
            print("[*] Expected Host header, found none...")
            return None
        hostname = hostname[0].strip('Host: ')
        hostname = hostname.strip('\r\n')
        addrport = hostname + ':' + str(port)
    return addrport


def send_data(cir: circuit.Circuit, data: bytes, streamID: int):
    """
    The function separates the string of client data from the client into cells
    :param cir:
    :param data:
    :param streamID:
    :return: None
    """
    max_data_len = public_constants.PAYLOAD_LEN - public_constants.RELAY_PAYLOAD_HEADER_LEN
    # While the client data is longer than MAX_DATA_LEN = 498, split it up into packets with the same stream ID
    while len(data) > (max_data_len):
        cir.send_data(data[:max_data_len], streamID)
        data = data[max_data_len:]
    if len(data) > 0:  # that means there is still some bytes left over that need to be sent
        cir.send_data(data, streamID)


def determine_connnection(data: bytes):
    """
    Determines the type of HTTP request client has given
    :param data: client data in bytes
    :return: HTTP method as string
    """
    conn_method = data.decode().split()[0]
    if conn_method in RECOGNIZED_METHODS:
        return conn_method
    else:
        print("[*] Unrecognized Command... Close Connection")
        return None


def tunnel_mode(client_soc: socket.socket, cir: circuit.Circuit, streamID: int):
    """
    If the client uses HTTP CONNECT method, this functions handles the HTTP proxy tunnel that is required
    :param client_soc: Current connection
    :param cir: the circuit which we want the tunnecl to go through
    :param streamID: stream ID of the traffic going through the tunnel
    :return: None
    """
    # Close Connection after one second if client doesnt respond
    client_soc.settimeout(1)
    end_stream = False
    # Until one of the sides dosent respond, tunnel traffic between them
    while True:
        data = b''
        # Receive Client Data
        try:
            while True:
                recv = client_soc.recv(2048)
                if not recv:
                    break
                data += recv
        except Exception as e:
            pass
        # print("[*] Done Receiving from Client ({})... Sending to Circuit".format(e))
        print("[*] Done Receiving from client")
        if end_stream:
            break

        elif data:
            # Send Client Data to Server through circuit, get server response, and then send it back to client
            print("[*] Client Responded With: {}".format(data))
            send_data(cir, data, streamID)
            response, end_stream = cir.receive_data()
            print("[*] Circuit Response Data: {}".format(response))
            client_soc.sendall(response)
        else:
            print("[*] Didn't Receive any Data... Closing Socket")
            break

    print("[*] Finished Tunneling... Closing Connection")
    client_soc.close()


def handle_request(req_type: str, client_soc: socket.socket, cir: circuit.Circuit, data: bytes):
    """
    Main handler for client request after client data has been received
    :param req_type: http method
    :param client_soc: the client connection
    :param cir: given circuit object
    :param data: the client data
    :return: status code
    """
    # Create random stream ID and get the address port
    streamID = random.randint(100, 1000)
    addr_port = get_addrport(data, req_type)
    # If the client used connect, do http tunneling
    if req_type == 'CONNECT':
        status_code = cir.start_stream(streamID, addr_port)
        if status_code == 0:
            # client_soc.sendall(CONNECT_RESPONSE_SUCCESS)
            print("CONNECT Successful, Tunneling Encrypted Data...")
            client_soc.sendall(CONNECT_RESPONSE_SUCCESS)
            tunnel_mode(client_soc, cir, streamID)
    # Else send the client request as is because no encryption with tls is needed
    else:
        status_code = cir.start_stream(streamID, addr_port)
        if status_code == 0:
            send_data(cir, data, streamID)
            response, _ = cir.receive_data()
            print(response)
            client_soc.sendall(response)
            tunnel_mode(client_soc, cir, streamID)
            # client_soc.close()
        return status_code


def get_random_circID():
    """
    Genereates the random Circuit ID by xoring a valid one with a random number
    :return:
    """
    # 32 bit value circID
    circID = int("10000000000000000000000000000000", 2)
    # random value a
    a = random.randint(200, 2000000000)
    circID = circID ^ a
    # while the MSB of b is not 1 keep xoring with a
    while bin(circID)[2] != '1':
        a = bin(random.randint(200, 2000000000))
        circID = circID ^ a
    return circID
