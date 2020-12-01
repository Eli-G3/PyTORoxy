import socket
import ssl
import sys

MAX_READ_BUFFER_LEN = 4096
HOST = '127.0.0.1'
PORT = 9150


def listen_for_connection(context):
    if 'listener_socket' in context:
        context['listener_socket'].listen()
        conn, addr = context['listener_socket'].accept()
        print('Connected by', addr)
        return conn


def listener_open():
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.bind((HOST, PORT))
    return {'listener_socket': listener_socket}


def get_connect_context(context):
    if context == None:
        print("Error: Check if OR is online.")
        sys.exit(1)
    if 'link' in context:
        context = context['link']
    assert 'tcp_socket' in context
    return context


def tcp_request(ip, port, request_bytes, do_shutdown, max_response_len=MAX_READ_BUFFER_LEN):
    context = tcp_open(ip, port)
    tcp_write(context, request_bytes)
    response_bytes = tcp_read(context, max_response_len)
    tcp_close(context, do_shutdown)
    return response_bytes


def tcp_open(ip, port):
    tcp_sock = socket.create_connection((ip, port))
    return {'tcp_socket': tcp_sock}


def tcp_write(context, request_bytes):
    context = get_connect_context(context)
    context['tcp_socket'].sendall(request_bytes)


def tcp_read(context, max_response_len=MAX_READ_BUFFER_LEN):
    context = get_connect_context(context)
    return bytearray(context['tcp_socket'].recv(max_response_len))


def tcp_close(context, do_shutdown):
    context = get_connect_context(context)
    if do_shutdown:
        try:
            context['tcp_socket'].shutdown(socket.SHUT_RDWR)
        except socket.error as e:
            print("Socket error '{}' during shutdown".format(e))
    context['tcp_socket'].close()


def tls_open(ip, port):
    context = tcp_open(ip, port)
    ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    ssl_sock = ssl_context.wrap_socket(context['tcp_socket'], server_hostname=ip)
    ssl_sock.do_handshake()
    context.update({'ssl_socket': ssl_sock})
    return context


def tls_write(context, request_bytes):
    context = get_connect_context(context)
    context['ssl_socket'].sendall(request_bytes)


def tls_read(context, max_response_len=MAX_READ_BUFFER_LEN):
    context = get_connect_context(context)
    context['ssl_socket'].settimeout(3)
    return bytearray(context['ssl_socket'].recv(max_response_len))


def tls_close(context, do_shutdown=True):
    context = get_connect_context(context)
    if do_shutdown:
        try:
            context['ssl_socket'].shutdown(socket.SHUT_RDWR)
        except socket.error as e:
            # A "Socket is not connected" error here is harmless
            print("Socket error '{}' during shutdown".format(e))
    context['ssl_socket'].close()


def tls_request(ip, port, request_bytes, do_shutdown, max_response_len=MAX_READ_BUFFER_LEN):
    context = tls_open(ip, port)
    tls_write(context, request_bytes)
    response = tls_read(context, max_response_len)
    return response
