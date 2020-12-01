import stem.descriptor.remote

import socket
import ssl

ADDRESS = "148.72.150.176"
OR_PORT = 9001
global CELL_LEN
global g
global modulus

# try:
#     relay = stem.descriptor.remote.get_server_descriptors().run()[0]
#     print(relay.version)
#     print(relay)
#     #if verison is < 4, cell_len = 512 byts
#     #else, 514 bytes



try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    t_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = context.wrap_socket(t_sock, server_hostname=ADDRESS)
    sock.connect((ADDRESS, OR_PORT))
    sock.do_handshake()
    print(sock.cipher())
    print(sock.shared_ciphers())
    print("Connection Successful with host")


    sock.close()

except Exception as e:
    print("Failed to connect to onion router: %s" % e)
#
# except Exception as exc:
#   print("Unable to retrieve the consensus: %s" % exc)
