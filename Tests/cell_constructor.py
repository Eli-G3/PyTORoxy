import struct
import ctypes
import ssl
import socket



ADDRESS = "148.72.150.176"
OR_PORT = 9001


# # Create Cell:
# buff = ctypes.create_string_buffer(512)
# format_string = '!hB509s'
# offset = 0

# g= 2
# modulus = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
# private_key =  179769313
#
# gx = pow(g,private_key) % modulus
# print(gx)
# CREATE_CELL = struct.pack_into(format_string, buff, offset, 24, 1, b'%d' % gx)
#
# print(buff.raw)
# print(len(buff))
# #
# try:
#     context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#     t_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sock = context.wrap_socket(t_sock, server_hostname=ADDRESS)
#     sock.connect((ADDRESS, OR_PORT))
#     sock.do_handshake()
#     print("Handshake successful")
#     print(sock.cipher())
#     print(sock.shared_ciphers())
#
#     sock.sendall(buff)
#     sock.settimeout(15)
#     sock.setblocking(True)
#     b2 = sock.recv(512)
#     print(b2)
#     sock.close()
#     print("Connection Successful with host")
# except Exception as e:
#     print("Failed to connect to onion router: %s" % e)
#
hostname='www.google.com:443'
print(len(hostname + '\x00'))
print(len(hostname.encode() + bytes(1)))
print(hostname.encode() + bytes(1))
