import cell
import connect
from crypto import core_crypto
from cryptography.hazmat.primitives import serialization
import node
from circuit import Circuit


n = node.Node(host='10.0.0.28', port=9150, onion_key= """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK9ym96O+nobfp9zEvQiqOXLp6PagchM80XUvlrPvOympVj0X3pvOHZY
9+ducXmZCOtTTRTAa/upcxcm+i4A0JUz6Mf3nlInUliJvQdilns0CfDuWdjsXY/1
lk3FgUELf6bKGUynzN/cGjVqzC0536nW/MOiu0g0PNx2std+QVR5AgMBAAE=
-----END RSA PUBLIC KEY-----""", identity_key="""-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK9ym96O+nobfp9zEvQiqOXLp6PagchM80XUvlrPvOympVj0X3pvOHZY
9+ducXmZCOtTTRTAa/upcxcm+i4A0JUz6Mf3nlInUliJvQdilns0CfDuWdjsXY/1
lk3FgUELf6bKGUynzN/cGjVqzC0536nW/MOiu0g0PNx2std+QVR5AgMBAAE=
-----END RSA PUBLIC KEY-----""")
circutID = 2290644851
link_version = 5



x, handshake_data = core_crypto.Handshake.create_TAP_C_DATA(n.onion_key)
identity_hash = core_crypto.Hash.hash_bytes(n.identity_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1)) #defaults to SHA1 hash
relay_extend_cell = cell.RelayExtend(circID=circutID, link_version=link_version,
                                     address=node.host, port=node.port, onion_skin=handshake_data, identity_fingerprint=identity_hash)
relay_extend_cell_bytes = relay_extend_cell.pack_cell()

Df_hash = Circuit.generate_hash_context(n.key_dict['Df'])
core_crypto.Hash.hash_update(Df_hash, relay_extend_cell_bytes)
updated_digest = core_crypto.Hash.hash_extract(Df_hash, reuse=True)

# extending_node.key_dict['Df'] = core_crypto.Hash.update_digest(extending_node.key_dict['Df'], relay_extend_cell_bytes)
relay_extend_cell.digest = updated_digest[:cell.RelayCell.DIGEST_LEN]
print(relay_extend_cell.circID)
print(relay_extend_cell.command)
print(relay_extend_cell.relay_command)
print(relay_extend_cell.recognized)
print(relay_extend_cell.streamID)
print(relay_extend_cell.digest)
print(relay_extend_cell.length)
print(relay_extend_cell.data)

relay_extend_cell_bytes = relay_extend_cell.pack_cell()
print("Unencrpted Relay:{}\nWith length:{}".format(relay_extend_cell_bytes, len(relay_extend_cell_bytes)))
relay_extend_cell_bytes = relay_extend_cell.pack_cell(extending_node.key_dict['Kf'])
print("Encrpted Relay:{}\nWith length:{}".format(relay_extend_cell_bytes, len(relay_extend_cell_bytes)))
print("Sending Encrypted Relay Extend Cell to OR...")

connect.tls_write(self.context, relay_extend_cell_bytes)
print("Reading OR Response...")
buffer = connect.tls_read(self.context)
print("Response: {}".format(buffer))
