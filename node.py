from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class Node:
    """
    This Class represents a Single Onion Router.
    """
    def __init__(self, host: str = None, port: int = None, node_type: str = None, onion_key: str = None,
                 identity_key: str = None, min_link_version: int = None):
        """
        The OR initialization function.
        :param host: the IP address of the OR
        :param port: the port on which the OR runs
        :param node_type: The Type of OR (Guard, Middle, or Exit)
        :param onion_key: The RSA public onion key in PEM format
        :param identity_key: The RSA public identity key in PEM format
        :param min_link_version: The lowest version of link protocol that the OR supports
        """
        self.host = host
        self.port = port
        self.node_type = node_type
        self.min_link_version = min_link_version
        self.key_dict = None
        self.crypto_context = None
        if onion_key is None:
            self.onion_key = onion_key
        else:
            # Load the PEM format into an RSAPublicKey Object
            self.onion_key = serialization.load_pem_public_key(onion_key.encode(), default_backend())
        if identity_key is None:
            self.identity_key = identity_key
        else:
            # Load the PEM format into an RSAPublicKey Object
            self.identity_key = serialization.load_pem_public_key(identity_key.encode(), default_backend())
