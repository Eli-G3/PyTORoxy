from cryptography.hazmat.primitives.asymmetric import padding, rsa, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from crypto.crypto_constants import CryptoConstants
import os
import pack


class RSA:
    @staticmethod
    def hybrid_encrypt(message: bytes, pk: rsa.RSAPublicKey):
        """
        Some specifications will refer to the "legacy hybrid encryption" of a
        byte sequence M with a public key PK.  It is computed as follows:

      1. If the length of M is no more than PK_ENC_LEN-PK_PAD_LEN,
         pad and encrypt M with PK.
      2. Otherwise, generate a KEY_LEN byte random key K.
         Let M1 = the first PK_ENC_LEN-PK_PAD_LEN-KEY_LEN bytes of M,
         and let M2 = the rest of M.
         Pad and encrypt K|M1 with PK.  Encrypt M2 with our stream cipher,
         using the key K.  Concatenate these encrypted values.
        :param message: the message to encrypt
        :param pk: the public RSA key
        :return: the encrypted message
        """
        # This if shouldn't ever be true, because this algorithm is used with diffie hellman 128 bit keys.
        # M will be 128 bits, and adding key and padding to it will always make it more than 128 bits
        if len(message) <= CryptoConstants.PK_ENC_LEN - CryptoConstants.PK_PAD_LEN:
            encrpt_msg = pk.encrypt(message,
                                    padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
            padding_bytes = bytes(CryptoConstants.PK_PAD_LEN)
            tap_h_data = "temporary"
            print("[*] We got a shorter message. Weird")
        else:
            # Split the message
            m1 = message[:CryptoConstants.PK_ENC_LEN - CryptoConstants.PK_PAD_LEN - CryptoConstants.KEY_LEN]
            m2 = message[CryptoConstants.PK_ENC_LEN - CryptoConstants.PK_PAD_LEN - CryptoConstants.KEY_LEN:]
            # Generate encryption key for AES
            key = bytearray(os.urandom(CryptoConstants.KEY_LEN))
            m1 = bytes(key + m1)
            # Encrypt first part with RSA
            encrpt_msg1 = pk.encrypt(m1,
                                     padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
            nonce = bytes(CryptoConstants.KEY_LEN)
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            # Encrypt second part with AES
            encryptor = cipher.encryptor()
            encrpt_msg2 = encryptor.update(m2) + encryptor.finalize()
            return encrpt_msg1 + encrpt_msg2


class DH:
    DH_GENERATOR = 2
    PRIME_MODULO = int(
        "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A4"
        "31B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B"
        "1FE649286651ECE65381FFFFFFFFFFFFFFFF",
        16)

    PARAM_NUMBERS = dh.DHParameterNumbers(p=PRIME_MODULO, g=DH_GENERATOR)

    @staticmethod
    def generate_keys():
        """
        Generates the 128 bit diffe hellman private (x) and public (g^x) keys.
        :return: x value, x as bytes, gx value, and gx as bytes
        """
        # Use cryptography module to generate secure keys
        dh_params = DH.PARAM_NUMBERS.parameters(default_backend())
        x = dh_params.generate_private_key()
        x_bytes = x.private_numbers().x.to_bytes(128, 'big')
        # Also create the public key ==> gx
        gx = x.public_key()
        gx_bytes = gx.public_numbers().y.to_bytes(128, 'big')
        return x, x_bytes, gx, gx_bytes

    @staticmethod
    def derrive_shared_key(x: dh.DHPrivateKey, gy: bytes, hash: bytes):
        """
        Derrive the shared key from gy with x, as done in Diffie Hellman
        :param x: OP's private key
        :param gy: OR's public key
        :param hash: a hash of the shared key given by the OR (known as KH)
        :return: a dict of keys for encryption, decryption, and hashing
        """
        # Generate the shared key material
        gy = DH.dh_public_from_bytes(gy)
        shared_key_material = x.exchange(gy)
        # Derrive from shared key material the set of keys
        kdf_dict = DH.kdf_tor(shared_key_material)
        if not kdf_dict['KH'] == hash:
            raise ValueError("[*] ERROR: Hash Value is not what the shared key should be")
        else:
            print("[*] TAP handshake completed successfully.")
            return kdf_dict

    @staticmethod
    def dh_public_from_bytes(key_bytes: bytes):
        """
        Turn a key represtented in bytes into a diffie hellman public key object
        :param key_bytes: the key in bytes format
        :return: the public key as an object
        """
        y = int.from_bytes(key_bytes, 'big')
        peer_pub_numbers = dh.DHPublicNumbers(y, DH.PARAM_NUMBERS)
        return peer_pub_numbers.public_key(default_backend())

    @staticmethod
    def kdf_tor(key_material: bytes):
        """
         From the base key material K0, they compute KEY_LEN*2+HASH_LEN*3 bytes of
        derivative key data as

        K = H(K0 | [00]) | H(K0 | [01]) | H(K0 | [02]) | ...

        The first HASH_LEN bytes of K form KH; the next HASH_LEN form the forward
        digest Df; the next HASH_LEN 41-60 form the backward digest Db; the next
        KEY_LEN 61-76 form Kf, and the final KEY_LEN form Kb.
        :param key_material: K0 which is g^xy in TAP handshake
        :return: the dict of keys
        """
        expanded_key = bytearray()
        i = 0
        while len(expanded_key) < CryptoConstants.KDF_TOR_LEN:
            assert i < 256
            counter_byte = pack.pack_value(CryptoConstants.COUNTER_BYTE_LEN, i)
            expanded_key += Hash.hash_bytes(key_material + counter_byte, hashes.SHA1())
            i += 1
        kdf_tor_dict = {
            'KH': expanded_key[:CryptoConstants.HASH_LEN],
            'Df': expanded_key[CryptoConstants.HASH_LEN:(CryptoConstants.HASH_LEN * 2)],
            'Db': expanded_key[(CryptoConstants.HASH_LEN * 2):(CryptoConstants.HASH_LEN * 3)],
            'Kf': expanded_key[(CryptoConstants.HASH_LEN * 3):(CryptoConstants.HASH_LEN * 3 + CryptoConstants.KEY_LEN)],
            'Kb': expanded_key[(CryptoConstants.HASH_LEN * 3 + CryptoConstants.KEY_LEN):(
                    CryptoConstants.HASH_LEN * 3 + CryptoConstants.KEY_LEN * 2)]
        }
        return kdf_tor_dict


class SymCipher:

    @staticmethod
    def create_cipher_context(key: bytes, decrypt: bool = False):
        """
        Create a cipher object and return its reference.
        :param key: the AES symmetric key
        :param decrypt: True if its a decryption cipher, False if encryption
        :return: the cipher object
        """
        # nonce is the initialization vector in ctr
        nonce = bytes(CryptoConstants.KEY_LEN)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        if decrypt:
            return cipher.decryptor()
        else:
            return cipher.encryptor()

    @staticmethod
    def AES_crypt(message: bytes, crypt_context):
        """
        Encrypt or Decrypt the message
        :param message: given message
        :param crypt_context: given cipher object
        :return: the cipher text or plain text (depending on whether your encrypting or decrypting
        """
        # dont need to call .finalize() becuase its a stream cipher
        ciphertext = crypt_context.update(message)
        return ciphertext


class Hash:

    @staticmethod
    def hash_bytes(message: bytes, algorithm=hashes.SHA1()):
        """
        Hash a given message with any given hash algorithm
        :param message:
        :param algorithm:
        :return:
        """
        digest = hashes.Hash(algorithm, default_backend())
        digest.update(message)
        return digest.finalize()

    @staticmethod
    def create_hash_context(seed: bytes = None, algorithm=hashes.SHA1()):
        """
        Create a hash object and return its reference.
        :param seed: an optianl initial seed for the hash
        :param algorithm: the specified hash algorithm which defaults to SHA1
        :return:
        """
        if seed is None:
            return hashes.Hash(algorithm, default_backend())
        else:
            hash_context = hashes.Hash(algorithm, default_backend())
            Hash.hash_update(hash_context, seed)
            return hash_context

    @staticmethod
    def hash_update(hash_context, message: bytes, inplace=True):
        """
        Update a given hash object with a message.
        :param hash_context: the given hash object
        :param message: the given message
        :param inplace: change the object or a copy of the object
        :return: an updated context
        """
        update_context = hash_context
        if not inplace:
            update_context = hash_context.copy()
        update_context.update(message)
        return update_context

    @staticmethod
    def hash_extract(hash_context, reuse=True):
        """
        Extract the bytes from a hash object with .finalize()
        :param hash_context: the given hash object
        :param reuse: true if we want to reuse the hash object
        :return: the hashed bytes
        """
        extract_context = hash_context
        if reuse:
            extract_context = hash_context.copy()
        return extract_context.finalize()


class Handshake:
    @staticmethod
    def create_TAP_C_DATA(onion_key: rsa.RSAPublicKey):
        """
        An 'onion skin', which consists of
        the first step of the DH handshake data (also known as g^x).  This
        value is encrypted using the "legacy hybrid encryption" algorithm
        (see 0.4 above) to the server's onion key, giving a client handshake:

       PK-encrypted:
         Padding                       [PK_PAD_LEN bytes]
         Symmetric key                 [KEY_LEN bytes]
         First part of g^x             [PK_ENC_LEN-PK_PAD_LEN-KEY_LEN bytes]
       Symmetrically encrypted:
         Second part of g^x            [DH_LEN-(PK_ENC_LEN-PK_PAD_LEN-KEY_LEN)
                                           bytes]
        :param onion_key: the servers onion key
        :return: the OPs private key, and the hybrid encrypted 'onion skin'
        """
        x, _, gx, gx_bytes = DH.generate_keys()
        return x, RSA.hybrid_encrypt(gx_bytes, onion_key)  # self.node_list[0].onion_key

    @staticmethod
    def create_crypto_context(key_dict: dict):
        """
        Create a context (dict) of refrences to the corresponding hash and cipher objects.
        This saved by each Node and used for encryption, decryption, and message digests.
        :param key_dict: the dictionary of keys and digest seeds
        :return: the context of references
        """
        # For cipher objects, supply the forward and backward keys derived from kdf tor function
        # For the hash objects, supply the forward and backward digest seed values derived from kdf tor function
        crypto_context = {'Kf': SymCipher.create_cipher_context(key_dict['Kf'], decrypt=False),
                          'Kb': SymCipher.create_cipher_context(key_dict['Kb'], decrypt=True),
                          'Df': Hash.create_hash_context(key_dict['Df'], algorithm=hashes.SHA1()),
                          'Db': Hash.create_hash_context(key_dict['Db'], algorithm=hashes.SHA1())
                          }
        return crypto_context
