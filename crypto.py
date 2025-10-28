
import hmac
from hashlib import sha256
from Crypto.Cipher import AES

import logging
logger = logging.getLogger(__name__)

def MACanddecrypt(key, mac, encrypted):
    """
    Decrypt a message using the key.

    Check for the MAC first, to see if the message is valid for this key. If so, decrypt
    the message. Otherwise, return None.

    Return decrypted message, or None if decryption fails
    """

    h = hmac.digest(key, encrypted, 'SHA256')

    if not isinstance(mac, bytes):
        raise ValueError("MAC must be a bytes object")
    
    if not isinstance(h, bytes):
        raise ValueError("hmac must be a bytes object")
    
    # Only the first two bytes of the hash are used as the MAC
    if h[:2] != mac:
        # MAC doesn't match, return None
        logger.debug(f"MAC doesn't match: {h[:2]} {mac}")
        return None
    
    # Decrypt the message using the key, as AES128 ECB

    # Only use half of the key - 128 bits
    cipher = AES.new(key[:16], AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)

    return decrypted

def encryptandMAC(key, message):
    """
    Encrypt a message using the key.
    
    Return the MAC and the encrypted message, padded with zeroes as necessary
    """
    # Only use 16 bytes (128 bits) of the key
    cipher = AES.new(key[:16], AES.MODE_ECB)
    
    # Pad the message to a multiple of 16 bytes. If the length is already a multiple of 16, don't add padding
    padding = (16 - (len(message) % 16)) & 15

    encrypted = cipher.encrypt(message + b'\00'*padding)

    mac = hmac.digest(key, encrypted, 'SHA256')

    # First two bytes of HMAC output are used as the MAC

    return mac[0:2] + encrypted

def ackhash(data):
    """
    Calculate a 4-byte hash of data, used for message acknowledgements
    
    The hash is the first 4 bytes of a SHA256 of the data
    """
    return sha256(data).digest()[0:4]
