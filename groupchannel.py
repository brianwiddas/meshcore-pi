import struct
import time
from binascii import unhexlify, hexlify
import hmac
from hashlib import sha256
from Crypto.Cipher import AES
import json

from exceptions import *

import logging

from misc import CallbackList, pad
logger = logging.getLogger(__name__)

class GroupTextMessage:
    """
    GroupTextMessage Class

    This class represents a group text message. It contains the message, and timestamp.

    Parameters:
        Either
            messagedata - inbound message data bytes
        Or
            message - text message, including sender ("Sender: Message", 160 bytes max)
            timestamp - message timestamp (default to now)
            type - should be TXT_TYPE_PLAIN (plain text)
    """

    # Message types
    TXT_TYPE_PLAIN = 0          # a plain text message
    TXT_TYPE_CLI_DATA = 1       # a CLI command
    TXT_TYPE_SIGNED_PLAIN = 2   # plain text, signed by sender

    def __init__(self, messagedata=None, message=None, timestamp=None, messagetype=None):
        if messagedata is None:
            self.messagedata = bytearray(16)
            if message is not None:
                self.message = message
            else:
                # Default message is empty
                self.message = b''

            if timestamp is not None:
                self.timestamp = timestamp
            else:
                self.timestamp = int(time.time())
            
            if messagetype is not None:
                self.messagetype = messagetype
            else:
                self.messagetype = self.TXT_TYPE_PLAIN

        elif len(messagedata) % 16 != 0:
            raise InvalidMeshcorePacket("Message length must be a multiple of 16 bytes.")
        elif messagedata[4] != self.TXT_TYPE_PLAIN:
            raise InvalidMeshcorePacket(f"Unknown message type: {messagedata[4]}")
        else:
            if message is not None or timestamp is not None:
                raise ValueError("Cannot set message or timestamp when messagedata is provided.")
            self.messagedata = messagedata

    @property
    def timestamp(self):
        """
        Get the timestamp.
        """
        return struct.unpack("<I", self.messagedata[0:4])[0]
    
    @timestamp.setter
    def timestamp(self, value):
        """
        Set the timestamp.
        """
        if not isinstance(value, int):
            raise ValueError("Timestamp must be an integer.")
        self.messagedata[0:4] = struct.pack("<I", value)

    @property
    def messagetype(self):
        """
        Get the message type.
        """
        return self.messagedata[4]
    
    @messagetype.setter
    def messagetype(self, value):
        """
        Set the message type.
        """
        if not isinstance(value, int):
            raise ValueError("Message type must be an integer.")
        self.messagedata[4] = value

    @property
    def message(self):
        # Remove any zero padding at the end of the message
        return self.messagedata[5:].rstrip(b'\x00')

    @message.setter
    def message(self, value):
        """
        Set the message.
        """
        if not isinstance(value, bytes):
            raise ValueError("Message must be of type bytes.")

        length = len(value)
        if length > 155:    # (10*blocksize; 160) - length (4) - type (1)
            raise ValueError("Message length exceeds maximum size.")
        length += 5     # 4 bytes for timestamp, 1 byte for type

        # Pad the message to a multiple of 16 bytes. If the length is already a multiple of 16, don't add padding
        padding = (16 - (length % 16)) & 15

        timestamp_type = self.messagedata[0:5]
        self.messagedata = timestamp_type + value + b'\x00' * padding


class Channel:
    """
    Channel Class

    This class represents a channel in the mesh network. It contains the name and shared key.

    Meshcore can have multiple channels, each identified by a the shared key, and a hash, which
    is the first byte of the SHA256 digest of their key. The hash is used to identify the channel
    in the packet.

    Channels can have any name, and any key. However, a hashtag channel (eg. #jokes) has a name
    beginning with a '#' character, and is intended for public use. The key for a hashtag channel
    is the first 16 bytes of the 32-byte SHA256 digest of the channel name, so anyone can join
    the channel if they know the name.
    """

    def __init__(self, key=None, name=None):
        """
        Initialize the Channel class with the given channel key and name.
        """

        self._key = key
        self._name = name
        self._empty = False

        if isinstance(name, str):
            name = name.encode('utf-8','replace')

        if name is None or name.rstrip(b'\x00') == b'':
            # Empty channel slot
            self._name = bytes(32)
            self._key = bytes(16)
            self._empty = True
            return

        if len(name) > 32:
            raise ValueError("Channel name too long")

        # Hashtag channel - key should be first half of SHA256 of name; though since you can call a channel
        # anything as a local name we're not going to enforce that
        if name.startswith(b'#') and key is None:

            self._name = name
            self._key = sha256(name).digest()[:16]

        else:
            if key is None:
                raise ValueError("Channel key required for non-hashtag channels")

            if not isinstance(key, bytes) or len(key) != 16:
                raise ValueError("Channel key must be 16 bytes")

            self._key = key
            self._name = pad(name, 32)

    # Getters only, no setters - channels are immutable once created
    # If you want to change a channel, create a new one and replace it in the list
    @property
    def key(self):
        """
        Get the channel key.
        """
        return self._key
    
    @property
    def name(self):
        """
        Get the channel name.
        """
        return self._name
    
    @property
    def strname(self):
        """
        Get the channel name as a string.
        """
        return self._name.rstrip(b'\x00').decode('utf-8',errors='replace')

    @property
    def key_hash(self):
        """
        Get the hash of the channel key.

        As with other hashes, it's really just the first byte of the key.
        """
        return sha256(self._key).digest()[0]

    @property
    def empty(self):
        """
        Check if the channel is empty (no name and no key).
        """
        return self._empty

    def decrypt(self, message):
        """
        Decrypt a message using the channel key.

        Message:
         * 1 byte hash
         * 2 byte MAC to match channel key
         [ encrypted
         * 4 byte timestamp
         * message
         ]

         Return decrypted message, or None if decryption fails
        """

        if len(message) < 19:       # hash + mac + minimum cipher block size
            raise InvalidMeshcorePacket("Channel message payload too short")

        hash = message[0]
        if hash != self.key_hash:
            # Hash doesn't match, return None
            return None
        
        mac = message[1:3]
        encrypted = message[3:]

        h = hmac.digest(self._key, encrypted, 'SHA256')

        # Only the first two bytes of the hash are used as the MAC
        if h[:2] != mac:
            # MAC doesn't match, return None
            return None
        
        # Decrypt the message using the channel key, as AES128 ECB

        cipher = AES.new(self._key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)

        return decrypted
    
    def encrypt(self, message):
        """
        Encrypt a message using the channel key, and add MAC and hash.
        """
        hash = bytes([self.key_hash])

        # Encrypt the message using the channel key, as AES128 ECB
        cipher = AES.new(self._key, AES.MODE_ECB)
        encrypted = cipher.encrypt(message)
        # Create the MAC
        h = hmac.digest(self._key, encrypted, 'SHA256')
        mac = h[:2]

        # Prepend the hash and MAC to the encrypted message
        return hash + mac + encrypted

    def __repr__(self):
        if self._empty:
            return "Channel(empty)"
        return f"Channel(name={self.strname}, key={hexlify(self.key).decode()})"

# Theoretical maximum number of channels is 255, but the app will load the details of each one
# whether it's in use or not, so we limit it to a more reasonable number
MAX_CHANNELS = 32

def writechannels(channels, filename):
    """
    Write the list of channels to a JSON file. Each channel is written as a name and key,
    except for hashtag channels which are written as just the name (if the key matches).

    Empty channels are skipped
    """

    ch_list = {}

    for ch in channels:
        if ch.empty:
            # Empty channel, skip
            continue

        if ch.strname.startswith('#') and ch.key == sha256(ch.name.rstrip(b'\x00')).digest()[:16]:
            # Hashtag channel, write just the name
            ch_list[ch.strname] = None
        else:
            # Non-hashtag channel, write name and key
            ch_list[ch.strname] = hexlify(ch.key).decode('utf-8')

    with open(filename, 'w') as f:
        json.dump({"channels": ch_list}, f, indent=4)
        # Newline at the end
        print(file=f)

PUBLIC_CHANNEL_KEY = unhexlify(b'8b3387e9c5cdea6ac9e5edbaa115cd72')

def channels(filename=None, max_channels=MAX_CHANNELS, add_public=True):
    """
    Load the list of channels from a JSON file, or create a new list if the file doesn't exist.
    If the file is not specifies, an empty list is created in memory only.
    If add_public is True, the Public channel is added to the list if it doesn't exist
    """
    channel_list = CallbackList()

    file_not_found = False

    if filename is not None:
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                ch_list = data.get("channels", {})
                for name, key in ch_list.items():
                    if key is None:
                        # Hashtag channel
                        channel_list.append(Channel(name=name))
                    else:
                        k = unhexlify(key.encode())
                        if k == PUBLIC_CHANNEL_KEY:
                            # Found the Public channel, doesn't need adding
                            add_public = False
                        channel_list.append(Channel(k, name=name))

        except FileNotFoundError as e:
            logger.error(f"Could not load channels from {filename}, file not found")
            file_not_found = True
        # Other errors (eg. JSON decode errors) will be raised

    # Pad the list with empty channels up to max_channels
    channel_list += [ Channel() ] * (max_channels - len(channel_list))

    if filename is not None:
        # Set the save callback on the list
        channel_list.set_callback(writechannels, filename)

    # Add the Public channel if it's not already in the list, and the add_public flag is set.
    # Doing this will also write the channels back to the file if a filename was given
    if add_public:
        # Find the first free channel
        for c in range(len(channel_list)):
            if channel_list[c].empty:
                channel_list[c] = Channel(PUBLIC_CHANNEL_KEY, name="Public")
                logger.info("Added Public channel to channel list")
                break
        else:
            logger.warning("No free channel slots to add Public channel")

    elif file_not_found:
        # If the file was not found, and we didn't add the Public channel, we should still write it
        writechannels(channel_list, filename)
        logger.info(f"Wrote new channel file {filename}")

    return channel_list
