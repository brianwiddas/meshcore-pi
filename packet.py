

import struct
import time
from binascii import hexlify

from identity import Identity, AdvertData, AdvertType
from groupchannel import Channel, GroupTextMessage
from misc import unique_time, pathstr

from exceptions import *
from crypto import *


import logging
logger = logging.getLogger(__name__)

types = ['REQ', 'RESPONSE', 'TXT_MSG', 'ACK', 'ADVERT', 'GRP_TXT', 'GRP_DATA', 'ANON_REQ',
         'PATH', 'TRACE', 'RESERVED1', 'RESERVED2', 'RESERVED3', 'RESERVED4', 'RESERVED5', 'RAW_CUSTOM']

def typename(t):
    try:
        return types[t]
    except IndexError:
        raise UnknownMeshcoreType("Type value out of range")

# Meshcore packet handling
#
# MC_Packet         - base class for all Meshcore packets
# +  MC_Incoming    - class for all incoming packets
#    + MC_Unknown   - received packet which is not recognised (eg, type RESERVED1)
#    + MC_Advert    - received advert
#    + MC_SrcDest   - any received packet with a source and destination (such as a text message)
#      + MC_Text    - text message, including room server messages and CLI requests/responses
#      + MC_Response    - received response packet from a request
#      + MC_Path    - received path in response to a flooded message. May contain ACK or RESPONSE data
#      + MC_Req     - received request
#    + MC_Ack       - acknowledgement of sent message
#    + MC_Group     - incoming encrypted channel message
#      + MC_GroupText   - channel text message
#      + MC_GroupData   - channel data message (not implemented)
#    + MC_AnonReq   - received anonymous request
#    + MC_Trace     - received trace
# + MC_Outgoing     - class for all outgoing packets
#    + MC_Advert_Outgoing   - advert to send
#    + MC_SrcDest_Out       - outgoing message with source and destination (don't use this class directly)
#       + MC_Text_Out       - outgoing text/CLI/room message
#       + MC_Path_Out       - outgoing path (with optional ACK or RESPONSE)
#       + MC_Req_Out        - request to send
#       + MC_Response_Out   - response to send
#    + MC_Ack_Outgoing  - acknowledge an received text message
#    + MC_Group_Outgoing    - group message (don't use this class, use GroupText)
#    + MC_GroupText_Outgoing    - group/channel text message
#    + MC_AnonReq_Out   - anonymous request to send
#    + MC_Trace_Out     - outbound trace request or trace data
#
# To create an outbound packet (ie, to send), create an instance of the desired class. Each class
# constructor's parameters are slightly different, which reflects what the class is for an how it's
# used. For example, MC_Text_Out requires a source and destination, while MC_GroupText_Out only
# needs a channel to send to.
#
# Inbound packets are created by calling the appropriate class with the packet data and any other parameters
# needed to construct the packet. For instance, MC_Advert requires the packet data, while MC_Text also needs
# the client's identity and known contacts, so it can decode the message.
#
# A class method in MC_Inbound takes care of identifying the packet type and calling the correct class
# constructor
#
# An MC_Inbound packet can be sent to the dispatcher the same way as an MC_Outbound packet; this is used
# for repeaters

class MC_Packet:
    """
    MC_Packet Class

    Base class of all Meshcore packets.

    Methods:
        __init__(): Initializes an instance of the Meshcore class.
    """

    # Define constants

    # V1
    CIPHER_MAC_SIZE = 2
    PATH_HASH_SIZE = 1

    MAX_PACKET_PAYLOAD = 184
    MAX_PATH_SIZE = 64
    MAX_TRANS_UNIT = 255

    # Text data is sent in multiples of 16 bytes (cipher block size); maximum number of 16 byte blocks
    # in 184 bytes is 11 (176 bytes). Less 4 for the timestamp and 1 for the flags
    # This doesn't include the extra two bytes needed for attempt numbers larger than 3; the message will
    # have to be chopped short if necessary
    #
    # This applies to both text messages and channel messages; though channel messages include the client
    # name and ": ", so the actual message length available is shorter by at least 3 bytes
    # Room server messages are 4 bytes shorter to account for the pubkey of the sender
    MAX_TEXT_MESSAGE = 171

    ROUTE_FLOOD = 0x01      # flood mode, needs path to be built up (max 64 bytes)
    ROUTE_DIRECT = 0x02     # direct route, path is supplied

    TYPE_REQ = 0x00          # request (prefixed with dest/src hashes, MAC) (enc data: timestamp, blob)
    TYPE_RESPONSE = 0x01     # response to REQ or ANON_REQ (prefixed with dest/src hashes, MAC) (enc data: timestamp, blob)
    TYPE_TXT_MSG = 0x02      # a plain text message (prefixed with dest/src hashes, MAC) (enc data: timestamp, text)
    TYPE_ACK = 0x03          # a simple ack
    TYPE_ADVERT = 0x04       # a node advertising its identity
    TYPE_GRP_TXT = 0x05      # an (unverified) group text message (prefixed with channel hash, MAC) (enc data: timestamp, "name: msg")
    TYPE_GRP_DATA = 0x06     # an (unverified) group datagram (prefixed with channel hash, MAC) (enc data: timestamp, blob)
    TYPE_ANON_REQ = 0x07     # generic request (prefixed with dest_hash, ephemeral pub_key, MAC) (enc data: ...)
    TYPE_PATH = 0x08         # returned path (prefixed with dest/src hashes, MAC) (enc data: path, extra)
    TYPE_TRACE = 0x09        # trace a path, collecting SNI for each hop
    TYPE_RESERVED1 = 0x0A    # FUTURE
    TYPE_RESERVED2 = 0x0B    # FUTURE
    TYPE_RESERVED3 = 0x0C    # FUTURE
    TYPE_RESERVED4 = 0x0D    # FUTURE
    TYPE_RESERVED5 = 0x0E    # FUTURE
    TYPE_RAW_CUSTOM = 0x0F   # custom packet as raw bytes, for applications with custom encryption, payloads, etc

    VER_1 = 0x00  # 1-byte src/dest hashes, 2-byte MAC
    VER_2 = 0x01  # FUTURE (e.g., 2-byte hashes, 4-byte MAC ??)
    VER_3 = 0x02  # FUTURE
    VER_4 = 0x03  # FUTURE

    # Message types
    TXT_TYPE_PLAIN = 0          # a plain text message
    TXT_TYPE_CLI_DATA = 1       # response to a CLI command
    TXT_TYPE_SIGNED_PLAIN = 2   # plain text, signed by sender

    # Request types
    REQ_TYPE_LOGIN = 0x00
    REQ_TYPE_GET_STATUS = 0x01      # Also, get stats
    REQ_TYPE_KEEP_ALIVE = 0x02
    REQ_TYPE_GET_TELEMETRY_DATA = 0x03
    REQ_TYPE_GET_AVG_MIN_MAX = 0x04
    REQ_TYPE_GET_ACCESS_LIST = 0x05

    # Response types
    # There appears to be only one defined, for a successful login via AnonReq
    # Failed logins are just ignored and left to time out in the client
    RESP_SERVER_LOGIN_OK = 0

    def __init__(self):
        self.header = 0
        self.path = bytearray()
        self._payload = b''
        self._computed_payload = b''

        # Whether this is an external payload (ie inbound) or being generated locally (outbound)
        # An external payload may be modified and retransmitted; for instance by a repeater
        self.externalpayload = False

        # Set this to be a Future which can be awaited if this packet is going to be sent
        # (eg, it's originated here, or being repeated).
        # It will either be done (result set to True), or cancelled if it times out
        self.sent = None

    def __repr__(self):
        return f"MC_Packet(packet={self.version}, {self.type}, {self.route})"

    def __len__(self):
        return len(self.packet)

    # The whole packet, including header, path and payload
    @property
    def packet(self):
        if self.route == self.ROUTE_DIRECT or self.route == self.ROUTE_FLOOD:
            packet = bytearray([self.header, self.pathlen]) + self.path + self.payload
            if len(packet) > self.MAX_PACKET_PAYLOAD:
                raise InvalidMeshcorePacket("Packet exceeds maximum payload size.")
            return packet
        else:
            raise InvalidMeshcorePacket("Invalid route type for packet construction.")

    # The path length, either of the received path (for flood packets), or the remaining path (for direct packets)
    @property
    def pathlen(self):
        return len(self.path)

    # The payload of the packet
    # Derived classes should set the computed payload
    @property
    def payload(self):
        if self.externalpayload:
            return self._payload
        else:
            # Some packet types (eg. adverts) include timestamps, which plays havoc if you call
            # MC_Packet.payload more than once and the time changes.
            # Fix the packet contents when it is first accessed, unless recompute() is called
            if self._computed_payload is None:
                self._computed_payload = self.compute_payload()

            return self._computed_payload

    def recompute(self):
        """
        Mark the packet for recomputing its payload
        """
        self._computed_payload = None

    def compute_payload(self):
        """
        Compute the payload based on the packet type.
        This is a placeholder method and should be overridden in derived classes.
        """
        print("This is a placeholder method. Please override in derived classes.")
        return self._payload

    @property
    def version(self):
        return self.header >> 6

    @property
    def type(self):
        return (self.header >> 2) & 0x0F

    @property
    def typename(self):
        return typename(self.type)

    @property
    def route(self):
        return self.header & 0x03

    @route.setter
    def route(self, value):
        self.header = self.header & 0xFC | value

    @property
    def routename(self):
        if self.route == self.ROUTE_DIRECT:
            return "Direct"
        if self.route == self.ROUTE_FLOOD:
            return "Flood"
        return "Unknown"

    # FIXME - these don't account for packets with transport codes
    def is_flood(self):
        """
        Is this a flooded packet?
        """
        return self.route == self.ROUTE_FLOOD

    def is_direct(self):
        """
        Is this a direct packet?
        """
        return self.route == self.ROUTE_DIRECT

    # Check the payload length is at least the value supplied
    # Raise an exception if not
    def minpayload(self, length):
        if len(self.payload) < length:
            raise InvalidMeshcorePacket(f"Payload too short, {len(self.payload)} bytes, should be at least {length}")

    # Return a human-readable representation of the packet
    def __str__(self):
        """
        Return the packet details.
        """
        # Only v1 is supported
        if self.version != self.VER_1:
            raise InvalidMeshcorePacket(f"Unsupported packet version {self.version}")
        s = f"Packet class: {self.__class__.__name__}\nPacket Length: {len(self)}\n"
        s += f"Route: {self.routename}, Path Length: {self.pathlen}"
        if self.pathlen:
            s += ", path: " + ",".join( (f"{hop:02x}" for hop in self.path[0:self.pathlen]) ) 
        s += "\n"
        return s

class MC_Incoming(MC_Packet):
    """
    MC_Incoming Class

    Base class of all inbound Meshcore packets.
    """

    def __init__(self, packet, rssi=0.0, snr=0.0):
        super().__init__()

        if isinstance(packet, (bytes, bytearray)):
            # Split the packet into header, path, and payload
            self.header = packet[0]
            pathlen = packet[1]
            if pathlen > 63 or pathlen > (len(packet)-2):
                raise InvalidMeshcorePacket("Path length too long")
            
            self.path = bytearray(packet[2:2 + pathlen])
            self._payload = packet[2 + pathlen:]
            self.externalpayload = True
            
            # If we're a repeater, should we repeat this packet?
            # Can be later set to false if it was intended for us or otherwise not to be repeated
            self.repeat = True
        else:
            raise ValueError("Packet must be of type bytes or bytearray.")

        self.rssi = rssi
        self.snr = snr

    @classmethod
    def convert_packet(cls, packet, selfid, ids, channels, rssi=0.0, snr=0.0):
        """
        Create an instance of the right subclass from the packet.

        eg. for an incoming packet that has an ADVERT payload type:
          convert_packet(packet, selfid, ids, channels)
         -> MC_Advert()

        Parameters:
            packet - raw packet data
            selfid - object of type SelfIdentity containing local ID
            ids - object of type IdentityStore containing known IDs
            channels - list of known group channels
            rssi - RSSI of the received packet
            snr = SNR of the received packet

        Return: typed packet
        """

        # Minimum packet is 2 bytes (header, pathlen=0, no payload)
        if len(packet) < 2:
            raise InvalidMeshcorePacket("Packet length too short:", len(packet))

        packettype = (packet[0] >> 2) & 0x0F

        if packettype == cls.TYPE_REQ:
            p = MC_Req(packet, selfid, ids)
        elif packettype == cls.TYPE_RESPONSE:
            p = MC_Response(packet, selfid, ids)
        elif packettype == cls.TYPE_TXT_MSG:
            p = MC_Text(packet, selfid, ids)
        elif packettype == cls.TYPE_ACK:
            p = MC_Ack(packet)
        elif packettype == cls.TYPE_ADVERT:
            p = MC_Advert(packet)
        elif packettype == cls.TYPE_GRP_TXT:
            p = MC_GroupText(packet, channels)
        elif packettype == cls.TYPE_GRP_DATA:
            p = MC_GroupData(packet, channels)
        elif packettype == cls.TYPE_ANON_REQ:
            p = MC_AnonReq(packet, selfid)
        elif packettype == cls.TYPE_PATH:
            p = MC_Path(packet, selfid, ids)
        elif packettype == cls.TYPE_TRACE:
            p = MC_Trace(packet)
        else:
            p = MC_Unknown(packet)

        p.rssi = rssi
        p.snr = snr

        return p
        
    def __str__(self):
        return f"Incoming packet: rssi={self.rssi}, snr={self.snr}\n" + super().__str__()

    def __repr__(self):
        return f"MC_Incoming(packet={self.version}, {self.type}, {self.route}, rssi={self.rssi}, snr={self.snr})"

    def __len__(self):
        return len(self.packet)
            


class MC_Unknown(MC_Incoming):
    """
    Unknown packet type. Could still be repeated
    """
    def __str__(self):
        return f"Unknown packet type ({self.typename})\n" + super().__str__()

class MC_Outgoing(MC_Packet):
    """
    MC_Outgoing Class

    Base class of all outbound Meshcore packets.
    """

    def __init__(self, type=None, path=None):
        super().__init__()

        if type is None:
            raise ValueError("Packet type needs to be set")
        
        if path is None:
            # Flood
            self.route = self.ROUTE_FLOOD
        else:
            # Direct path
            # If [], then zero-hop broadcast
            self.route = self.ROUTE_DIRECT
            # Check for [] directly, as it's convenient to provide it to a function, but it's
            # not a bytes/bytearray
            if path == [] or isinstance(path, bytes):
                self.path = bytearray(path)
            elif isinstance(path, bytearray):
                self.path = path
            else:
                raise ValueError("Path must be bytes or bytearray")
            if len(path) > 63:
                raise ValueError("Path is too long")

        self.header |= (type << 2) | (self.VER_1 << 6)


    def flood(self):
        """
        Change the route type to flood. Useful for the final retry of a send after
        direct messages have failed
        """
        self.path = bytearray()
        self.route = self.ROUTE_FLOOD


    def __str__(self):
        return f"{self.__class__.__name__}({self.typename}, {self.routename}, path: {pathstr(self.path, self.is_flood())})\n"

    def __repr__(self):
        return f"{self.__class__.__name__}({self.typename}, {self.routename})"

    def __len__(self):
        return len(self.packet)


    # Get the next hop from the path
    def nexthop(self):
        if self.route == self.ROUTE_DIRECT and len(self.path):
            return self.path[0]
        else:
            return None


class MC_Advert(MC_Incoming):
    """
    Meshcore Advert Class
    """
    def __init__(self, packet):
        """
        Scan the packet for information.
        """
        super().__init__(packet)
        
        # Check for valid packet length
        # Minimum is pubkey (32) + timestamp (4) + signature (64) + flags (1)
        self.minpayload(101)

        self.advert = AdvertData(self._payload)
        
        if self.advert is None:
            raise InvalidMeshcorePacket("Advert data not found.")
        
    def __str__(self):
        s = super().__str__()
        if self.advert is not None:
            s += str(self.advert)
        else:
            s += "No advert data found.\n"
        return s


class MC_Advert_Outgoing(MC_Outgoing):
    """
    Meshcore Advert Class for outgoing adverts

    Sends the advert data of the (Self)Identity
    flood = whether to send a flood, or zero-hop direct advert
    """
    def __init__(self, identity, flood=False):
        super().__init__(self.TYPE_ADVERT, None if flood else bytes())
        self.identity = identity

    def compute_payload(self):
        return self.identity.data


class MC_SrcDest(MC_Incoming):
    """
    General class for Meshcore packets with source and destination hashes and a MAC

    These are used for TXT_MSG, REQ, RESPONSE, and PATH packets.
    """
    def __init__(self, packet, selfid, ids):
        """
        Scan the packet for information.
        """
        super().__init__(packet)
        # Check for valid payload length
        # Minimum is source hash (1) + dest hash (1) + MAC (2) + encrypted data (at least 16)
        self.minpayload(20)

        # Destination and source hashes are 1 byte each, MAC is 2 bytes
        (self.dsthash, self.srchash) = struct.unpack('BB', self._payload[0:2])
        self.mac = bytes(self._payload[2:4])
        self.encryptedpacketdata = self._payload[4:]
        self.source = None
        self.packetdata = None

        # Attempt to decrypt the packet data using the given identity, and store it in self.packetdata

        if self.dsthash != selfid.hash:
            logger.debug(f"Destination hash {self.dsthash:02x} does not match us ({selfid.hash:02x})")
            return

        logger.debug(f"Attempting to decrypt packet from {self.srchash:02x}")

        for identity in ids.find_by_hash(self.srchash):
            if identity.sharedsecret is None:
                continue

            data = MACanddecrypt(identity.sharedsecret, self.mac, self.encryptedpacketdata)

            if data is not None:
                self.packetdata = data
                self.source = identity
                # This packet has reached its destination, so don't repeat it (if we're a repeater)
                self.repeat = False
                logger.debug(f"Decrypted using shared secret with {self.source.name}")
                break
        else:
            logger.debug("Could not decrypt")

    # Whether or not we were able to decrypt the message
    @property
    def decrypted(self):
        return self.packetdata is not None

    def __str__(self):
        s = super().__str__()
        s += f"Source hash: {self.srchash:02x}"
        if self.source is not None:
            s += f" ({self.source.name})"
        s += f"\nDestination hash: {self.dsthash:02x}, MAC: {self.mac.hex()}\n"
        s += f"Packet data length: {len(self.encryptedpacketdata)}, data: {self.encryptedpacketdata.hex()}\n"
        if self.packetdata is not None:
            s += f"Unencryted data: {self.packetdata.hex()}\n"
        else:
            s += "Unable to decrypt packet data\n"

        return s

class MC_Text(MC_SrcDest):
    """
    Meshcore Text Class
    """
    def __init__(self, packet, selfid, ids):
        super().__init__(packet, selfid, ids)

        if self.packetdata is not None:
            # The encrypted packet has been decoded
            (self.timestamp, self.flags) = struct.unpack('<LB', self.packetdata[0:5])
            text = self.packetdata[5:].rstrip(b'\x00')

            # Attempt number was originally 0-3 and stored in the bottom 2 bits of the flags.
            # Now it can be more; if it's >3 then it is stored in the last byte of the data,
            # after the null-terminated text
            #
            # eg, H E L L O \0 \0 = Text
            #     H E L L O \0 \4 = Text, plus attempt number (4+1)
            if len(text) > 1 and text[-2] == 0:
                self.attempt = text[-1]
                text = text[0:-2]
                logger.debug(f"Long attempt number: {self.attempt}")
            else:
                self.attempt = self.flags & 3

            self.text = text

            self.my_pubkey = selfid.private_key.public_key

    @property
    def txt_type(self):
        # Rest of flags is the text type (eg, TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA)
        return self.flags >> 2

    # Calculate a 4-byte hash which we, the receiver, should return to prove we got the message
    def message_ackhash(self):
        # 4 bytes of SHA256 hash of timestamp, flags, message and sender's public key
        # UNLESS the incoming text is from a room server; then it uses the recipient (ie. our) key
        if self.txt_type == self.TXT_TYPE_SIGNED_PLAIN:
            ackdata = self.packetdata.rstrip(b'\x00') + self.my_pubkey
        else:
            ackdata = self.packetdata.rstrip(b'\x00') + self.source.pubkey
        return ackhash(ackdata) # Function in crypto module

    def __str__(self):
        s = super().__str__()
        if self.packetdata is not None:
            s += f"Flags: {self.flags}, Timestamp: {self.timestamp} ({time.ctime(self.timestamp)}), Ackhash: {hexlify(self.message_ackhash()).decode()}"
            s += f"\nText: {self.text.decode('utf-8', errors='replace')}\n"
        return s

class MC_Response(MC_SrcDest):
    """
    Meshcore Response Class

    Sent in response to a req/anonreq. The data depends on the request
    """
    def __init__(self, packet, selfid, ids):
        super().__init__(packet, selfid, ids)

    # Retrieve the packet data as object.response; this interface is shared with the MC_Path class where that
    # contains a response. Returns None if the packet is not decoded.
    @property
    def response(self):
        return self.packetdata

    def __str__(self):
        s = super().__str__()
        if self.packetdata is not None:
            if len(self.packetdata) > 4:
                timestamp = struct.unpack("<L", self.packetdata[0:4])[0]
            s += f"Timestamp {timestamp} ({time.ctime(timestamp)})\nRemaining data: {hexlify(self.packetdata[4:]).decode()}\n"
        return s


class MC_Path(MC_SrcDest):
    """
    Meshcore Path Class

    Sent by a recipient in response to a flood message, showing how the message arrived (ie the direct path to that recipient)
    Optionally contains an acknowledgement of the message, instead of sending a separate ACK, or a response, instead
    of sending a separate RESPONSE
    """
    def __init__(self, packet, selfid, ids):
        super().__init__(packet, selfid, ids)

        self.ackhash = None
        self.response = None

        if self.packetdata is not None:
            pathlen = self.packetdata[0]
            # If pathlen = 0 (direct), pathdata = []
            self.pathdata = self.packetdata[0:pathlen]

            self.extra_type = None
            # Gather up anything left after the path
            extra = self.packetdata[pathlen+1:]

            # If there is more data, and the first byte is not 0 (because the unencrypted data is zero padded)
            # or 0xff (indicates the remaining data is just random filler)
            if len(extra)==0 or extra[0]==0 or extra[0]==0xff:
                return

            extra_type = extra[0]

            if extra_type == self.TYPE_ACK:
                if len(extra) >= 5:
                    # At least (because the data is zero-padded to 16 bytes) 5 bytes of type+data
                    self.extra_type = extra_type
                    self.ackhash = bytes(extra[1:5])
                else:
                    raise InvalidMeshcorePacket("Ack packet payload is not 4 bytes")

            elif extra_type == self.TYPE_RESPONSE:
                if len(extra) >= 6:
                    # At least (because the data is zero-padded to 16 bytes) 6 bytes of type+timestamp+data
                    self.extra_type = extra_type
                    # Set self.response to the remaining data (will be None if there is not a RESPONSE; this
                    # interface is shared with MC_Response)
                    self.response = extra[1:]   # 4 bytes of timestamp, plus whatever response to the Req/AnonReq
                else:
                    raise InvalidMeshcorePacket("Response payload is too short")
            else:
                raise InvalidMeshcorePacket("Unknown extra data type")

    def __str__(self):
        s = super().__str__()
        if self.packetdata is None:
            return s
        
        s += f"Path: Length {len(self.pathdata)}"
        if len(self.pathdata):
            s += f", path = {pathstr(self.pathdata)}"

        if self.extra_type is not None:
            s += f"\nExtra data, type: {self.extra_type}"

            if self.extra_type == self.TYPE_ACK:
                s += f", ackhash: {hexlify(self.ackhash).decode()}"
            elif self.extra_type == self.TYPE_RESPONSE:
                s += f", response:  {hexlify(self.response).decode()}"
                if len(self.response) > 4:
                    timestamp = struct.unpack("<L", self.packetdata[0:4])[0]
                    s += f"\nTimestamp {timestamp} ({time.ctime(timestamp)})\n"
                    s += f"Remaining data: {hexlify(self.packetdata[4:]).decode()}"

        s += "\n"
        return s


class MC_Req(MC_SrcDest):
    """
    Meshcore Request class
    """
    def __init__(self, packet, selfid, ids):
        super().__init__(packet, selfid, ids)

        if self.packetdata is not None:
            # The encrypted packet has been decoded
            # Timestamp (4 bytes), request (1 byte)
            # Reserved (4 bytes), random blob (4 bytes)  <- these 2 are ignored
            (self.timestamp, self.request) = struct.unpack('<LB', self.packetdata[0:5])
            self.data = self.packetdata[5:]

    def __str__(self):
        s = super().__str__()
        if self.packetdata is not None:
            s += f"Request: {self.request}, Timestamp: {self.timestamp} ({time.ctime(self.timestamp)})"
            s += f"\nRequest data: {hexlify(self.data).decode()}\n"
        return s



class MC_SrcDest_Out(MC_Outgoing):
    """
    General class for outbound Meshcore packets with source and destination hashes,
    a MAC and data encrypted with a shared secret known to the source and destination

    These are used for TXT_MSG, REQ, RESPONSE, and PATH packets.
    """
    def __init__(self, src, dest, type=None):
        # How to reach the destination (None = Flood, [...] = direct path)
        # Defaults to flood until updated by a PATH packet from the destination
        path = dest.path

        super().__init__(type, path)
        self.src = src
        self.srchash = src.hash
        self.destination = dest
        self.dsthash = dest.hash

        self.mac = None

    def compute_payload(self):
        # Packet payload is a source and destination hash, 2-byte MAC and AES-128 encrypted message
        encrypted_payload = encryptandMAC(self.destination.sharedsecret, self.plaintext_data())

        return bytes([self.dsthash, self.srchash]) + encrypted_payload

    # Whatever data is to be encrypted, depending on the packet type, as a byte array
    def plaintext_data(self):
        raise NotImplementedError('This needs to be implemented in a derived class')

    def __str__(self):
        s = super().__str__()
        s += f"Source hash: {self.srchash:02x}, Destination: {self.dsthash:02x} ({self.destination.name})\n"
        return s

class MC_Text_Out(MC_SrcDest_Out):
    """
    Meshcore Text Class for outbound text messages

    Parameters:
    * src - source (ie, SelfIdentity for this client)
    * dest - destination (ie, Identity including shared secret)
    * text - message text
    * type - mesage type (Plain, CLI data, signed), defaults to TXT_TYPE_PLAIN (0)
    * attempt - attempt number, 0-4 (normally; corresponding to attempts 1-5)
    * timestamp - message timestamp. Defaults to now.
    """
    def __init__(self, src, dest, text, txt_type=MC_Packet.TXT_TYPE_PLAIN, attempt=0, timestamp=None):
        super().__init__(src, dest, self.TYPE_TXT_MSG)

        logger.debug(f"Create MC_Text_Out, type {txt_type}, attempt {attempt}")
        if isinstance(text,str):
            self.text = text.encode()
        else:
            # Bytes
            self.text = text

        # Default timestamp is now
        self.timestamp = timestamp or unique_time()

        self.txt_type = txt_type
        self.attempt = attempt

    # Attempt number (bits 0,1) and text type (bits 2+)
    @property
    def flags(self):
        return (self.attempt & 3) + (self.txt_type << 2)

    # Return the plaintext which needs to be encrypted for transmission
    # The encryption function will take care of packing to 16 bytes
    def plaintext_data(self):
        # 4 byte timestamp, 1 byte flags, text as UTF-8 bytes
        data = struct.pack("<LB", self.timestamp, self.flags) + self.text
        # If attempt number is >3, we need to add an extra byte at the end of the text, preceded
        # by a null byte, to store the attempt number
        # There is a small risk of exceeding the maximum message length if the text is already
        # at the maximum length; the caller should ensure this doesn't happen. However, if it
        # does, truncate the text to make it fit
        if self.attempt > 3:
            if len(data) >= self.MAX_TEXT_MESSAGE-1:
                logger.warning("Text message too long; truncating to fit attempt number")
                data = data[0:self.MAX_TEXT_MESSAGE-2]
            data += bytes([0, self.attempt])

        return data

    # Calculate a 4-byte hash which the receiver should return to prove it got the message
    # Plain text messages are acked with the sender's public key, while signed (ie room server)
    # messages are acked with the recipeint's public key
    # CLI messages are not acked, but we need to generate something to compare in case an ack does
    # come back for any reason
    def message_ackhash(self):
        if self.txt_type == self.TXT_TYPE_SIGNED_PLAIN:
            # 4 bytes of SHA256 hash of timestamp, flags, message and recipient (ie their) public key
            ack = self.plaintext_data() + self.destination.pubkey
        else:
            # 4 bytes of SHA256 hash of timestamp, flags, message and sender (ie our) public key
            ack = self.plaintext_data() + self.src.private_key.public_key
        return ackhash(ack) # Function in crypto module        

    def __str__(self):
        s = super().__str__()
        s += f"Timestamp: {self.timestamp} ({time.ctime(self.timestamp)})\n"
        s += f"Flags: {self.flags}\n"
        s += f"Text: {self.text}\n"
        s += f"Expected ackhash: {hexlify(self.message_ackhash()).decode()}\n"
        return s


class MC_Path_Out(MC_SrcDest_Out):
    """
    Meshcore Path class for outbound paths, with optional ACK/RESPONSE data

    Parameters:
    * src - source (ie, SelfIdentity for this client)
    * dest - destination (ie, Identity including shared secret)
    * returnpath - path to send (ie, the path the inbound flood packet arrived on)
    * ackhash - optional ack hash for a received message
    * response - optional response to req/anonreq
    """
    def __init__(self, src, dest, returnpath, ackhash=None, response=None):
        super().__init__(src, dest, self.TYPE_PATH)
        
        # Save these values in case we want to print the packet
        self.returnpath = returnpath
        self.ackhash = ackhash
        self.response = response

        self.data = bytes([len(returnpath)]) + returnpath

        if ackhash is not None:
            self.data += bytes([self.TYPE_ACK]) + ackhash
 
        elif response is not None:
            self.data += bytes([self.TYPE_RESPONSE]) + response

        else:
            # Add a timestamp, to make the packet hash unique, if there's no other data
            # Denoted by the 'type' 0xff
            self.data += struct.pack("<BL", 0xff, unique_time())

    # Return the plaintext which needs to be encrypted for transmission
    # The encryption function will take care of packing to 16 bytes
    def plaintext_data(self):
        return self.data

    def __str__(self):
        s = super().__str__()
        s += f"Return path: {pathstr(self.returnpath)}\n"
        if self.ackhash:
            s += f"ACK: {hexlify(self.ackhash).decode()}\n"
        return s

class MC_Req_Out(MC_SrcDest_Out):
    """
    Meshcore Class for outbound requests

    Parameters:
    * src - source (ie, SelfIdentity for this client)
    * dest - destination (ie, AnonIdentity including shared secret)
    * request_type - REQ_TYPE...
    * data - request data
    """
    def __init__(self, src, dest, request_type, data, timestamp=None):
        super().__init__(src, dest, self.TYPE_REQ)

        # Requests are prefixed with a timestamp
        self.timestamp = timestamp if timestamp else unique_time()
        self.request_type=request_type
        self.data = data

    # Return the plaintext which needs to be encrypted for transmission
    # The encryption function will take care of packing to 16 bytes
    def plaintext_data(self):
        # 4 byte timestamp, request type, data
        return struct.pack("<LB", self.timestamp, self.request_type) + self.data

    def __str__(self):
        s = super().__str__()
        s += f"Timestamp: {self.timestamp} ({time.ctime(self.timestamp)})\n"
        s += f"Request type: {self.request_type}, request data: {hexlify(self.data).decode()}\n"
        return s


class MC_Response_Out(MC_SrcDest_Out):
    """
    Meshcore Class for outbound responses to REQ/ANON_REQ packets

    Parameters:
    * src - source (ie, SelfIdentity for this client)
    * dest - destination (ie, AnonIdentity including shared secret)
    * data - response data
    """
    def __init__(self, src, dest, data, timestamp=None):
        super().__init__(src, dest, self.TYPE_RESPONSE)
        
        # Responses are prefixed with a timestamp
        self.timestamp = timestamp or unique_time()
        self.data = data

    # Return the plaintext which needs to be encrypted for transmission
    # The encryption function will take care of packing to 16 bytes
    def plaintext_data(self):
        # 4 byte timestamp, data
        return struct.pack("<L", self.timestamp) + self.data

    def __str__(self):
        s = super().__str__()
        s += f"Timestamp: {self.timestamp} ({time.ctime(self.timestamp)})\n"
        s += f"Data: {hexlify(self.data).decode()}\n"
        return s


class MC_Ack(MC_Incoming):
    """
    Acknowledgement of a received message

    Sent in response to a direct message (ie, one where the path is known).
    If the sender sent the message as a flood, the ack is instead included
    as part of a return PATH message
    """
    def __init__(self, packet):
        super().__init__(packet)
        """
        Scan the packet for information.
        """
        # Ack hashes are 4 bytes
        if len(self._payload) != 4:
            raise InvalidMeshcorePacket("Ack packet payload is not 4 bytes")
        self.ackhash = bytes(self._payload)

    def __str__(self):
        return super().__str__() + f"Ackhash: {hexlify(self.ackhash).decode()}\n"


class MC_Ack_Outgoing(MC_Outgoing):
    """
    Acknowledge an incoming text message by sending the ackhash back - a 4-byte hash (first 4 bytes of SHA256) of the message
    plus the sender's public key, to prove that we got the message, could decode it successfully, and know who the sender is

    Input:
        * packet - the message to acknowledge, as we can extract the ackhash from there
        * path - path to return the ack via
    """
    def __init__(self, packet:MC_Text, path=[]):
        super().__init__(self.TYPE_ACK, path)

        self.ackhash = packet.message_ackhash()

    def compute_payload(self):
        return self.ackhash

    def __str__(self):
        s = super().__str__()
        s += f"ACK: {hexlify(self.ackhash).decode()}\n"
        return s


class MC_Group(MC_Incoming):
    """
    Meshcore Group Class

    This class represents a Meshcore Group packet. There are two types of group packets:
     * Group Text (GRP_TXT): A group text message
     * Group Data (GRP_DATA): A group data message - not sure what this is for
    Packets are sent to channels, which are identified by a hash of the channel key.
    """
    def __init__(self, packet, channels):
        super().__init__(packet)
        
        self.channel = None
        self.plaintext = None

        if (len(self._payload) -3) % 16 != 0:
            raise InvalidMeshcorePacket("Invalid encryted data length")

        # Find the channel in the list of channels.

        if channels is None or len(channels) == 0:
            logger.debug("No channels to match incoming message to")
            return

        logger.debug("Searching for channel")
        for channel in channels:
            if channel.empty:
                # Skip empty channel slot
                continue

            plaintext = channel.decrypt(self._payload)
            if plaintext is not None:
                self.plaintext = plaintext
                self.channel = channel
                logger.debug(f"Channel message matched channel {channel.strname}")
                break
        else:
            logger.debug("Channel message did not match any channel")

    # Whether or not we were able to decrypt the message
    @property
    def decrypted(self):
        return self.plaintext is not None


class MC_GroupText(MC_Group):
    """
    Meshcore Group Text Class

    This class represents a Meshcore Group Text packet. It contains the group text message.
    """
    def __init__(self, packet, channels):
        super().__init__(packet, channels)
        self._msg = None

    @property
    def message(self):
        if self._msg is None:
            if self.plaintext is not None:
                self._msg = GroupTextMessage(self.plaintext)
        return self._msg

    def __str__(self):
        s = super().__str__()
        if self.channel is None:
            s += "No channel found.\n"
        else:
            s += f"Channel: {self.channel.strname}\n"
            message = self.message
            s += f"Timestamp: {message.timestamp} ({time.ctime(message.timestamp)})\n"
            s += f"Message: {message.message.decode(errors='replace')}\n"

        return s

class MC_GroupData(MC_Group):
    """
    Meshcore Group Data Class

    This class represents a Meshcore Group Data packet. It contains the group message.
    """
    def __str__(self):
        s = super().__str__()
        if self.channel is None:
            s += "No channel found.\n"
        else:
            s += f"Channel: {self.channel.strname}\n"
            message = GroupTextMessage(self.plaintext)
            s += f"Timestamp: {message.timestamp} ({time.ctime(message.timestamp)})\n"
            s += f"Message: {message.message.decode(errors='replace')}\n"

        return s

class MC_Group_Outgoing(MC_Outgoing):
    """
    Meshcore Group Class

    This class represents a Meshcore Group packet. There are two types of group packets:
     * Group Text (GRP_TXT): A group text message
     * Group Data (GRP_DATA): A group data message - not sure what this is for
    Packets are sent to channels, which are identified by a hash of the channel key.
    """

    def __init__(self, channel:Channel, plaintext=None, type=MC_Packet.TYPE_GRP_TXT):
        # All group messages are flooded, so don't set a path
        # If we really wanted to do something else, we could change the path before sending
        super().__init__(type)
        self.channel = channel
        self.plaintext = plaintext

    def compute_payload(self):
        """
        Get the payload of the packet.
        """
        if self.plaintext is not None and self.channel is not None:
            return self.channel.encrypt(self.plaintext)
        
        raise InvalidMeshcorePacket("Packet incomplete, plaintext or channel is missing")

    def __str__(self):
        s = super().__str__()
        s += f"Message: {self.plaintext}\n"
        return s


class MC_GroupText_Outgoing(MC_Group_Outgoing):
    """
    Meshcore Group Text Class

    This class represents a Meshcore Group Text packet. It contains the group text message.
    """
    def __init__(self, channel:Channel, message, timestamp=None, messagetype=GroupTextMessage.TXT_TYPE_PLAIN):
        super().__init__(channel)

        grouptextmessage = GroupTextMessage(None, message, timestamp,messagetype)

        self.plaintext = grouptextmessage.messagedata


class MC_AnonReq(MC_Incoming):
    """
    Anonymous request from a potentially unknown client. It knows our public key, and supplies
    its own public key to calculate a shared secret

    """
    def __init__(self, packet, selfid):
        """
        Scan the packet for information.
        """
        super().__init__(packet)

        # Check for valid packet length
        # Minimum is dest (1), sender pubkey (32), MAC (2), encrypted data (min 16)
        self.minpayload(51)

        # Destination hash - 1 byte
        # Sender public key - 32 bytes
        # MAC - 2 bytes
        # Encrypted data (multiple of 16 bytes)
        #    Client timestamp (4 bytes)
        #    Client last seen (4 bytes)
        #    Password
        #    Padding to nearest 16 bytes
        self.dsthash = self._payload[0]
        self.senderpubkey = bytes(self._payload[1:33])     # 32 bytes of public key
        self.mac = bytes(self._payload[33:35])      # 2 byte MAC
        self.encryptedpacketdata = self._payload[35:]

        self.packetdata = None
        self.timestamp = None
        self.synctime = None
        self.password = None

        logger.debug("Attempting to decrypt ANON_REQ")

        if self.dsthash != selfid.hash:
            logger.debug(f"Destination hash {self.dsthash:02x} does not match us ({selfid.hash:02x})")
            return

        # Attempt to decrypt the packet data using the supplied key, and our identity (to generate a shared secret)
        self.sharedsecret = selfid.private_key.shared_secret(self.senderpubkey)
        
        data = MACanddecrypt(self.sharedsecret, self.mac, self.encryptedpacketdata)

        if data is not None:
            self.packetdata = data
            if selfid.devicetype == AdvertType.ROOM:
                # This is a room server - anon requests contain a "last sync" time
                (self.timestamp, self.synctime) = struct.unpack('<LL', data[0:8])
                self.password = data[8:].rstrip(b'\00')     # Remove 0-padding
            else:
                # Just contains a timestamp and password
                self.timestamp = struct.unpack('<L', data[0:4])[0]
                self.password = data[4:].rstrip(b'\00')     # Remove 0-padding
            # This packet has reached its destination, so don't repeat it (if we're a repeater)
            self.repeat = False
            logger.debug("Decrypt successful")
        else:
            logger.debug("Decrypt failed")

    # Whether or not we were able to decrypt the message
    @property
    def decrypted(self):
        return self.packetdata is not None

class MC_AnonReq_Out(MC_Outgoing):
    """
    Anonymous request to a server. We have its public key (eg from an advert), and supply
    our own public key to calculate a shared secret
    Parameters:
        src - source id
        dest - destination id
        password - can be blank
        since - optional, if logging into room server
    """
    def __init__(self, src, dest, password, since=None):

        # Path to destination is taken from the destination Identity
        super().__init__(self.TYPE_ANON_REQ, dest.path)
        self.src = src
        self.srchash = src.hash
        self.destination = dest
        self.dsthash = dest.hash

        self.password = password
        self.since = since

        self.mac = None

    def compute_payload(self):
        # Packet payload is destination hash, source (our) public key, 2-byte MAC and AES-128 encrypted message
        encrypted_payload = encryptandMAC(self.destination.sharedsecret, self.plaintext_data())

        return bytes([self.dsthash]) + self.src.private_key.public_key + encrypted_payload

    def plaintext_data(self):
        # Timestamp, sync timestamp (messages since; if present), password
        if self.since is None:
            return struct.pack("<L", unique_time()) + self.password

        return struct.pack("<LL", unique_time(), self.since) + self.password

    def __str__(self):
        s = super().__str__()
        s += f"Source hash: {self.srchash:02x}, Destination: {self.dsthash:02x} ({self.destination.name})\n"
        if self.since:
            s += f"Room server messages since: {self.since} ({time.ctime(self.since)})"
        s += f"Password: {self.password}"
        return s


class MC_Trace(MC_Incoming):
    """
    Trace requests are direct packets (non-flooded) which pass from repeater to repeater
    following the path in the trace. Each repeater records the SNR of the packet it receieved.

    Trace packets are not flooded
    """
    def __init__(self, packet):
        """
        Scan the packet for information.
        """
        super().__init__(packet)

        # At least 10 bytes: tag (4), auth (4), flag (1) and at least one path element (1 byte each)
        self.minpayload(10)

        # No more than 64 path elements
        if len(self.payload) > 8+1+64:
            raise InvalidMeshcorePacket("Too long")
        
        self.tag = self.payload[0:4]
        self.auth = self.payload[4:8]
        self.flags = self.payload[8]
        self.tracepath = self.payload[9:]

    def __str__(self):
        s = super().__str__()
        s += f"Packet data: {hexlify(self.payload).decode()} ({len(self.payload)} bytes)"
        s += f"\nTrace tag: {hexlify(self.tag).decode()}"
        s += f"\nAuth code: {hexlify(self.auth).decode()}"
        s += f"\nFlags: {self.flags}"
        s += f"\nPath: {pathstr(self.tracepath)}"
        s += f"\nSNR: {[snr/4 for snr in struct.unpack('b' * len(self.path), self.path)]}"
        return s


class MC_Trace_Out(MC_Outgoing):
    """
    Trace requests are direct packets (non-flooded) which pass from repeater to repeater
    following the path in the trace. Each repeater records the SNR of the packet it receieved.

    Trace packets are not flooded
    """
    def __init__(self, path, tag, auth=0, flags=0):
        """
        Parameters:
        * tag - 4-byte tag for this trace
        * auth - 4-byte auth code
        * flags - not sure what is set here, Meshcore doesn't seem to use it
        """
        # Create a packet, direct, 0 hop
        super().__init__(self.TYPE_TRACE, path=[])

        if isinstance(tag, bytes) or isinstance(tag, bytearray):
            if len(tag) == 4:
                self.tag = tag
            else:
                raise ValueError("tag must be 4 bytes")
        elif isinstance(tag, int):
            self.tag = struct.pack("<L", tag)
        else:
            raise ValueError("tag must be bytes or int")
        
        if isinstance(auth, bytes) or isinstance(auth, bytearray):
            if len(auth) == 4:
                self.auth = auth
            else:
                raise ValueError("auth must be 4 bytes")
        elif isinstance(auth, int):
            self.auth = struct.pack("<L", auth)
        else:
            raise ValueError("auth must be bytes or int")

        if isinstance(flags, bytes) or isinstance(flags, bytearray):
            if len(flags) == 1:
                self.flags = flags
            else:
                raise ValueError("flags must be 1 byte")
        elif isinstance(flags, int):
            self.flags = struct.pack("<B", flags)
        else:
            raise ValueError("flags must be bytes or int")

        # Can't call it self.path, that's the packet's path in the header (which, for
        # a TRACE, is a zero-hop direct path)
        self.tracepath = bytes(path)
        if len(self.tracepath) < 1:
            raise ValueError("Path is too short")
        if len(self.tracepath) > 64:
            raise ValueError("Path is too long")
        
    # Trace payload consists of
    # tag - 4 bytes
    # auth - 4 bytes
    # flags 1 bytes
    # path to trace - 1-64 bytes
    def compute_payload(self):
        return self.tag + self.auth + self.flags + self.tracepath


    def __str__(self):
        s = super().__str__()
        s += f"Path: {hexlify(self.tracepath).decode()}, ({len(self.tracepath)} hops)"
        s += f"\nTrace tag: {hexlify(self.tag).decode()}"
        s += f"\nAuth code: {hexlify(self.auth).decode()}"
        s += f"\nFlags: {hexlify(self.flags).decode()}"

        return s
