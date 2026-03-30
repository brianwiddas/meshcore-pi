
import asyncio
import struct
from aiotools import current_taskgroup
from itertools import cycle

from binascii import unhexlify, hexlify

from .interface import Interface
from misc import fletcher16

import sys
sys.path.append("./lib/ESPythoNOW")

from ESPythoNOW import *


import logging
logger = logging.getLogger(__name__)

class ESPNOWInterface(Interface):
    """
    Send and recieve via ESP-NOW using a compatible wifi interface

    * interfacename     - WiFi interface to use for ESP-NOW
    * secret            - Optional secret to use for bridging packets to other interfaces.
    * plain             - whether to send/receive unencrypted packets
    If the secret is set, the interface will behave like a MeshCore bridge, and will only talk to
    other bridges using the same secret.

    If plain is true, the bridge will send/receive in the clear. The bridge can do both
    (WiFi is fast and ESP-NOW packets are small).

    If plain is None, it will be set to True if secret is not set and False otherwise

     * Packet Structure:
     * [2 bytes] Magic Header - Used to identify ESPNowBridge packets
     * [2 bytes] Fletcher-16 checksum of encrypted payload (calculated over payload only)
     * [246 bytes max] Encrypted payload containing the mesh packet

    If the secret is not set, the interface will accept all packets and will not perform
    any encryption or decryption. In this mode, a bridge packet is likely to appear as junk
    and will be discarded when packet.py attempts to process it. This mode is for exchanging
    packets with ESP-NOW companion radios.
    """

    BRIDGE_PACKET_MAGIC = 0xC03E

    def __init__(self, interfacename, secret=None, plain=None):
        super().__init__() 
        self._name = "ESP-NOW interface"

        self.espnow = None

        self.interfacename = interfacename
        self.secret = secret

        # If "plain" is None, set it to True if "secret" is None, False otherwise
        if plain is None:
            self.plain = secret is None
        else:
            self.plain = plain

        if self.secret is None and not self.plain:
            logger.warning("Secret is not set, but plaintext is disabled. This interface will not send or receive any packets.")


    def xor(self, data):
        """
        XOR the data with the secret, repeating the secret as necessary
        """

        key = cycle(self.secret.encode())
        return bytes(a ^ b for a, b in zip(data, key))

    def rx_callback(self, from_mac, to_mac, msg):
        # Don't really care about the MAC addresses, just the message

        rssi = self.espnow.packet.dBm_AntSignal
        # SNR doesn't seem to be available
        snr = 0

        logger.debug(f"ESP-NOW packet from {from_mac} @{rssi}dBm: {hexlify(msg).decode()}")

        # Encrypted bridge packet? First two bytes are a magic value
        # The magic number for an encrypted packet (0xc03e) is not a valid Meshcore packet
        # header. It would correspond to
        # * version 3
        # * type 0 (request)
        # * flood route with transport codes
        # * plus first byte of a transport code, with the next 3 bytes (checksum
        #   and first byte of packet, encrypted), forming an (invalid) transport code
        # So if it has the magic value, it's safe to assume it's encrypted
        if struct.unpack(">H", msg[0:2])[0] == self.BRIDGE_PACKET_MAGIC:
            if self.secret is None:
                logger.debug("Received encrypted bridge packet, but no secret set. Ignoring")
                return

            # Minimum length is 2 bytes for the magic value, 2 for the checksum, and 1 for the payload
            if len(msg) < 5:
                logger.debug("Received too-short encrypted packet on secret-enabled ESP-NOW interface, ignoring")
                return

            # This interface is expecting bridged packets encrypted with a secret
            # First 2 bytes of the message are a magic value to identify the packet as a bridged packet
            # Decrypt the rest of the payload using the secret, and verify the checksum
            xormsg = self.xor(msg[2:])

            # First 2 bytes of the payload are a Fletcher-16 checksum of the rest of it, used to verify the secret is correct
            checksum = struct.unpack(">H", xormsg[0:2])[0]
            payload = xormsg[2:]

            if fletcher16(payload) != checksum:
                logger.info("Received packet with correct magic value but invalid checksum on secret-enabled ESP-NOW interface, ignoring")
                return

        else:
            # This is a plaintext packet from an ESP-NOW companion
            if not self.plain:
                logger.debug("Received plaintext ESP-NOW packet on encrypted-only interface, ignoring")
                return

            # Accept the message as it is
            payload = msg

        self.eventloop.call_soon_threadsafe(self.rx_q.put_nowait, (payload,rssi,snr))

    async def transmit(self, packetdata):
        logger.debug(f"Transmitting: {hexlify(packetdata).decode()}")

        if self.espnow is None:
            logger.warning("ESP-NOW interface is not running, not transmitting")
            return

        # Send encrypted and/or plaintext packets, depending on settings.
        # It's fine to send both, there are no airtime limits to worry about and WiFi is fast
        if self.secret is not None:
            # Send encypted packet
            # First two bytes are magic value, followed by
            # [ 2 bytes of Fletcher-16 checksum on payload
            #   Payload ]  XORed with the secret
            xormsg = self.xor(struct.pack(">H", fletcher16(packetdata)) + packetdata)
            encryptedpacket = struct.pack(">H", self.BRIDGE_PACKET_MAGIC) + xormsg
            self.espnow.send("FF:FF:FF:FF:FF:FF", encryptedpacket)
            logger.debug("Sent encrypted ESP-NOW packet")

        if self.plain:
            self.espnow.send("FF:FF:FF:FF:FF:FF", packetdata)
            logger.debug("Sent plaintext ESP-NOW packet")

        # Transmit time not available, but also not important as there are no airtime restrictions
        return 0

    async def start(self):
        self.eventloop = asyncio.get_running_loop()

        espnow = ESPythoNow(interface=self.interfacename, accept_all=True, callback=self.rx_callback)

        # Start the ESP-NOW interface
        espnow.start()

        # Is it running?
        espnow.listener.thread.join(timeout=1)

        if espnow.listener.thread.is_alive():
            logger.info("ESP-NOW interface started")
            self.espnow = espnow
        else:
            logger.warning("ESP-NOW interface failed to start")
            raise RuntimeError("ESP-NOW interface failed to start")
