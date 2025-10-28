
import asyncio
from aiotools import current_taskgroup

from binascii import unhexlify, hexlify


from .interface import Interface

import sys
sys.path.append("./lib/ESPythoNOW")

from ESPythoNOW import *


import logging
logger = logging.getLogger(__name__)

class ESPNOWInterface(Interface):
    """
    Send and recieve via ESP-NOW using a compatible wifi interface

    * interfacename     - WiFi interface to use for ESP-NOW
    """
    def __init__(self, interfacename):
        super().__init__() 
        self._name = "ESP-NOW interface"

        self.espnow = ESPythoNow(interface=interfacename, accept_all=True, callback=self.rx_callback)

        # Start the ESP-NOW interface
        self.espnow.start()

        # Is it running?
        self.espnow.listener.thread.join(timeout=1)

        if self.espnow.listener.thread.is_alive():
            logger.info("ESP-NOW interface started")
        else:
            logger.warning("ESP-NOW interface failed to start")
            raise RuntimeError("ESP-NOW interface failed to start")


    def rx_callback(self, from_mac, to_mac, msg):
        # Don't really care about the MAC addresses, just the message

        rssi = self.espnow.packet.dBm_AntSignal
        # SNR doesn't seem to be available
        snr = 0

        logger.debug(f"ESP-NOW packet from {from_mac} @{rssi}dBm: {hexlify(msg).decode()}")

        self.eventloop.call_soon_threadsafe(self.rx_q.put_nowait, (msg,rssi,snr))

    async def transmit(self, packetdata):
        logger.debug(f"Transmitting: {hexlify(packetdata).decode()}")
                
        self.espnow.send("FF:FF:FF:FF:FF:FF", packetdata)

        # Transmit time not available, but also not important as there are no airtime restrictions
        return 0

    async def start(self):
        self.eventloop = asyncio.get_running_loop()

