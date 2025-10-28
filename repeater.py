
# Repeater

import asyncio
from aiotools import current_taskgroup
from binascii import unhexlify, hexlify

from exceptions import *
from clidevice import CLIDevice


import logging

logger = logging.getLogger(__name__)


class Repeater(CLIDevice):
    """
    Mesh for a repeater
    """
    def __init__(self, me, ids, dispatcher, hardware, config):
        super().__init__(me, ids, dispatcher, hardware, config)
        # This is a repeater
        self.repeater = True

        self.internalname = "Repeater"


    # Respond to a trace
    async def rx_trace(self, rx_packet):
        logger.debug("Trace packet")

        # Trace is 4+4+1 bytes (tag, auth, flags) plus a path
        # We only care about the path; the other bits are for the originating client
        if len(rx_packet.tracepath) == len(rx_packet.path):
            # Have reached the last hop. Repeaters don't originate traces(?), so ignore
            logger.debug("End of trace reached. Not for us.")
        elif len(rx_packet.tracepath) < len(rx_packet.path):
            # Packet path (SNR data) is longer than trace path - something is wrong
            raise InvalidMeshcorePacket("Trace data is longer than trace path")
        else:
            currenthop = rx_packet.tracepath[len(rx_packet.path)]
            logger.debug(f"Current hop is: {hex(currenthop)}")

            if currenthop == self.me.hash:
                # Current hop matches my pubkey hash, so this is (probably) for me
                # Add the current packet SNR to the path
                rx_packet.path += bytes([int(rx_packet.snr * 4) & 0xff])
                # And resend the packet
                current_taskgroup.get().create_task(self.transmit_packet(rx_packet))

