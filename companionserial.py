import asyncio

import serial_asyncio

from binascii import unhexlify, hexlify
import struct

import logging
logger = logging.getLogger(__name__)

class BaseCompanionInterface:
    """
    Base class for sending and receiving frames of data to and from Meshcore apps
    """
    def __init__(self):
        pass

    async def rx(self):
        pass

    async def tx(self, frame):
        pass

    async def start(self):
        pass


class CompanionInterface(BaseCompanionInterface):
    """
    Communicate with a Meshcore app over serial port.

    Input frames are requests which should be responded to
    Output frames are a mixture of responses and asynchronous notifications

    See https://github.com/ripplebiz/MeshCore/wiki/Companion-Radio-Protocol for the format
    """

    def __init__(self, config):
        super().__init__()

        self._interface = config.get('port', '/dev/ttyS0')
        self._speed = config.get('speed', 115200)
        self.connected = False

    # Inbound queue
    async def rx(self):
        while True:
            logger.debug("Waiting for frame")
            # Fetch one byte. Hopefully it's a '<'
            r = await self._reader.readexactly(1)

            if r != b'<':
                # Not a start of frame
                junkdata = r
                while True:
                    try:
                        # Keep reading until we hit a < or data stops arriving (1 second pause)
                        r = await asyncio.wait_for(self._reader.readexactly(1), 1)
                        if r == b'<':
                            if len(junkdata):
                                logger.warning(f"Junk data before frame in companion serial data, {len(junkdata)} bytes: {hexlify(junkdata).decode()}")
                            break
                        junkdata += r
                    except TimeoutError:
                        if len(junkdata):
                            logger.warning(f"Junk data in companion serial data, {len(junkdata)} bytes: {hexlify(junkdata).decode()}")
                            # FIXME this needs improving
                        break


            # Next two bytes are the frame size
            try:
                r = await asyncio.wait_for(self._reader.readexactly(2), 1)
                size = struct.unpack("<H", r)[0]

                r = await asyncio.wait_for(self._reader.readexactly(size), 5)

                logger.debug(f"Received frame, {len(r)} bytes")

                # If we're receiving frames, we must be connected
                self.connected = True

                return r

            except TimeoutError:
                logger.warning("Timed out waiting frame")



    async def tx(self, frame):
        if not self.connected:
            logger.debug("Not connected to app via serial port, not sending frame")
            return

        logger.debug(f"Sending frame: {hexlify(frame).decode()} (len: {len(frame)})")
        framelength = struct.pack("<H", len(frame))

        self._writer.write(b'>')
        self._writer.write(framelength)
        self._writer.write(frame)
        try:
            # Drain the write buffer (ie, wait for it to be sent to the app)
            # If it takes more than a second, we've lost connection
            await asyncio.wait_for(self._writer.drain(), 1)
        except TimeoutError:
            logger.debug("Data not sent; connection lost")
            self.connected = False
            return

        logger.debug("Data sent to app device.")

    async def start(self):
        self._reader,self._writer = await serial_asyncio.open_serial_connection(url=self._interface, baudrate=self._speed)

