import asyncio

from binascii import hexlify
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
    Communicate with a Meshcore app over wifi.

    Input frames are requests which should be responded to
    Output frames are a mixture of responses and asynchronous notifications

    See https://github.com/ripplebiz/MeshCore/wiki/Companion-Radio-Protocol for the format
    
    WiFi uses the same wire format as the serial device
    """

    def __init__(self, config):
        super().__init__()

        self.port = config.get('port', 5000)
        self.listen = config.get('listen', None)

        self._reader = None
        self._writer = None

        self._connected = asyncio.Event()

    # Inbound queue
    async def rx(self):
        while True:
            while self._writer is None:
                logger.debug("Waiting for client to connect")
                # Wait for the connection to be established
                await self._connected.wait()

            try:
                while True:
                    logger.debug("Waiting for frame")
                    # Fetch one byte. Hopefully it's a '<'

                    if True:    # config.timeout
                        # The companion app requests battery status every minute, so we should
                        # not go for much longer than that without seeing something
                        r = await asyncio.wait_for(self._reader.readexactly(1), 90)
                    else:
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

                        return r

                    except TimeoutError:
                        logger.warning("Timed out waiting frame")
            except asyncio.exceptions.IncompleteReadError:
                # The connection was lost
                logger.info("Connection to Meshcore app lost")
                self._writer = None
                self._connected.clear()
            except TimeoutError:
                # Connection time out
                logger.info("Connection to Meshcore app timed out")
                self._writer.close()
                self._writer = None
                self._connected.clear()
            except Exception as e:
                logger.error(f"Connection lost due to: {repr(e)}")
                self._writer = None
                self._connected.clear()
    

    async def tx(self, frame):
        if self._writer is None:
            logger.debug(f"Unable to send frame, client is disconnected: {hexlify(frame).decode()} (len: {len(frame)})")
            return
        
        logger.debug(f"Sending frame: {hexlify(frame).decode()} (len: {len(frame)})")
        framelength = struct.pack("<H", len(frame))
        
        try:
            self._writer.write(b'>')
            self._writer.write(framelength)
            self._writer.write(frame)
            await self._writer.drain()
        except Exception as e:
            logger.debug(f"Exception sending data: {repr(e)}")
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
            self._connected.clear()
            return

        logger.debug("Data sent to app device.")

    async def connected(self, reader, writer):
        addr = writer.get_extra_info('peername')[0]

        logger.debug(f"Connection callback - client has connected from {addr}")

        if self._writer is not None:
            logger.info("Client already connected, disconnecting")
            writer.close()
            return

        self._reader = reader
        self._writer = writer
        self._connected.set()
    
    async def start(self):
        result = await asyncio.start_server(self.connected, host=self.listen, port=self.port, backlog=1)

        # If anything's wrong, it should have raised an exception
        if result.is_serving():
            for addr in result.sockets:
                logger.debug(f"Server listening on {addr.getsockname()}")

