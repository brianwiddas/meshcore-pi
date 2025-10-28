import asyncio
from aiotools import current_taskgroup

from binascii import unhexlify, hexlify

from .interface import Interface

import logging
logger = logging.getLogger(__name__)

class MockInterface(Interface):
    """
    Mock interface class for testing purposes.

    Gets fake packets from a pretend network. Does not output
    """
    def __init__(self, file=None, repeat=False):
        super().__init__()
        self._name = "Mock interface class"

        self._file = open(file, 'r') if file else None
        self._repeat = repeat

    # Function to simulate receiving packets
    async def _rx_queue_runner(self):
        # Let things settle down before starting
        logger.debug("Mock interface started, sleeping 10 seconds before input")
        await asyncio.sleep(10)

        if self._file:
            while True:
                line = self._file.readline()
                if not line:
                    if self._repeat:
                        self._file.seek(0)
                    else:
                        break

                if (not line.startswith("#")) and len(line.strip()) > 0:
                    logger.debug(f"Mock packet: {line.strip()} (len: {len(line.strip())})")
                    # Simulate a packet by converting the hex string to bytes
                    await self.rx_q.put(unhexlify(line.strip()))

                    # 1 second delay to simulate network latency
                    logger.debug("Reading from mock interface...")
                    await asyncio.sleep(2)

            logger.warning("Reached the end of the mock input")
    
    async def transmit(self, output):
        # Simulate sending packets
        # In this mock implementation, we don't send anything
        logger.warning("Ignoring TX output: %s", hexlify(output).decode())
        return 0

    async def start(self):
        current_taskgroup.get().create_task(self._rx_queue_runner())
