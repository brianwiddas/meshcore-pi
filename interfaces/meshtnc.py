
import asyncio
import time
from aiotools import current_taskgroup

import serial_asyncio

from binascii import unhexlify, hexlify

from configuration import ConfigView, get_config
from .interface import Interface

import logging
logger = logging.getLogger(__name__)

class TNCException(Exception):
    """
    Exception for any kind of problem arising from communicating with
    a MeshTNC interface
    """
    pass


class MeshTNC(Interface):
    """
    Use a radio running MeshTNC as an interface.

    https://github.com/datapartyjs/MeshTNC/

    The MeshTNC firmware provides a simple serial protocol for sending
    and receiving raw LoRa packets. It also supports KISS, but if we
    use that, we don't get RSSI and SNR data.
    """

    def __init__(self, config:ConfigView):
        super().__init__()
        self._name = "MeshTNC radio interface"

        self._reader = None
        self._writer = None

        # Command responses from MeshTNC
        self._rx_cli = asyncio.Queue()

        self._connected = False

        self.lastpacket = b''

        # Fetch all the config we need
        # Default config is UK/EU Narrow
        config.set_default(get_config({
            "frequency": 869618000, "sf": 8, "bw":62500, "cr":8,
            "port": "/dev/ttyUSB0"
        }))

        self._interface = config.get('port')

        self.freq = config.get("frequency")
        self.sf = config.get("sf")
        self.bw = config.get("bw")
        self.cr = config.get("cr")
        logger.debug(f"MeshTNC interface config: freq={self.freq}, sf={self.sf}, bw={self.bw}, cr={self.cr}")


    # Send command to radio, await response
    async def tx(self, command):
        logger.debug(f"Sending command: {command.decode(errors='replace')}")

        if self._writer is None:
            logger.debug("No serial connection to MeshTNC radio")
            return
        
        try:
            self._writer.write(command)
            # Commands are terminated by carriage return
            self._writer.write(b'\r')
            await self._writer.drain()

            response = await asyncio.wait_for(self._rx_cli.get(), timeout=1)
            # Should be the command echoed back to us. If it takes more than
            # a second, something's wrong
            if response != command:
                logger.warning(f"Unexpected response from MeshTNC radio: {response.decode(errors='replace')}")
                return

            response = await asyncio.wait_for(self._rx_cli.get(), timeout=1)
            # Response, should begin with ->
            # Unless it's a txraw command, which starts with the sent data
            # Again, should not take more than a second
            arrowindex = response.find(b'-> ')
            if arrowindex == -1:
                logger.warning(f"Unexpected response from MeshTNC radio: {response.decode(errors='replace')}")
                self._connected = False
                return

            return response[arrowindex+3:]  # Strip off the '-> ' and anything preceding it

        except Exception as e:
            logger.error(f"Error communicating with MeshTNC: {repr(e)}")
            return


    # Recieve data from radio
    async def rx_loop(self):
        try:
            while True:
                l = await self._reader.readuntil(b'\r')

                # Remove whitespace, including newline and carriage return
                line = l.lstrip().rstrip()

                logger.debug("Read line from MeshTNC: " + line.decode(errors='replace'))

                # Should be either command echoed back to us,or a command response,
                # or an RXLOG line
                # RXLOG lines look like this:
                # 1715773375,RXLOG,-51.00,12.50,1500A6CDD697BD91C3BB0919F56B53971654C6EC7491FEC8C0511471CE88853688C7A864B3
                # (timestamp, RXLOG, RSSI, SNR, hex data)

                # RXLOG lines start with a digit (the timestamp), check we're not getting the
                # last packet returned to us
                if (not line.startswith(self.lastpacket)) and line[0:1].isdigit():
                    # RXLOG line
                    parts = line.split(b',')
                    if len(parts) < 5 or parts[1] != b'RXLOG':
                        logger.warning(f"Invalid RXLOG line from MeshTNC: {line.decode(errors='replace')}")
                        continue

                    try:
                        rssi = int(float(parts[2]))
                        snr = float(parts[3])
                        data = unhexlify(parts[4])
                    except Exception as e:
                        logger.warning(f"Error decoding RXLOG line from MeshTNC: {line.decode(errors='replace')}, {repr(e)}")
                        continue

                    # Add the packet to the receive queue
                    await self.rx_q.put((data, rssi, snr))

                else:
                    # Command response, put it in the CLI response queue
                    await self._rx_cli.put(line)
        except Exception as e:
            logger.error(f"Error reading from MeshTNC serial port: {repr(e)}")
            self._connected = False


    async def radiointerface_loop(self):
        # Set up connection to MeshTNC radio
        try:
            self._reader,self._writer = await serial_asyncio.open_serial_connection(url=self._interface, baudrate=115200)
        except Exception as e:
            logger.error(f"Unable to open MeshTNC radio serial port {self._interface}: {repr(e)}")
            _connected = False
            raise

        rx_loop = current_taskgroup.get().create_task(self.rx_loop(), name="MeshTNC read loop")

        try:
            # Poke the MeshTNC radio and see if it responds
            response = await self.tx(b'ver')

            logger.debug(f"MeshTNC version: {response.decode(errors='replace')}")
            self._connected = True

            # Configure the radio parameters
            freq = self.freq/1000000 # MHz
            bw = self.bw/1000     # kHz
            # 12 = LoRa sync word for Meshcore, 0x12
            response = await self.tx(f"set radio {freq},{bw},{self.sf},{self.cr},12".encode('utf-8'))
            if response.count(b'OK') == 0:
                raise TNCException(f"MeshTNC radio configuration failed: {response.decode(errors='replace')}")

            logger.info(f"MeshTNC interface connected: freq: {freq} MHz, bw: {bw} kHz, SF: {self.sf}, CR: {self.cr}")

            # Wait for the rx_loop task to finish (it won't, unless there's an error)
            await rx_loop
        except Exception as e:
            rx_loop.cancel()
            raise

    async def radiointerface(self):
        # Main radio interface loop
        # Try to connect to the MeshTNC radio, and if we lose the connection, retry
        # after a delay
        delay = 1

        while True:
            start = time.time()
            try:
                await self.radiointerface_loop()
            except Exception as e:
                logger.error(f"MeshTNC interface error: {repr(e)}")

            self._connected = False

            elapsed = time.time() - start
            if elapsed > 2:
                # Connection lasted more than 2 seconds, reduce delay
                delay = delay - int(elapsed)
                if delay < 1:
                    delay = 1
            elif delay < 60:
                delay *= 2

            logger.info(f"MeshTNC interface disconnected, retrying in {delay} seconds")
            await asyncio.sleep(delay)


    async def transmit(self, tx_packet):
        """
        Transmit packet. Sends it to the MeshTNC radio, which takes care of
        queuing it, transmitting it, etc.
        Transmit time isn't something we can obtain from this process
        """
        if self._connected:
            logger.debug("Sending packet to MeshTNC radio")

            # Store this, because it should get sent back to us in an OK message
            self.lastpacket = hexlify(tx_packet).upper()

            response = await self.tx(b'txraw ' + self.lastpacket)
            if response is not None:
                logger.debug(f"MeshTNC txraw response: {response.decode(errors='replace')}")
            else:
                logger.warning("No response from MeshTNC radio on transmit")
        else:
            logger.warning("Cannot send, MeshTNC radio not connected")

        return 0

    def transmit_wait(self):
        """
        Period of time until the airtime duty cycle falls below the threshold
        0 if the threshold is not exceeded
        The MeshTNC radio takes care of this. If we overfill the radio's TX
        queue, it will bin off the excess packets
        """
        return 0

    # Return a tuple containing frequency (kHz), bandwidth (Hz), spreading factor, coding rate,
    # tx power (dBm), maximum tx power (dBm)
    def get_radioconfig(self):
        return (self.freq//1000, self.bw, self.sf, self.cr, 0, 0)

    async def start(self):
        current_taskgroup.get().create_task(self.radiointerface(), name="MeshTNC radio interface")
