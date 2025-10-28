
import asyncio
import time
from aiotools import current_taskgroup

import serial_asyncio

from binascii import unhexlify, hexlify
import struct

from configuration import ConfigView

from .interface import Interface

import logging
logger = logging.getLogger(__name__)

CMD_APP_START = 1
CMD_GET_DEVICE_TIME = 5
CMD_SET_DEVICE_TIME = 6
CMD_SET_RADIO_PARAMS = 11
CMD_SET_RADIO_TX_POWER = 12
CMD_REBOOT = 19
CMD_GET_BATTERY_VOLTAGE = 20
CMD_SET_TUNING_PARAMS = 21
CMD_DEVICE_QUERY = 22
CMD_SET_OTHER_PARAMS = 38

# Naughty extra command
CMD_SEND_RAW_PACKET = 0xc0

PUSH_CODE_LOG_RX_DATA = 0x88

RESP_CODE_ERR = 1
RESP_CODE_SELF_INFO = 5

RESP_CODE_DEVICE_INFO = 13

ERR_CODE_UNSUPPORTED_CMD = 1

class CompanionInterface(Interface):
    """
    This is a slightly perverse class which uses an existing companion
    radio as an interface.

    Using the PUSH_LOG_RX_DATA mechanism, which sends a copy of any recieved
    packet from the companion radio to the app, we can use an unmodified
    companion radio as a receive-only interface.

    A lightly modified radio with an unofficial extra CMD (CMD_SEND_RAW_PACKET,
    0xc0, definitely not approved by any Meshcore developers) can be used as
    a transceiver.
    """

    def __init__(self, config:ConfigView):
        super().__init__()
        self._name = "Companion radio interface"

        self._reader = None
        self._writer = None

        self._connected = False

        self._interface = config.get('port', '/dev/ttyUSB0')

        if self._interface is None:
            raise ValueError("No serial port specified for companion interface")

        # Radio configuration parameters, to taken from the companion radio
        # on connection
        self.freq = 0
        self.bw = 0
        self.sf = 0
        self.cr = 0
        self.txpower = 0
        self.txmaxpower = 0

        # If we can't transmit, tell the user only once
        self.txwarned = False

    # Send frame to radio
    async def tx(self, frame):
        logger.debug(f"Sending frame: {hexlify(frame).decode()} (len: {len(frame)})")
        framelength = struct.pack("<H", len(frame))

        if self._writer is None:
            logger.debug("No serial connection to companion radio")
            return
        
        try:
            self._writer.write(b'<')
            self._writer.write(framelength)
            self._writer.write(frame)
            await self._writer.drain()
        except Exception as e:
            logger.error(f"Error writing to companion radio serial port: {repr(e)}")
            self._connected = False
            return

        logger.debug("Data sent to companion radio")

    # Recieve frame from radio
    async def rx(self):
        try:
            while True:
                logger.debug("Waiting for frame")
                # Fetch one byte. Hopefully it's a '>'
                r = await self._reader.readexactly(1)

                if r != b'>':
                    # Not a start of frame
                    junkdata = r
                    while True:
                        try:
                            # Keep reading until we hit a > or data stops arriving (1 second pause)
                            r = await asyncio.wait_for(self._reader.readexactly(1), 1)
                            if r == b'>':
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
                r = await asyncio.wait_for(self._reader.readexactly(2), 1)
                size = struct.unpack("<H", r)[0]

                r = await asyncio.wait_for(self._reader.readexactly(size), 5)

                logger.debug(f"Received frame, {len(r)} bytes")

                return r

        except TimeoutError:
            logger.warning("Timed out waiting frame")
            raise
        except Exception as e:
            logger.error(f"Error reading from companion radio serial port: {repr(e)}")
            raise


    async def do_radiointerface(self):
        # Set up connection to companion radio
        try:
            self._reader,self._writer = await serial_asyncio.open_serial_connection(url=self._interface, baudrate=115200)
        except Exception as e:
            logger.error(f"Unable to open companion serial port {self._interface}: {repr(e)}")
            _connected = False
            raise

        # CMD_DEVICE_QUERY, API version (3)
        # Need some timeouts here
        await self.tx(bytes([CMD_DEVICE_QUERY, 3]))
        frame = await self.rx()

        if len(frame) < 20 or frame[0] != RESP_CODE_DEVICE_INFO:
            logger.error(f"Invalid response to device query from companion radio: {hexlify(frame).decode()}")
            self._connected = False
            return

        logger.debug(f"Connected: version {frame[1]}, device: {frame[8:20].rstrip(bytes(1)).decode(errors='replace')}")
        # CMD_APP_START, version, 6 reserved bytes, app name (string)
        await self.tx(bytes([CMD_APP_START, 1, 0,0,0,0,0,0]) + b'CompanionInterface')
        frame = await self.rx()
        if len(frame) and frame[0] == RESP_CODE_SELF_INFO:
            logger.debug(f"Started: {hexlify(frame).decode()}")
        else:
            logger.error(f"Invalid response to app start from companion radio: {hexlify(frame).decode()}")
            self._connected = False
            return

        # Decode self-info response
        #  code: byte,   // constant: 5
        #  type: byte,   // one of ADV_TYPE_*
        #  tx_power_dbm: byte    // current TX power, in dBm
        #  max_tx_power: byte,     // max TX power radio supports
        #  public_key: bytes(32),
        #  adv_lat: int32,   // advert latitude * 1E6
        #  adv_lon: int32,   // advert longitude * 1E6
        #  multi_acks: byte,     // 0 = no extra ACKs, 1 = send extra ACK
        #  advert_loc_policy: byte,    // 0 = don't share, 1 = share
        #  telemetry_modes: byte,    // bits: 0..1 = Base mode, bits: 2..3 = Location mode. (modes: 0 = DENY, 1 = apply contact.flags, 2 = ALLOW ALL)
        #  manual_add_contacts: byte,    // 0 or 1
        #  radio_freq: uint32,    // freq * 1000
        #  radio_bw: uint32,      // bandwidth(khz) * 1000
        #  radio_sf: byte,        // spreading factor
        #  radio_cr: byte,        // coding rate
        #  name: varchar   // remainder of frame

        self.txpower = frame[2]
        self.txmaxpower = frame[3]
        self.freq, self.bw, self.sf, self.cr = struct.unpack("<LLBB", frame[48:58])

        self.companionname = frame[58:].rstrip(b'\0').decode(errors='replace')

        logger.info(f"Companion radio interface connected: {self.companionname}, freq: {self.freq} kHz, bw: {self.bw} Hz, SF: {self.sf}, CR: {self.cr}, tx power: {self.txpower} dBm (max {self.txmaxpower} dBm)")

        self._connected = True

        while True:
            frame = await self.rx()
            logger.debug(f"Received frame: {hexlify(frame).decode()}")

            if len(frame) == 2 and frame[0] == RESP_CODE_ERR:
                if frame[1] == ERR_CODE_UNSUPPORTED_CMD:
                    # The only command we're sending is CMD_SEND_RAW_PACKET, so any error relates to that
                    logger.error("Companion radio does not support CMD_SEND_RAW_PACKET, cannot transmit")
                    if not self.txwarned:
                        print("Companion radio is receive-only; transmit disabled")
                        self.txwarned = True
                else:
                    logger.error(f"Error response from companion radio: {frame[1]}")
                continue

            if len(frame) < 3:
                logger.warning("Received frame from companion radio is too short")
                continue

            if frame[0] == PUSH_CODE_LOG_RX_DATA:
                logger.debug("PUSH_CODE_LOG_RX_DATA")

                snr,rssi = struct.unpack("<bb", frame[1:3])
                snr = snr / 4
                await self.rx_q.put((frame[3:], rssi, snr))

    async def radiointerface(self):
        # Main radio interface loop
        # Try to connect to the companion radio, and if we lose the connection, retry
        # after a delay
        delay = 1

        while True:
            start = time.time()
            try:
                await self.do_radiointerface()
            except Exception as e:
                logger.error(f"Companion radio interface error: {repr(e)}")

            self._connected = False

            elapsed = time.time() - start
            if elapsed > 2:
                # Connection lasted more than 2 seconds, reduce delay
                delay = delay - int(elapsed)
                if delay < 1:
                    delay = 1
            elif delay < 60:
                delay *= 2

            logger.info(f"Companion radio interface disconnected, retrying in {delay} seconds")
            await asyncio.sleep(delay)


    async def transmit(self, tx_packet):
        """
        Transmit packet. Sends it to the companion, which takes care of queuing it, transmitting it, etc.
        Transmit time isn't something we can usefully obtain from this process
        """
        if self._connected:
            logger.debug("Sending packet to companion radio")
            await self.tx(bytes([CMD_SEND_RAW_PACKET]) + tx_packet)
        else:
            logger.warning("Cannot send, companion radio not connected")

        return 0

    def transmit_wait(self):
        """
        Period of time until the airtime duty cycle falls below the threshold
        0 if the threshold is not exceeded
        The companion radio takes care of this. If we overfill the radio's TX queue, it will bin off the excess packets
        """
        return 0

    # Return a tuple containing frequency (kHz), bandwidth (Hz), spreading factor, coding rate,
    # tx power (dBm), maximum tx power (dBm)
    # This is taken from the companion radio
    def get_radioconfig(self):
        return (self.freq, self.bw, self.sf, self.cr, self.txpower, self.txmaxpower)

    async def start(self):

        current_taskgroup.get().create_task(self.radiointerface(), name="Companion radio interface")
