
import asyncio
from aiotools import current_taskgroup
import threading
import time
from binascii import unhexlify, hexlify
from collections import deque

from .interface import Interface
from configuration import ConfigView, get_config

from LoRaRF import SX126x

import logging
logger = logging.getLogger(__name__)

# DIO3 TCXO control settings
# SetDio3AsTcxoCtrl
#    DIO3_OUTPUT_1_6                        = 0x00        # DIO3 voltage output for TCXO: 1.6 V
#    DIO3_OUTPUT_1_7                        = 0x01        #                               1.7 V
#    DIO3_OUTPUT_1_8                        = 0x02        #                               1.8 V
#    DIO3_OUTPUT_2_2                        = 0x03        #                               2.2 V
#    DIO3_OUTPUT_2_4                        = 0x04        #                               2.4 V
#    DIO3_OUTPUT_2_7                        = 0x05        #                               2.7 V
#    DIO3_OUTPUT_3_0                        = 0x06        #                               3.0 V
#    DIO3_OUTPUT_3_3                        = 0x07        #                               3.3 V
#    TCXO_DELAY_2_5                         = 0x0140      # TCXO delay time: 2.5 ms
#    TCXO_DELAY_5                           = 0x0280      #                  5 ms
#    TCXO_DELAY_10                          = 0x0560      #                  10 ms

DIO3_VOLTAGE = {
    1.6: 0x00,
    1.7: 0x01,
    1.8: 0x02,
    2.2: 0x03,
    2.4: 0x04,
    2.7: 0x05,
    3.0: 0x06,
    3.3: 0x07
}

TCXO_DELAY = {
    2.5: 0x0140,
    5: 0x0280,
    10: 0x0560
}

class LoRaInterface(Interface):
    """
    Communicate with a directly connected LoRa interface

    """
    def __init__(self, config:ConfigView):
        super().__init__() 
        self._name = "SX126x device interface"

        # Flag to signal when data has been transmitted
        self.txdone = asyncio.Event()
        # Last transmit duration (ms)
        self.txtime = 0

        # Fetch all the config we need
        # Default config is UK/EU Narrow
        config.set_default(get_config({
            "frequency": 869618000, "sf": 8, "bw":62500, "cr":8,
            "txpower":22, "airtime": 10,
            # WaveShare SX1262 HAT for Raspberry Pi
            "spi":0, "cs": 0, "irq":16, "busy":20, "reset":18, "txen": 6
        }))

        self.freq = config.get("frequency")
        self.sf = config.get("sf")
        self.bw = config.get("bw")
        self.cr = config.get("cr")
        self.txpower = config.get("txpower")
        airtime = config.get("airtime", 10)

        spi = config.get("spi")
        cs = config.get("cs")
        irq = config.get("irq")
        busy = config.get("busy")
        reset = config.get("reset")
        txen = config.get("txen", -1)
        rxen = config.get("rxen", -1)
        wake = config.get("wake", -1)

        dio3_voltage = config.get("dio3.voltage", None)
        dio3_txco_delay = config.get("dio3.tcxo_delay", None)

        dio2_rfswitch = config.get("dio2.rfswitch", False)

        if (dio3_voltage is not None and dio3_txco_delay is None) or (dio3_voltage is None and dio3_txco_delay is not None):
            raise ValueError("Both dio3.voltage and dio3.tcxo_delay must be set to enable DIO3 control")

        self.LoRa = SX126x()

        if not self.LoRa.begin(spi, cs, reset, busy, irq, txen, rxen, wake):
            logger.error("LoRa interface did not start")
            # FIXME - need a better exception
            raise ValueError("LoRa interface did not start")

        self.LoRa.setFrequency(self.freq)
        self.LoRa.setTxPower(self.txpower)
        self.LoRa.setRxGain(self.LoRa.RX_GAIN_BOOSTED)
        # SF, BW, CR, LDRO (low data rate optimization; off)
        self.LoRa.setLoRaModulation(self.sf, self.bw, self.cr, False)

        # DIO3 as TCXO control (optional)
        if dio3_voltage is not None:
            d3v = DIO3_VOLTAGE.get(dio3_voltage, None)
            d3t = TCXO_DELAY.get(dio3_txco_delay, None)
            if d3v is None or d3t is None:
                raise ValueError("Invalid dio3.voltage or dio3.tcxo_delay value")

            self.LoRa.setDio3TcxoCtrl(d3v, d3t)

        # DIO2 as RF switch control (optional)
        if dio2_rfswitch:
            self.LoRa.setDio2RfSwitch(True)

        self.LoRa.setLoRaPacket(self.LoRa.HEADER_EXPLICIT, 16, 255, True, False)
        self.LoRa.setSyncWord(0x12)

        self.airtime_dutycycle = airtime     # % duty cycle (default 10%)

        self.airtime_txtimestamp = deque([0,0,0,0,0], maxlen=5)
        self.airtime_txtime = deque([0,0,0,0,0], maxlen=5)

        logger.debug(f"Configired LoRa interface on SPI{spi}:{cs} for {self.freq/1000000:0.3f}MHz, BW: {self.bw/1000}KHz, SF: {self.sf}, CR: {self.cr}")

    # Receive thread
    #
    # FIXME: This thread busywaits on data from the LoRa chip. This could be a setting I've missed,
    # or it might just be how the library works. Either way, it sits there using up an entire core.
    # Need either better config, a better library, or to rewrite the current one so it behaves nicely.
    def rx_thread(self):
        logger.debug("LoRa rx thread listening")

        self.LoRa.request(self.LoRa.RX_CONTINUOUS)
    
        s = ["STATUS_DEFAULT", "STATUS_TX_WAIT", "STATUS_TX_TIMEOUT", "STATUS_TX_DONE", "STATUS_RX_WAIT", "STATUS_RX_CONTINUOUS", "STATUS_RX_TIMEOUT", "STATUS_RX_DONE", "STATUS_HEADER_ERR", "STATUS_CRC_ERR", "STATUS_CAD_WAIT", "STATUS_CAD_DETECTED", "STATUS_CAD_DONE"]
        while True:
            self.LoRa.wait()

            status = self.LoRa.status()
            logger.debug(f"Status: {s[status]}")

            if status == self.LoRa.STATUS_RX_DONE:
                logger.debug(f"Packet received, {self.LoRa.available()} bytes")

                data = bytearray()

                while self.LoRa.available():
                    data.append(self.LoRa.read())

                rssi = self.LoRa.packetRssi()
                snr = self.LoRa.snr()

                self.eventloop.call_soon_threadsafe(self.rx_q.put_nowait, (data,rssi,snr))
                logger.debug(f"Packet data, {hexlify(data).decode()}")
                continue

            elif status == self.LoRa.STATUS_CRC_ERR:
                logger.info("RX packet CRC error")
                continue
            elif status == self.LoRa.STATUS_HEADER_ERR:
                logger.info("RX packet header error")
                continue

            elif status == self.LoRa.STATUS_TX_DONE:
                self.eventloop.call_soon_threadsafe(self.tx_done, self.LoRa.transmitTime())

            self.LoRa.request(self.LoRa.RX_CONTINUOUS)

    # FIXME race condition here - what is the proper timeout for a transmission?
    def tx_done(self, tx_time):
        self.txtime = tx_time
        self.txdone.set()

    def transmit_wait(self):
        # Based on the last 5 transmissions, are we within the duty cycle limit?
        tx_earliest = self.airtime_txtimestamp[0]

        # How long since the first transmission in the log?
        tx_period = time.time() - tx_earliest
        # Total time (ms)
        tx_total = sum(self.airtime_txtime)
        duty_cycle = 100*(tx_total/1000)/tx_period

        if tx_earliest > 0:
            # We have recorded 5 transmissions
            logger.debug(f"Duty cycle for last {len(self.airtime_txtimestamp)} transmissions: {duty_cycle:0.2f}%")

        # Sleep until the duty cycle would be less than 10% (or whatever airtime_dutycycle is)
        # Rather than wait until we hit the duty cycle limit and then sleep, if the duty cycle is half
        # the limit (eg, 5%), sleep for half the required time. If it's a quarter, sleep for 25% of the
        # required time. This will have the effect of spreading out the wait periods, rather than
        # transmitting a bunch of packets then a long pause
        for c in range(3):
            fraction = 1/(1<<c)     # 1/1, 1/2, 1/4
            airtime_dutycycle = self.airtime_dutycycle * fraction

            if duty_cycle > airtime_dutycycle:
                tx_min = (tx_earliest + (tx_total/1000)/(airtime_dutycycle / 100) - time.time()) * fraction

                if tx_min>0:
                    logger.debug(f"Sleep for {tx_min:0.2f} seconds for duty cycle compliance ({airtime_dutycycle}%)")
                    return tx_min

        return 0

    async def transmit(self, packetdata):
        logger.debug(f"Transmitting: {hexlify(packetdata).decode()}")
                
        self.txdone.clear()
        self.txtime = 0

        self.LoRa.beginPacket()
        self.LoRa.put(packetdata)
        self.LoRa.endPacket()

        try:
            await asyncio.wait_for(self.txdone.wait(), 5)

            logger.debug("Transmit time: {0:0.2f} ms".format(self.txtime))

            self.airtime_txtimestamp.append(time.time())
            self.airtime_txtime.append(self.txtime)

        except TimeoutError:
            logger.debug("Transmit timed out")
    
        self.txdone.clear()
        return self.txtime

    # Return a tuple containing frequency (kHz), bandwidth (Hz), spreading factor, coding rate,
    # tx power (dBm), maximum tx power (dBm)
    def get_radioconfig(self):
        return (self.freq//1000, self.bw, self.sf, self.cr, self.txpower, 27)

    async def start(self):
        self.eventloop = asyncio.get_running_loop()
        # Start the receiver in its own thread as it's not asynchronous, make it a daemon thread so it
        # doesn't stop the program terminating
        self.rxthread = threading.Thread(target=self.rx_thread, daemon=True)
        self.rxthread.start()
