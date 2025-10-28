import asyncio
from aiotools import current_taskgroup

from exceptions import *
from interfaces.interface import Interface

from binascii import hexlify

from hashlib import sha256
from collections import defaultdict

from time import time, ctime

from packet import MC_Packet

import logging
logger = logging.getLogger(__name__)

class SeenPacket:
    """
    Record a packet's duplicate count and any callback to carry out
    """
    def __init__(self):
        self.count = 0
        self.callback = None
        self.time = time()
    def __repr__(self):
        return f"SeenPacket ({self.count}, CB: {self.callback})"


class Dispatch:
    """
    This class deals with sending and receiving packets, including prioritising and discarding delayed transmissions
    """

    PRIORITY_TOP = 1
    PRIORITY_MESSAGE = 2
    PRIORITY_CHANNEL = 3
    PRIORITY_ADVERT = 4
    PRIORITY_REPEAT = 5
    PRIORITY_ROOMTRAFFIC = 6
    PRIORITY_SCHEDULED_ADVERT = 7
    PRIORITY_LOWEST = 8

    def __init__(self):

        # Transmit queue, for outbound packets, including priority and timestamp
        # PriorityQueue works by removing data - typically a tuple of (priority, value) - from the queue
        # in sort order,  which means that lower priorities come first. Where two entries have the same
        # priority, they are removed in sort order of the value, which isn't what we want.
        #
        # Instead, we will store data in as (priority, timestamp, value), so where two items have the same
        # priority, the one which will time out first (typically, if the timeouts are the same, the one
        # which was stored first) will be retreived first.
        self.transmitqueue = asyncio.PriorityQueue()

        # Interfaces to send/receive packets
        self.interfaces = []

        # Which packets have we seen (for deduplication)
        self.seen = defaultdict(SeenPacket)

        # Special receive queue for moving packets between internal devices
        self.internal_rx = asyncio.Queue()

        # Whether or not to pass packets between internal devices or not
        # The default is False; it can be set to true if there are multiple devices which need to communicate
        # between themselves.
        # Even if True, only zero-hop (flood and direct) packets are passed
        self.pass_internal = False

        # Receive queues, one per "device", for incoming packets
        self.rx_queues = []

        # Total of airtime used (for stats)
        self.airtime = 0

    async def _queue_aggregator(self, queue, name):
        # Read from the interface's supplied queue and write to the rx_queues
        while True:
            d = await queue.get()
            logger.debug(f"Data from {name} queue: {d}")
            for rx_queue,name in self.rx_queues:
                try:
                    rx_queue.put_nowait(d)
                    logger.debug(f"Written data to queue for {name}, entries in queue: {rx_queue.qsize()}")
                except asyncio.QueueFull:
                    logger.error(f"Device queue for {name} is full")
    

    def add_interface(self, iface:Interface):
        """
        Add an interface to be used for sending/receiving
        """
        self.interfaces.append(iface)
        current_taskgroup.get().create_task(self._queue_aggregator(iface.rx_q, name=iface.name), name="Dispatcher inbound queue: "+iface.name)

    def add_queue(self, device_name="unnamed device"):
        """
        Create a queue for the device (ie. whatever is recieving packets from the air)
        Typically, this is one device (companion radio, repeater, etc), but this gives us the
        option to run several devices on one shared radio 
        """
        # Each queue is 50 items long. If the queue fills, something has gone seriously wrong
        # with whatever is supposed to be draining it.
        queue = asyncio.Queue(maxsize=50)

        self.rx_queues.append((queue, device_name))

        logger.debug(f"Added receive queue for {device_name}")

        return queue

    def packethash(self, p: MC_Packet, extra=b""):
        """
        Generate an 8-byte hash of the packet contents, taking the first 8 bytes of a SHA256
        of the packet header and payload, so we know if we've seen this packet before.

        Excludes the path from calculations, as that can change as the packet is repeated

        'extra' is added to the mix, which allows for different devices to maintain their
        own "seen" lists in the same table
        """
        type = p.type
        hash = sha256(bytes([type]))

        if type == p.TYPE_TRACE:
            # Trace packets can legitimately be seen more than once (eg, on the way back)
            # The packet payload will be the same, but the path will be different as that's
            # where the trace SNR values get stored, so include the path length in the hash
            hash.update(bytes([p.pathlen]))

        hash.update(bytes(p.payload))
        hash.update(extra)

        return hash.digest()[0:8]
    
    def hasSeen(self, p: MC_Packet, callback=None, extra=b"", checkonly=False):
        """
        Have we already seen this packet in the last ~60 seconds?
        
        * p - packet
        * callback - optional function to call when a duplicate is seen
        * checkonly - optional, if True check whether we've seen the packet but don't do anything else
        """
        hash = self.packethash(p, extra)

        dupe = self.seen[hash]

        if checkonly:
            return dupe.count > 0

        if dupe.count:
            # Number of times we've already had this packet >0
            if dupe.callback is not None:
                dupe.callback(hash, dupe.count)
            dupe.count +=1

            return True
        else:
            dupe.count=1
            dupe.callback = callback

            return False

    async def tablecleantask(self):
        """
        Clear out the seen table - anything older than 60 seconds can be deleted
        """
        while True:
            deletetime = time() - 60
            clean = []

            # Iterate over the dict finding all the values older than 60s
            # Keep a list of which ones to delete - can't delete in place
            # as python3 doesn't like it
            for k,v in self.seen.items():
                if v.time < deletetime:
                    clean.append(k)
                
            if clean:
                for k in clean:
                    self.seen.pop(k)

                logger.debug("tablecleantask removed %s items(s)", len(clean))

            await asyncio.sleep(60)


    def queue(self, tx_packet:MC_Packet, priority=PRIORITY_LOWEST, timeout=None):
        """
        Queue a packet for transmission

        Record the packet's contents so we can see if it comes back to us, along with a callback to
        be called if it does

        Unsent packets are discarded after the timeout interval
        This defaults to 10 seconds multiplied by the priority, on the assumption that lower priority
        (higher "priority" number) packets are less time-sensitive (eg. scheduled adverts)
        """

        if timeout is None:
            logger.debug(f"No timeout specified, using default ({10 * priority} seconds)")
            timeout = 10 * priority

        # Record what this packet looks like, so we don't send it more than once
        # This is only likely if multiple devices are attached to one dispatcher, and
        # one of them is a repeater
        if self.hasSeen(tx_packet):
            logger.debug("This packet has been sent already")

            if tx_packet.sent is not None:
                tx_packet.sent.cancel()

        else:
            self.transmitqueue.put_nowait((priority, time()+timeout, tx_packet))

    async def queue_get(self):
        """
        Retrieve the first, highest priority item from the queue
        If it has timed out, throw it away and get the next one
        Items are retrieved by priority first, then timestamp
        As the timestamp is the time the message times out, items with the same
        priority are retrieved in the order they will time out. If they all have
        the same timeout (default 5 sec), this will effectively retrieve them in
        the order they went in.
        """
        while True:
            data = await self.transmitqueue.get()
            (priority, timeout, tx_packet) = data
            logger.debug(f"Retrieved data from queue, priority {priority}, timeout {ctime(timeout)}: {hexlify(tx_packet.packet).decode('utf8')}")

            if timeout < time():
                logger.debug("Packet has timed out, discarding")
                
                if tx_packet.sent is not None:
                    tx_packet.sent.cancel()

                continue

            return tx_packet

    def queue_length(self):
        """
        Length of the transmit queue (ie, number of untransmitted items)
        """
        return self.transmitqueue.qsize()


    async def tx_queue_run(self):
        while True:
            # Sleep if any of the tx interfaces are exceeding their duty cycle limit
            try:
                dutycycle_sleep = max([i.transmit_wait() for i in self.interfaces])
                if dutycycle_sleep > 0:
                    await asyncio.sleep(dutycycle_sleep)
            except ValueError:
                # Ignore any problems caused by bad values or an empty list
                pass

            # Fetch the next thing to send, if any
            tx_packet = await self.queue_get()

            # Transmit data on all interfaces
            tx_times = await asyncio.gather(*[i.transmit(tx_packet.packet) for i in self.interfaces])

            # Send to other devices attached to the dispatcher
            # Packets are only sent from one device to another if their path length is zero, ie
            # they are originated locally and are flooded, or direct. Anything else is either
            # meant for somewhere else, or originated externally and has already been received.
            # The "True" flag marks it as an internal packet
            #
            # Only actually do this if self.pass_internal is set, and there is more than one
            # rx_queue (ie, more than just one device; otherwise, there's no point)
            if self.pass_internal and len(tx_packet.path) == 0 and len(self.rx_queues) > 1:
                self.internal_rx.put_nowait((tx_packet.packet, True))

            # Set the sent Future, so anything waiting for this packet to be sent knows it has been
            if tx_packet.sent is not None:
                tx_packet.sent.set_result(True)

            # Add the largest transmit time (probably LoRa, if there is more than one interface)
            # to the airtime total
            self.airtime += max(tx_times) / 1000    # Airtime from interfaces is in ms

    # Get the current radio configuration from the best interface (ie, a LoRa one, if present)
    # in order to pass it to the app
    def get_radioconfig(self):
        logger.debug("Radio config requested")

        for i in self.interfaces:
            if hasattr(i, "get_radioconfig"):
                logger.debug(f"Using radio config from interface {i.name}")
                radioconfig = i.get_radioconfig()
                logger.debug(f"Radio config: {radioconfig}")
                return radioconfig

        # No interface has a get_radioconfig method
        logger.debug("No interface has radio config information, returning zeros")

        # (frequency, bandwidth, spreading factor, coding rate, tx power, max tx power)
        return (0, 0, 0, 0, 0, 0)

    async def start(self):
        current_taskgroup.get().create_task(self.tx_queue_run(), name="Dispatcher TX queue runner")
        current_taskgroup.get().create_task(self.tablecleantask(), name="Dispatcher duplicates table cleanup")
        current_taskgroup.get().create_task(self._queue_aggregator(self.internal_rx, name="internal"), name="Dispatcher internal queue")


# While it's possible to have multiple dispatchers, you probably only want one
_default_dispatch = None

def default_dispatch():
    global _default_dispatch
    if _default_dispatch is None:
        _default_dispatch = Dispatch()

    return _default_dispatch
