
import asyncio
from aiotools import current_taskgroup

from binascii import unhexlify, hexlify
import time
from collections import Counter

from groupchannel import Channel, GroupTextMessage, channels
import packet
from identity import Identity, IdentityStore, SelfIdentity
from exceptions import *
from ed25519_wrapper import ED25519_Wrapper
from dispatch import Dispatch
from misc import pathstr

import logging
logger = logging.getLogger(__name__)

class BasicMesh:
    """
    This is the basic mesh interface, which other types of mesh device can extend
    """

    def __init__(self, me:SelfIdentity, ids:IdentityStore, channels, dispatcher: Dispatch):
        self.me = me
        self.ids = ids
        self.channels = channels
        self.dispatch = dispatcher
        self.stats = Counter()
        self.repeater = False

        self.rx_queue = None

        # How this device is identified to the dispatcher; override in subclasses
        self.internalname = "Mesh device"

        self.version = "0.1"
        self.version_date = time.strftime('%Y-%m-%d')

        # Sent messages which are awaiting an ack
        # ackhash => Future()
        self.waiting_ack = {}

    # Stubs of various recive operations, to be overridden by subclasses

    # Receives all packets, even duplicates
    async def rx_raw(self, rx_packet):
        return

    # Packet received, after processing, including deduplicatiom
    async def rx(self, rx_packet):
        return

    async def rx_advert(self, rx_packet):
        # Default behaviour is to add the identity if it's valid;
        # Repeaters, etc, don't do this and should override this method

        id = Identity(rx_packet.advert, advertpath=rx_packet.path)
        id.create_shared_secret(self.me.private_key)

        result = self.ids.add_identity(id)
        if result:
            logger.debug("Identity added")

        return result

    async def rx_text(self, rx_packet:packet.MC_Text):
        return

    async def rx_path(self, rx_packet):
        return

    async def rx_req(self, rx_packet):
        return

    async def rx_anonreq(self, rx_packet):
        return

    async def rx_resposne(self, rx_packet):
        return

    async def rx_trace(self, rx_packet):
        return

    async def rx_grouptext(self, rx_packet):
        return


    # Sending messages direct to one recipient, including retries and processing ACKs

    # Wait for an ack reponse to a sent message
    async def await_ack(self, ackhash, sent, timeout=90):
        """
        Wait until 'sent' is done, then wait up to 'timeout' seconds for an ack
        """
        result = False
        try:
            ackfuture = asyncio.Future()
            self.waiting_ack[ackhash] = ackfuture

            await sent
            logger.debug(f"Packet for ack {hexlify(ackhash).decode()} has been sent")

            result = await asyncio.wait_for(ackfuture, timeout)

            logger.debug(f"Ack {hexlify(ackhash).decode()} has been received")
            result = True
        except TimeoutError:
            logger.debug(f"Timed out waiting for ack {hexlify(ackhash).decode()}")
        except asyncio.CancelledError:
            logger.debug(f"Packet send for ackhash {hexlify(ackhash).decode()} was cancelled")
        finally:
            del self.waiting_ack[ackhash]

        return result

    # Receive an ACK
    async def rx_ack(self, rx_packet):
        logger.debug("Received ACK: %s", hexlify(rx_packet.ackhash).decode())

        # Inform anything waiting on this ack that it has arrived
        waitingfuture = self.waiting_ack.get(rx_packet.ackhash)
        if waitingfuture is not None:
            logger.debug("Ack is being waited for")
            waitingfuture.set_result(True)
        else:
            logger.debug("Nothing is waiting for this ack; might not be ours")


    async def send_text_with_retries(self, text:packet.MC_Text_Out, retries=3):
        """
        Send a text message to the recipient. Wait for acknowledgement. Retry if necessary
        Parameters:
        * text - MC_Text_Out packet to send
        * retries - number of times to retry

        Returns: True if receieved and acknowledged after retries, false otherwise

        CLI_DATA messages are not acknowledged, so this returns immediately with True if asked to send one

        The packet will be modified if necessary to update the attempt number
        """
        if text.txt_type == text.TXT_TYPE_CLI_DATA:
            # CLI data is not acknowledged, so attempting multiple acked deliveries makes no sense
            current_taskgroup.get().create_task(self.transmit_packet(text), name="TX CLI packet")
            return True
        
        for count in range(retries):
            logger.debug(f"Sending, attempt number {count+1}")
            if count+1 == retries:
                # Last attempt; flood the packet (if it's been Direct so far)
                text.flood()

            # Add a Future to the packet which gets set when it's sent, so we know when to start expecting an ACK
            sent = asyncio.Future()
            text.sent = sent

            text.attempt = count
            ackhash = text.message_ackhash()

            current_taskgroup.get().create_task(self.transmit_packet(text), name="TX acked packet")
            if await self.await_ack(ackhash, sent, timeout=5):
                logger.debug(f"Message sent and acked, attempt number {count+1}")
                return True
            else:
                logger.debug(f"Ack timeout, attempt number {count+1}")

        return False


    
    # Send an ACK for the text message in rx_packet
    async def send_ack(self, rx_packet:packet.MC_Text):
        # Text received; process the path and/or ack message, before it is passed to the client
        logger.info(f"Received text message from {rx_packet.source.name}")

        if rx_packet.txt_type == rx_packet.TXT_TYPE_CLI_DATA:
            # CLI data does not get acked
            # See BaseChatMesh::onPeerDataRecv in Meshcore
            if rx_packet.is_flood():
                # If the packet is flooded to us, respond with a PATH (without the ACK)
                path_ack = packet.MC_Path_Out(self.me, rx_packet.source, rx_packet.path)
                logger.debug("Responding to flood CLI_DATA message with PATH")
            else:
                logger.debug("Direct CLI_DATA message, no response")
                return
        else:
            # Respond with ack
            ackhash = rx_packet.message_ackhash()

            if rx_packet.is_flood():
                path_ack = packet.MC_Path_Out(self.me, rx_packet.source, rx_packet.path, ackhash)
                logger.debug("Responding to flood message with PATH+ACK")
            else:
                path_ack = packet.MC_Ack_Outgoing(rx_packet, rx_packet.source.path)
                logger.debug("Responding to direct message with ACK")

        # FIXME - do we need a delay? Try this delay thing - 200ms
        await asyncio.sleep(0.2)

        # Send the ACK
        current_taskgroup.get().create_task(self.transmit_packet(path_ack), name="TX packet")


    async def received_text(self, rx_packet:packet.MC_Text):
        # Send ack/path response, if needed. Default action is to ACK everything but CLI_DATA, and
        # send paths to flooded packets. This can be overridden by specific device types -
        # room servers have different requirements
        await self.send_ack(rx_packet)
        # Pass the received text on to the application to process
        await self.rx_text(rx_packet)


    async def tx_advert(self, flood=False, priority=Dispatch.PRIORITY_ADVERT):
        """
        Send an advert for this device.
        By default, it is sent as direct (ie, zero hop) advert with PRIORITY_ADVERT
        A scheduled advert (ie, one which is not the result of a client request) should
        be sent at the lower PRIORITY_SCHEDULED_ADVERT
        """
        advert = packet.MC_Advert_Outgoing(self.me, flood)
        await self.transmit_packet(advert, priority=priority)


    async def mesh_task(self):
        logger.debug(f"Starting mesh task ({self.internalname})...")

        self.rx_queue = self.dispatch.add_queue(self.internalname)

        while True:
            try:
                m = await self.rx_queue.get()

                if isinstance(m, bytes):
                    # Contains just a packet
                    receivedpacket = packet.MC_Incoming.convert_packet(bytearray(m), self.me, self.ids, self.channels)
                elif isinstance(m, bytearray):
                    # Contains just a packet
                    receivedpacket = packet.MC_Incoming.convert_packet(m, self.me, self.ids, self.channels)
                elif len(m) == 2:
                    # Packet, True (or False) - is an internal transmission
                    (p, internal) = m
                    receivedpacket = packet.MC_Incoming.convert_packet(bytearray(p), self.me, self.ids, self.channels)

                    if internal:
                        # This packet has been received internally. Check we didn't send it; if we did, bin it
                        # immediately without further processing
                        if self.dispatch.hasSeen(receivedpacket, extra=self.me.private_key.public_key, checkonly=True):
                            logger.debug("Internally forwarded packet came back to us, discarding")
                            # Yup, we sent it
                            continue

                else:
                    # Packet, RSSI, SNR
                    (p, rssi, snr) = m
                    receivedpacket = packet.MC_Incoming.convert_packet(bytearray(p), self.me, self.ids, self.channels, rssi, snr)

                logger.debug("New packet: %s", str(receivedpacket))

            except InvalidPacket as e:
                logger.warning(f"Bad packet: {e.args}")
                self.stats["badpacket"] += 1
                continue


            # Do something with the raw packet, if needed
            # Companion apps use it to see if a message has been repeated
            await self.rx_raw(receivedpacket)

            self.stats["received"] += 1

            if self.dispatch.hasSeen(receivedpacket, extra=self.me.private_key.public_key):
                # Duplicate packet
                logger.debug("Duplicate packet, already seen; discarding")

                # Record it as a statistic and throw it away
                self.stats["duplicate"] += 1
                # DIRECT or FLOOD
                self.stats[f"duplicate.{receivedpacket.routename}"] += 1
                continue

            # More stats
            # DIRECT or FLOOD, plus hop count
            self.stats[f"received.{receivedpacket.routename}"] += 1
            self.stats[f"received.{receivedpacket.routename}.{receivedpacket.pathlen}"] += 1
            # ADVERT, PATH, etc
            self.stats[f"type.{receivedpacket.typename}"] += 1

            logger.debug("Class: %s", receivedpacket.__class__.__name__)

            if isinstance(receivedpacket, packet.MC_Path) and receivedpacket.decrypted:
                logger.debug(f"Received path from {receivedpacket.source.name}: {pathstr(receivedpacket.pathdata)}")
                id = receivedpacket.source
                id.path = receivedpacket.pathdata
                self.ids.add_identity(id)
                # Callback to UI update path?

            if isinstance(receivedpacket, packet.MC_Advert):
                if receivedpacket.advert.validate():
                    await self.rx_advert(receivedpacket)

            elif isinstance(receivedpacket, packet.MC_GroupText) and receivedpacket.decrypted:
                await self.rx_grouptext(receivedpacket)

            elif isinstance(receivedpacket, packet.MC_Ack) or (
                    isinstance(receivedpacket, packet.MC_Path) and receivedpacket.decrypted and
                    receivedpacket.ackhash is not None):
                # Packet contains an acknowledgement of a previously-sent message
                await self.rx_ack(receivedpacket)

            elif ((isinstance(receivedpacket, packet.MC_Response) or isinstance(receivedpacket, packet.MC_Path)) and
                    receivedpacket.decrypted and receivedpacket.response is not None):
                # Packet contains a response
                await self.rx_response(receivedpacket)

            elif isinstance(receivedpacket, packet.MC_Text) and receivedpacket.decrypted:
                await self.received_text(receivedpacket)

            elif isinstance(receivedpacket, packet.MC_AnonReq) and receivedpacket.decrypted:
                await self.rx_anonreq(receivedpacket)

            elif isinstance(receivedpacket, packet.MC_Req) and receivedpacket.decrypted:
                await self.rx_req(receivedpacket)

            elif isinstance(receivedpacket, packet.MC_Trace):
                await self.rx_trace(receivedpacket)

            # Any general-purpose activity can go here (eg, printing the packet out)
            await self.rx(receivedpacket)

            # Repeater actions
            # Only repeat the packet if we're a repeater, and this packet is repeatable
            if self.repeater and receivedpacket.repeat:
                # Don't repeat TRACE packets
                # They're handled (and forwarded) in rx_trace()
                if isinstance(receivedpacket, packet.MC_Trace):
                    continue

                # Repeat this packet
                if receivedpacket.is_flood():
                    # Add our id to this packet and send it onwards
                    if receivedpacket.pathlen < 63:
                        receivedpacket.path.append(self.me.hash)
                        self.stats[f"repeat.Flood.{receivedpacket.pathlen}"] += 1
                    else:
                        # Hop limit reached
                        logger.warning("Flood repeat: path length exceeded")
                        self.stats["repeat.Flood.too_long"] += 1
                        continue
                else:
                    # Only forward this packet if the first hop matches our id
                    if receivedpacket.pathlen == 0:
                        self.stats["repeat.Direct.zerohop"] += 1
                        continue
                    elif receivedpacket.path[0] != self.me.hash:
                        self.stats["repeat.Direct.notme"] += 1
                        continue
                    else:
                        receivedpacket.path.pop()
                        self.stats[f"repeat.Direct.{receivedpacket.pathlen}"] += 1

                # Reached this point - we have a packet to forward

                current_taskgroup.get().create_task(self.transmit_packet(receivedpacket), name="TX repeater")

    async def transmit_packet(self, tx_packet:packet.MC_Packet, callback=None, priority=None):
        # Fix the packet's payload
        tx_packet.recompute()

        logger.debug("Sending packet:")
        logger.debug(tx_packet)

        if priority is None:
            # Work out a priority based on what the packet is
            if isinstance(tx_packet, packet.MC_Text_Out) and tx_packet.txt_type == tx_packet.TXT_TYPE_SIGNED_PLAIN:
                # Room server traffic. Low priority
                priority = Dispatch.PRIORITY_ROOMTRAFFIC
            if isinstance(tx_packet, packet.MC_SrcDest_Out) or isinstance(tx_packet, packet.MC_Ack_Outgoing):
                # Direct message
                priority = Dispatch.PRIORITY_MESSAGE
            elif isinstance(tx_packet, packet.MC_Group_Outgoing) or isinstance(tx_packet, packet.MC_Path_Out):
                priority = Dispatch.PRIORITY_CHANNEL
            elif isinstance(tx_packet, packet.MC_Advert_Outgoing):
                priority = Dispatch.PRIORITY_ADVERT
            elif isinstance(tx_packet, packet.MC_Incoming):
                # Repeated message
                priority = Dispatch.PRIORITY_REPEAT
            else:
                # This needs improving
                priority = Dispatch.PRIORITY_ADVERT

        # Record the fact we've sent this packet, so we know if it comes back to us from
        # a repeater, and can discard it
        self.dispatch.hasSeen(tx_packet, callback=callback, extra=self.me.private_key.public_key)

        # Queue it for transmission
        self.dispatch.queue(tx_packet, priority=priority)
        logger.debug(f"Packet queued for transmit with priority {priority}")

        self.stats["sent"] += 1
        self.stats[f"sent.{tx_packet.routename}"] += 1

    # Return statistics
    def get_stats(self):
        return self.stats

    # Start the mesh task
    async def start(self):
        current_taskgroup.get().create_task(self.mesh_task(), name=f"Mesh task ({self.internalname})")
