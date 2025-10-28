
# Room server

import asyncio
from aiotools import TaskGroup, current_taskgroup
import struct
import time
from binascii import unhexlify, hexlify
from collections import deque


from exceptions import *
import packet
from clidevice import CLIDevice
from misc import split_unicode_string, unique_time


import logging

logger = logging.getLogger(__name__)

class Client():
    """
    Client record
    """
    def __init__(self, pubkey, destination, last_message):
        self.pubkey = pubkey
        self.destination = destination
        self.last_message = last_message

class Message():
    """
    A message received by the room
    """
    def __init__(self, message, pubkey):
        self.text = message
        # Room server signed messages only use the first 4 bytes of the sender's key
        self.pubkey = pubkey[0:4]
        # Time message received - only interested in when we received it, not when the
        # sender thinks they sent it
        self.timestamp = unique_time()


class Room(CLIDevice):
    """
    Mesh for a room server
    """
    def __init__(self, me, ids, dispatcher, hardware, config):
        super().__init__(me, ids, dispatcher, hardware, config)

        self.internalname = "Room server"

        # Current clients
        self.clients = {}

        # Flag for new message
        self.newmessage = asyncio.Event()

        # Message queue
        self.messagequeue = deque(maxlen=32)

    async def rx_cli_data(self, rx_packet:packet.MC_Text):
        print(f"--[ {rx_packet.source.name} ]--------")
        print(time.ctime(rx_packet.timestamp))
        print(f"  CLI: {rx_packet.text.decode(errors='replace')}")

        await super().rx_cli_data(rx_packet)

    async def rx_text_data(self, rx_packet:packet.MC_Text):
        print(f"--[ {rx_packet.source.name} ]--------")
        print(time.ctime(rx_packet.timestamp))
        print(f"  Text: {rx_packet.text.decode(errors='replace')}")

        if self.config.get('readonly', False) and not (rx_packet.source.admin or getattr(rx_packet.source, 'writer', False)):
            logger.info(f"Read only mode, ignoring text message from {rx_packet.source.name}")
            return

        # A full length text message could be 4 bytes too long with a pubkey prefix on the start of it
        text = rx_packet.text
        if len(text) > packet.MC_Packet.MAX_TEXT_MESSAGE - 4:
            text = text[0:packet.MC_Packet.MAX_TEXT_MESSAGE - 4]
            logger.debug(f"Truncating message to {len(text)} bytes")

        self.messagequeue.append(Message(text, rx_packet.source.pubkey))

        self.stats['room.posted'] += 1

        self.newmessage.set()
        # As soon as we set this, anything waiting for new messages is flagged to wake up,
        # so we can clear it immediately ready for the next message
        self.newmessage.clear()


    async def client_messages(self, client:Client):
        """
        Asynchronous coroutine which returns new messages for a given client
        Filters out anything from the client itself
        """
        now = int(time.time())

        if client.last_message == 0:
            welcome_message = self.config.get('welcome')

            if welcome_message is None:
                logger.debug("New client, setting timestamp to {client.last_message} (now)")
                client.last_message = now
            else:
                logger.debug("New client, sending welcome message")
                # Split the welcome message into chunks small enough to fit in a text message, less 4 bytes for the
                # public key of this room server, and 2 bytes in case >3 attempts are needed to send it
                welcome_texts = split_unicode_string(welcome_message, packet.MC_Packet.MAX_TEXT_MESSAGE - 6)

                for count,text in enumerate(welcome_texts):
                    welcome = Message(text, self.me.private_key.public_key)
                    welcome.timestamp = now

                    logger.debug(f"New client, sending welcome text {count+1}/{len(welcome_texts)}; setting timestamp to {client.last_message} (now)")

                    yield welcome

                # Welcome message received - set the last message time to now
                # There is a slight problem here if the welcome message is long enough to split
                # into multiple parts - if the client disconnects before all the parts are sent,
                # then they will get all the parts when they reconnect, even the ones they already
                # got.
                client.last_message = now

        while True:
            # Look for any messages newer than the last message seen
            for message in self.messagequeue:
                if message.timestamp <= client.last_message:
                    continue
                if message.pubkey == client.pubkey[0:4]:
                    # Don't send a client's own messages back to itself
                    continue

                yield message

                # At this point, another task could come along and change the message queue
                # Also, we don't know if the message was acknowledged
                break
            else:
                # Reached the end of the messages without finding anything
                # Wait for a new message
                logger.debug(f"Client {hexlify(client.pubkey[0:4]).decode()}  Waiting for new message")
                await self.newmessage.wait()


    async def client_loop(self, client:Client):
        messages = self.client_messages(client)

        async for message in messages:
            signedmessage = message.pubkey + message.text

            text = packet.MC_Text_Out(self.me, client.destination, signedmessage,
                                        packet.MC_Packet.TXT_TYPE_SIGNED_PLAIN, timestamp=message.timestamp)
            if await self.send_text_with_retries(text):
                client.last_message = message.timestamp

                self.stats["room.pushed"] += 1
            else:
                logger.debug(f"Too many failed attempts, disconnecting client {hexlify(client.pubkey).decode()}")
                del self.clients[client.pubkey]
                return


    async def logged_in(self, rx_packet):
        client_pubkey = rx_packet.senderpubkey
        since = rx_packet.synctime
        source = self.ids.find_by_pubkey(client_pubkey)

        if self.clients.get(client_pubkey) is None:
            # Start up a new client loop for    this client
            logger.debug(f"Creating new client entry: pubkey {hexlify(client_pubkey).decode()}, last message {since} ({time.ctime(since)})")
            client = Client(client_pubkey, source, since)
            current_taskgroup.get().create_task(self.client_loop(client), name=f"Client loop ({hexlify(client_pubkey).decode()})")

            self.clients[client_pubkey] = client


    def login(self, pubkey, password):
        """
        Check login details - check for writer login, then pass to parent class for normal user login

        Returns an AnonIdentity if successful, None if not
        """

        writer_pw = self.config.get('writer.password')
        writer_keys = self.config.get('writer.pubkeys', [])

        writerlogin = False

        if writer_pw is not None and password == writer_pw.encode('utf8'):
            logger.info(f"Writer login for {hexlify(pubkey).decode('utf8')} by password")
            writerlogin = True

        if hexlify(pubkey).decode('utf8') in writer_keys:
            logger.info(f"Writer login for {hexlify(pubkey).decode('utf8')} by pubkey")
            writerlogin = True

        if writerlogin:
            response = self.login_success(pubkey, admin=False)
            response.writer = True
            return response

        # Not a writer login, so pass to parent class to see if it's an admin or a guest
        return super().login(pubkey, password)


    # Room server device stats
    # Same as repeater device stats, but with a couple of extra stats at the end
    def devicestats(self, rx_rssi, rx_snr):
        data = super().devicestats(rx_rssi, rx_snr)

        # Extra stats
        #   Room server messages posted (ie, received)  - unsigned 16 bits
        #   Room server messages pushed (delivered to recipients)   - unsigned 16 bits
        data += struct.pack("<HH",
            self.stats["room.posted"], self.stats["room.pushed"]
            )

        return data
