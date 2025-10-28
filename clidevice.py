
# Common device type for repeaters, room servers and other things with a CLI

import asyncio
from aiotools import current_taskgroup

import struct
import time
from random import randbytes
from binascii import unhexlify, hexlify

from dispatch import Dispatch
from exceptions import *
import packet
from identity import AnonIdentity, Identity, IdentityStore, AdvertType
from misc import unique_time
from basicmesh import BasicMesh

import logging

logger = logging.getLogger(__name__)

class CLIDevice(BasicMesh):
    """
    Mesh for a device with the following characteristics:
     * CLI interface for configuration
     * Anonymous requests
    ie, a repeater or room server
    """
    def __init__(self, me, neighbour_ids, dispatcher, hardware, config):
        # Store of identities which have logged in
        # This doesn't need to be stored to disk, as it's just a cache of currently logged in users
        logged_in_ids = IdentityStore()

        super().__init__(me, logged_in_ids, None, dispatcher)

        # Neighbour identities - used for keeping track of neighbouring routers
        # In Meshcore, this is for repeaters only, but room servers can also have neighbours
        self.neighbour_ids = neighbour_ids

        # What time we started (in order to calculate device uptime)
        self.begintime = time.time()

        self.hardware = hardware

        # Additional configuration
        self.config = config

        self.flood_interval = 0
        self.last_flood_advert = 0

        self.direct_interval = 0
        self.last_direct_advert = 0

    # Send adverts periodically
    # Flood adverts are sent every 3 hours (default, configurable); direct adverts every 90 minutes (same).
    # Don't send a direct advert if we sent a flood advert in the last 2 minutes, or will do in the next 2.
    # This is to avoid sending two adverts in quick succession.
    async def tx_advert_flood(self):

        # Interval between flood adverts, -1 = disabled, 0 = once only on startup, >0 = repeat in hours
        flood_interval = self.config.get('advert.flood', -1)
        if flood_interval >= 0:
            self.flood_interval = flood_interval * 60 * 60
        else:
            # Disabled
            self.flood_interval = 0
            logger.debug("Flood adverts disabled")
            return

        while True:
            await self.tx_advert(flood=True, priority=Dispatch.PRIORITY_SCHEDULED_ADVERT)
            self.last_flood_advert = time.time()
            logger.debug("Scheduled flood advert sent")

            if self.flood_interval == 0:
                # Only once
                break

            await asyncio.sleep(self.flood_interval)

        logger.debug("Exiting flood advert task")


    async def tx_advert_direct(self):
        # Interval between direct adverts, -1 = disabled, 0 = once only on startup, >0 = repeat in minutes
        direct_interval = self.config.get('advert.direct', 0)
        if direct_interval >= 0:
            self.direct_interval = direct_interval * 60
        else:
            # Disabled
            self.direct_interval = 0
            logger.debug("Direct adverts disabled")
            return

        # Sleep for 2 seconds to allow flood advert to be sent first if both are enabled
        await asyncio.sleep(2)

        while True:
            # Don't send a direct advert if we sent a flood advert in the last 2 minutes,
            # or will do in the next 2 minutes
            now = time.time()
            next_flood = self.last_flood_advert + self.flood_interval

            if (self.last_flood_advert + 120) > now or (        # within 2 minutes of last flood advert; or
                (next_flood > now) and      # next flood is in the future and
                ((next_flood - 120) < now) or ( # less than 2 minutes away; or
                (next_flood < now) and self.flood_interval > 0) # next flood is in the past,
                                                                # but floods are on, so the next one is immediately imminent
                ):
                logger.debug("Skipping scheduled direct advert to avoid clash with scheduled flood advert")
            else:
                await self.tx_advert(flood=False, priority=Dispatch.PRIORITY_SCHEDULED_ADVERT)
                logger.debug("Scheduled direct advert sent")

            if self.direct_interval == 0:
                # Only once
                break

            await asyncio.sleep(self.direct_interval)

        logger.debug("Exiting direct advert task")


    # Advert received; log it as a neighbour if it's a zero-hop repeater advert
    async def rx_advert(self, rx_packet:packet.MC_Advert):
        if rx_packet.advert.adv_type != AdvertType.REPEATER:
            logger.debug("Non-repeater advert ignored")
            return

        # Only add zero-hop adverts
        if rx_packet.pathlen != 0:
            logger.debug("Non-zero hop advert ignored")
            return

        id = Identity(rx_packet.advert, advertpath=rx_packet.path)
        id.snr = rx_packet.snr

        # Don't need to bother with a shared secret, we won't be sending anything to this identity

        result = self.neighbour_ids.add_identity(id)
        if result:
            logger.debug(f"Zero-hop repeater neighbour added, {id.name} {hexlify(id.pubkey).decode('utf8')}")


    def neighbours(self):
        """
        Return up to 8 neighbours, in a compact format suitable for one Meshcore packet
        """
        neighbours = self.neighbour_ids.get_all()
        # Returned data is neighbour ID (4 bytes of pubkey), seconds since last heard, last SNR
        # Store here as seconds,SNR,pubkey, so the most recent come out first in a sort
        now = int(time.time())

        n_list = [ (now - n.rxtime, int((n.snr or 0)*4) & 0xff, n.pubkey[0:4]) for n in neighbours ]

        response = ""

        count = None

        for count, neighbour in enumerate(sorted(n_list)):
            if count>0:
                response += "\n"
            response += f"{hexlify(neighbour[2]).decode()}:{neighbour[0]}:{neighbour[1]}"

            if count>6:
                # count=7, which means 8 entries
                break
        else:
            # Didn't break out. Did we do any?
            if count is None:
                response = "-none-"

        return response


    async def cli_command(self, command):
        """
        Process a CLI command

        Return a text response if the command was recognised, None if not
        """

        if command == b"advert":
            await self.tx_advert(flood=True)
            return "OK - Advert sent"
        elif command == b"clock":
            # The MeshCore firmware returns UTC time in the format "HH:MM - DD/MM/YYYY UTC"
            return time.strftime("%H:%M - %d/%m/%Y UTC", time.gmtime())
        elif command == b"ver":
            return f"{self.version} ({self.version_date})"
        elif command == b"neighbors" or command == b"neighbours":     # 🇬🇧😊
            return self.neighbours()

        # Not recognised
        return None

    # Send a text message with all the details supplied;
    # returns the ackhash
    async def tx_text(self, recipient, txt_type, attempt, timestamp, text):
        textpacket = packet.MC_Text_Out(self.me, recipient, text, txt_type, attempt, timestamp)
        
        # Store the ackhash of the message
        msghash = textpacket.message_ackhash()

        logger.info(f"Sending text, attempt {attempt+1}, waiting for {msghash}")

        await self.transmit_packet(textpacket)

        return msghash

    async def rx_text_data(self, rx_packet:packet.MC_Text):
        """
        A text message has been received. If this is a repeater, treat it the same as CLI data
        """
        # Override this in a room server
        await self.rx_cli_data(rx_packet)

    async def rx_cli_data(self, rx_packet:packet.MC_Text):
        """
        CLI request
        """

        # Only accept CLI commands from logged in admin users
        if not rx_packet.source.admin:
            logger.info(f"Non-admin user {rx_packet.source.name} attempted CLI command")
            return

        command = rx_packet.text.strip()

        # Commands from a companion app's menu are prefixed with a number and |
        # eg. 01|advert
        if b'|' in command:
            (tag, command) = command.split(b'|', 1)
        else:
            tag = None

        logger.info(f"Command: {command.decode(errors='replace')} from {rx_packet.source.name}")

        response = await self.cli_command(command)

        if response is not None:
            if isinstance(response, str):
                response = response.encode('utf8')

            logger.info(f"Command {command.decode(errors='replace')} executed, reponse: {response.decode(errors='replace')}")
        else:
            logger.info(f"Unknown command: {command.decode(errors='replace')}")
            response = b"Unknown command"

        if tag:
            response = tag + b'|' +response

        # Timestamp on responses is the incoming timestamp plus 1, per the Meshcore source:
        # "// WORKAROUND: the two timestamps need to be different, in the CLI view"
        current_taskgroup.get().create_task(self.tx_text(rx_packet.source, packet.MC_Packet.TXT_TYPE_CLI_DATA, 0,
                                         rx_packet.timestamp+1, response))


    async def rx_text(self, rx_packet:packet.MC_Text):
        # Received text from client
        if rx_packet.txt_type == packet.MC_Packet.TXT_TYPE_PLAIN:
            await self.rx_text_data(rx_packet)
        elif rx_packet.txt_type == packet.MC_Packet.TXT_TYPE_CLI_DATA:
            await self.rx_cli_data(rx_packet)
        else:
            logger.warning(f"Unknown text type: {rx_packet.txt_type}")
    
    # When a client logs in. eg, room servers will start sending stored messages
    async def logged_in(self, pubkey):
        pass

    # Repeater device stats
    # Room server device stats are the same, but with a couple of extra stats which need tacking on
    # in the room server subclass
    def devicestats(self, rx_rssi, rx_snr):
        # Return a bytes object containing device stats
        # Battery (mV)  - 2 bytes
        # TX queue length - 2 bytes
        # noise floor - 2 bytes, signed
        # last RSSI - 2 bytes, signed
        # number packets received - 4 bytes
        #    "     "     sent - 4 bytes
        # air time (seconds) - 4 bytes
        # uptime (seconds) - 4 bytes
        # number...
        #   sent flood - 4 bytes
        #   sent direct - 4 bytes
        #   rec flood - 4 bytes
        #   rec direct - 4 bytes
        #   errors - 2 bytes
        # last SNR - 2 bytes, signed ( *4 )
        # number of direct message duplicates - 2 bytes
        # number of flood message duplicates - 2 bytes
        #
        # The RSSI and SNR are for the last received packet, which will be
        # the one that requested the stats
        data = struct.pack("<HHhhLLLLLLLLHhHH",
            self.hardware.batterymillivolts(),       # Battery
            self.dispatch.queue_length(), # TX queue
            0,          # Noise floor - TODO
            int(rx_rssi),   # Last packet RSSI
            self.stats["received"], # RX
            self.stats["sent"],          # TX
            int(self.dispatch.airtime),  # Airtime
            int(time.time() - self.begintime), # Uptime
            self.stats["sent.Flood"], self.stats["sent.Direct"],
            self.stats["received.Flood"], self.stats["received.Direct"],
            self.stats["badpacket"], # errors
            int(rx_snr * 4), # SNR
            self.stats["duplicate.Direct"], self.stats["duplicate.Flood"]
            )

        return data

    def login_success(self, pubkey, admin=False):
        # Successful login
        dest = AnonIdentity(pubkey)
        dest.create_shared_secret(self.me.private_key)
        dest.admin = admin
        return dest

    def login(self, pubkey, password):
        """
        Check login details

        Returns an AnonIdentity if successful, None if not; the AnonIdentity will have the
        admin flag set if the user is an admin
        """

        admin_pw = self.config.get('admin.password')
        admin_keys = self.config.get('admin.pubkeys', [])

        if admin_pw is not None and password == admin_pw.encode('utf8'):
            logger.info(f"Admin login for {hexlify(pubkey).decode('utf8')} by password")
            return self.login_success(pubkey, admin=True)

        if hexlify(pubkey).decode('utf8') in admin_keys:
            logger.info(f"Admin login for {hexlify(pubkey).decode('utf8')} by pubkey")
            return self.login_success(pubkey, admin=True)

        if self.config.get('guest.open', True):
            logger.info(f"Guest login for {hexlify(pubkey).decode('utf8')}")
            return self.login_success(pubkey, admin=False)

        guest_pw = self.config.get('guest.password')
        guest_keys = self.config.get('guest.pubkeys', [])

        if guest_pw is not None and password == guest_pw.encode('utf8'):
            logger.info(f"Guest login for {hexlify(pubkey).decode('utf8')} by password")
            return self.login_success(pubkey, admin=False)

        if hexlify(pubkey).decode('utf8') in guest_keys:
            logger.info(f"Guest login for {hexlify(pubkey).decode('utf8')} by pubkey")
            return self.login_success(pubkey, admin=False)

        # Login failed
        return None

    async def rx_anonreq(self, rx_packet):
        # This method is only called for decrypted requests
        logger.debug(f"Received ANON_REQ from {hexlify(rx_packet.senderpubkey).decode()}")

        # Check login

        dest = self.login(rx_packet.senderpubkey, rx_packet.password)
        if not dest:
            logger.info(f"Login failed for {hexlify(rx_packet.senderpubkey).decode()}")
            # No response to a failed login; the client will time out
            return

        self.ids.add_identity(dest)

        # The only response to an ANON_REQ appears to be 0 (RESP_SERVER_LOGIN_OK).
        # Any sort of failure (eg, wrong password) is just ignored and the client times out
        #
        #  * Response (RESP_SERVER_LOGIN_OK)
        #  * Reccomended keepalive interval (deprecated, now always 0)
        #  * is_admin?
        #  * Permissions (various PERM_ACL_ options, currently 0; PERM_ACL_GUEST)
        #  * random number (4 bytes)
        data = bytes([packet.MC_Packet.RESP_SERVER_LOGIN_OK, 0, 1 if dest.admin else 0, 0]) + randbytes(4)

        if rx_packet.is_flood():
            # Return a PATH packet with the response
            timestamp = struct.pack("<L", unique_time())

            response = packet.MC_Path_Out(self.me, dest, rx_packet.path, response=timestamp+data)
        else:
            # Packet came direct, no need to tell the sender how to get here
            response = packet.MC_Response_Out(self.me, dest, data)

        await self.transmit_packet(response)

        # Trigger anything that happens when a client logs in
        await self.logged_in(rx_packet)

    async def rx_req(self, rx_packet):
        logger.debug(f"Request: {rx_packet.request}")

        if rx_packet.request == packet.MC_Packet.REQ_TYPE_GET_STATUS:
            # Stats
            logger.debug(f"Status/stats request from {rx_packet.source.name}")

            data = self.devicestats(rx_packet.rssi, rx_packet.snr)

            # Response - timestamp from request (4 bytes), plus repeater stats data from above

            if rx_packet.is_flood():
                # Return a PATH packet with the response
                ts = struct.pack("<L", rx_packet.timestamp)

                response = packet.MC_Path_Out(self.me, rx_packet.source, rx_packet.path, response=ts+data)
            else:
                # Packet came direct, no need to tell the sender how to get here
                response = packet.MC_Response_Out(self.me, rx_packet.source, data, rx_packet.timestamp)

            await self.transmit_packet(response)
        else:
            logger.info(f"Unknown REQ type: {rx_packet.request}")

    def get_stats(self):
        # Return stats for this device
        stats = super().get_stats()

        stats['uptime'] = int(time.time() - self.begintime)
        stats['neighbours'] = len(self.neighbour_ids.get_all())

        return stats

    # Start flood and direct advert tasks
    async def start(self):
        await super().start()

        # Start the advert tasks
        current_taskgroup.get().create_task(self.tx_advert_flood(), name="Flood advert task")
        current_taskgroup.get().create_task(self.tx_advert_direct(), name="Direct advert task")

