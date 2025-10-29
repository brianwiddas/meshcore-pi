
# Pretends to be a companion radio

import asyncio
from aiotools import current_taskgroup

import struct
import time
from random import randbytes
from binascii import unhexlify, hexlify

import packet
from identity import AdvertType
import groupchannel
from exceptions import *
from misc import pad, pathstr, validate_latlon
from basicmesh import BasicMesh


import logging
logger = logging.getLogger(__name__)

# ------------ Frame Protocol --------------

FIRMWARE_VER_CODE = 5

FIRMWARE_BUILD_DATE = "9 May 2025"
FIRMWARE_VERSION = "v1.6.0"

CMD_APP_START = 1
CMD_SEND_TXT_MSG = 2
CMD_SEND_CHANNEL_TXT_MSG = 3
CMD_GET_CONTACTS = 4  # with optional 'since' (for efficient sync)
CMD_GET_DEVICE_TIME = 5
CMD_SET_DEVICE_TIME = 6
CMD_SEND_SELF_ADVERT = 7
CMD_SET_ADVERT_NAME = 8
CMD_ADD_UPDATE_CONTACT = 9
CMD_SYNC_NEXT_MESSAGE = 10
CMD_SET_RADIO_PARAMS = 11
CMD_SET_RADIO_TX_POWER = 12
CMD_RESET_PATH = 13
CMD_SET_ADVERT_LATLON = 14
CMD_REMOVE_CONTACT = 15
CMD_SHARE_CONTACT = 16
CMD_EXPORT_CONTACT = 17
CMD_IMPORT_CONTACT = 18
CMD_REBOOT = 19
CMD_GET_BATTERY_VOLTAGE = 20
CMD_SET_TUNING_PARAMS = 21
CMD_DEVICE_QUERY = 22
CMD_EXPORT_PRIVATE_KEY = 23
CMD_IMPORT_PRIVATE_KEY = 24
CMD_SEND_RAW_DATA = 25
CMD_SEND_LOGIN = 26
CMD_SEND_STATUS_REQ = 27
CMD_HAS_CONNECTION = 28
CMD_LOGOUT = 29  # 'Disconnect'
CMD_GET_CONTACT_BY_KEY = 30
CMD_GET_CHANNEL = 31
CMD_SET_CHANNEL = 32
CMD_SIGN_START = 33
CMD_SIGN_DATA = 34
CMD_SIGN_FINISH = 35
CMD_SEND_TRACE_PATH = 36
CMD_SET_DEVICE_PIN = 37
CMD_SET_OTHER_PARAMS = 38
CMD_SEND_TELEMETRY_REQ = 39
CMD_GET_CUSTOM_VARS = 40
CMD_SET_CUSTOM_VAR = 41
CMD_GET_ADVERT_PATH = 42

RESP_CODE_OK = 0
RESP_CODE_ERR = 1
RESP_CODE_CONTACTS_START = 2  # first reply to CMD_GET_CONTACTS
RESP_CODE_CONTACT = 3  # multiple of these (after CMD_GET_CONTACTS)
RESP_CODE_END_OF_CONTACTS = 4  # last reply to CMD_GET_CONTACTS
RESP_CODE_SELF_INFO = 5  # reply to CMD_APP_START
RESP_CODE_SENT = 6  # reply to CMD_SEND_TXT_MSG
RESP_CODE_CONTACT_MSG_RECV = 7  # a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
RESP_CODE_CHANNEL_MSG_RECV = 8  # a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
RESP_CODE_CURR_TIME = 9  # a reply to CMD_GET_DEVICE_TIME
RESP_CODE_NO_MORE_MESSAGES = 10  # a reply to CMD_SYNC_NEXT_MESSAGE
RESP_CODE_EXPORT_CONTACT = 11
RESP_CODE_BATTERY_VOLTAGE = 12  # a reply to CMD_GET_BATTERY_VOLTAGE
RESP_CODE_DEVICE_INFO = 13  # a reply to CMD_DEVICE_QUERY
RESP_CODE_PRIVATE_KEY = 14  # a reply to CMD_EXPORT_PRIVATE_KEY
RESP_CODE_DISABLED = 15
RESP_CODE_CONTACT_MSG_RECV_V3 = 16  # a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
RESP_CODE_CHANNEL_MSG_RECV_V3 = 17  # a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
RESP_CODE_CHANNEL_INFO = 18  # a reply to CMD_GET_CHANNEL
RESP_CODE_SIGN_START = 19
RESP_CODE_SIGNATURE = 20
RESP_CODE_CUSTOM_VARS = 21
RESP_CODE_ADVERT_PATH = 22

# These are _pushed_ to client app at any time
PUSH_CODE_ADVERT = 0x80
PUSH_CODE_PATH_UPDATED = 0x81
PUSH_CODE_SEND_CONFIRMED = 0x82
PUSH_CODE_MSG_WAITING = 0x83
PUSH_CODE_RAW_DATA = 0x84
PUSH_CODE_LOGIN_SUCCESS = 0x85
PUSH_CODE_LOGIN_FAIL = 0x86
PUSH_CODE_STATUS_RESPONSE = 0x87
PUSH_CODE_LOG_RX_DATA = 0x88
PUSH_CODE_TRACE_DATA = 0x89
PUSH_CODE_NEW_ADVERT = 0x8A
PUSH_CODE_TELEMETRY_RESPONSE = 0x8B

ERR_CODE_UNSUPPORTED_CMD = 1
ERR_CODE_NOT_FOUND = 2
ERR_CODE_TABLE_FULL = 3
ERR_CODE_BAD_STATE = 4
ERR_CODE_FILE_IO_ERROR = 5
ERR_CODE_ILLEGAL_ARG = 6

# --------------------------------------------------------------------------------------

REQ_TYPE_GET_STATUS = 0x01  # same as _GET_STATS
REQ_TYPE_KEEP_ALIVE = 0x02
REQ_TYPE_GET_TELEMETRY_DATA = 0x03

MAX_SIGN_DATA_LEN = 8 * 1024  # 8K

# Various responses to CMD_ requests
OK = bytes([RESP_CODE_OK])
def ERR(code):
    return bytes([RESP_CODE_ERR, code])

def sent_resp(sentpacket:packet.MC_Outgoing, tag:bytes):
        # Response to various commands that send requests over the mesh
        # The eventual result is returned separately as a PUSH_ message
        #   RESP_CODE_SENT
        #   whether packet was direct (0) or flood (1)
        #   tag (or ackhash), 4 bytes
        #   estimated RTT in ms, 4 bytes
        if len(tag) != 4:
            raise ValueError("tag should be 4 bytes")
        flood = 1 if sentpacket.is_flood() else 0

        response = bytes([RESP_CODE_SENT, flood ]) + tag
        # FIXME: Fake estimated RTT of 10 seonds
        rtt = 10000
        response += struct.pack("<L", rtt)

        logger.debug(f"RESP_CODE_SENT, flood? {flood}, tag: {hexlify(tag).decode()}, estimated rtt: {rtt} ms")

        return response

class CompanionRadio(BasicMesh):
    """
    Mesh for a chat client which is compatible with the Meshcore app
    """
    def __init__(self, me, ids, channels, dispatcher, config):
        super().__init__(me, ids, channels, dispatcher)

        self.internalname = "Companion radio"

        app_interface_name = config.get('interface', 'wifi')
        if app_interface_name == 'wifi':
            from companionwifi import CompanionInterface
        elif app_interface_name == 'serial':
            from companionserial import CompanionInterface
        else:
            raise ValueError(f"Unknown app interface {app_interface_name}")

        self.appinterface = CompanionInterface(config.get(app_interface_name, view=True))

        # Queue of messages waiting to be delivered to the app
        self.msgqueue = asyncio.Queue()

        # Hash of message ackhash vs time
        # Records the time a message was sent, in order to work out the round trip time
        self.messagetime = {}

        # Pending responses
        # Since a RESPONSE can arise for several different requests, we have to keep
        # a record of pending response types and, when a RESPONSE arrives, check what
        # we're waiting for.
        # The variables hold the public key of the target we've sent a ... request to
        self.pending_login = None       # Target we tried to log in to
        self.pending_status = None      # Target we sent a status request to
        self.pending_telemetry = None   # Target we sent a telemetry request to
        self.pending_discovery = None   # Target we sent a discovery request to
        self.pending_req = None         # Target we sent a binary request to


    # Clean up the messagetime hash - delete the entry from the hash table after delay seconds
    async def reap(self, ackhash, delay):
        await asyncio.sleep(delay)

        self.messagetime.pop(ackhash, None)


    # Send a text message with all the details supplied;
    # returns the ackhash
    async def tx_text(self, recipient, txt_type, attempt, timestamp, text):
        textpacket = packet.MC_Text_Out(self.me, recipient, text, txt_type, attempt, timestamp)
        # Store the ackhash of the message
        msghash = textpacket.message_ackhash()

        logger.info(f"Sending text, attempt {attempt+1}, waiting for {msghash}")

        await self.transmit_packet(textpacket)

        return msghash

    # Send a copy of all received packets to the app
    # It used them to determine if a message has been repeated, and to report on the
    # received path of channel messages
    async def rx_raw(self, rx_packet:packet.MC_Incoming):
        """
        Send PUSH_CODE_LOG_RX_DATA, to inform the client that there is a new packet
        """
        if rx_packet.snr:
            snr = int(rx_packet.snr * 4) & 0xff
        else:
            snr = 0
        if rx_packet.rssi:
            rssi = int(rx_packet.rssi) & 0xff
        else:
            rssi = 0

        # PUSH_CODE_LOG_RX_DATA, (snr * 4), rssi, packet
        msg = bytes([PUSH_CODE_LOG_RX_DATA, snr, rssi]) + rx_packet.packet
        await self.appinterface.tx(msg)

        logger.info(f"Sent PUSH_CODE_LOG_RX_DATA to app")        

    async def rx_advert(self, rx_packet:packet.MC_Advert):
        await super().rx_advert(rx_packet)

        print("--[ Advert ]--------")
        print(f"  {rx_packet.advert.name}")

        msg = bytes([PUSH_CODE_ADVERT]) + rx_packet.advert.identity
        await self.appinterface.tx(msg)
        logger.info(f"Pushed advert notification for {hexlify(rx_packet.advert.identity).decode()}")

    async def push_new_message_waiting(self):
        """
        Send PUSH_CODE_MSG_WAITING, to inform the client that there is a queued message
        or channel message to be collected
        """
        msg = bytes([PUSH_CODE_MSG_WAITING])
        await self.appinterface.tx(msg)

        logger.info(f"Sent PUSH_CODE_MSG_WAITING to app")

    async def rx_text(self, rx_packet:packet.MC_Text):
        print(f"--[ {rx_packet.source.name} ]--------")
        print(time.ctime(rx_packet.timestamp), end='')
        if rx_packet.txt_type == rx_packet.TXT_TYPE_CLI_DATA:
            print("  CLI data")
            print(f"  {rx_packet.text.decode(errors='replace')}")
        elif rx_packet.txt_type == rx_packet.TXT_TYPE_SIGNED_PLAIN:
            if len(rx_packet.text) < 4:
                print("Bad data")
            else:
                sender = self.ids.find_by_pubkey(rx_packet.text[0:4])
                if sender is None:
                    print("  [Unknown sender]")
                else:
                    print(f"  {sender.name}")
                print(rx_packet.text[4:].decode(errors='replace'))
        else:
            print()
            print(f"  {rx_packet.text.decode(errors='replace')}")

        if rx_packet.txt_type == rx_packet.TXT_TYPE_SIGNED_PLAIN:
            # This message has come from a room server
            logger.debug(f"Room server message timestamp: {rx_packet.timestamp}, last message timestamp {rx_packet.source.lastmsgtime}")
            if rx_packet.timestamp > rx_packet.source.lastmsgtime:
                logger.debug("Updating last message timestamp")
                rx_packet.source.lastmsgtime = rx_packet.timestamp
                self.ids.add_identity(rx_packet.source)

        await self.msgqueue.put(rx_packet)
        logger.info(f"Queued text packet from {rx_packet.source.name}")
        await self.push_new_message_waiting()
    
    async def rx_grouptext(self, rx_packet:packet.MC_GroupText):
        # Received a channel message (that we can decrypt)
        print(f"--[ {rx_packet.channel.strname} ]--------")
        print(time.ctime(rx_packet.message.timestamp))
        print(f"  {rx_packet.message.message.decode(errors='replace')}")

        await self.msgqueue.put(rx_packet)
        logger.info(f"Queued group text packet in channel {rx_packet.channel.strname}")
        await self.push_new_message_waiting()
        return

    async def rx_path(self, rx_packet):
        return
    
    async def rx_ack(self, rx_packet):
        logger.debug("Received ACK: %s", hexlify(rx_packet.ackhash).decode())

        # Ack has been received. Send a message to the client:
        # * PUSH_CODE_SEND_CONFIRMED
        # * ackhash (4 bytes)
        # * round-trip time (4 bytes)
        txtime = self.messagetime.get(rx_packet.ackhash)
        if txtime is None:
            logger.debug("Ack is not for a message we sent")
        else:
            rtt = int(1000*(time.time() - txtime))

            logger.debug(f"Ack for message sent at{txtime}, round trip time: {rtt} ms")

            msg = bytes([PUSH_CODE_SEND_CONFIRMED]) + rx_packet.ackhash + struct.pack("<L", rtt)
            await self.appinterface.tx(msg)
 
    async def rx_anonreq(self, rx_packet):
        return


    def contactframe(self, responsecode, contact):
        """
        Create the response frame for a single contact
        """
        # Response code, public key
        contactresponse = bytes([responsecode]) + contact.pubkey
        # Type (Chat, repeater, etc), flags, out path length
        if contact.path is None:
            path = bytes()
        else:
            path = contact.path
        contactresponse += struct.pack("<BBB", contact.advert.adv_type.value, contact.advert.adv_flags.value, len(path))
        # Path, padded to 64 bytes
        contactresponse += pad(path, 64)
        # Advert name, padded to 32 bytes
        contactresponse += pad(contact.name, 32)
        # Last advert time, lat, long, last modified time
        latlon = contact.latlon
        if latlon is None:
            lat = 0
            lon = 0
        else:
            lat = int(latlon[0] * 1000000)
            lon = int(latlon[1] * 1000000)
        contactresponse += struct.pack("<LllL", contact.timestamp, lat,lon, contact.timestamp)

        return contactresponse

    def getcontacts(self, since):
        # Return the list of responses when contacts are requested
        #   RESP_CODE_CONTACTS_START
        #   RESP_CODE_CONTACT for each contact
        #   RESP_CODE_END_OF_CONTACTS
        # TODO: "since" parameter needs to be handled
        contacts = self.ids.get_all()
        response = [ struct.pack("<BL", RESP_CODE_CONTACTS_START, len(contacts)) ]

        mostrecent = 0

        for c in contacts:
            contactresponse = self.contactframe(RESP_CODE_CONTACT, c)
            response.append(contactresponse)

            if c.timestamp > mostrecent:
                mostrecent = c.timestamp

        response.append( struct.pack("<BL", RESP_CODE_END_OF_CONTACTS, mostrecent))

        return response

    def add_update_contact(self, contactdata):
        # Contact data is:
        #   pubkey (32 bytes)
        #   type (1 byte, ADV_TYPE_*)
        #   flags (1 byte, ADV_FLAG_*)
        #   path length (1 byte)
        #   path (0-64 bytes)
        #   name (32 bytes, null terminated)
        #   last advert time (4 bytes)
        #   lat (4 bytes, int32, millionths; optional)
        #   lon (4 bytes, int32, millionths; optional)

        pubkey = contactdata[0:32]
        type = contactdata[32]
        flags = contactdata[33]
        pathlen = contactdata[34]
        if pathlen:
            path = contactdata[35:35+pathlen]

        rest = contactdata[35+pathlen:]
        name = rest[0:32].rstrip(b'\x00')
        last_advert_time = struct.unpack("<L", rest[32:36])[0]

        if len(rest) >= 44:
            lat = struct.unpack("<l", rest[36:40])[0] / 1000000.0
            lon = struct.unpack("<l", rest[40:44])[0] / 1000000.0
            latlon = (lat, lon)

        contact = self.ids.find_by_pubkey(pubkey)
        if contact is None:
            # New contact
            logger.error(f"Contact {hexlify(pubkey).decode()} not found")
            return ERR(ERR_CODE_NOT_FOUND)
            # FIXME, need to add contacts
        else:
            # Update existing contact
            # This command is used for various things, including updating the path for a contact,
            # which is the only thing we're supporting right now
            # FIXME: do the rest of it too

            contact.path = path
            # Update the contact in the store
            self.ids.add_identity(contact)

            logger.info(f"Updated contact {contact.name} ({hexlify(contact.pubkey).decode()})")

        return OK

    def send_text_callback(self, hash, dupecount):
        logger.info(f"Packet ({hexlify(hash).decode()}) repeated by {dupecount} neighbouring repeater(s)")

    async def send_txt(self, txt_type, attempt, timestamp, pubkey_prefix, message):
        # Identify recipient
        recipient = self.ids.find_by_pubkey(pubkey_prefix)
        if recipient is None:
            logger.info("Recipient not found")
            return ERR(ERR_CODE_NOT_FOUND)

        textpacket = packet.MC_Text_Out(self.me, recipient, message, txt_type, attempt, timestamp)

        # Store the ackhash of the message
        ackhash = textpacket.message_ackhash()

        logger.info(f"Sending text, attempt {attempt+1}, waiting for {ackhash}")

        # Store the timestamp in a dict with the message hash as a key, so if we get a response, we
        # know what the round trip time was
        self.messagetime[ackhash] = time.time()
        # Clean it up after 30 seconds
        current_taskgroup.get().create_task(self.reap(ackhash, 30), name="Ack reaper")

        await self.transmit_packet(textpacket, self.send_text_callback)
        logger.info(f"Sent, expecting ackhash {hexlify(ackhash).decode()}")

        return sent_resp(textpacket, ackhash)

    async def send_channel_txt(self, channel_index, txt_type, timestamp, message):
        # Fetch channel
        try:
            channel = self.channels[channel_index]
        except IndexError:
            logger.debug(f"Channel index {channel_index} not found")
            return ERR(ERR_CODE_NOT_FOUND)
        
        logger.debug(f"Sending message to channel {channel.strname}, timestamp {timestamp}, message: {message}")

        # Prepend the message with the sender name and a colon and space.
        # Yes, if you put a colon and space in your name, things will break; don't do that.
        message = self.me.name + b': ' + message

        # Length check
        if len(message) > packet.MC_Packet.MAX_TEXT_MESSAGE:
            logger.debug("Message too long, truncating")
            message = message[0:packet.MC_Packet.MAX_TEXT_MESSAGE]

        channelpacket = packet.MC_GroupText_Outgoing(channel, message, timestamp, txt_type)

        await self.transmit_packet(channelpacket, self.send_text_callback)

        return OK

    # Log in to repeater, room server, etc
    async def send_login(self, pubkey, password):
        dest = self.ids.find_by_pubkey(pubkey)
        if dest is None:
            # We don't have this pubkey
            # Wouldn't really expect this to happen, but it's a possibility
            return ERR(ERR_CODE_NOT_FOUND)

        if dest.advert.adv_type == AdvertType.ROOM:
            # Timestamp of the last message recived, so the room server knows
            # to only send newer messages
            since = dest.lastmsgtime

            login = packet.MC_AnonReq_Out(self.me, dest, password, since)
        else:
            login = packet.MC_AnonReq_Out(self.me, dest, password)

        # Store the fact that we're waiting for this device to respond to our login
        self.pending_login = dest.pubkey

        await self.transmit_packet(login)
        # Fire the packet off - if the login is successful, a separate PUSH will be
        # sent to the client
        # Return RESP_CODE_SENT with 4 bytes of the destination pubkey as the tag
        return sent_resp(login, pubkey[0:4])

    # Send status request to repeater, room server, etc
    async def send_status_req(self, pubkey):
        dest = self.ids.find_by_pubkey(pubkey)
        if dest is None:
            # We don't have this pubkey
            # Wouldn't really expect this to happen, but it's a possibility
            return ERR(ERR_CODE_NOT_FOUND)

        # Request data
        #   reserved (0), 4 bytes
        #   random number for packet uniqueness, 4 bytes
        data = bytes(4) + randbytes(4)

        statusreq = packet.MC_Req_Out(self.me, dest, packet.MC_Packet.REQ_TYPE_GET_STATUS, data)

        # Store the fact that we're waiting for this device to respond to our status request
        self.pending_status = dest.pubkey

        await self.transmit_packet(statusreq)
        # Fire the packet off - if the login is successful, a separate PUSH will be
        # sent to the client
        # Return RESP_CODE_SENT with 4 bytes of the packet timestamp as the tag
        return sent_resp(statusreq, struct.pack("<L", statusreq.timestamp))


    async def rx_response(self, packet:packet.MC_SrcDest):
        # Packet is either a MC_Response or an MC_Path. Either will contain a
        # 'response' property
        frame = packet.response

        timestamp = struct.unpack("<L", frame[0:4])[0]
        # What response is this?
        logger.debug(f"Got RESPONSE frame: {hexlify(frame).decode()}, timestamp: {timestamp} ({time.ctime(timestamp)})")
        if self.pending_login and self.pending_login == packet.source.pubkey:
            logger.debug("Received pending login response")
            self.pending_login = None

            if frame[4] == packet.RESP_SERVER_LOGIN_OK:
                # Frame data:
                #   RESP_CODE_LOGIN_OK
                #   keep alive interval /16 (ie 1 = 16 seconds), room server only (0 otherwise)
                #      - keep alive interval is now 0 (disabled) on room servers, so ignore
                #   Is admin? (0/1)
                #   Unsynced message count (room server), (reserved) 0 (repeater), permissions (sensor)
                #   "OK" (2 bytes, room server), or random number (4 bytes, repeater/sensor)
                if frame[5] != 0:
                    logger.warning("Keep-alive interval is not 0")
                logger.debug(f"Unread/reserved/permissions field = {frame[7]}")
                admin = frame[6]
                src = packet.source.pubkey[0:6]

                # Send to client
                #   PUSH_CODE_LOGIN_SUCCESS
                #   Is admin? (0/1)
                #   First 6 bytes of pubkey of the endpoint logged in to
                msg = bytes([PUSH_CODE_LOGIN_SUCCESS, admin]) + src

                await self.appinterface.tx(msg)

                logger.info(f"Sent PUSH_CODE_LOGIN_SUCCESS to app, logged in to {hexlify(src).decode()} admin={admin}")
            else:
                logger.debug("Unknown RESPONSE type")

        elif self.pending_status and self.pending_status == packet.source.pubkey:
            logger.debug("Received pending status response")
            self.pending_status = None

            # Send to client
            #   PUSH_CODE_STATUS_RESPONSE
            #   0 (reserved)
            #   First 6 bytes of responding enpoint pubkey
            #   Status data as received (everything after first 4 bytes of response)
            msg = bytes([PUSH_CODE_STATUS_RESPONSE, 0]) + packet.source.pubkey[0:6] + frame[4:]

            await self.appinterface.tx(msg)

            logger.info("Sent PUSH_CODE_STATUS_RESPONSE to app")

        else:
            logger.warning("Unexpected response received")

    # Send TRACE packet - used for ping and path trace operations
    async def send_trace(self, tag, auth, flags, path):
        if len(path)>64:
            logger.warning("Trace path too long")
            return ERR(ERR_CODE_UNSUPPORTED_CMD)

        trace = packet.MC_Trace_Out(path, tag, auth, flags)
        await self.transmit_packet(trace)

        return sent_resp(trace, tag)

    # Return the results of a trace to the app
    async def rx_trace(self, rx_packet:packet.MC_Trace):
        logger.debug(f"Received Trace, tag {hexlify(rx_packet.tag).decode()}, {len(rx_packet.tracepath)} hops, {len(rx_packet.path)} results")

        if len(rx_packet.tracepath) != len(rx_packet.path):
            logger.debug("Incomplete trace, ignoring")
            return

        # Completed trace has been received. Send a message to the client:
        # * PUSH_CODE_TRACE_DATA
        # * reserved (0), 1 byte
        # * path length, 1 byte
        # * flags (1 byte)          \
        # * tag (4 bytes)            --- data copied from app into outgoing trace packet
        # * auth code (4 bytes)     /
        # * path hashes
        # * SNR values (1 byte per path hop)
        # * SNR value of the final hop back to this device (1 byte)
        #
        # It's possible this is someone else's trace. In which case, the tag won't match and the client
        # should discard it

        msg = bytes([PUSH_CODE_TRACE_DATA, 0, len(rx_packet.path), rx_packet.flags]) + rx_packet.tag + rx_packet.auth

        # Path hashes
        msg += rx_packet.tracepath
        # Path SNR values (strored in the packet path) have already converted to signed byte * 4
        msg += rx_packet.path
        # Final SNR for the packet we received
        msg += bytes([int(rx_packet.snr * 4) & 0xff])

        await self.appinterface.tx(msg)


    async def run(self):

        # Start the app interface
        await self.appinterface.start()

        while True:
            frame = await self.appinterface.rx()
            response = None

            command = frame[0]

            logger.debug(f"Command received: {command}, frame = {hexlify(frame).decode()}, length = {len(frame )}")

            if command == CMD_APP_START:
                logger.debug("CMD_APP_START")
                # App sends a whole bunch of data to let us know it's running
                self.app_version = frame[1]
                # Bytes 2-7 are reserved
                self.app_name = frame[8:].decode(errors='replace')
                logger.info(f"Application started, version: {self.app_version}, name: {self.app_name}")

                # Send back a whole bunch of data about this pretend companion radio

                (r_freq, r_bw, r_sf, r_cr, r_tx_pow, r_tx_max) = self.dispatch.get_radioconfig()

                # Response code, device type (0=chat, 1=repeater, 2=sensor, 3=room), TX power, max TX power
                response = struct.pack("<BBBB", RESP_CODE_SELF_INFO, self.me.devicetype.value, r_tx_pow, r_tx_max)
                # Public key
                response += self.me.private_key.public_key

                latlon = self.me.latlon
                if latlon is None:
                    lat = 0
                    lon = 0
                else:
                    lat = int(latlon[0] * 1000000)
                    lon = int(latlon[1] * 1000000)

                # Lat, long, reserved, telemetry modes, manual add contacts, radio freq,bw,sf,cr
                response += struct.pack("<llHBBLLBB", lat, lon, 0, 0, 0, r_freq, r_bw, r_sf, r_cr)
                # Name of the device
                response += self.me.name

            elif command == CMD_SEND_TXT_MSG:
                logger.debug("CMD_SEND_TXT_MSG")
                # Send a text message
                (txt_type, attempt, timestamp) = struct.unpack("<BBL", frame[1:7])
                # First 6 bytes of the recipient's public key
                pubkey_prefix = frame[7:13]
                # Message to send (160 bytes max)
                message = frame[13:]

                logger.info(f"Sending text message to {hexlify(pubkey_prefix).decode()}, type {txt_type}, attempt {attempt}, timestamp {time.ctime(timestamp)}, message: {message.decode(errors='replace')}")

                response = await self.send_txt(txt_type, attempt, timestamp, pubkey_prefix, message)

            elif command == CMD_SEND_CHANNEL_TXT_MSG:
                logger.debug("CMD_SEND_CHANNEL_TXT_MSG")
                (text_type, channel_index, timestamp) = struct.unpack("<BBL", frame[1:7])
                # Message to send (160 - (length of this client's name) bytes max)
                message = frame[7:]

                response = await self.send_channel_txt(channel_index, text_type, timestamp, message)

            elif command == CMD_GET_CONTACTS:
                if len(frame) == 5:
                    since = struct.unpack("<L", frame[1:])[0]
                    logger.debug(f"CMD_GET_CONTACTS, since = {since}")
                    # Optional "since" parameter is present
                    # FIXME - handle this
                else:
                    logger.debug("CMD_GET_CONTACTS")
                    since = 0

                response = self.getcontacts(since)

            elif command == CMD_SET_DEVICE_TIME:
                # Quietly ignore this
                t = struct.unpack("<L", frame[1:])[0]
                logger.debug(f"CMD_SET_DEVICE_TIME = {time.ctime(t)}")
                response = OK

            elif command == CMD_SEND_SELF_ADVERT:
                flood = False
                if len(frame) == 2:
                    # Optional "flood" parameter is present
                    # 0 = zero-hop advert (default), 1 = flood advert
                    flood = frame[1] == 1
                logger.debug(f"CMD_SEND_SELF_ADVERT, {'flood' if flood else 'zero-hop'}")

                advert = packet.MC_Advert_Outgoing(self.me, flood)
                await self.transmit_packet(advert)
                response = OK

            elif command == CMD_SET_ADVERT_NAME:
                name = frame[1:]
                logger.debug(f"CMD_SET_ADVERT_NAME, {name.decode('utf-8', errors='replace')}")
                try:
                    self.me.name = name
                    response = OK
                except ValueError as e:
                    logger(f"Name change rejected: {repr(e)}")
                    response = ERR(ERR_CODE_ILLEGAL_ARG)

            elif command == CMD_ADD_UPDATE_CONTACT:
                data = frame[1:]
                logger.debug(f"CMD_ADD_UPDATE_CONTACT")

                response = self.add_update_contact(data)

            elif command == CMD_RESET_PATH:
                logger.debug(f"CMD_RESET_PATH, {hexlify(frame[1:]).decode()}")

                contact = self.ids.find_by_pubkey(frame[1:])
                if contact is None:
                    logger.debug("Not found")
                    response = ERR(ERR_CODE_NOT_FOUND)
                else:
                    logger.info(f"Resetting path for {contact.name}")
                    contact.path = None
                    # Update the identity store
                    self.ids.add_identity(contact)
                    response = OK

            elif command == CMD_SET_ADVERT_LATLON:
                # Latitude, longitude, optional 32 bit future field (ignore)
                (lat,lon) = struct.unpack("<ll", frame[1:9])
                f_lat = lat/1000000.0
                f_lon = lon/1000000.0
                logger.debug(f"CMD_SET_ADVERT_LATLON, {f_lat},{f_lon}")

                try:
                    # Updates self.me.latlon.
                    # At the moment, this is not saved in the config, so it will be forgotten on restart
                    self.me.latlon = validate_latlon(f_lat, f_lon)
                    response = OK
                except ValueError as e:
                    logger(f"Lat/lon change rejected: {repr(e)}")
                    response = ERR(ERR_CODE_ILLEGAL_ARG)

            elif command == CMD_REMOVE_CONTACT:
                logger.debug(f"CMD_REMOVE_CONTACT, {hexlify(frame[1:]).decode()}")

                result= self.ids.del_identity(frame[1:])
                if result:
                    logger.debug("Deleted")
                    response = OK
                else:
                    logger.debug("Not found")
                    response = ERR(ERR_CODE_NOT_FOUND)

            elif command == CMD_SHARE_CONTACT:
                logger.debug(f"CMD_SHARE_CONTACT, {hexlify(frame[1:]).decode()}")

                contact = self.ids.find_by_pubkey(frame[1:])
                if contact is None:
                    logger.debug("Not found")
                    response = ERR(ERR_CODE_NOT_FOUND)
                else:
                    logger.info(f"Sharing contact for {contact.name}")
                    advert = packet.MC_Advert_Outgoing(contact.advert)
                    await self.transmit_packet(advert)
                    response = OK

            elif command == CMD_SET_RADIO_PARAMS:
                logger.debug(f"CMD_SET_RADIO_PARAMS, {hexlify(frame[1:]).decode()}")

                # FIXME - don't just ignore this
                response = OK

            elif command == CMD_SET_RADIO_TX_POWER:
                logger.debug(f"CMD_SET_RADIO_TX_POWER, {hexlify(frame[1:]).decode()}")

                # FIXME - don't just ignore this
                response = OK


            elif command == CMD_SET_OTHER_PARAMS:
                logger.debug(f"CMD_SET_OTHER_PARAMS, {hexlify(frame[1:]).decode()}")

                # FIXME - don't just ignore this
                response = OK


            elif command == CMD_SYNC_NEXT_MESSAGE:
                logger.debug("CMD_SYNC_NEXT_MESSAGE")
                # Get the next message from the queue, if there is one
                if self.msgqueue.empty():
                    # No messages
                    logger.debug("No more messages to pass")
                    response = bytes([RESP_CODE_NO_MORE_MESSAGES])
                else:
                    msg = self.msgqueue.get_nowait()
                    # Turn the SNR into a signed integer. Multiply it by 4, so 1 = 0.25dB, -2 = -0.5dB, etc
                    # Gives an SNR range of -32 to 31.75
                    if msg.snr:
                        snr = int(msg.snr * 4) & 0xff
                    else:
                        snr = 0
                    if isinstance(msg, packet.MC_Text):
                        # Text message from a contact
                        logger.debug(f"Passing text message from {msg.source.name} to app")

                        # Response code, SNR, 2x reserved bytes
                        # First 6 bytes of sender's id
                        response = bytes([RESP_CODE_CONTACT_MSG_RECV_V3, snr, 0, 0]) + msg.source.pubkey[0:6]
                        # Path length (0xff for direct), text type, sender's timestamp
                        response += struct.pack("<BBL", msg.pathlen if msg.is_flood() else 0xff, msg.txt_type, msg.timestamp)
                        # Text of message
                        response += msg.text
                    elif isinstance(msg, packet.MC_Group):
                        logger.debug(f"Passing group text message from {msg.channel.strname} to app")
                        # Find channel ID from channel
                        for index,channel in enumerate(self.channels):
                            if msg.channel == channel:
                                break
                        else:
                            logger.error(f"Could not match channel {msg.channel.strname} with a channel in the list!")
                            # This should really never happen, so we'll just carry on with the wrong channel index

                        # Response code, SNR, 2x reserved bytes, channel index, pathlength/direct (0xff)
                        response = bytes([RESP_CODE_CHANNEL_MSG_RECV_V3, snr, 0, 0,
                                          index, msg.pathlen if msg.is_flood() else 0xff])
                        # Text type (fixed as PLAIN), timestamp
                        response += struct.pack("<BL", 0, msg.message.timestamp)
                        # Message text
                        response += msg.message.message


            elif command == CMD_DEVICE_QUERY:
                # Respond with device results
                self.app_protocol_version = frame[1]
                
                logger.debug(f"CMD_DEVICE_QUERY, app protocol version:{self.app_protocol_version}")

                if self.app_protocol_version <3:
                    logger.error("Protocol version < 3 not supported")
                    break

                # We haven't really defined the maximum number of contacts.
                # Maximum channels is arbritarily set in channel.py
                # Set it to the max, 510 (255*2). Set the BLE PIN code to 123456
                # Although 510 is the max, going above this seems not to cause
                # any problems
                response = struct.pack("<BBBBL", RESP_CODE_DEVICE_INFO, FIRMWARE_VER_CODE, 255, len(self.channels), 123456)

                response += pad(FIRMWARE_BUILD_DATE, 12) + pad("Python Companion", 40) + pad(FIRMWARE_VERSION, 20)

            elif command == CMD_GET_BATTERY_VOLTAGE:
                # Respond with fake battery voltage
                logger.debug(f"CMD_GET_BATTERY_VOLTAGE")

                # Battery is apparently at 4V (4000mV)
                #response = struct.pack("<BH", RESP_CODE_BATTERY_VOLTAGE, 4000)

                # Show battery at 0xffff (65.536V) - it's a bogus value, but clearly so, and will still show as
                # 100% in the client
                response = struct.pack("<BH", RESP_CODE_BATTERY_VOLTAGE, 0xffff)

            elif command == CMD_GET_CONTACT_BY_KEY:
                key = frame[1:]
                logger.debug(f"CMD_GET_CONTACT_BY_KEY: {hexlify(key).decode()}")

                contact = self.ids.find_by_pubkey(key)

                if contact is None:
                    logger.debug("Contact not found")
                    response = ERR(ERR_CODE_NOT_FOUND)
                else:
                    logger.debug(f"Contact found: {contact.name}")
                    response = self.contactframe(RESP_CODE_CONTACT, contact)

            elif command == CMD_GET_CHANNEL:
                channel_index = frame[1]
                logger.debug(f"CMD_GET_CHANNEL: {channel_index}")

                if channel_index < len(self.channels):
                    c = self.channels[channel_index]

                    response = bytes([RESP_CODE_CHANNEL_INFO, channel_index]) + pad(c.name, 32) + c.key
                    logger.debug(f"Channel: {c.name}")
                else:
                    response = ERR(ERR_CODE_NOT_FOUND)
                    logger.debug(f"Channel does not exist")

            elif command == CMD_SET_CHANNEL:
                channel_index = frame[1]
                # Apparently it might be possible in future to have other channel key lengths than 16 bytes
                logger.debug(f"CMD_SET_CHANNEL: {channel_index}")
                if len(frame) != 2+32+16:
                    logger.debug(f"Incorrect frame length: {len(frame)} should be 50")
                    response = ERR(ERR_CODE_UNSUPPORTED_CMD)
                else:
                    name = frame[2:34]
                    key = frame[34:50]
                    self.channels[channel_index] = groupchannel.Channel(key, name)
                    logger.debug(f"Channel set to name: {name.rstrip(bytes(1)).decode()}, key: {hexlify(key).decode()}")
                    response = OK

            elif command == CMD_SEND_LOGIN:
                # Log in to remote device
                # - device public key (32 bytes)
                # - password (optional)
                if len(frame) < 33:
                    # Need at least the command code (CMD_SEND_LOGIN) and pubkey
                    response = ERR(ERR_CODE_NOT_FOUND)
                else:
                    pubkey = frame[1:33]
                    password = frame[33:]
                    logger.debug(f"CMD_SEND_LOGIN, to: {hexlify(pubkey).decode()} with password: {password.decode(errors='replace')}")
                    response = await self.send_login(pubkey, password)

            elif command == CMD_SEND_STATUS_REQ:
                # Get status from remote device
                # - device public key (32 bytes)
                if len(frame) < 33:
                    # Need at least the command code (CMD_SEND_STATUS_REQ) and pubkey
                    response = ERR(ERR_CODE_NOT_FOUND)
                else:
                    pubkey = frame[1:33]
                    logger.debug(f"CMD_SEND_STATUS_REQ, to: {hexlify(pubkey).decode()}")
                    response = await self.send_status_req(pubkey)


            elif command == CMD_SEND_TRACE_PATH:
                # Send a trace
                # Data from the app consists of
                #    tag (4 bytes) - random number to identify this trace
                #    auth (4 bytes) - authentication code (optional, probably 0)
                #    flags (1 byte) - currently all zeroes
                #    path (remaining bytes)
                if len(frame) < 10:
                    logger.warnimg("Data frame too short")
                    return ERR(ERR_CODE_UNSUPPORTED_CMD)

                tag = frame[1:5]
                auth = frame[5:9]
                flags = frame[9]
                path = frame[10:]

                logger.debug(f"CMD_SEND_TRACE_PATH: tag=0x{hexlify(tag).decode()}, auth=0x{hexlify(auth).decode()}, flags={flags}, path={pathstr(path)}")

                response = await self.send_trace(tag, auth, flags, path)

            elif command == CMD_GET_ADVERT_PATH:
                # frame[1] is a reserved byte
                key = frame[2:]
                logger.debug(f"CMD_GET_ADVERT_PATH: {hexlify(key).decode()}")

                contact = self.ids.find_by_pubkey(key)

                if contact is None or contact.advertpath is None:
                    logger.debug("Contact not found")
                    response = ERR(ERR_CODE_NOT_FOUND)
                else:
                    logger.debug(f"Contact found: {contact.name}, advert path = {pathstr(contact.advertpath)}")
                    response = struct.pack("<BLB", RESP_CODE_ADVERT_PATH, contact.rxtime, len(contact.advertpath)) + bytes(contact.advertpath)

            else:
                logger.warning(f"Unknown command: {command}")
                response = ERR(ERR_CODE_NOT_FOUND)

            if response is None:
                logger.debug("No response to send")
            elif isinstance(response, list):
                for c,r in enumerate(response):
                    logger.debug(f"Sending response {c+1}/{len(response)}")
                    await self.appinterface.tx(r)
            else:
                logger.debug("Sending response")
                await self.appinterface.tx(response)

    async def start(self):
        # Start the mesh
        await super().start()

        # Start the main task
        current_taskgroup.get().create_task(self.run(), name="Companion radio main")
