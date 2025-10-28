#!/usr/bin/env python

import asyncio
from aiotools import current_taskgroup, TaskGroup

import sys
from collections import Counter
import time

import packet
from identity import Identity, AdvertData, IdentityStore, FileIdentityStore, SelfIdentity
from binascii import unhexlify, hexlify

import groupchannel
from exceptions import *
from ed25519_wrapper import ED25519_Wrapper
import interfaces.interface as interface
import configuration
from dispatch import default_dispatch


import logging

# Config file
if len(sys.argv)>1:
    configfile = sys.argv[1]

    config = configuration.get_config(configfile)
else:
    config = configuration.get_config("readonly.toml")

# Default logging configuration
if sys.version_info >= (3,12):
    # 3.12 adds 'taskName' to the LogRecord attributes
    logformat = '%(asctime)s %(levelname)-8s %(taskName)s: %(name)s: %(message)s'
else:
    logformat = '%(asctime)s %(levelname)-8s: %(name)s: %(message)s'

logging_default_config = configuration.get_config(
    {'format': logformat,
     'dateformat': '%Y-%m-%d %H:%M:%S',
     'level': 'debug',
     'file': 'readonly.log' })

loggingconfig = config.get('log', view=True)
loggingconfig.set_default(logging_default_config)


loglevel = getattr(logging, loggingconfig.get('level','DEBUG').upper(), logging.DEBUG)

logger = logging.getLogger(__name__)
logging.basicConfig(
    format=loggingconfig.get('format'),
    datefmt=loggingconfig.get('dateformat'),
    filename=loggingconfig.get('file'),
    level=loglevel)

logger.debug("Logging configured")

# Configure interfaces
packetinterfaces = interface.configure_interfaces(config)

# Create dispatcher
dispatcher = default_dispatch()

# Identity, if one is provided in config use that, else a random one
k = config.get('privatekey')
if k is not None:
    k = unhexlify(k.encode())
private_key = ED25519_Wrapper(k)

if k is None:
    print("Generated random identity key:", hexlify(private_key.private_key).decode('utf-8'))
    logger.info(f"Generated random identity key {hexlify(private_key.private_key).decode('utf-8')}")

print("Identity public key:", hexlify(private_key.public_key).decode('utf-8'))

me = SelfIdentity(private_key=private_key, name='Readonly device')

ids_file = config.get('contacts')
if ids_file is None:
    logger.debug("No identity file configured, using memory store")
    ids = IdentityStore()
else:
    logger.debug(f"Using identity file {ids_file}")
    ids = FileIdentityStore(ids_file, private_key)

# Channels
# Create a list consisting of only the public channel
channels = groupchannel.channels(None, 1, True)

# Any additional channels
additional_channels = config.get('channels', [])

for c in additional_channels:
    if c.startswith('#'):
        channel = groupchannel.Channel(name=c)
    else:
        k = config.get('channel.'+c)
        if k is not None:
            channel = groupchannel.Channel(name=c, key=unhexlify(k.encode()))
        else:
            logger.error(f"No key configured for channel {c}")
            continue

    channels.append(channel)
    logger.info(f"Configured additional channel {c}")

# Stats
stats_duplicate=0
stats_flood=Counter()
stats_direct=Counter()
stats_packettype=Counter()

async def periodicstats(file=None):

    if file is None:
        return

    with open(file, "a") as statsfile:
        logger.info(f"Writing periodic stats to {file}")

        while True:
            await asyncio.sleep(300)

            t = int(time.time())
            s = f"Packet receive stats at {time.ctime(t)} ({t})"
            print(s, file=statsfile)
            print("-" * len(s), file=statsfile)
            rx = sum(stats_flood.values()) + sum(stats_direct.values())
            print("RX packets:", rx, file=statsfile)
            print("Duplicates:", stats_duplicate, file=statsfile)
            print("Direct:", sum(stats_direct.values()), file=statsfile)
            for hop in sorted(stats_direct.keys()):
                print(f"  {hop} hop(s): {stats_direct[hop]}", file=statsfile)
            print("Flood:", sum(stats_flood.values()), file=statsfile)
            for hop in sorted(stats_flood.keys()):
                print(f"  {hop} hop(s): {stats_flood[hop]}", file=statsfile)
            print("Received packet types:", file=statsfile)
            for type in sorted(stats_packettype.keys()):
                print(f"  {type}:{' '*(10-len(type))}{stats_packettype[type]}", file=statsfile)
            print('', file=statsfile)


async def processpackets():
    global stats_duplicate

    rx_queue = dispatcher.add_queue('Read only device')

    while True:
        try:
            m = await rx_queue.get()

            if isinstance(m, bytes):
                # Contains just a packet
                receivedpacket = packet.MC_Incoming.convert_packet(bytearray(m), me, ids, channels)
            else:
                # Packet, RSSI, SNR
                (p, rssi, snr) = m
                receivedpacket = packet.MC_Incoming.convert_packet(bytearray(p), me, ids, channels, rssi, snr)

            logger.debug("New packet: %s", hexlify(receivedpacket.packet).decode('utf-8'))

            if receivedpacket.is_direct():
                stats_direct[receivedpacket.pathlen] += 1
            elif receivedpacket.is_flood():
                stats_flood[receivedpacket.pathlen] += 1

            stats_packettype[receivedpacket.typename] += 1

            if dispatcher.hasSeen(receivedpacket):
                logger.info(f"Duplicate! Already seen this packet")
                stats_duplicate += 1
                continue

            logger.debug("Class: %s", receivedpacket.__class__.__name__)
            if isinstance(receivedpacket, packet.MC_Advert):
                if receivedpacket.advert.validate():
                    id = Identity(receivedpacket.advert)
                    id.create_shared_secret(private_key)
                    ids.add_identity(id)

            output = None
            if isinstance(receivedpacket, packet.MC_Advert) and receivedpacket.advert.validate():
                output = f"[Advert] {receivedpacket.advert.name}"
                if receivedpacket.advert.latlon is not None:
                    output += f" {receivedpacket.advert.latlon}"
            elif isinstance(receivedpacket, packet.MC_GroupText) and receivedpacket.channel is not None:
                output = f"[{receivedpacket.channel.strname}] {receivedpacket.message.message.decode('utf8')}"
            elif isinstance(receivedpacket, packet.MC_Text) and receivedpacket.decrypted:
                output = f"[@ {receivedpacket.source.name}] {receivedpacket.text}"

            if output:
                print(time.strftime('%Y-%m-%d %H:%M:%S'), output)

            logger.info(str(receivedpacket))

        except InvalidMeshcorePacket as e:
            logger.warning(f"Error: {repr(e)}")


async def main():
    async with TaskGroup() as tg:
        for packetinterface in packetinterfaces:
            await packetinterface.start()
            dispatcher.add_interface(packetinterface)

        await dispatcher.start()

        tg.create_task(processpackets(), name="Packet processor")

        statsfile = config.get('statsfile')
        tg.create_task(periodicstats(statsfile), name="Periodic stats")


try:
    asyncio.run(main())
except KeyboardInterrupt:
    logger.info("Exiting on keyboard interrupt")
    print("\nBye")
