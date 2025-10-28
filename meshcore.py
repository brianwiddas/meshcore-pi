#!/usr/bin/env python

import asyncio
from aiotools import TaskGroup

from binascii import unhexlify, hexlify
import sys
import logging

from identity import IdentityStore, FileIdentityStore, SelfIdentity, AdvertType
from exceptions import *
from ed25519_wrapper import ED25519_Wrapper
from dispatch import default_dispatch
import configuration
from misc import validate_latlon
from sensors import HardwarePlatform

import interfaces.interface as interface

# Config file
if len(sys.argv)>1:
    configfile = sys.argv[1]

    config = configuration.get_config(configfile)
else:
    config = configuration.get_config()

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
     'file': 'meshcore.log' })

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


# Print a summary of system statistics every 5 minutes
async def stats_printer():
    while True:
        print("---- Device statistics ----")
        for d in devices:
            print(f"{d.internalname}, {d.me.name.decode(errors='replace')}:")
            stats = d.get_stats()
            for k in sorted(stats):
                print(f"  {k}: {stats[k]}")
        await asyncio.sleep(300)

###
### Main program
###
logger.info("MeshcorePi starting")

# Hardware interface (battery reading)
hardware = HardwarePlatform()

# Create interfaces
packetinterfaces = interface.configure_interfaces(config)

# Create dispatcher
dispatcher = default_dispatch()

dispatcher.pass_internal = config.get('dispatcher.pass_internal', False)

# Configure devices

devices = []

device_list = config.get('devices', None)

if device_list is None:
    logger.error("No devices configured")
    print("No devices configured")
    exit(1)

for device in device_list:
    logger.info(f"Configuring device: {device}")

    data = config.get('device.'+device)

    if data is None:
        logger.error(f"No configuration for device {device}")
        continue

    device_type = data.get("type", device)
    logger.debug(f"Configuring device {device}, type {device_type}")

    # Common configuration items:
    # privatekey - hex encoded private key (default: new random key)
    # name - device name (default: "[type] "+first 4 bytes of public key)
    # lat - latitude (default: unset)
    # lon - longitude (default: unset)
    # contacts - identity store file (default: memory only)
    k = data.get('privatekey')
    if k is not None:
        k = unhexlify(k.encode())
    private_key = ED25519_Wrapper(k)

    name = data.get('name', default=f"{device_type.capitalize()} {hexlify(private_key.public_key[0:4]).decode('utf8')}")

    if k is None:
        logger.info(f"Created private key {hexlify(private_key.private_key).decode()} for {name}")
        print(f"Created private key: {hexlify(private_key.private_key).decode()}")
    else:
        print("Loaded private key from config")
    print(f"{name}, public key: {hexlify(private_key.public_key).decode()}\n")

    lat = data.get('lat')
    lon = data.get('lon')

    if lat is not None and lon is not None:
        try:
            latlon = validate_latlon(lat, lon)
        except ValueError as e:
            logger.error(f"Device {device} has invalid lat/lon: {e}")
            latlon = None
    else:
        latlon = None

    ids_file = data.get('contacts')
    if ids_file is None:
        logger.debug("No identity file configured, using memory store")
        ids = IdentityStore()
    else:
        logger.debug(f"Using identity file {ids_file}")
        ids = FileIdentityStore(ids_file, private_key)

    if device_type == "companion":
        import groupchannel
        numchannels = data.get('channels', 32)
        channelfile = data.get('channelfile')
        add_public = data.get('add_public_channel', True)

        channels = groupchannel.channels(channelfile, numchannels, add_public)

        me = SelfIdentity(private_key=private_key, name=name, latlon=latlon, devicetype=AdvertType.CHAT)

        from companionradio import CompanionRadio

        companion = CompanionRadio(me, ids, channels, dispatcher, data)
        devices.append(companion)

    elif device_type == "room":
        me = SelfIdentity(private_key=private_key, name=name, latlon=latlon, devicetype=AdvertType.ROOM)

        from roomserver import Room

        room = Room(me, ids, dispatcher, hardware, data)
        devices.append(room)

    elif device_type == "repeater":
        me = SelfIdentity(private_key=private_key, name=name, latlon=latlon, devicetype=AdvertType.REPEATER)

        from repeater import Repeater

        repeater = Repeater(me, ids, dispatcher, hardware, data)
        devices.append(repeater)

    else:
        logger.error(f"Device {device} is unknown type {device_type}")
        continue

if len(devices)==0:
    logger.error("No valid device configuration found")
    print("No valid device configuration found")
    exit(1)

if len(devices)==1:
    # No point doing this if there's only one device
    dispatcher.pass_internal = False


async def main():
    async with TaskGroup() as tg:

        # Start all the interfaces
        for packetinterface in packetinterfaces:
            await packetinterface.start()
            dispatcher.add_interface(packetinterface)

        # Start the dispatcher
        await dispatcher.start()

        # Start all the devices
        for d in devices:
            logger.debug(f"Starting {type(d).__name__}, {d.me.name.decode(errors='replace')}")
            await d.start()

            print(f"Started {d.internalname}, {d.me.name.decode(errors='replace')}")

        # Start stats printer
        # Writes stats every 5 minutes to stdout; disabled by default
        # tg.create_task(stats_printer())

try:
    asyncio.run(main())
except KeyboardInterrupt:
    logger.info("Exiting on keyboard interrupt")
    print("\nBye")
