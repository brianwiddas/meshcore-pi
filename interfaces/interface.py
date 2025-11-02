
import asyncio

import logging
from configuration import get_config

logger = logging.getLogger(__name__)

# Fetch a list of interfaces from the configuration, and bring them up
def configure_interfaces(config):
    interfaces = []

    # Expect a list of interfaces
    interface_list = config.get('interfaces')

    interface_config = config.get('interface')

    for i in interface_list:
        logger.info(f"Configuring interface: {i}")

        data = interface_config.get(i)

        if data is None:
            logger.error(f"No configuration for interface {i}")
            continue

        interface_type = data.get("type", i)
        logger.debug(f"Configuring interface {i}, type {interface_type}")

        if interface_type == "mock":
            file = data.get("file", None)
            repeat = data.get("repeat", False)
            try:
                from . import mockinterface
                i_face = mockinterface.MockInterface(file=file, repeat=repeat)

                interfaces.append(i_face)
            except Exception as e:
                logger.error(f"Unable to configure interface {i}: {repr(e)}")
                raise

        if interface_type == "espnow":
            interface_name = data.get("device")
            if interface_name is None:
                logger.error(f"Missing WiFi device name for {i}")
            try:
                from . import espnow as espnow_interface
                i_face = espnow_interface.ESPNOWInterface(interface_name)

                interfaces.append(i_face)
            except Exception as e:
                logger.error(f"Unable to configure interface {i}: {repr(e)}")
                raise

        elif interface_type == "lora":
            try:
                from . import lorainterface
                i_face = lorainterface.LoRaInterface(data)

                interfaces.append(i_face)
            except Exception as e:
                logger.error(f"Unable to configure interface {i}: {repr(e)}")
                raise

        elif interface_type == "companion":
            try:
                from . import companioninterface
                i_face = companioninterface.CompanionInterface(data)

                interfaces.append(i_face)
            except Exception as e:
                logger.error(f"Unable to configure interface {i}: {repr(e)}")
                raise

        elif interface_type == "meshtnc":
            try:
                from . import meshtnc
                i_face = meshtnc.MeshTNC(data)

                interfaces.append(i_face)
            except Exception as e:
                logger.error(f"Unable to configure interface {i}: {repr(e)}")
                raise

        else:
            logger.error(f"Interface {i} is unknown type {interface_type}")

    if len(interfaces):
        logger.debug(f"{len(interfaces)} interface(s) configured")
    else:
        raise ValueError("No valid interface configuration found")

    return interfaces

class Interface:
    def __init__(self):
        self._name = "Base interface class"

        # Queue for received packets
        self._rx_q = asyncio.Queue()
    
    @property
    def name(self):
        return self._name

    @property
    def rx_q(self):
        return self._rx_q
    
    async def get(self):
        x= await self.rx_q.get()
        #print(f"Packet: {x}")
        return x

    async def transmit(self, tx_packet):
        """
        Transmit packet
        Returns transmit time (sec)
        """
        print("Not implemented")
        return 0

    def transmit_wait(self):
        """
        Period of time until the airtime duty cycle falls below the threshold
        0 if the threshold is not exceeded
        """
        return 0


    async def start(self):
        print("Not implemented")
        return None
    
    
