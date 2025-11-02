Implementing Meshcore in python
===============================

What this is
------------

This an implementation of the MeshCore protocol in Python, intended to
run on a Raspberry Pi or other Linux device. It can make use of SX1262
interfaces such as the Waveshare LoRa HAT or an HT-RA62 connected to SPI
and GPIO.

It can also communicate over ESP-NOW with a suitable WiFi interface (one
which can be put into "monitor" mode), and for experimenting, it can use
an existing companion radio (such as a Heltec) running MeshCore as a
receive-only radio interface, or (if you modify it slightly) as a
transmitter too.

It is able to be a companion radio (which can connect to the MeshCore app
over WiFi or serial), a room server or a repeater, or several of these at
once. As it can be configured with multiple interfaces, it is capable of
repeating/bridging between LoRa and ESP-NOW meshes.

Get started
-----------

You will need:
* python 3.11 minimum, 3.12 is better
* Some external modules

It is recommended to create a virtual environment for this:

```
$ python -m venv venv
$ . ./venv/bin/activate
```

Then install the following:

* pycryptodome - cyptographic functions
* aiotools - asyncio utilities
* pyserial_asyncio - serial modules
* typing-extensions - seems to be needed for recent aiotools

If you have an SX1262 board, you'll need:
* LoRaRF - SX1262 driver

If you're using ESP-NOW:
* scapy - must be 2.5.0, newer versions don't work

```
$ pip install pycryptodome aiotools pyserial_asyncio typing-extensions
$ pip install LoRaRF
$ pip install scapy==2.5.0
```

### Using LoRa interfaces

The LoRaRF library assumes you're running on a Raspberry Pi. There is
configuration for a Waveshare LoRa/GNSS HAT in the example config, as
well as a HT-RA62 wired as follows:

| HT-RA62 pin | GPIO |
|-------------|------|
| Reset       | 22   |
| Busy        | 23   |
| DIO1        | 26   |
| MOSI        | 10   |
| MISO        | 9    |
| SCK         | 11   |
| NSS         | 8    |

Other pins (TXEN, RXEN, DIO2, DIO3) are not connected

The LoRaRF library installs RPi.GPIO for GPIO access. Unfortunately, if
you're running newer versions of Raspberry Pi OS (eg, Bookworm), you'll
need to replace it with lgpio

```
$ pip uninstall rpi.gpio
$ pip install rpi-lgpio
```

### Using ESP-NOW

Using ESP-NOW requires a WiFi interface which can support monitor mode.

``iw list`` will show the capabilities of your WiFi interface; for instance:

```
        Supported interface modes:
                 * IBSS
                 * managed
                 * AP
                 * AP/VLAN
                 * monitor
                 * P2P-client
                 * P2P-GO
                 * P2P-device
```

If the interface doesn't list "monitor" mode, it won't support ESP-NOW.

The standard Raspberry Pi WiFi interface doesn't support monitor mode.
However, the nexmon project can enable it.

https://github.com/seemoo-lab/nexmon

I have tested ESP-NOW on a Raspberry Pi 3B 1.2 running kernel 6.12, which
required this fork:

https://github.com/thau0x01/nexmon

It also worked on an ASUS laptop running Linux, which has a suitable WiFi
interface.

For nexmon on a Raspberry Pi 3, the following seems to work

```
# cd nexmon
# . ./setup_env.sh
# cd patches/bcm43430a1/7_45_41_46/nexmon/
# make install-firmware
# killall NetworkManager
# killall nm-dispatcher
# iw phy `iw dev wlan0 info | gawk '/wiphy/ {printf "phy" $2}'` interface add mon0 type monitor
# iwconfig wlan0 channel 1
# ifconfig wlan0 up
# ifconfig mon0 up
```

mon0 will need to be set in the config file as the WiFi interface under the
espnow section

For other Linux devices, the simplest way to enable monitor mode is using the
``prep.sh`` script in ``lib/ESPythoNOW/``

```
sh prep.sh <wifi interface> 1
```

The WiFi interface needs to be on channel 1 in order for ESP-NOW packets to
be sent to and recieved from ESP32 devices. It may also be necessary to stop
or kill the NetworkManager daemon to prevent it reconfiguring the interface.

In order for meshcore-pi to connect to the monitor interface in raw mode,
it will need either to be run as root, or to have the CAP_NET_RAW capability.

The easiest way to set this up is to make a copy of the python binary in
your virtual environment (so it's not just a symlink), then add the
capability to that

```
cd venv/bin/
mv python python.orig
cp python.orig python
sudo setcap cap_net_raw=pe python
```

### Using an existing companion radio

As part of the companion radio interface, the radio will send a copy of
every received packet to the application. This is how the "number of
repeats heard" and Discover list functions work. We can make use of this
to use a companion radio as a receive-only interface.

With a small modification, the companion radio firmware can be augmented
with an extra command (CMD_SEND_RAW_PACKET), which accepts a packet and
sends it on our behalf.

To do this, you'll need to clone the MeshCore repository, and apply the
patch in meshcore.patch, before building and installing it on your
radio.

```
$ git clone https://github.com/meshcore-dev/MeshCore.git
$ cd MeshCore
$ patch -p 1 < ../meshcore-pi/meshcore.patch
```

The companion radio has to be connected over a serial port. While in use
as a radio for meshcore-pi, it can't be used with the app. It will not see
a copy of anything transmitted, unless it is repeated back to the radio.


### MeshTNC

An alternative way to use an existing radio device is to flash it with
MeshTNC

https://github.com/datapartyjs/MeshTNC/

MeshTNC is a tool for piping LoRa data to and from consumer grade radios.

Simple connect the MeshTNC device by USB, and configure the serial port and
radio parameters int he config file.


### Serial interfaces

In order to connect a MeshCore app running in a browser to the companion
radio device, a virtual null modem is required

https://github.com/freemed/tty0tty

Then, if the meshcore-pi companion device is listening on /dev/tnt0,
the browser app can connect to /dev/tnt1



Configuration file
------------------

The default config file is config.toml; it uses the TOML config language.

https://toml.io/en/

The complete set of configuration options are shown in example-config.toml

The main options to be aware of are:

```
interfaces = ["waveshare", "espnow"]
```

The ``interfaces`` option selects which of the interfaces defined in the
config file are to be used.

```
devices = ["companion", "room"]
```

The ``devices`` option selects which of the device profiles defined in the
config file are in use.

The default config file creates a single companion radio listening on
port 5000, with a randomly-created private key.

You can use a private key from the MeshCore app. If you want to use the
randomly-generated key again, it will be displayed at startup and recorded
in the log file (which defaults to 'meshcore.log')

You can connect the companion radio app on your phone to this using the
experimental "connect via WiFi" feature. Alternatively, to use the
MeshCore browser app, change the config to a serial port (see above
regarding serial interfaces) and connect to that.

At present, Bluetooth connections are not supported.

Other files
-----------

### Contacts

Where a companion radio records its contacts, they are stored in a file
(default: contacts.mesh). Each contact is stored as a comment giving the
contact name, followed by the advert for the contact (in hex) and some
other data, such as the path to the client (if known).

This file is updated every time the contacts list is updated.

If you run more than one companion, each must have its own file

### Channels

If stored to disk, the channel list for a companion radio is a JSON
file, defaulting to channels.json

This file contains a single key, "channels", containing a dict of
channel names and keys in hex.

If a channel name is a hashtag, it is not necessary to specify the key

```
{
    "channels": {
        "Public": "8b3387e9c5cdea6ac9e5edbaa115cd72",
        "#london": null,
        "#jokes": null,
        "#meshcorepi": null
    }
}
```

### Log

The default log file is meshcore.log

If the log level is set to DEBUG, it can be very chatty.

Unsupported features
--------------------

Most of the basic functionality of MeshCore is supported. However, the
main missing items are:

* Uncollected messages are not stored persistently - at the moment,
  messages received by the companion radio device but not passed to the
  Meshcore app are stored in memory. If meshcore-pi is restarted before
  the messages are collected, they will be lost.
* Telemetry - not yet supported
* Sensors - the battery reading is fake: 0xffff, which will appear in the
  app as 65.5V, 100%
* The companion radio name can be changed in the app, though the change is
  not written to the config, so it is not persistent
* Most other config cannot be changed through the app (except channels).
* Radio parameters cannot be changed in the app, though if a LoRa interface
  is in use, it will display the parameters currently set
* Room servers and repeaters can't have their configs changed either


Future improvements
-------------------
(aka the TODO list)

* Telemetry, both for the companion radio and the sensor device type
* Ability to modify the config through the app or via CLI messages
* Support more of the companion radio protocol
* Find a better SX126x library
* More interface types than just SX126x
* Look again at the crypto libraries

FAQ
---

Q. Do I have to run this on a Raspberry Pi?

A. No, though the only supported directly connected interface is the
   SX126x via SPI and GPIO.

Q. Does it support the GPS functions of the Waveshare LoRa/GNSS HAT?

A. Not at the moment.

Q. Which Raspberries Pi will it run on?

A. 3B and 4, definitely (because I've tested it). It should probably run
   on all of them.

Q. Will this run under Micropython?

A. No. It might be possible, but some things would have to be rewritten, and
   it prioritises straightforward code over a light memory footprint.

Q. What do all the different python files do?

A. See below


What all the files are
----------------------

The structure of the software is a series of Python classes which represent
some kind of Meshcore device. The base class is BasicMesh, and other
classes build on top of that. A separate ReadonlyDevice class implements
just enough of the protocol to be able to watch passing traffic but not
participate in the mesh.

* BasicMesh - Send and receive data from the interface(s) via the dispatcher
  + CompanionRadio - Client device which acts like a companion radio,
    talking to the Meshcore app
  + CLIDevice - Any device which has a CLI and uses Anonymous Requests
      + Repeater - A repeater
      + Room - A room server
* ReadonlyDevice - Just logs arriving packets, decrypting what it can;
  makes no attempt to respond to anything


The dispatcher (dispatch.py) is responsible for taking packets from the
device class(es) and sending it via the interface

Interfaces:
* interface.py - Interface class, which other interfaces should subclass
* espnow.py - Communicate using ESP-NOW, requires an interface which can
  be put into "monitor" mode
* lorainterface.py - SX126x LoRa interface
* mockinterface.py - Pretend, read-only interface which will read packets
  from a file
* companioninterface.py - (Mis)use a companion radio as an interface.

Cypto:
* crypto.py - Wrap crypto functions, allowing the library to be changed if
  needed
* ed25519_wrapper.py - Wrap the ED25519 functions, as they have been
  modified to support 64-byte Meshcore-style private keys

Other:
* companionserial.py - Talk to a Meshcore app over a serial link
* companionwifi.py - Ditto, but wifi
* configuration.py - Config file reader
* exceptions.py - Various exceptions for packet handling
* groupchannel.py - Classes related to channels/group messages
* identity.py - Classes relating to adverts, contacts and private/public keys
* misc.py - Useful functions that don't fit in another category
* packet.py - Protocol encoding and decoding classes
* sensors.py - Interface with hardware sensors, such as the (fake) battery
  level reading

External files:
* lib/pure-25519   - pure python library for ED25519, modified to accept
  64-bit Meshcore private keys
* lib/ESPythoNOW.py   - ESP-NOW library for python


Contact
-------

Please feel free to raise issues or PRs.

If you're in the UK, you could also try sending a message to the
#meshcorepi channel, or messaging me directly at

```
659228096caba81b8b32f6e15eb031eea606fd5dfab0302275f848bbac99b24a
```

Please be aware that I live in a slightly spotty coverage area as far as
Meshcore is concerned, so while your message will *probably* get through,
it might not.
