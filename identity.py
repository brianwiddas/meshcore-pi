
import struct
import time
from enum import Enum, Flag
from collections import defaultdict
from binascii import hexlify,unhexlify

from ed25519_wrapper import ED25519_Wrapper
from exceptions import InvalidMeshcorePacket


import logging

logger = logging.getLogger(__name__)


class AdvertType(Enum):
    NONE = 0          # No advertisement type
    CHAT = 1          # Chat client advertisement
    REPEATER = 2      # Repeater advertisement
    ROOM = 3          # Room server advertisement
    SENSOR = 4        # Sensor device advertisement
    # FUTURE: 5..15

class AdvertDataFlags(Flag):
    NONE = 0x00  # No flags - is this actually a valid advert?
    LATLON = 0x10   # Latitude and Longitude data included
    BATTERY = 0x20  # Battery data included (future use)
    TEMPERATURE = 0x40  # Temperature data included (future use)
    NAME = 0x80 # Name data included

class AdvertBase:
    """
    AdvertBase Class

    This class represents the base class for all advertisements.
    """
    PUB_KEY_SIZE = 32
    TIMESTAMP_SIZE = 4
    SIGNATURE_SIZE = 64
    AD_START = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE
    MAX_ADVERT_DATA_SIZE = 32

    def __init__(self, data = None):
        self.data = data


class AdvertData(AdvertBase):
    """
    AdvertData Class

    This class represents the advertisement data. It contains the advertisement type and flags.
    """

    def __init__(self, data):
        # Keep the data as is, as we may need it later
        super().__init__(data)
        """
        Initialize the AdvertData class with the given data.
        """
        # TODO: Check for valid packet length
        self._identity = data[0:self.PUB_KEY_SIZE]
        self._timestamp = struct.unpack('<L', data[self.PUB_KEY_SIZE:self.PUB_KEY_SIZE + self.TIMESTAMP_SIZE])[0]
        self._signature = data[self.PUB_KEY_SIZE + self.TIMESTAMP_SIZE:self.PUB_KEY_SIZE + self.TIMESTAMP_SIZE + self.SIGNATURE_SIZE]
        self._advert = data[self.PUB_KEY_SIZE + self.TIMESTAMP_SIZE + self.SIGNATURE_SIZE:]
        try:
            self._adv_type = AdvertType(self._advert[0] & 0x0f)
            self._adv_flags = AdvertDataFlags(self._advert[0] & 0xf0)
        except ValueError as e:
            raise InvalidMeshcorePacket(e.args)
        self._latlon = None
        self._battery = None
        self._temperature = None
        self._name = None

        # FIXME - is no longer battery or temperature data, just unnamed "features"
        # Data always appears in the order of latlon, battery, temperature, name
        start = 1
        if self._adv_flags & AdvertDataFlags.LATLON:
            self._latlon = self._advert[start:start + 8]    
            start += 8

            # Unpack the latlon data
            # Each is a 4-byte signed integer, containing the lat/lon in microdegrees
            (lat,lon) = struct.unpack("<ll", self._latlon)

            # Convert to degrees
            self._latlon = (lat / 1000000.0, lon / 1000000.0)

        # The format for these two is undefined
        if self._adv_flags & AdvertDataFlags.BATTERY:
            self._battery = self._advert[start:start + 2]
            start += 2
        if self._adv_flags & AdvertDataFlags.TEMPERATURE:
            self._temperature = self._advert[start:start + 2]
            start += 2

        # This comment used to say "Not even sure what an advert without this
        # would look like."
        # Turns out (thanks to someone sending one), it breaks various things
        # which didn't expect None as the name. So now we'll change the name
        # the app displays
        if self._adv_flags & AdvertDataFlags.NAME:
            self._name = (self._advert[start:]).decode('utf-8', errors="replace")
        else:
            # Set it to something
            self._name = '❓ Unnamed ' + hexlify(self._identity[:4]).decode()

    # Read-only properties - can't set these as they would break the signature
    @property
    def identity(self):
        """
        Get the identity.
        """
        return self._identity
    
    @property
    def timestamp(self):
        """
        Get the timestamp.
        """
        return self._timestamp

    @property
    def signature(self):
        """
        Get the signature.
        """
        return self._signature

    @property
    def adv_type(self):
        """
        Get the advertisement type.
        """
        return self._adv_type
    
    @property
    def adv_flags(self):
        """
        Get the advertisement flags.
        """
        return self._adv_flags
    
    @property
    def latlon(self):
        """
        Get the latitude and longitude.
        """
        return self._latlon

    # These two have no defined format, so there's nothing useful to return
    @property
    def battery(self):
        return self._battery
    
    @property
    def temperature(self):
        return self._temperature
    
    @property
    def name(self):
        """
        Get the name.
        """
        return self._name

    def validate(self, publickey=None):
        """
        Validate the advert using the public key, or its own identity if no key supplied.
        """
        if publickey is None:
            publickey = self.identity

        # message = identity + timestamp + advert
        message = (self.identity + self.data[self.PUB_KEY_SIZE:self.PUB_KEY_SIZE + self.TIMESTAMP_SIZE] +
            self.data[self.AD_START:])
        
        # Verify the signature
        try:
            logger.debug("Verifying signature from advert")
            result = ED25519_Wrapper.verify(publickey, message, self.signature)
            logger.debug(f"Signature is {'' if result else 'in'}valid")
            return result

        except ValueError as e:
            # Bad data in the signature, can't be properly calculated
            logger.debug(f"Bad signature: {repr(e)}")
            return False
        except Exception as e:
            # The eddsa library doesn't have very useful Exceptions
            logger.debug(f"Exception while validating signature: {repr(e)}")
            return False

    def __str__(self):
        # These two are repeated in the line below
        s = f"Identity: {self.identity.hex()}\n"
        s += f"Timestamp: {self.timestamp} ({time.ctime(self.timestamp)})\n"
        s += f"Data: {self.adv_type.name}/{self.adv_flags.name}: {self.latlon}, {self.name}\n"
        s += f"Signature is {'valid' if self.validate() else 'invalid'}\n"
        return s

class Destination:
    """
    Contains the minimum methods required for encrypting a message to a recipient.
    The recipient will either be an Identity or an AnonIdentity
    """

    def __init__(self):
        # Flood
        self.path = None
        self._sharedsecret = None
        self._pubkey = None

        # Is this an admin identity (for repeaters, room servers, etc)?
        self.admin = False

        # Signal-to-noise ratio (for repeater neighbour data)
        self.snr = None

    @property
    def sharedsecret(self):
        return self._sharedsecret

    @property
    def pubkey(self):
        return self._pubkey

    # Return the first byte of the public key, to use as a hash
    # This is not intended to be a secure hash, just an identifier to speed up searching; it's how Meshcore does it
    @property
    def hash(self):
        return self.pubkey[0]

    # Set the shared secret
    def create_shared_secret(self, private_key:ED25519_Wrapper):
        self._sharedsecret = private_key.shared_secret(self.pubkey)

    @property
    def name(self):
        return "AnonReq: " + hexlify(self.pubkey).decode()

    @property
    def timestamp(self):
        return int(time.time())


class AnonIdentity(Destination):
    """
    A single anonymous contact's identity (public key)
    """
    def __init__(self, pubkey):
        super().__init__()

        self._timestamp = int(time.time())
        self._pubkey = pubkey

    @property
    def timestamp(self):
        return int(time.time())

    @property
    def timestamp(self):
        return self._timestamp


class Identity(Destination):
    """
    Represent a single contact's identity, as received from the sender, along with
    data relevant to that identity, such as the path to reach them.
    """

    # Public key and timestamp are required
    def __init__(self, advert:AdvertData, path=None, advertpath=None):
        super().__init__()

        self.advert = advert

        # None = Flood, [] = direct, [ x, y, z ... ] = path
        self.path = path
        # How their advert got to us - this isn't useful for sending, it's just interesting
        self.advertpath = advertpath
        # When their advert arrived (irrespective of advert timestamp, which could be wrong)
        self.rxtime = int(time.time())
        # Last received message timestamp - used for room servers
        self.lastmsgtime = 0

    def __repr__(self):
        return f"Identity(name={self.advert.name}, pk={self.advert.identity.hex()})"
    
    def __str__(self):
        return f"{self.advert.identity.hex()} ({self.advert.name})"
    
    # Read-only values
    @property
    def pubkey(self):
        return self.advert.identity
    
    @property
    def timestamp(self):
        return self.advert.timestamp
    
    @property
    def latlon(self):
        return self.advert.latlon
    
    @property
    def name(self):
        return self.advert.name


class SelfIdentity(AdvertBase):
    """
    SelfIdentity Class

    This class represents the identity of this client, which has a private key, a timestamp and possibly variable data for the other elements
    """

    def __init__(self, private_key:ED25519_Wrapper=None, latlon:tuple=None,
                 name:str=None, devicetype:AdvertType = AdvertType.CHAT):
        """
        Initialize the SelfIdentity class
            * Private key (64-byte Meshcore style or 32-byte seed, or none for new key
            * Lat/lon tuple (latitude, longitude) in degrees
            * Name string
            * Device type (default is CHAT, ie. user client)
        """
        if not isinstance(private_key, ED25519_Wrapper):
            raise ValueError('Private key is wrong type')
        self.private_key = private_key
        
        self._identity = self.private_key.public_key
        
        self.latlon = latlon

        self.name = name

        self.battery = None
        self.temperature = None

        self.devicetype = devicetype

    @property
    def name(self):
        return self._name
    
    @name.setter
    def name(self, value):
        # TODO: check this limit
        if isinstance(value, str):
            name = value.encode('utf-8')
        else:
            name = value
        if len(name) > self.MAX_ADVERT_DATA_SIZE:
            raise ValueError(f"Name is too long, maximum is {self.MAX_ADVERT_DATA_SIZE} bytes")
        
        self._name = name


    def sign(self, data):
        """
        Sign the data with the private key.
        """
        return self.private_key.sign(data)

    # Fetch advert data from this object the same as you would for any other stored advert
    @property
    def data(self):
        identity = self.private_key.public_key
        # Update the timestamp every time we do the advert
        timestamp = struct.pack("<L", int(time.time()))

        flags = AdvertDataFlags.NONE
        # Set the flags based on the data we have
        if self.latlon is not None:
            flags |= AdvertDataFlags.LATLON
        if self.name is not None:
            flags |= AdvertDataFlags.NAME

        advert = bytes([self.devicetype.value | flags.value])

        if self.latlon is not None:
            advert += struct.pack("<ll", int(self.latlon[0] * 1000000), int(self.latlon[1] * 1000000))

        # Ignoring battery and temperature for now

        if self.name is not None:
            advert += self.name

        message = identity + timestamp + advert
        signature = self.private_key.sign(message)

        # Return the full advert data
        return identity + timestamp + signature + advert

    # Return the first byte of the public key, to use as a hash
    # This is not intended to be a secure hash, just an identifier to speed up searching; it's how Meshcore does it
    @property
    def hash(self):
        return self.private_key.public_key[0]


class IdentityStore:
    """
    IdentityStore Class

    This class represents a simple store of identities in local memory. This class can be overridden to provide
    persistance in files, databases, etc.
    """

    def __init__(self):
        self._identities = defaultdict(list)
    
    def add_identity(self, identity:Destination):
        """
        Add the identity to the list of known IDs

        Return True if we added/updated the list, False otherwise
        """
        hash = identity.hash
        for x, id in enumerate(self._identities[hash]):
            if id.pubkey == identity.pubkey:
                # Already have this identity, so update it
                if id.timestamp <= identity.timestamp or id.lastmsgtime <= identity.lastmsgtime:
                    self._identities[hash][x] = identity
                    logger.debug(f"Updating identity {identity.pubkey.hex()} ({identity.name})")
                    return True
                else:
                    # Already have a newer identity, so ignore this one
                    logger.debug(f"Already have newer identity for {identity.pubkey.hex()}")
                    return False
                return
        # New identity, so add it
        logger.debug(f"Adding identity for {identity.name} under hash {hash:02x}")
        self._identities[hash].append(identity)
        return True

    # Delete the identity from the store. It could come back if it is received as an advert again
    def del_identity(self, pubkey:bytes):
        """
        Delete the identity (by pubkey) from the list of known IDs

        Return True if we found/deleted the identity, False otherwise
        """
        hash = pubkey[0]
 
        for x, id in enumerate(self._identities[hash]):
            if id.pubkey == pubkey:
                del self._identities[hash][x]
                return True
 
        return False


    def get_all(self):
        """
        Get all identities.
        """
        # Flatten the list of identities
        return sum(self._identities.values(), [])
    
    def find_by_hash(self, hash):
        """
        Return all identities with the given hash, so they can be iterated over to attempt to decrypt a message.
        """
        return self._identities[hash]

    def find_by_name(self, partial):
        """
        Return the first identity that partially matches the name
        """
        for id in self.get_all():
            if id.name is not None and id.name.count(partial):
                return id
        return None
    
    def find_by_pubkey(self, pubkey):
        # Can do partial matches, eg for client apps that use 6-byte partial ids
        for id in self.get_all():
            if id.pubkey.startswith(pubkey):
                return id
        return None

    # This is mostly for debugging
    def print(self):
        print("Identities:")
        for hash, ids in self._identities.items():
            print(f"Hash: {hash:02x}")
            for id in ids:
                print(f"  {id}")

class FileIdentityStore(IdentityStore):
    """
    Version of the identity store which reads contacts from a file, and writes out to file every time
    it's updated.
    The file format is:
        # Comment lines start with #
        <hex identity>/<hex path>/<hex advertpath>@<last message time>:<snr>
        <hex identity> is the hex encoded identity public key
        <hex path> is the hex encoded path to reach this identity (empty for flood, omitted for direct)
        <hex advertpath> is the hex encoded path the advert took to reach us (optional)
        <last message time> is the timestamp of the last message received from this identity (optional)
        <snr> is the signal-to-noise ratio of the last message received from this identity (optional)
    
    Requires a SelfIdentity object or private key to be passed in, so that the shared secret can be
    calculated for each identity as it is loaded.
    """
    def __init__(self, filename, selfidentity):
        super().__init__()

        if isinstance(selfidentity, SelfIdentity):
            selfidentity = selfidentity.private_key

        self.filename = filename

        try:
            with open(filename, "r") as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    snr = line.rstrip().split(':')
                    since = snr[0].rstrip().split('@')
                    fields = since[0].rstrip().split('/')
                    data = unhexlify(fields[0])
                    if len(fields) >= 2:
                        path = bytearray(unhexlify(fields[1]))
                    else:
                        path = None
                    if len(fields) >= 3:
                        advertpath = bytearray(unhexlify(fields[2]))
                    else:
                        advertpath = None
                    id = Identity(AdvertData(data), path, advertpath)
                    id.create_shared_secret(selfidentity)

                    if len(since) >= 2:
                        id.lastmsgtime = int(since[1])
                    if len(snr) >= 2:
                        id.snr = float(snr[1])
    
                    super().add_identity(id)
        except FileNotFoundError:
            logger.info(f"No contacts to load: file {filename} not found")

    def _writefile(self):
        # Write everything back to file
        with open(self.filename, "w") as f:
            print("# Stored adverts for contacts", file=f)
            for id in self.get_all():
                if isinstance(id, AnonIdentity):
                    # Skip anon
                    continue
                # Only writing advertised identities to file
                print('#', id.name, file=f)
                print(hexlify(id.advert.data).decode('utf-8'), file=f, end='')
                if id.path is not None:
                    print(f"/{hexlify(id.path).decode('utf-8')}", file=f, end='')
                    if id.advertpath is not None:
                        print(f"/{hexlify(id.advertpath).decode('utf-8')}", file=f, end='')
                if id.lastmsgtime > 0:
                    print(f"@{id.lastmsgtime}", file=f, end='')
                if id.snr is not None:
                    print(f":{id.snr}", file=f, end='')

                print(file=f)

    def add_identity(self, identity):
        result = super().add_identity(identity)

        if result:
            self._writefile()

        return result

    def del_identity(self, pubkey):
        result = super().del_identity(pubkey)

        if result:
            self._writefile()

        return result
