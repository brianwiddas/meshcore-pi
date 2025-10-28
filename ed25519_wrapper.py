
import sys
sys.path.append("./lib/pure25519")
from pure25519 import eddsa, mckey, basic
from hashlib import sha512

import logging
logger = logging.getLogger(__name__)

class ED25519_Wrapper:
    """
    This class wraps whatever library is used for cryptographic operations.

    Meshcore uses ED25519 for signing and verifying messages, and AES256 for
    encryption. An ED25519 private key is a 32-byte seed number which is fed
    into SHA-512 to generate a 64-bit number to sign transactions. This number
    can be used to generate a 32-byte public key.

    Most libraries use either the 32-byte seed as the private key, or a 64-byte
    number which is the 32-byte seed followed by the 32-byte public key.

    Unfortunately, the Meshcore implementation uses the 64-byte SHA-512 number
    as the private key. The seed is thrown away once it has been used, and is
    not recoverable. The 64-byte key generated is enough to use as a private
    key, and to create the public key, but is not compatible with any library.
    So we have to use a version of the ED25519 library which has been modified
    to accept the 64-byte key as the private key. Since this risks confusion
    with the 64-byte "private key" which is really the 32-byte seed followed by
    the 32-byte public key, the 64-byte Meshcore key is wrapped in a class
    called MCKey.

    https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/ explains the steps
    a 32-byte seed goes through to create the 64-byte key. In the nomenclature
    of the diagram, Meshcore is creating and storing keys as (a,RH). However,
    none of the python libraries, including pynacl, appear to use this format.
    """

    def __init__(self, key=None):
        """
        Initialize the ED25519_Wrapper class with the given key.

        If no key is provided, a new one is generated.

        A 32-byte key is assumed to be a seed, and a 64-byte key is assumed to be
        a Meshcore-style private key imported from elsewhere.
        """
        if key is None:
            # Generate a new key
            while True:
                self.key = eddsa.create_signing_key()
                # IDs (ie, the first byte of the public key) of 0 and 255 are
                # reserved for future use from the Meshcore commit of 2025-04-06
                if self.public_key[0] != 0x00 and self.public_key[0] != 0xff:
                    break
                logger.debug(f"Reserved ID produced (0x{self.public_key[0]:02x}), trying again")
        elif len(key) == 32:
            # Assume the key is a seed
            self.key = key
        elif len(key) == 64:
            # Assume the key is a Meshcore-style private key
            self.key = mckey.MCKey(key)
        else:
            raise ValueError("Key must be either 32 or 64 bytes long.")
 
    @property
    def public_key(self):
        """
        Return the public key.
        """
        return eddsa.publickey(self.key)

    @property
    def private_key(self):
        """
        Return the private key.
        """
        return self.key

    @property
    def meshcore_private_key(self):
        """
        Return the Meshcore-style private key.
        """
        if isinstance(self.key, mckey.MCKey):
            return self.key.privkey
        else:
            # Convert the private key to a Meshcore-style private key
            pk = sha512(self.key).digest()

            # Technically, this is (LH,RH), not (a,RH), beause a handful of bits
            # haven't been manipulated. However, that will happen when it gets
            # imported.

            return pk

    def sign(self, message):
        """
        Sign the given message with the private key.
        """
        return eddsa.sign(self.key, message)

    @classmethod
    def verify(cls, public_key, message, signature):
        """
        Verify the given signature with the public key.

        Parameters:
            public_key (bytes): The public key used for verification.
            message (bytes): The original message that was signed.
            signature (bytes): The signature to verify.
        Returns:
            bool: True if the signature is valid, False otherwise.

        """
        if len(public_key) != 32:
            raise ValueError("Bad verifying key length %d" % len(public_key))
        if len(signature) != 64:
            raise ValueError("Bad signature length %d" % len(signature))

        return eddsa.checkvalid(signature, message, public_key)

    def shared_secret(self, other_public_key):
        """
        Calculate the shared secret with another public key.

        Parameters:
            other_public_key (bytes): The public key of the other party.
        Returns:
            bytes: The shared secret.
        """

        if len(other_public_key) != 32:
            raise ValueError("Bad public key length %d" % len(other_public_key))

        # Only need the first 32 bytes of the private key
        privkey = self.meshcore_private_key[:32]

        # I haven't been able to find this algorithm in any library, so this is taken
        # directly from the ed25519 library in the Meshcore source
        # Define the prime modulus for Curve25519

        p = 2**255 - 19

        # Convert the private key to an integer and clamp it
        e = int.from_bytes(privkey, "little")
        e &= (1 << 254) - 8  # Clear the lowest 3 bits
        e |= 1 << 254        # Set the second-highest bit
        e &= ~(1 << 255)     # Clear the highest bit

        # Convert the public key to an integer and clear the top bit
        edwards_y = int.from_bytes(other_public_key, "little") 
        edwards_y &= ~(1 << 255)     # Clear the highest bit

        # Convert Edwards Y to Montgomery X
        # montgomeryX = (edwardsY + 1) * inverse(1 - edwardsY) mod p
        tmp0 = (edwards_y + 1) % p
        tmp1 = (1 - edwards_y) % p
        tmp1 = pow(tmp1, p - 2, p)  # Modular inverse using Fermat's Little Theorem
        x1 = (tmp0 * tmp1) % p

        # Initialize ladder variables
        x2 = 1
        z2 = 0
        x3 = x1
        z3 = 1

        # Constant-time Montgomery ladder multiplication
        swap = 0
        for pos in range(254, -1, -1):
            # Extract the current bit of the private key
            b = (e >> pos) & 1
            swap ^= b

            # Conditional swap
            if swap:
                x2, x3 = x3, x2
                z2, z3 = z3, z2
            swap = b

            # Montgomery ladder step
            tmp0 = (x3 - z3) % p
            tmp1 = (x2 - z2) % p
            x2 = (x2 + z2) % p
            z2 = (x3 + z3) % p
            z3 = (tmp0 * x2) % p
            z2 = (z2 * tmp1) % p
            tmp0 = (tmp1 * tmp1) % p
            tmp1 = (x2 * x2) % p
            x3 = (z3 + z2) % p
            z2 = (z3 - z2) % p
            x2 = (tmp1 * tmp0) % p
            tmp1 = (tmp1 - tmp0) % p
            z2 = (z2 * z2) % p
            z3 = (tmp1 * 121666) % p
            x3 = (x3 * x3) % p
            tmp0 = (tmp0 + z3) % p
            z3 = (x1 * z2) % p
            z2 = (tmp1 * tmp0) % p

        # Final conditional swap
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2

        # Convert back to affine coordinates
        z2 = pow(z2, p - 2, p)  # Modular inverse of z2
        x2 = (x2 * z2) % p

        # Convert the result to bytes
        return x2.to_bytes(32, "little")
