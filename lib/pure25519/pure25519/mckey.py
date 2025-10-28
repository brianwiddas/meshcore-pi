
class MCKey:
    """
    This class represents a private key in the format used by Meshcore.

    Unlike the standard Ed25519 private key, which is 32 bytes, Meshcore uses a 64-byte private key
    derived from the 32-byte key. Unfortunately, the 64-byte key cannot be turned back into a 32-byte key,
    so we need a way to import it, in case we want to import an existing Meshcore private key.
    """
    def __init__(self, privkey: bytes):
        if len(privkey) != 64:
            raise ValueError('Private key should be 64 bytes')
        self._privkey = privkey

    @property
    def privkey(self):
        return self._privkey
