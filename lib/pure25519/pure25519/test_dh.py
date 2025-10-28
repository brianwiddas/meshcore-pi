import os, unittest
from binascii import hexlify
from pure25519.basic import encodepoint
from pure25519.dh import dh_start, dh_finish

class DH(unittest.TestCase):
    def assertElementsEqual(self, e1, e2):
        self.assertEqual(hexlify(encodepoint(e1)), hexlify(encodepoint(e2)))
    def assertBytesEqual(self, e1, e2):
        self.assertEqual(hexlify(e1), hexlify(e2))

    def test_dh(self):
        for i in range(10):
            x,X_s = dh_start(os.urandom)
            y,Y_s = dh_start(os.urandom)
            z1 = dh_finish(x, Y_s)
            z2 = dh_finish(y, X_s)
            self.assertBytesEqual(z1, z2)
