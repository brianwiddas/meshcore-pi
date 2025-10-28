import os, unittest
from binascii import hexlify
from pure25519.spake2 import start_U, finish_U, start_V, finish_V, U, V

class SPAKE2(unittest.TestCase):
    def assertBytesEqual(self, e1, e2):
        self.assertEqual(hexlify(e1), hexlify(e2))

    def test_success(self):
        pw = b"password"
        sd_U,X = start_U(pw, os.urandom, b"idA", b"idB")
        sd_V,Y = start_V(pw, os.urandom, b"idA", b"idB")
        K1 = finish_U(sd_U,Y)
        K2 = finish_V(sd_V,X)
        self.assertBytesEqual(K1, K2)

    def test_failure(self):
        sd_U,X = start_U(b"password", os.urandom, b"idA", b"idB")
        sd_V,Y = start_V(b"wrong", os.urandom, b"idA", b"idB")
        K1 = finish_U(sd_U,Y)
        K2 = finish_V(sd_V,X)
        self.assertNotEqual(hexlify(K1), hexlify(K2))

    def test_blinding_factors(self):
        self.assertEqual(hexlify(U.to_bytes()).decode("ascii"), expected_U)
        self.assertEqual(hexlify(V.to_bytes()).decode("ascii"), expected_V)

expected_U = "6d7107929f9fb8ddeb0788f4bd6cd0a39b5cdcf71b03c41029aae74eda5f64f3"
expected_V = "48032d6a3406ad4860cca367750cea4f26ea14265ad57ffc6aefe9bf68994054"
