from __future__ import print_function
import sys
import unittest
from binascii import hexlify, unhexlify
import hashlib
from pure25519 import basic

if sys.version_info[0] == 2:
    def asbytes(b):
        """Convert array of integers to byte string"""
        return ''.join(chr(x) for x in b)
    def bit(h, i):
        """Return i'th bit of bytestring h"""
        return (ord(h[i//8]) >> (i%8)) & 1
else:
    asbytes = bytes
    def bit(h, i):
        return (h[i//8] >> (i%8)) & 1

b = 256 # =32*8
def H(m):
    return hashlib.sha512(m).digest()

class Compare(unittest.TestCase):
    # I want to replace some very manual (and slow) loops with builtins.
    # These tests are to ensure that the replacements work the same way

    # Hint turns bytes into a 512-bit integer, little-endian (the first byte
    # of H(m) is used for the low-order 8 bits of the integer, with the LSB
    # of H(m)[0] used as the LSB of the integer).
    def orig_Hint(self, m):
        h = H(m)
        return sum(2**i * bit(h,i) for i in range(2*b))
    def new_Hint(self, m):
        h = H(m)
        return int(hexlify(h[::-1]), 16)
    def test_Hint(self):
        for i in range(200):
            m = str(i).encode("ascii")
            self.assertEqual(self.orig_Hint(m), self.new_Hint(m))

    def orig_decodepoint_sum(self, s):
        # the original. 802us.
        y = sum(2**i * bit(s,i) for i in range(0,b-1))
        #print("%064x" % y)
        return y

    def new_decodepoint_sum_1(self, s):
        # the range(0,b-1) means we don't use the MSB of the last byte, so
        # the high-order bit of the int will be zero. In this form, we clamp
        # the int. 337us
        unclamped = int(hexlify(s[:32][::-1]), 16)
        clamp = (1 << 255) - 1
        clamped = unclamped & clamp
        return clamped

    def new_decodepoint_sum_2(self, s):
        # In this form, we remap the last byte before conversion. 340us
        s = s[:32]
        clamped_byte = unhexlify("%02x" % (int(hexlify(s[-2:]), 16) & 0x7f))
        clamped_s = s[:-1] + clamped_byte
        clamped = int(hexlify(clamped_s[::-1]), 16)
        #print("%064x" % clamped)
        return clamped

    def test_decodepoint_sum(self):
        for i in range(200):
            #print()
            s = H(str(i).encode("ascii"))[:32]
            self.assertEqual(self.orig_decodepoint_sum(s),
                             self.new_decodepoint_sum_1(s))
            self.assertEqual(self.new_decodepoint_sum_1(s),
                             self.new_decodepoint_sum_2(s))

    def orig_decodepoint_2(self, s):
        # already sped up once
        unclamped = int(hexlify(s[:32][::-1]), 16)
        clamp = (1 << 255) - 1
        y = unclamped & clamp
        x = basic.xrecover(y)
        if x & 1 != bit(s,b-1): x = basic.Q-x
        P = [x,y]
        if not basic.isoncurve(P):
            raise Exception("decoding point that is not on curve")
        return P

    def new_decodepoint_2(self, s):
        # already sped up once
        unclamped = int(hexlify(s[:32][::-1]), 16)
        clamp = (1 << 255) - 1
        y = unclamped & clamp
        x = basic.xrecover(y)
        if bool(x & 1) != bool(unclamped & (1<<255)): x = basic.Q-x
        P = [x,y]
        if not basic.isoncurve(P):
            raise Exception("decoding point that is not on curve")
        return P

    def test_decodepoint_2(self):
        for i in range(200):
            P_s = basic.Base.scalarmult(i).to_bytes()
            self.assertEqual(self.orig_decodepoint_2(P_s),
                             self.new_decodepoint_2(P_s))

    def orig_decodeint(self, s):
        return sum(2**i * bit(s,i) for i in range(0,b))
    def new_decodeint(self, s):
        return int(hexlify(s[:32][::-1]), 16)

    def test_decodeint(self):
        for i in range(200):
            s = H(str(i).encode("ascii"))[:32]
            self.assertEqual(self.orig_decodeint(s),
                             self.new_decodeint(s))

    def orig_signature_sum(self, sk):
        h = H(sk)
        a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
        #print("%064x" % a)
        return a

    def new_signature_sum(self, sk):
        h = H(sk)
        unclamped = int(hexlify(h[:32][::-1]), 16)
        # top byte is      01xxxxxx
        # middle bytes are xxxxxxxx
        # bottom byte is   xxxxx000
        top_reset_clamp = (0x40 << (31*8)) - 1
        bottom_reset_clamp = ((1 << (32*8)) - 1) ^ 0x7
        set_clamp = 0x40 << (31*8)
        clamped = (unclamped & top_reset_clamp & bottom_reset_clamp) | set_clamp
        #print("%064x" % unclamped)
        #print("%064x" % set_clamp)
        #print("%064x" % top_reset_clamp)
        #print("%064x" % bottom_reset_clamp)
        #print("%064x" % clamped)
        return clamped

    def test_signature_sum(self):
        for i in range(200):
            #print()
            sk = H(str(i).encode("ascii"))[:32]
            self.assertEqual(self.orig_signature_sum(sk),
                             self.new_signature_sum(sk))

    def orig_encodeint(self, y):
        bits = [(y >> i) & 1 for i in range(b)]
        e = [(sum([bits[i * 8 + j] << j for j in range(8)]))
                                        for i in range(b//8)]
        return asbytes(e)

    def new_encodeint(self, y):
        assert 0 <= y < 2**256
        return unhexlify("%064x" % y)[::-1]

    def test_encodeint(self):
        for i in range(200):
            s = H(str(i).encode("ascii"))[:32]
            sint = self.orig_decodeint(s)
            self.assertEqual(self.orig_encodeint(sint),
                             self.new_encodeint(sint))

    def orig_encodepoint(self, P):
        x = P[0]
        y = P[1]
        bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
        e = [(sum([bits[i * 8 + j] << j for j in range(8)]))
                                        for i in range(b//8)]
        return asbytes(e)

    def new_encodepoint(self, P):
        x = P[0]
        y = P[1]
        # MSB of output equals x.b0 (=x&1)
        # rest of output is little-endian y
        assert 0 <= y < (1<<255) # always < 0x7fff..ff
        if x & 1:
            y += 1<<255
        return unhexlify("%064x" % y)[::-1]

    def test_encodepoint(self):
        for i in range(200):
            P = basic.xform_extended_to_affine(basic.Base.scalarmult(i).XYTZ)
            self.assertEqual(self.orig_encodepoint(P),
                             self.new_encodepoint(P))
