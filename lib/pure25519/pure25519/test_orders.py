import unittest
from binascii import hexlify
from pure25519.basic import Zero, ElementOfUnknownGroup
from pure25519.basic import xform_affine_to_extended, L, bytes_to_unknown_group_element

ORDERS = {1: "1", 2: "2", 4: "4", 8: "8",
          1*L: "1*L", 2*L: "2*L", 4*L: "4*L", 8*L: "8*L"}
def get_order(e):
    for o in sorted(ORDERS):
        if e.scalarmult(o) == Zero:
            return o

class Orders(unittest.TestCase):
    def assertElementsEqual(self, e1, e2, msg=None):
        self.assertEqual(hexlify(e1.to_bytes()), hexlify(e2.to_bytes()),
                         msg)

    def collect(self, e):
        values = set()
        for i in range(400):
            values.add(e.scalarmult(i).to_bytes())
        return values

    def test_orders(self):
        # all points should have an order that's listed in ORDERS. Test some
        # specific points. For low-order points, actually find the complete
        # subgroup and measure its size.

        p = Zero
        values = self.collect(p)
        self.assertEqual(len(values), 1)
        self.assertEqual(values, set([Zero.to_bytes()]))
        self.assertEqual(get_order(p), 1)

        # (0,-1) should be order 2
        p = ElementOfUnknownGroup(xform_affine_to_extended((0,-1)))
        values = self.collect(p)
        self.assertEqual(len(values), 2)
        self.assertEqual(values, set([Zero.to_bytes(), p.to_bytes()]))
        self.assertEqual(get_order(p), 2)

        # (..,26) is in the right group (order L)
        b = b"\x1a" + b"\x00"*31
        p = bytes_to_unknown_group_element(b)
        self.assertEqual(get_order(p), L)

        # (..,35) is maybe order 2*L
        b = b"\x23" + b"\x00"*31
        p = bytes_to_unknown_group_element(b)
        self.assertEqual(get_order(p), 2*L)

        # (..,48) is maybe order 4*L
        b = b"\x30" + b"\x00"*31
        p = bytes_to_unknown_group_element(b)
        self.assertEqual(get_order(p), 4*L)

        # (..,55) is maybe order 8*L
        b = b"\x37" + b"\x00"*31
        p = bytes_to_unknown_group_element(b)
        self.assertEqual(get_order(p), 8*L)
