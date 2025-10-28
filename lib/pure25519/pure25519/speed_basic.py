import timeit

def do(setup_statements, statement):
    # extracted from timeit.py
    t = timeit.Timer(stmt=statement,
                     setup="\n".join(setup_statements))
    # determine number so that 0.2 <= total time < 2.0
    for i in range(1, 10):
        number = 10**i
        x = t.timeit(number)
        if x >= 1.0:
            break
    return x / number

def abbrev(t):
    if t > 1.0:
        return "%.3fs" % t
    if t > 1e-3:
        return "%.2fms" % (t*1e3)
    if t > 1e-6:
        return "%.2fus" % (t*1e6)
    return "%.2fns" % (t*1e9)

def p(name, setup_statements, statements):
    t = sorted([do(setup_statements, statements) for i in range(3)])
    print("%-32s: %s (%s)" % (name,
                             abbrev(min(t)),
                             " ".join([abbrev(s) for s in t])))

# pure_ed25519.sign() is doing an extra publickey(), doubles the cost

def run():
    S1 = "from pure25519 import basic, slow_basic"
    S2 = "p=slow_basic.scalarmult_affine(basic.B, 16*1000000000)"
    S3 = "P=basic.encodepoint(p)"
    S4 = "basic.decodepoint(P)"
    S5big =   r"i = b'\xf0'+b'\xff'*31"
    S5medium =   r"i = b'\xf0'+b'\x55'*31"
    S5small = r"i = b'\xf0'+b'\x00'*31"
    S6 = "si=basic.bytes_to_scalar(i)"
    S7 = "basic.scalar_to_bytes(si)"
    S8 = "slow_basic.slow_scalarmult_affine(p, si)"
    S9 = "slow_basic.scalarmult_affine(p, si)"
    S10 = "x=basic.xform_affine_to_extended(p)"
    S11 = "basic.xform_extended_to_affine(x)"
    S12 = "p2 = slow_basic.scalarmult_affine(basic.B, 17)"
    S13 = "slow_basic.slow_add_affine(p, p2)"
    S14 = "x2=basic.xform_affine_to_extended(p2)"
    S15 = "basic.add_elements(x, x2)"
    S16 = "basic.xrecover(basic.Bx)"
    S17 = "basic.isoncurve(p)"
    S18 = "(si + si) % basic.Q"
    S19 = "(si * si) % basic.Q"
    S20 = "basic.inv(si)"
    S21 = "basic._add_elements_nonunfied(x, x2)"
    S22 = "e=basic.bytes_to_unknown_group_element(P)"
    S23 = "e=basic.bytes_to_element(P)"
    S24 = "e=basic.arbitrary_element(b'seed')"
    S25 = "e.scalarmult(si)"

    print("speed_basic")
    if 1:
        p("encodepoint", [S1,S2], S3)
        p("decodepoint", [S1,S2,S3], S4)
        p("scalar_to_bytes", [S1,S5big,S6], S7)
        p("bytes_to_scalar", [S1,S5big], S6)
        p("slow_scalarmult_affine (big)", [S1,S2,S5big,S6], S8)
        p("slow_scalarmult_affine (medium)", [S1,S2,S5medium,S6], S8)
        p("slow_scalarmult_affine (small)", [S1,S2,S5small,S6], S8)
        p("scalarmult_affine (big)", [S1,S2,S5big,S6], S9)
        p("scalarmult_affine (medium)", [S1,S2,S5medium,S6], S9)
        p("scalarmult_affine (small)", [S1,S2,S5small,S6], S9)
        p("xform_affine_to_extended", [S1,S2], S10)
        p("xform_extended_to_affine", [S1,S2,S10], S11)
        p("slow_add_affine", [S1,S2,S12], S13)
        p("add (extended)", [S1,S2,S12,S10,S14], S15)
        p("add_nonunified (extended)", [S1,S2,S12,S10,S14], S21)
        p("xrecover", [S1], S16)
        p("isoncurve", [S1,S2], S17)
    if 1:
        p("field_add", [S1,S5medium,S6], S18)
        p("field_mul (big)", [S1,S5big,S6], S19)
        p("field_mul (medium)", [S1,S5medium,S6], S19)
        p("field_mul (small)", [S1,S5small,S6], S19)
        p("field_inv", [S1,S5medium,S6], S20)
    if 1:
        p("bytes_to_unknown_group_element", [S1,S2,S3], S22)
        p("bytes_to_element", [S1,S2,S3], S23)
        p("arbitrary_element", [S1], S24)
        p("scalarmult(unknown-medium)", [S1,S2,S3,S22,S5medium,S6], S25)
        p("scalarmult(medium)", [S1,S2,S3,S23,S5medium,S6], S25)

if __name__ == "__main__":
    run()
