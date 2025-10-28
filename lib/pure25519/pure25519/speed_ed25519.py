import timeit

def do(setup_statements, statement):
    # extracted from timeit.py
    t = timeit.Timer(stmt=statement,
                     setup="\n".join(setup_statements))
    # determine number so that 1.0 <= total time < 10.0
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
    return "%.2fus" % (t*1e6)

def p(name, setup_statements, statements):
    t = sorted([do(setup_statements, statements) for i in range(3)])
    print("%12s: %s (%s)" % (name,
                             abbrev(min(t)),
                             " ".join([abbrev(s) for s in t])))

def run():
    S1 = "from pure25519 import ed25519_oop; msg=b'hello world'"
    S2 = "sk,vk = ed25519_oop.create_keypair()"
    S3 = "sig = sk.sign(msg)"
    S4 = "vk.verify(sig, msg)"

    print("speed_ed25519")
    p("generate", [S1], S2)
    p("sign", [S1, S2], S3)
    p("verify", [S1, S2, S3], S4)

    S5 = "from pure25519 import eddsa"
    S6 = "h=eddsa.Hint(b'')"
    S7 = "eddsa.checkvalid(sig, msg, vk.vk_s)"

    p("Hint", [S5], S6)
    p("checkvalid", [S1,S2,S3,S5], S7)

if __name__ == "__main__":
    run()
