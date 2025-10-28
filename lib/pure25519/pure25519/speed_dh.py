import timeit

def do(setup_statements, statement):
    # extracted from timeit.py
    t = timeit.Timer(stmt=statement,
                     setup="\n".join(setup_statements))
    # determine number so that 0.2 <= total time < 2.0
    for i in range(1, 10):
        number = 10**i
        x = t.timeit(number)
        if x >= 0.5:
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
    S1 = "import os; from pure25519 import dh"
    S2 = "x,X_s = dh.dh_start(os.urandom)"
    S3 = "y,Y_s = dh.dh_start(os.urandom)"
    S4 = "dh.dh_finish(x,Y_s)"

    print("speed_dh")
    p("start", [S1], S2)
    p("finish", [S1, S2, S3], S4)

if __name__ == "__main__":
    run()
