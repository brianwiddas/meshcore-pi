from hashlib import sha256
from pure25519.basic import (arbitrary_element, bytes_to_element, Base,
                             random_scalar, password_to_scalar)

# a,b random. X=G*a+U*pw. Y=G*b+V*pw. Z1=(Y-V*pw)*a. Z2=(X-U*pw)*b

U = arbitrary_element(b"U")
V = arbitrary_element(b"V")

def _start(pw, entropy_f, blinding):
    a = random_scalar(entropy_f)
    pw_scalar = password_to_scalar(pw)
    X = Base.scalarmult(a).add(blinding.scalarmult(pw_scalar))
    X_s = X.to_bytes()
    return (a, pw_scalar), X_s

def _finish(start_data, Y_s, blinding):
    (a, pw_scalar) = start_data
    Y = bytes_to_element(Y_s) # rejects zero and non-group
    Z = Y.add(blinding.scalarmult(-pw_scalar)).scalarmult(a)
    return Z.to_bytes()


def start_U(pw, entropy_f, idA, idB, U=U, V=V):
    sdata, X_s = _start(pw, entropy_f, U)
    start_data = (sdata, pw, X_s, idA, idB, U, V)
    return start_data, X_s

def finish_U(start_data, Y_s):
    (sdata, pw, X_s, idA, idB, U, V) = start_data
    Z_s = _finish(sdata, Y_s, V)
    transcript = idA + idB + X_s + Y_s + Z_s + pw
    key = sha256(transcript).digest()
    return key


def start_V(pw, entropy_f, idA, idB, U=U, V=V):
    sdata, Y_s = _start(pw, entropy_f, V)
    start_data = (sdata, pw, Y_s, idA, idB, U, V)
    return start_data, Y_s

def finish_V(start_data, X_s):
    (sdata, pw, Y_s, idA, idB, U, V) = start_data
    Z_s = _finish(sdata, X_s, U)
    transcript = idA + idB + X_s + Y_s + Z_s + pw
    key = sha256(transcript).digest()
    return key

