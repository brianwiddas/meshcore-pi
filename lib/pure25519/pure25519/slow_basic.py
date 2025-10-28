
from pure25519.basic import (inv, d, Q, L,
                             xform_extended_to_affine,
                             scalarmult_element,
                             xform_affine_to_extended,
                             double_element, _add_elements_nonunfied)

# Affine Coordinates: only here to compare against faster versions

def slow_add_affine(A,B): # affine->affine
    # Complete: works even when A==B. Slow: 50x slower than extended
    x1 = A[0]
    y1 = A[1]
    x2 = B[0]
    y2 = B[1]
    x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
    y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
    return (x3 % Q,y3 % Q)

def slow_scalarmult_affine(A,e): # affine->affine
    e = e % L
    if e == 0: return [0,1]
    B = slow_scalarmult_affine(A,e//2)
    B = slow_add_affine(B,B)
    if e & 1: B = slow_add_affine(B,A)
    return B

# other functions that are only here for speed comparisons

def scalarmult_affine(pt, e): # affine->affine
    e = e % L
    return xform_extended_to_affine(
            scalarmult_element(
             xform_affine_to_extended(pt),
            e))

def scalarmult_affine_to_extended(pt, n): # affine->extended
    assert len(pt) == 2 # affine
    n = n % L
    if n==0: return xform_affine_to_extended((0,1))
    xpt = xform_affine_to_extended(pt) # so Z=1
    return _scalarmult_affine_to_extended_inner(xpt, n)

def _scalarmult_affine_to_extended_inner(xpt, n):
    if n==0: return xform_affine_to_extended((0,1))
    _ = double_element(_scalarmult_affine_to_extended_inner(xpt, n>>1))
    return _add_elements_nonunfied(_, xpt) if n&1 else _
