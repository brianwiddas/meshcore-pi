# python-pure25519

This contains a collection of pure-python functions to implement Curve25519-based cryptography, including:

* Diffie-Hellman Key Agreement
* Ed25519 digital signatures
* SPAKE2 Password Authenticated Key Agreement

You almost certainly want to use [pynacl](https://pypi.python.org/pypi/PyNaCl/) or [python-ed25519](https://pypi.python.org/pypi/ed25519) instead, which are python bindings to djb's C implementations of Curve25519/Ed25519 (and the rest of the NaCl suite).

Bad things about this module:

* much slower than C
* not written by djb, so probably horribly buggy and insecure
* very much not constant-time: leaks hamming weights like crazy

Good things about this module:

* can be used without a C compiler
* compatible with python2 and python3
* exposes enough point math (addition and scalarmult) to implement SPAKE2

## Slow

The pure-python functions are considerably slower than their pynacl (libsodium) equivalents, using python-2.7.9 on my 2.6GHz Core-i7:

| function       | pure25519 | pynacl (C) |
| -------------- | --------- | ---------- |
| Ed25519 sign   |    2.8 ms |     142 us |
| Ed25519 verify |   10.8 ms |     240 us |
| DH-start       |    2.8 ms |      72 us |
| DH-finish      |    5.4 ms |      89 us |
| SPAKE2 start   |    5.4 ms |        N/A |
| SPAKE2 finish  |    8.0 ms |        N/A |

This library is conservative, and performs full subgroup-membership checks on decoded points, which adds considerable overhead. The Curve25519/Ed25519 algorithms were designed to not require these checks, so a careful application might be able to improve on this slightly (Ed25519 verify down to
6.2ms, DH-finish to 3.2ms).

# Compatibility, and the lack thereof

The sample Diffie-Hellman key-agreement code in dh.py is not actually Curve25519: it uses the Ed25519 curve, which is sufficiently similar for security purposes, but won't interoperate with a proper Curve25519 implementation. It is included just to exercise the API and obtain a comparable performance number.

The Ed25519 implementation *should* be compatible with other versions, and includes the known-answer-tests from http://ed25519.cr.yp.to/software.html to confirm this.

The SPAKE2 implementation is new, and there's nothing else for it to interoperate with yet.

## Sources

This code is adapted and modified from a number of original sources,
including:

* https://bitbucket.org/dholth/ed25519ll
* http://ed25519.cr.yp.to/python/ed25519.py
* http://ed25519.cr.yp.to/software.html
* http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html

Many thanks to Ron Garret, Daniel Holth, and Matthew Dempsky.

## License

This software is released under the MIT license.
