from . import eddsa

# adapt pure25519/ed25519.py to behave like (C/glue) ed25519/_ed25519.py, so
# ed25519_oop.py doesn't have to change

# ed25519 secret/private/signing keys can be built from a 32-byte random seed
# (clamped and treated as a scalar). The public/verifying key is a 32-byte
# encoded group element. Signing requires both, so a common space/time
# tradeoff is to glue the two together and call the 64-byte combination the
# "secret key". Signatures are 64 bytes (one encoded group element and one
# encoded scalar). The NaCl code prefers to glue the signature to the
# message, rather than pass around detacted signatures.
#
# for clarity, we use the following notation:
#  seed: 32-byte secret random seed (unclamped)
#  sk: = seed
#  vk: 32-byte verifying key (encoded group element)
#  seed+vk: 64-byte glue thing (sometimes stored as secret key)
#  sig: 64-byte detached signature (R+S)
#  sig+msg: signature concatenated to message

# that glue provides:
#  SECRETKEYBYTES=64, PUBLICKEYBYTES=32, SIGNATUREBYTES=64
#  (vk,seed+vk)=publickey(seed)
#  sig+msg = sign(msg, seed+vk)
#  msg = open(sig+msg, vk) # or raise BadSignatureError

# pure25519/ed25519.py provides:
#  vk = publickey(sk)
#  sig = signature(msg, sk or sk+vk, vk)
#  bool = checkvalid(sig, msg, vk)

class BadSignatureError(Exception):
    pass

SECRETKEYBYTES = 64
PUBLICKEYBYTES = 32
SIGNATUREKEYBYTES = 64

def publickey(seed32):
    assert len(seed32) == 32
    vk32 = eddsa.publickey(seed32)
    return vk32, seed32+vk32

def sign(msg, skvk):
    assert len(skvk) == 64
    sk = skvk[:32]
    vk = skvk[32:]
    sig = eddsa.signature(msg, sk, vk)
    return sig+msg

def open(sigmsg, vk):
    assert len(vk) == 32
    sig = sigmsg[:64]
    msg = sigmsg[64:]
    try:
        valid = eddsa.checkvalid(sig, msg, vk)
    except ValueError as e:
        raise BadSignatureError(e)
    except Exception as e:
        if str(e) == "decoding point that is not on curve":
            raise BadSignatureError(e)
        raise
    if not valid:
        raise BadSignatureError()
    return msg
