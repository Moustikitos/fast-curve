# -*- encoding:utf-8 -*-

from . import *
from . import _schnorr


# https://github.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js
def bcrypto410_sign(msg, seckey0):
    """
    Generate message signature according to `Bcrypto 4.10 schnorr <https://git\
hub.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js>`_ spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        secret0 (:class:`bytes`): private key
    Returns:
        :class:`bytes`: RAW signature
    """
    return _schnorr.bcrypto410_sign(msg, seckey0).contents.raw()


def bcrypto410_verify(msg, pubkey, sig):
    """
    Check if public key match message signature according to `Bcrypto 4.10 sch\
norr <https://github.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js>`_
    spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        pubkey (:class:`bytes`): encoded public key
        sig (:class:`bytes`): signature
    Returns:
        :class:`bool`: True if match
    """
    hS = HexSig.from_raw(sig)
    puk = PublicKey.decode(pubkey)
    return bool(_schnorr.bcrypto410_verify(msg, puk.x, puk.y, hS.r, hS.s))


def sign(msg, seckey0):
    """
    Generate message signature according to `BIP schnorr <https://github.com/b\
itcoin/bips/blob/master/bip-0340.mediawiki>`_ spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        seckey0 (:class:`bytes`): private key
    Returns:
        :class:`bytes`: RAW signature
    """
    k = rand_k() % n
    return _schnorr.sign(msg, seckey0, b"%x" % k).contents.raw()


# Note that bip schnorr uses a very different public key format (32 bytes) than
# the ones used by existing systems (which typically use elliptic curve points
# as public keys, 33-byte or 65-byte encodings of them). A side effect is that
# `PubKey(sk) = PubKey(bytes(n-int(sk))`, so every public key has two
# corresponding private keys.
def verify(msg, pubkey, sig):
    """
    Check if public key match message signature according to `BIP schnorr <htt\
ps://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>`_ spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        pubkey (:class:`bytes`): encoded public key x value
        sig (:class:`bytes`): signature
    Returns:
        :class:`bool`: True if match
    """
    hS = HexSig.from_raw(sig)
    puk = PublicKey.decode(pubkey)
    return bool(_schnorr.verify(msg, puk.x, hS.r, hS.s))
