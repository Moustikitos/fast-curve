# -*- encoding:utf-8 -*-

import binascii
from . import *
from . import _ecdsa


def sign(msg, secret0, k=None, canonical=True):
    """
    Generate signature according to ``ECDSA`` scheme.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        secret0 (:class:`bytes`): private key
        k (:class:`int`): nonce (random nonce used if k=None)
        canonical (:class:`bool`): canonalize signature
    Returns:
        :class:`bytes`: DER signature
    """
    if not k:
        k = rand_k() % n
    return _ecdsa.sign(
        msg, secret0, b"%x" % k, 1 if canonical else 0
    ).contents.der()


def rfc6979_sign(msg, secret0, canonical=True):
    """
    Generate signature according to ``ECDSA`` scheme using a `RFC-6979 nonce <\
https://tools.ietf.org/html/rfc6979#section-3.2>`_

    Args:
        msg (:class:`bytes`): sha256 message-hash
        secret0 (:class:`bytes`): private key
        canonical (:class:`bool`): canonalize signature
    Returns:
        :class:`bytes`: DER signature
    """
    return sign(
        msg, secret0, rfc6979_k(
            binascii.unhexlify(msg), binascii.unhexlify(secret0)
        )[0], canonical
    )


def verify(msg, pubkey, sig):
    """
    Check signature according to ``ECDSA`` scheme.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        pubkey (:class:`bytes`): encoded public key
        sig (:class:`bytes`): DER signature
    Returns:
        :class:`bool`: True if match
    """
    hS = HexSig.from_der(sig)
    puk = PublicKey.decode(pubkey)
    return bool(_ecdsa.verify(msg, puk.x, puk.y, hS.r, hS.s))
