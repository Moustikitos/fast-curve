# -*- encoding:utf-8 -*-

import os
import sys
import hmac
import ctypes
import random
import hashlib
import binascii

from importlib import machinery
EXT = \
    ".dll" if sys.platform.startswith("win") else \
    machinery.all_suffixes()[-1]


def _setNget(cls, attr, value):
    v = getattr(cls, attr, None)
    if v != value:
        setattr(cls, attr, value)
        return value
    return v


class HexPoint(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_char * 65),
        ("y", ctypes.c_char * 65),
    ]

    def __setattr__(self, attr, value):
        if attr in HexPoint._fields_:
            delattr(self, "_"+attr, None)
        ctypes.Structure.__setattr__(self, attr, value)

    def __repr__(self):
        return "<secp256k1 point:\n  x:%s\n  y:%s\n>" % (self.x, self.y)

    def __getitem__(self, item):
        return self._xget() if item % 2 == 0 else self._yget()

    def __add__(self, hP):
        return _ecdsa.py_point_add(self.x, self.y, hP.x, hP.y).contents

    def __mul__(self, k):
        return _ecdsa.py_point_mul(self.x, self.y, b"%064x" % k).contents

    def _xget(self):
        return getattr(self, "_x", _setNget(self, "_x", int(self.x, 16)))

    def _yget(self):
        return getattr(self, "_y", _setNget(self, "_y", int(self.y, 16)))

    @staticmethod
    def from_int(x):
        return _ecdsa.hex_point_from_hex_x(b"%064x" % x).contents

    def encode(self):
        return _ecdsa.encoded_from_hex_puk(self.x, self.y)


class HexSig(ctypes.Structure):
    _fields_ = [
        ("r", ctypes.c_char * 65),
        ("s", ctypes.c_char * 65),
    ]

    def __setattr__(self, attr, value):
        if attr in HexSig._fields_:
            delattr(self, "_"+attr, None)
        ctypes.Structure.__setattr__(self, attr, value)

    def __repr__(self):
        return "<secp256k1 signature:\n  r:%s\n  s:%s\n>" % (self.r, self.s)

    def __getitem__(self, item):
        return self._rget() if item % 2 == 0 else self._sget()

    def _rget(self):
        return getattr(self, "_r", _setNget(self, "_r", int(self.r, 16)))

    def _sget(self):
        return getattr(self, "_s", _setNget(self, "_s", int(self.s, 16)))

    def der(self):
        r = self[0].to_bytes(32, byteorder="big")
        s = self[1].to_bytes(32, byteorder="big")
        r = (b'\x00' if (r[0] & 0x80) == 0x80 else b'') + r
        s = (b'\x00' if (s[0] & 0x80) == 0x80 else b'') + s
        return binascii.hexlify(
            b'\x30' + int((len(r)+len(s)+4)).to_bytes(1, 'big') +
            b'\x02' + int(len(r)).to_bytes(1, 'big') + r +
            b'\x02' + int(len(s)).to_bytes(1, 'big') + s
        )

    @staticmethod
    def from_der(der):
        sig = bytearray(binascii.unhexlify(der))
        sig_len = sig[1] + 2
        r_offset, r_len = 4, sig[3]
        s_offset, s_len = 4 + r_len + 2, sig[4 + r_len + 1]
        if (
            sig[0] != 0x30 or sig_len != r_len+s_len+6
            or sig[s_offset-2] != 0x02
        ):
            return HexSig(b"%064x" % 0, b"%064x" % 0)
        return HexSig(
            b"%064x" % int.from_bytes(sig[r_offset:r_offset + r_len], "big"),
            b"%064x" % int.from_bytes(sig[s_offset:s_offset + s_len], "big")
        )

    @staticmethod
    def from_raw(raw):
        return HexSig(raw[:64].lstrip(b"0"), raw[64:].lstrip(b"0"))

    def raw(self):
        return self.r.zfill(64) + self.s.zfill(64)


_ecdsa = ctypes.CDLL(
    os.path.abspath(os.path.join(__path__[0], "_ecdsa%s" % EXT))
)
_ecdsa.py_point_add.restype = ctypes.POINTER(HexPoint)
_ecdsa.py_point_mul.restype = ctypes.POINTER(HexPoint)
_ecdsa.hex_point_from_hex_x.restype = ctypes.POINTER(HexPoint)
_ecdsa.hex_puk_from_encoded.restype = ctypes.POINTER(HexPoint)
_ecdsa.encoded_from_hex_puk.restype = ctypes.c_char_p
_ecdsa.hex_puk_from_hex.restype = ctypes.POINTER(HexPoint)
_ecdsa.sign.restype = ctypes.POINTER(HexSig)
_ecdsa.hash_sha256.restype = ctypes.c_char_p
_ecdsa.init()

_schnorr = ctypes.CDLL(
    os.path.abspath(os.path.join(__path__[0], "_schnorr%s" % EXT))
)
_schnorr.sign.restype = ctypes.POINTER(HexSig)
_schnorr.bcrypto410_sign.restype = ctypes.POINTER(HexSig)
_schnorr.tagged_hash.restype = ctypes.c_char_p
_schnorr.init()


def rand_k():
    return random.getrandbits(p.bit_length()) % p


def rfc6979_k(msg, secret0, V=None):
    hasher = hashlib.sha256
    if (V is None):
        h1 = msg
        hsize = len(h1)
        V = b'\x01'*hsize
        K = b'\x00'*hsize
        x = secret0
        K = hmac.new(K, V + b'\x00' + x + h1, hasher).digest()
        V = hmac.new(K, V, hasher).digest()
        K = hmac.new(K, V + b'\x01' + x + h1, hasher).digest()
        V = hmac.new(K, V, hasher).digest()

    while True:
        T = b''
        p_blen = p.bit_length()
        while len(T)*8 < p_blen:
            V = hmac.new(K, V, hasher).digest()
            T = T + V
        k = int.from_bytes(T, "big")
        k_blen = k.bit_length()

        if k_blen > p_blen:
            k = k >> (k_blen - p_blen)
        if k > 0 and k < (p-1):
            return k, V
        K = hmac.new(K, V+b'\x00', hasher).digest()
        V = hmac.new(K, V, hasher).digest()


class PublicKey(HexPoint):

    @staticmethod
    def decode(enc):
        hPuk = _ecdsa.hex_puk_from_encoded(
            enc if isinstance(enc, bytes) else enc.encode()
        ).contents
        return PublicKey(hPuk.x, hPuk.y)

    @staticmethod
    def from_hex(value):
        hPuk = _ecdsa.hex_puk_from_hex(
            value if isinstance(value, bytes) else value.encode("utf-8")
        ).contents
        return PublicKey(hPuk.x, hPuk.y)

    @staticmethod
    def from_secret(secret):
        return PublicKey.from_hex(hash_sha256(secret))

    @staticmethod
    def from_int(value):
        return PublicKey.from_hex(b"%064x" % value)

    @staticmethod
    def from_seed(seed):
        return PublicKey.from_hex(binascii.hexlify(seed))


def tagged_hash(tag, msg):
    return _schnorr.tagged_hash(
        None,
        tag if isinstance(tag, bytes) else tag.encode(),
        msg if isinstance(msg, bytes) else msg.encode()
    )


def hash_sha256(msg):
    return hashlib.sha256(
        msg if isinstance(msg, bytes) else msg.encode()
    ).hexdigest().encode()


p = int(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f)
n = int(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)
G = HexPoint(
    b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


class KeyRing(int):

    def __new__(self, secret):
        h = hash_sha256(
            secret.encode("utf-8") if not isinstance(secret, bytes) else
            secret
        )
        return int.__new__(self, int(h, 16))

    def puk(self):
        return PublicKey.from_int(self)

    def sig(self, obj):
        if isinstance(obj, bytes):
            return (
                HexSig.from_der if len(obj) > 128 else HexSig.from_raw
            )(obj)
        elif isinstance(obj, HexSig):
            return obj
        else:
            raise TypeError("%s is not a valid signature")


class Bcrpt410(KeyRing):

    def sign(self, data):
        return _schnorr.bcrypto410_sign(
            hash_sha256(data), b"%64x" % self
        ).contents

    def verify(self, data, sig):
        msg = hash_sha256(data)
        hS = self.sig(sig)
        puk = self.puk()
        return bool(_schnorr.bcrypto410_verify(msg, puk.x, puk.y, hS.r, hS.s))


class Schnorr(KeyRing):

    def sign(self, data, k=None, rfc6979=False):
        msg = hash_sha256(data)
        self_ = b"%64x" % self
        if k is None:
            if not rfc6979:
                k = b"%064x" % (rand_k() % n)
            else:
                k = b"%064x" % rfc6979_k(
                    binascii.unhexlify(msg), binascii.unhexlify(self_)
                )[0]
        return _schnorr.sign(msg, self_, k).contents

    def verify(self, data, sig):
        msg = hash_sha256(data)
        hS = self.sig(sig)
        puk = self.puk()
        return bool(_schnorr.verify(msg, puk.x, hS.r, hS.s))


class Ecdsa(KeyRing):

    def sign(self, data, k=None, rfc6979=False, canonical=True):
        msg = hash_sha256(data)
        self_ = b"%64x" % self
        if k is None:
            if not rfc6979:
                k = b"%064x" % (rand_k() % n)
            else:
                k = b"%064x" % rfc6979_k(
                    binascii.unhexlify(msg), binascii.unhexlify(self_)
                )[0]
        return _ecdsa.sign(msg, self_, k, 1 if canonical else 0).contents

    def verify(self, data, sig):
        msg = hash_sha256(data)
        hS = self.sig(sig)
        puk = self.puk()
        return bool(_ecdsa.verify(msg, puk.x, puk.y, hS.r, hS.s))
