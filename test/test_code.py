# -*- coding: utf-8 -*-
# © Toons

import ctypes
import cSecp256k1 as secp256k1


class TestCSecp256k1Hash:

    def test_hex_point(self):
        G = secp256k1.PublicKey.decode(secp256k1.G.encode())
        assert G.x == secp256k1.G.x
        assert G.y == secp256k1.G.y

    def test_algebra(self):
        _2G = secp256k1.G * 2
        GpG = secp256k1.G + secp256k1.G
        assert _2G.x == GpG.x
        assert _2G.y == GpG.y

    def test_hash_sha256(self):
        secp256k1._schnorr.hash_sha256.restype = ctypes.c_char_p
        py_h = secp256k1.hash_sha256(b"secret")
        c_h = secp256k1._schnorr.hash_sha256(None, b"secret")
        assert py_h == c_h

    def test_hexlification(self):
        secp256k1._schnorr.unhexlify.restype = ctypes.c_char_p
        secp256k1._schnorr.hexlify.restype = ctypes.c_char_p
        hexlified = secp256k1._schnorr.hexlify(b"secret", 6)
        unhexlified = secp256k1._schnorr.unhexlify(
            hexlified, len(hexlified)
        )
        assert unhexlified == b"secret"
