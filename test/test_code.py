# -*- coding: utf-8 -*-
# © Toons

import hashlib
import ctypes
import cSecp256k1 as secp256k1


# from https://github.com/sipa/bips/blob/bip-taproot/bip-0340/reference.py
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


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
        c_h = secp256k1._schnorr.hash_sha256(b"secret")
        assert py_h == c_h

    def test_tagged_hash(self):
        tag = "BIP340/test"
        msg = b"tagged hash test"
        assert (
            tagged_hash(tag, msg).hex().encode() ==
            secp256k1.tagged_hash(tag, msg)
        )
