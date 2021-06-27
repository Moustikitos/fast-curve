# -*- coding: utf-8 -*-
# © Toons

import ctypes
import hashlib
import binascii
import cSecp256k1 as secp256k1


# from https://github.com/sipa/bips/blob/bip-taproot/bip-0340/reference.py
def tagged_hash(tag, msg):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


class TestCSecp256k1Hash:

    def test_hex_point(self):
        G = secp256k1.HexPoint.from_int(secp256k1.G[0])
        assert G.x == secp256k1.G.x and G.y == secp256k1.G.y
        G = secp256k1.HexPoint.from_hex(secp256k1.G.x)
        assert G.x == secp256k1.G.x and G.y == secp256k1.G.y
        G = secp256k1.PublicKey.decode(secp256k1.G.encode())
        assert G.x == secp256k1.G.x and G.y == secp256k1.G.y

    def test_puk(self):
        puk0 = secp256k1.PublicKey.from_secret(b"secret")
        seed = hashlib.sha256(b"secret").digest()
        value = int(binascii.hexlify(seed), 16)
        puk = secp256k1.PublicKey.from_seed(seed)
        assert puk.x == puk0.x and puk.y == puk0.y
        puk = secp256k1.PublicKey.from_hex(binascii.hexlify(seed))
        assert puk.x == puk0.x and puk.y == puk0.y
        puk = secp256k1.PublicKey.from_int(value)
        assert puk.x == puk0.x and puk.y == puk0.y
        puk = secp256k1.PublicKey.decode(puk0.encode())
        assert puk.x == puk0.x and puk.y == puk0.y

    def test_algebra(self):
        GpG = secp256k1.G + secp256k1.G
        _2G = secp256k1.G * 2
        assert _2G.x == GpG.x and _2G.y == GpG.y

    def test_hash_sha256(self):
        secp256k1._schnorr.hash_sha256.restype = ctypes.c_char_p
        assert secp256k1.hash_sha256(
            b"secret"
        ) == secp256k1._schnorr.hash_sha256(
            b"secret"
        )

    def test_tagged_hash(self):
        tag = "BIP340/test"
        msg = b"tagged hash test"
        assert binascii.hexlify(
            tagged_hash(tag, msg)
        ) == secp256k1.tagged_hash(
            tag, msg
        )
