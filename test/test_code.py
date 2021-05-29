# -*- coding: utf-8 -*-
# © Toons

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
