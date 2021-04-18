# -*- coding: utf-8 -*-
# © Toons

from binascii import unhexlify
import cSecp256k1 as secp256k1
from cSecp256k1 import _ecdsa
from cSecp256k1 import _schnorr


msg = secp256k1.hash_sha256(b"message to sign")
pr_key = secp256k1.hash_sha256(b"secret")
pu_key = secp256k1.PublicKey.from_secret(b"secret")
enc_pu_key = secp256k1.PublicKey.from_secret(b"secret").encode()
rfc6979_k = b"%64x" % secp256k1.rfc6979_k(unhexlify(msg), unhexlify(pr_key))[0]
k = b"%64x" % secp256k1.rand_k()


class TestCSecp256k1Signatures:

    # def test_ecdsa_sign(self, benchmark):
    #     _k = int(k, 16)
    #     signer = ecdsa.sign
    #     sig = benchmark(signer, msg, pr_key, _k, canonical=True)
    #     assert ecdsa.verify(msg, enc_pu_key, sig) is True

    def test_C_ecdsa_sign(self, benchmark):
        signer = _ecdsa.sign
        sig = benchmark(signer, msg, pr_key, k, 1).contents
        assert _ecdsa.verify(msg, pu_key.x, pu_key.y, sig.r, sig.s) == 1

    # def test_ecdsa_rfc6949_sign(self, benchmark):
    #     signer = ecdsa.rfc6979_sign
    #     sig = benchmark(signer, msg, pr_key, canonical=True)
    #     assert ecdsa.verify(msg, enc_pu_key, sig) is True

    def test_C_ecdsa_rfc6949_sign(self, benchmark):
        signer = _ecdsa.sign
        sig = benchmark(signer, msg, pr_key, rfc6979_k, 1).contents
        assert _ecdsa.verify(msg, pu_key.x, pu_key.y, sig.r, sig.s) == 1

    # def test_schnorr_sign(self, benchmark):
    #     signer = schnorr.sign
    #     sig = benchmark(signer, msg, pr_key, k)
    #     assert schnorr.verify(msg, enc_pu_key, sig) is True

    def test_C_schnorr_sign(self, benchmark):
        signer = _schnorr.sign
        sig = benchmark(signer, msg, pr_key, k).contents
        assert _schnorr.verify(msg, pu_key.x, sig.r, sig.s) == 1

    # def test_schnorr_bcrypto410_sign(self, benchmark):
    #     signer = schnorr.bcrypto410_sign
    #     sig = benchmark(signer, msg, pr_key)
    #     assert schnorr.bcrypto410_verify(msg, enc_pu_key, sig) is True

    def test_C_schnorr_bcrypto410_sign(self, benchmark):
        signer = _schnorr.bcrypto410_sign
        sig = benchmark(signer, msg, pr_key).contents
        assert _schnorr.bcrypto410_verify(
            msg, pu_key.x, pu_key.y, sig.r, sig.s
        ) == 1
