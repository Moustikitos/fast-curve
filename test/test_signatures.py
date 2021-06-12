# -*- coding: utf-8 -*-
# © Toons

from binascii import unhexlify
import cSecp256k1 as secp256k1
from cSecp256k1 import _ecdsa
from cSecp256k1 import _schnorr


msg = secp256k1.hash_sha256(b"message to sign")
_msg = secp256k1.hash_sha256(b"bad message to check")
pr_key = secp256k1.hash_sha256(b"secret")
pu_key = secp256k1.PublicKey.from_secret(b"secret")
enc_pu_key = secp256k1.PublicKey.from_secret(b"secret").encode()
k = b"%064x" % secp256k1.rand_k()
rfc6979_k = b"%064x" % secp256k1.rfc6979_k(
    unhexlify(msg), unhexlify(pr_key)
)[0]


class TestCSecp256k1Signatures:

    def test_C_ecdsa_sign(self, benchmark):
        signer = _ecdsa.sign
        sig = benchmark(signer, msg, pr_key, k, 1).contents
        assert not _ecdsa.verify(_msg, pu_key.x, pu_key.y, sig.r, sig.s)

    def test_C_ecdsa_verify(self, benchmark):
        sig = _ecdsa.sign(msg, pr_key, k, 1).contents
        verifier = _ecdsa.verify
        assert benchmark(verifier, msg, pu_key.x, pu_key.y, sig.r, sig.s)

    def test_C_ecdsa_rfc6949_sign(self, benchmark):
        signer = _ecdsa.sign
        sig = benchmark(signer, msg, pr_key, rfc6979_k, 1).contents
        assert not _ecdsa.verify(_msg, pu_key.x, pu_key.y, sig.r, sig.s)

    def test_C_ecdsa_rfc6949_verify(self, benchmark):
        sig = _ecdsa.sign(msg, pr_key, rfc6979_k, 1).contents
        verifier = _ecdsa.verify
        assert benchmark(verifier, msg, pu_key.x, pu_key.y, sig.r, sig.s)

    def test_C_schnorr_bcrypto410_sign(self, benchmark):
        signer = _schnorr.bcrypto410_sign
        sig = benchmark(signer, msg, pr_key).contents
        assert not _schnorr.bcrypto410_verify(
            _msg, pu_key.x, pu_key.y, sig.r, sig.s
        )

    def test_C_schnorr_bcrypto410_verify(self, benchmark):
        sig = _schnorr.bcrypto410_sign(msg, pr_key).contents
        verifier = _schnorr.bcrypto410_verify
        assert benchmark(verifier, msg, pu_key.x, pu_key.y, sig.r, sig.s)

    def test_C_schnorr_sign(self, benchmark):
        signer = _schnorr.sign
        sig = benchmark(signer, msg, pr_key, k).contents
        assert not _schnorr.verify(_msg, pu_key.x, sig.r, sig.s)

    def test_C_schnorr_verify(self, benchmark):
        sig = _schnorr.sign(msg, pr_key, k).contents
        verifier = _schnorr.verify
        assert benchmark(verifier, msg, pu_key.x, sig.r, sig.s)


try:
    from pySecp256k1 import schnorr
    import binascii

    class TestCompare:
        def test_schnorr(self):
            signer = _schnorr.bcrypto410_sign
            sig = signer(msg, pr_key).contents
            assert sig.raw() == binascii.hexlify(
                schnorr.bcrypto410_sign(
                    binascii.unhexlify(msg), binascii.unhexlify(pr_key)
                )
            )

except ImportError:
    pass
