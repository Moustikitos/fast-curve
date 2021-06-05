# -*- coding: utf-8 -*-
# © Toons

import os
import io
import cSecp256k1 as secp256k1


with io.open(
    os.path.join(os.path.dirname(__file__), "test_vectors.csv"), "r"
) as test_vectors:
    SCHNORR_TEST_VECTORS = test_vectors.read().split("\n")

VECTORS = []
header = [e.strip() for e in SCHNORR_TEST_VECTORS[0].split(";")]
for column in SCHNORR_TEST_VECTORS[1:]:
    VECTORS.append(dict(zip(header, column.split(";"))))


def read_vector(v):
    return (
        v["secret key"].lower().encode(),
        v["public key"].lower().encode(),
        v["aux_rand"].lower().encode(),
        v["message"].lower().encode(),
        v["signature"].lower().encode(),
        v["verification result"].lower() == 'true'
    )


class TestSchnorrVectors:

    def testVector0to2(self):
        for v in VECTORS[:3]:
            secret0, pubkey, rnd, msg, sig, result = read_vector(v)
            print("secret0 =", secret0)
            print("pubkey =", pubkey)
            print("rnd =", rnd)
            print("msg =", msg)

            assert secp256k1.PublicKey.from_hex(secret0).x == pubkey
            assert (
                secp256k1._schnorr.sign(msg, secret0, rnd).contents.raw() ==
                sig
            ) == result

    def testVector3(self):
        secret0, pubkey, rnd, msg, sig, result = read_vector(VECTORS[3])
        print("secret0 =", secret0)
        print("pubkey =", pubkey)
        print("rnd =", rnd)
        print("msg =", msg)

        assert secp256k1.PublicKey.from_hex(secret0).x == pubkey
        assert (
            secp256k1._schnorr.sign(msg, secret0, rnd).contents.raw() ==
            sig
        ) == result

        msg_mod_p = b"%064x" % (int(msg, 16) % secp256k1.p)
        msg_mod_n = b"%064x" % (int(msg, 16) % secp256k1.n)
        r, s = sig[:64], sig[64:]
        assert not secp256k1._schnorr.verify(msg_mod_p, pubkey, r, s)
        assert not secp256k1._schnorr.verify(msg_mod_n, pubkey, r, s)

    def testVector4to14(self):
        for v in VECTORS[4:]:
            secret0, pubkey, rnd, msg, sig, result = read_vector(VECTORS[4])
            print("pubkey =", pubkey)
            print("msg =", msg)
            print("sig =", sig)

            r, s = sig[:64], sig[64:]
            assert (
                secp256k1._schnorr.verify(msg, pubkey, r, s) == 1
            ) == result
