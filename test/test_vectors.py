# -*- coding: utf-8 -*-
# © Toons

import os
import io
import ctypes
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

    def testVector1to3(self):
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

    def testVector4(self):
        secret0, pubkey, rnd, msg, sig, result = read_vector(VECTORS[3])
        print("secret0 =", secret0)
        print("pubkey =", pubkey)
        print("rnd =", rnd)
        print("msg =", msg)

        assert secp256k1.PublicKey.from_hex(secret0).x == pubkey
        assert (
            secp256k1._schnorr.sign(msg, secret0, rnd).contents.raw() ==
            sig
        )

    # def testVector4(self):
    #     v = VECTORS[3]
    #     pubkey = binascii.unhexlify(v["public key"])
    #     msg = binascii.unhexlify(v["message"])
    #     sig = binascii.unhexlify(v["signature"])

    #     msg_mod_p = schnorr.bytes_from_int(
    #         schnorr.int_from_bytes(msg) % schnorr.p
    #     )
    #     self.assertEqual(False, schnorr.verify(msg_mod_p, pubkey, sig))
    #     msg_mod_n = schnorr.bytes_from_int(
    #         schnorr.int_from_bytes(msg) % schnorr.n
    #     )
    #     self.assertEqual(False, schnorr.verify(msg_mod_n, pubkey, sig))

    # def testVector5(self):
    #     v = VECTORS[4]
    #     pubkey = binascii.unhexlify(v["public key"])
    #     msg = binascii.unhexlify(v["message"])
    #     sig = binascii.unhexlify(v["signature"])
    #     result = v["verification result"] == 'True'
    #     self.assertRaises(ValueError, schnorr.point_from_encoded, pubkey)
    #     self.assertEqual(result, schnorr.verify(msg, pubkey, sig))
