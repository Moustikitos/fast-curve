#ifndef _ECDSA_H
#define _ECDSA_H

#include "secp256k1.h"

Sig *ecdsa_sign(mpz_t msg, mpz_t secret0, mpz_t k, short canonical);
short ecdsa_verify(mpz_t msg, Point *pubkey, Sig *sig);

#endif
