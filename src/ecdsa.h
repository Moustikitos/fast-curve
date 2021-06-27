#ifndef _ECDSA_H
#define _ECDSA_H

#include "secp256k1.h"

Sig *ecdsa_sign(Sig *sig, mpz_t msg, mpz_t secret0, mpz_t k, short canonical);
EXPORT HexSig *sign(char *digest, char *secret, char *nonce, short canonical);
EXPORT short verify(char *msg, char *x, char *y, char *hr, char*hs);

#endif
